<?php

declare(strict_types=1);

namespace Coder999\SingleAuth;

use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PDO;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class Passkeys
{
    private PDO $pdo;
    private Auth $auth;
    private string $rpId;
    /**
     * Kept because `rp_name` is part of this library's approved public
     * API, but deliberately never handed to webauthn-lib: see
     * creationOptions() for why the library gets '' instead.
     */
    private string $rpName;
    private int $challengeTtl;
    private ?AttestationStatementSupportManager $attestationSupport = null;
    private ?SerializerInterface $serializer = null;

    public function __construct(PDO $pdo, Auth $auth, array $options = [])
    {
        if (empty($options['rp_id'])) {
            throw new InvalidArgumentException('Passkeys requires an rp_id option.');
        }
        $this->pdo = $pdo;
        $this->auth = $auth;
        $this->rpId = (string)$options['rp_id'];
        $this->rpName = (string)($options['rp_name'] ?? 'single-auth');
        $this->challengeTtl = (int)($options['challenge_ttl'] ?? 120);
    }

    /**
     * The WebAuthn spec's own RP ID rule: an origin is valid when it is
     * https and its host is the RP ID or a subdomain of it.
     *
     * There is deliberately no way to relax this. Local development is
     * plain HTTP and therefore cannot use passkeys at all; that is a
     * known, accepted consequence, not a bug to work around.
     */
    public function originMatchesRpId(string $origin): bool
    {
        $parts = parse_url($origin);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https') {
            return false;
        }
        $host = $parts['host'] ?? '';
        if ($host === '') {
            return false;
        }
        return $host === $this->rpId || str_ends_with($host, '.' . $this->rpId);
    }

    /**
     * Returns the credential creation options as JSON, for the browser to
     * hand to navigator.credentials.create().
     */
    public function beginRegistration(int $userId, string $label): string
    {
        $challenge = random_bytes(32);
        $options = $this->creationOptions($userId, $challenge);

        // Stored base64url so the challenge survives session serialisation
        // as text; the library wants the raw bytes back on the way in.
        $this->storeChallenge(self::b64u($challenge), 'register', $label);

        return $this->serializer()->serialize($options, 'json');
    }

    /**
     * Validates the authenticator's attestation response and, if it is
     * good, enrols the credential. Returns false on any rejection; the
     * challenge is consumed either way.
     */
    public function finishRegistration(int $userId, string $clientJson): bool
    {
        $challenge = $this->consumeChallenge('register');
        $label = (string)($_SESSION['passkey_label'] ?? '');
        unset($_SESSION['passkey_label']);
        if ($challenge === null) {
            return false;
        }

        try {
            $credential = $this->serializer()->deserialize($clientJson, PublicKeyCredential::class, 'json');
            // The denormalizer returns a bare array, not an object, when the
            // payload has no top-level "id" key -- it does not throw.
            if (!$credential instanceof PublicKeyCredential) {
                return false;
            }
            $response = $credential->response;
            if (!$response instanceof AuthenticatorAttestationResponse) {
                return false;
            }

            // Our own rule is the gate, and it runs before anything else
            // looks at this response. Only an origin it has already
            // accepted is then given to the library as its allowed origin,
            // so this codebase states the origin rule exactly once and has
            // no second copy of it to drift.
            $origin = $response->clientDataJSON->origin;
            if (!$this->originMatchesRpId($origin)) {
                return false;
            }

            $validator = AuthenticatorAttestationResponseValidator::create(
                $this->ceremonyFactory($origin)->creationCeremony()
            );
            $record = $validator->check(
                $response,
                $this->creationOptions($userId, self::b64uDecode($challenge)),
                (string)parse_url($origin, PHP_URL_HOST),
            );
        } catch (Throwable) {
            // check() signals failure by throwing, and a malformed payload
            // throws out of deserialize(). Neither is something the caller
            // can act on beyond "that did not work".
            return false;
        }

        $now = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->pdo->prepare(
            'INSERT INTO user_credentials
                (user_id, credential_id, public_key, sign_count, transports, label, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $userId,
            self::b64u($record->publicKeyCredentialId),
            self::b64u($record->credentialPublicKey),
            $record->counter,
            $record->transports === [] ? null : implode(',', $record->transports),
            $label,
            $now,
        ]);

        return true;
    }

    public function userHandle(int $userId): ?string
    {
        $st = $this->pdo->prepare('SELECT webauthn_user_handle FROM users WHERE id = ?');
        $st->execute([$userId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return ($row === false || $row['webauthn_user_handle'] === null)
            ? null
            : (string)$row['webauthn_user_handle'];
    }

    private function ensureUserHandle(int $userId): string
    {
        $existing = $this->userHandle($userId);
        if ($existing !== null) {
            return $existing;
        }
        $handle = self::b64u(random_bytes(32));
        $this->pdo->prepare('UPDATE users SET webauthn_user_handle = ? WHERE id = ?')
            ->execute([$handle, $userId]);
        return $handle;
    }

    public static function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public static function b64uDecode(string $encoded): string
    {
        return (string)base64_decode(strtr($encoded, '-_', '+/'), true);
    }

    private function storeChallenge(string $challenge, string $purpose, ?string $label = null): void
    {
        $this->auth->sessionStart();
        $_SESSION['passkey_challenge'] = $challenge;
        $_SESSION['passkey_purpose']   = $purpose;
        $_SESSION['passkey_expires']   = time() + $this->challengeTtl;
        $_SESSION['passkey_label']     = $label;
    }

    /** Returns the challenge if valid for $purpose, and always clears it. */
    private function consumeChallenge(string $purpose): ?string
    {
        $this->auth->sessionStart();
        $challenge = $_SESSION['passkey_challenge'] ?? null;
        $ok = $challenge !== null
            && ($_SESSION['passkey_purpose'] ?? null) === $purpose
            && (int)($_SESSION['passkey_expires'] ?? 0) > time();

        // Cleared whether or not it was valid: single use, no retries.
        unset($_SESSION['passkey_challenge'], $_SESSION['passkey_purpose'], $_SESSION['passkey_expires']);

        return $ok ? (string)$challenge : null;
    }

    /**
     * The options the browser is given at begin time, and the same options
     * rebuilt at finish time so the library can check the response against
     * them. Both must agree, so there is one builder.
     */
    private function creationOptions(int $userId, string $rawChallenge): PublicKeyCredentialCreationOptions
    {
        $st = $this->pdo->prepare('SELECT username FROM users WHERE id = ?');
        $st->execute([$userId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new InvalidArgumentException('No such user.');
        }
        $username = (string)$row['username'];
        $handle = $this->ensureUserHandle($userId);

        return PublicKeyCredentialCreationOptions::create(
            // rp.name is deprecated since webauthn-lib 5.3.0 and a non-empty
            // name triggers a deprecation notice; the serializer defaults
            // rp.name to the rp id. So $this->rpName stays our own option
            // and the library gets ''.
            PublicKeyCredentialRpEntity::create('', $this->rpId),
            PublicKeyCredentialUserEntity::create($username, self::b64uDecode($handle), $username),
            $rawChallenge,
            [
                // Only these two are verifiable by the library's default
                // algorithm manager; advertising more would enrol
                // credentials that can never log in.
                PublicKeyCredentialParameters::createPk(ES256::ID),
                PublicKeyCredentialParameters::createPk(RS256::ID),
            ],
            AuthenticatorSelectionCriteria::create(
                null,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            [],
            $this->challengeTtl * 1000,
        );
    }

    /** $origin must already have passed originMatchesRpId(). */
    private function ceremonyFactory(string $origin): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        // Without this the factory falls back to the deprecated CheckOrigin.
        $factory->setAllowedOrigins([$origin]);
        $factory->setAttestationStatementSupportManager($this->attestationSupport());
        return $factory;
    }

    /**
     * Empty of everything but "none", which its constructor adds: we ask
     * for attestation none, so no other format should ever be accepted.
     */
    private function attestationSupport(): AttestationStatementSupportManager
    {
        return $this->attestationSupport ??= AttestationStatementSupportManager::create();
    }

    /** Built once: it wires 27 denormalizers and a reflection extractor. */
    private function serializer(): SerializerInterface
    {
        return $this->serializer ??= (new WebauthnSerializerFactory($this->attestationSupport()))->create();
    }
}
