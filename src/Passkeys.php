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
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

final class Passkeys
{
    /**
     * Widths of the columns these values end up in
     * (`db/migrations/20260914115641_add_passkey_credentials.sql`). They are
     * enforced here, at the last point before the user is asked to touch an
     * authenticator, because the alternative is a PDOException thrown out of
     * finishRegistration() *after* a ceremony the user has already completed.
     *
     * VARCHAR(n) on utf8mb4 counts characters, not bytes, hence mb_strlen().
     */
    public const MAX_LABEL_LENGTH = 64;
    private const MAX_TRANSPORTS_LENGTH = 255;

    /**
     * We ask for attestation `none`, under which the authenticator reports
     * an all-zero AAGUID, so there is nothing per-device to store and the
     * schema has no column for one. The library still wants a Uuid on a
     * rehydrated record; this is the value that carries no information.
     */
    private const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

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
     *
     * @throws InvalidArgumentException if the user does not exist, or the
     *         label is wider than the column that has to hold it.
     */
    public function beginRegistration(int $userId, string $label): string
    {
        if (mb_strlen($label) > self::MAX_LABEL_LENGTH) {
            throw new InvalidArgumentException(
                'Passkey label may not exceed ' . self::MAX_LABEL_LENGTH . ' characters.'
            );
        }

        $username = $this->username($userId);
        if ($username === null) {
            throw new InvalidArgumentException('No such user.');
        }
        $user = self::userEntity($username, $this->ensureUserHandle($userId));

        $challenge = random_bytes(32);
        $options = $this->creationOptions($user, $challenge);

        // Stored base64url so the challenge survives session serialisation
        // as text; the library wants the raw bytes back on the way in.
        $this->storeChallenge(self::b64u($challenge), 'register', $userId, $label);

        return $this->serializer()->serialize($options, 'json');
    }

    /**
     * Validates the authenticator's attestation response and, if it is
     * good, enrols the credential. Returns false on any rejection; the
     * challenge is consumed either way.
     */
    public function finishRegistration(int $userId, string $clientJson): bool
    {
        $challenge = $this->consumeChallenge('register', $userId);
        $label = (string)($_SESSION['passkey_label'] ?? '');
        unset($_SESSION['passkey_label']);
        if ($challenge === null) {
            return false;
        }

        // Read the user outside the try, so a database failure here surfaces
        // as an exception rather than being swallowed as "credential
        // rejected". The handle must already exist: beginRegistration()
        // created it, and its absence means no ceremony was ever begun.
        $username = $this->username($userId);
        $handle = $this->userHandle($userId);
        if ($username === null || $handle === null) {
            return false;
        }
        $user = self::userEntity($username, $handle);

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
                $this->creationOptions($user, self::b64uDecode($challenge)),
                (string)parse_url($origin, PHP_URL_HOST),
            );
        } catch (Throwable) {
            // check() signals failure by throwing, and a malformed payload
            // throws out of deserialize(). Neither is something the caller
            // can act on beyond "that did not work". Nothing inside this
            // block touches the database, so no database error is hidden
            // by it.
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
            self::packTransports($record->transports),
            $label,
            $now,
        ]);

        return true;
    }

    /**
     * Returns the credential request options as JSON, for the browser to
     * hand to navigator.credentials.get().
     *
     * No username is asked for and `allowCredentials` is left empty: these
     * are discoverable credentials, so the authenticator offers the user
     * whichever passkeys it holds for this RP and the assertion says who
     * they belong to. Nothing here knows an account, which is why the
     * challenge is stored with no user id against it.
     */
    public function beginLogin(): string
    {
        $challenge = random_bytes(32);
        $options = $this->requestOptions($challenge);

        $this->storeChallenge(self::b64u($challenge), 'login');

        return $this->serializer()->serialize($options, 'json');
    }

    /**
     * Validates an assertion and, if every check holds, logs in the account
     * that owns the credential. Returns that user's row, or null on any
     * rejection. The challenge is consumed either way.
     *
     * This is the only method in the library that both discovers a user and
     * establishes a session, so the ordering below is the security property
     * and not a matter of taste: `loginAs()` is the last thing that runs,
     * and every check above it returns before reaching it. **No null return
     * may leave a session behind** — that would be an authentication bypass
     * nobody would ever see.
     *
     * @return array<string,mixed>|null
     */
    public function finishLogin(string $clientJson): ?array
    {
        // Null user id: a login challenge belongs to nobody. The gate
        // enforces that too, so a challenge issued for a named account's
        // registration cannot be redeemed here.
        $challenge = $this->consumeChallenge('login');
        // storeChallenge() writes this as null for a login; it is only
        // meaningful to a registration. Cleared so the key does not linger.
        unset($_SESSION['passkey_label']);
        if ($challenge === null) {
            return null;
        }

        try {
            $credential = $this->serializer()->deserialize($clientJson, PublicKeyCredential::class, 'json');
            // The denormalizer returns a bare array, not an object, when the
            // payload has no top-level "id" key -- it does not throw.
            if (!$credential instanceof PublicKeyCredential) {
                return null;
            }
            $response = $credential->response;
            if (!$response instanceof AuthenticatorAssertionResponse) {
                return null;
            }
            $origin = $response->clientDataJSON->origin;
        } catch (Throwable) {
            // A malformed payload throws out of deserialize(). Nothing in
            // this block touches the database, so no database error can be
            // hidden by it.
            return null;
        }

        // Our own rule is the gate, exactly as in finishRegistration(), and
        // only an origin it has already accepted is handed to the library
        // as its allowed origin. One statement of the rule, no second copy.
        if (!$this->originMatchesRpId($origin)) {
            return null;
        }

        // Read outside a try, so a database failure surfaces as an
        // exception rather than being swallowed as "login refused".
        $row = $this->findCredential(self::b64u($credential->rawId));
        if ($row === null) {
            return null;
        }
        $storedCount = (int)$row['sign_count'];

        try {
            $record = self::credentialRecord($row);
            AuthenticatorAssertionResponseValidator::create(
                $this->ceremonyFactory($origin)->requestCeremony()
            )->check(
                $record,
                $response,
                // The same options beginLogin() issued, carrying the same
                // challenge: that is how the library checks it.
                $this->requestOptions(self::b64uDecode($challenge)),
                (string)parse_url($origin, PHP_URL_HOST),
                // null, because nobody was identified before the ceremony.
                // The library then *requires* the assertion to carry a user
                // handle and to match the stored one, which is what ties
                // this credential to this account.
                null,
            );
        } catch (Throwable) {
            return null;
        }

        // check() has already overwritten $record->counter with the count the
        // authenticator just reported; $storedCount is what the row held
        // before it.
        //
        // The library's CheckCounter applies the same rule inside the
        // ceremony, so as the code stands this gate rejects nothing the
        // ceremony let through. It is not decoration, though: restating the
        // rule keeps it in this library's own directly-testable code, it
        // survives the ceremony's counter checker being reconfigured, and —
        // verified by mutation on a scratch copy, 2026-09-14 — it is what
        // still refuses a forged assertion against a credential with a
        // non-zero counter if the check() call above is ever lost. A
        // credential whose counter is zero has nothing behind it but that
        // call, which is what the sharpest test in the suite covers.
        if (!$this->signCountAcceptable($storedCount, $record->counter)) {
            return null;
        }

        $now = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->pdo->prepare('UPDATE user_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?')
            ->execute([$record->counter, $now, (int)$row['id']]);

        if (!$this->auth->loginAs((int)$row['user_id'])) {
            return null;    // loginAs() returns before it touches the session
        }
        $user = $this->auth->currentUser();
        if ($user === null) {
            // Unreachable short of the account being deleted between those
            // two statements. Undone anyway, because the contract is that a
            // null return means nobody was logged in, and the one thing
            // this method must never do is return null from a session.
            unset($_SESSION['user_id']);
            return null;
        }
        return $user;
    }

    /**
     * Many authenticators (notably iCloud Keychain) always report 0. A
     * pair of zeroes therefore means "this authenticator does not count"
     * and is accepted. Once a counter is in use, it must strictly
     * increase: equal means a replayed assertion, lower means a possible
     * cloned credential.
     */
    public function signCountAcceptable(int $stored, int $incoming): bool
    {
        if ($stored === 0 && $incoming === 0) {
            return true;
        }
        return $incoming > $stored;
    }

    /**
     * The stored credential an assertion names, or null if there is none
     * this library could authenticate with.
     *
     * The join does real work. A credential is only usable if its owner
     * still exists and still has a WebAuthn user handle, because that
     * handle is what the library matches the assertion's own handle
     * against. Production has `ON DELETE CASCADE` on `user_id`, so an
     * ownerless row cannot exist there — the join makes that true here
     * rather than depending on it.
     *
     * @internal Public only so it can be tested, for the same reason as
     *   challengeIsValid(): every rejection in finishLogin() returns the
     *   same null, so from outside, "no such credential" and "crashed on a
     *   missing row" are indistinguishable, and a black-box test cannot
     *   tell a working lookup from a missing one. It returns nothing
     *   secret — a public key, a counter, and two ids.
     *
     * @return array<string,mixed>|null
     */
    public function findCredential(string $credentialId): ?array
    {
        $st = $this->pdo->prepare(
            'SELECT c.id, c.user_id, c.credential_id, c.public_key, c.sign_count, c.transports,
                    u.webauthn_user_handle
               FROM user_credentials c
               JOIN users u ON u.id = c.user_id
              WHERE c.credential_id = ? AND u.webauthn_user_handle IS NOT NULL'
        );
        $st->execute([$credentialId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
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

    /**
     * $userId is the account the ceremony is for, or null for a login
     * ceremony, where nobody is identified until the assertion comes back.
     */
    private function storeChallenge(
        string $challenge,
        string $purpose,
        ?int $userId = null,
        ?string $label = null
    ): void {
        $this->auth->sessionStart();
        $_SESSION['passkey_challenge'] = $challenge;
        $_SESSION['passkey_purpose']   = $purpose;
        $_SESSION['passkey_user']      = $userId;
        $_SESSION['passkey_expires']   = time() + $this->challengeTtl;
        $_SESSION['passkey_label']     = $label;
    }

    /** Returns the challenge if the gate below accepts it, and always clears it. */
    private function consumeChallenge(string $purpose, ?int $userId = null): ?string
    {
        $this->auth->sessionStart();
        $challenge = $_SESSION['passkey_challenge'] ?? null;
        $ok = self::challengeIsValid($_SESSION, $purpose, $userId, time());

        // Cleared whether or not it was valid: single use, no retries.
        unset(
            $_SESSION['passkey_challenge'],
            $_SESSION['passkey_purpose'],
            $_SESSION['passkey_user'],
            $_SESSION['passkey_expires'],
        );

        return $ok ? (string)$challenge : null;
    }

    /**
     * The challenge gate, as a pure function of the session array and the
     * current time. Four independent conditions: a challenge exists, it was
     * issued for this ceremony, it was issued for this account, and it has
     * not expired.
     *
     * @internal Public only so it can be tested. It has no side effects and
     *   reads nothing but its arguments, so exposing it costs nothing —
     *   whereas leaving it inside a private method of a final class costs a
     *   great deal: every rejection in finishRegistration() returns the same
     *   `false`, and the challenge keys are cleared unconditionally, so no
     *   test driving the public API can tell a working gate from a missing
     *   one. Reviewed 2026-09-14 after exactly that was found to be true of
     *   the two tests that appeared to cover it.
     *
     * @param array<string,mixed> $session
     */
    public static function challengeIsValid(array $session, string $purpose, ?int $userId, int $now): bool
    {
        if (($session['passkey_challenge'] ?? null) === null) {
            return false;
        }
        if (($session['passkey_purpose'] ?? null) !== $purpose) {
            return false;
        }
        $storedUser = $session['passkey_user'] ?? null;
        if (($storedUser === null ? null : (int)$storedUser) !== $userId) {
            return false;
        }
        return (int)($session['passkey_expires'] ?? 0) > $now;
    }

    private function username(int $userId): ?string
    {
        $st = $this->pdo->prepare('SELECT username FROM users WHERE id = ?');
        $st->execute([$userId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : (string)$row['username'];
    }

    /** $handle is base64url as stored; the library wants the raw bytes. */
    private static function userEntity(string $username, string $handle): PublicKeyCredentialUserEntity
    {
        return PublicKeyCredentialUserEntity::create($username, self::b64uDecode($handle), $username);
    }

    /**
     * Comma-joined for the `transports` column, dropping anything that
     * cannot survive that encoding or that column.
     *
     * Both filters are defensive rather than expected: this array is
     * whatever the browser put in getTransports(), and webauthn-lib does
     * not validate it against its own list. A real authenticator sends a
     * handful of short tokens, so nothing is dropped in practice — but
     * transports are an advisory UI hint, and losing one must never be
     * able to fail an enrolment the user has already completed.
     *
     * @internal Public for the same reason as challengeIsValid(): a pure
     *   function with no other route to a test, since its only caller is
     *   the happy path, which needs an authenticator.
     *
     * @param string[] $transports
     */
    public static function packTransports(array $transports): ?string
    {
        $packed = '';
        foreach ($transports as $transport) {
            if (str_contains($transport, ',')) {
                continue; // would not round-trip out of a comma-joined column
            }
            $candidate = $packed === '' ? $transport : $packed . ',' . $transport;
            if (strlen($candidate) > self::MAX_TRANSPORTS_LENGTH) {
                break;
            }
            $packed = $candidate;
        }
        return $packed === '' ? null : $packed;
    }

    /**
     * The options the browser is given at begin time, and the same options
     * rebuilt at finish time so the library can check the response against
     * them. Both must agree, so there is one builder — and it reads nothing
     * but its arguments, so building options can never write to `users`.
     */
    private function creationOptions(
        PublicKeyCredentialUserEntity $user,
        string $rawChallenge
    ): PublicKeyCredentialCreationOptions {
        return PublicKeyCredentialCreationOptions::create(
            // rp.name is deprecated since webauthn-lib 5.3.0 and a non-empty
            // name triggers a deprecation notice; the serializer defaults
            // rp.name to the rp id. So $this->rpName stays our own option
            // and the library gets ''.
            PublicKeyCredentialRpEntity::create('', $this->rpId),
            $user,
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

    /**
     * The options the browser is given at begin time, and the same options
     * rebuilt at finish time so the library can check the assertion against
     * them. One builder, for the same reason creationOptions() is one.
     */
    private function requestOptions(string $rawChallenge): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            $rawChallenge,
            $this->rpId,
            // Empty on purpose: discoverable credentials. A non-empty list
            // would mean knowing the account before the ceremony, which is
            // the thing passkeys exist to avoid.
            [],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $this->challengeTtl * 1000,
        );
    }

    /**
     * Rebuilds a stored credential as the library's own value object. This
     * schema keeps the fixed passkey columns rather than a serialised
     * record, so the conversion is here: everything in the database is
     * base64url text, everything the library takes is raw bytes.
     *
     * backupEligible / backupStatus / uvInitialized are left null
     * deliberately — there are no columns for them, so there is nothing to
     * rehydrate. check() sets them on the returned object and we discard
     * them.
     *
     * @param array<string,mixed> $row as returned by findCredential()
     */
    private static function credentialRecord(array $row): CredentialRecord
    {
        $transports = $row['transports'] === null || $row['transports'] === ''
            ? []
            : explode(',', (string)$row['transports']);

        return CredentialRecord::create(
            self::b64uDecode((string)$row['credential_id']),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromString(self::ZERO_AAGUID),
            self::b64uDecode((string)$row['public_key']),
            self::b64uDecode((string)$row['webauthn_user_handle']),
            (int)$row['sign_count'],
        );
    }

    /**
     * $origin must already have passed originMatchesRpId().
     *
     * No TopOriginValidator is registered, in either ceremony. CheckTopOrigin
     * therefore rejects any response whose clientDataJSON carries a
     * topOrigin — that is, any ceremony run from inside a cross-origin
     * iframe. That is the posture we want for an identity provider: a
     * passkey may only be created or used from a top-level page on our own
     * origin, never from a frame a third-party site controls. Opting in
     * would mean calling enableTopOriginValidator() and deciding which
     * embedders to trust; we trust none.
     */
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
