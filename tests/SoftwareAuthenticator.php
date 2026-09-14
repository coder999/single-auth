<?php

declare(strict_types=1);

namespace Coder999\SingleAuth\Tests;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Coder999\SingleAuth\Passkeys;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use OpenSSLAsymmetricKey;
use RuntimeException;
use Webauthn\AttestationStatement\AttestationStatement;

/**
 * A WebAuthn authenticator, in PHP, for tests.
 *
 * It holds a real P-256 keypair and produces a real ES256 signature over
 * exactly the bytes the specification says an authenticator signs, so an
 * assertion it builds is accepted by the same code path a Touch ID or a
 * YubiKey assertion goes through — and one signed by the wrong key is
 * rejected by it. Nothing here is invented: every value the relying party
 * checks is computed. This is a genuine authenticator that happens to run
 * in PHP, which is a different thing from a hand-forged blob.
 *
 * It needs no new dependency and no device: `ext-openssl` is in the PHP
 * image, and `spomky-labs/cbor-php` and `web-auth/cose-lib` are already
 * transitive dependencies of `web-auth/webauthn-lib`. The COSE labels below
 * are taken from cose-lib's own constants rather than written as numbers.
 *
 * It exists because `finishLogin()`'s tail — the `sign_count` write-back,
 * the `last_used_at` stamp, `Auth::loginAs()` and the returned row — only
 * runs when an assertion actually verifies, as does the row
 * `finishRegistration()` writes. Without this, none of it is ever executed
 * by a test, and deleting any of it breaks nothing.
 *
 * @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion (assert)
 * @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred (attest)
 */
final class SoftwareAuthenticator
{
    /** @see \Webauthn\AuthenticatorData::FLAG_UP / FLAG_UV / FLAG_AT */
    private const FLAG_USER_PRESENT = 0b00000001;
    private const FLAG_USER_VERIFIED = 0b00000100;
    private const FLAG_ATTESTED_CREDENTIAL_DATA = 0b01000000;

    private const P256_COORDINATE_BYTES = 32;

    private OpenSSLAsymmetricKey $key;

    /**
     * @param string $rpId      the RP whose id hash this authenticator signs over
     * @param string $credentialId raw bytes; the id the browser echoes back
     * @param string $userHandle   raw bytes; must match the stored account's
     */
    public function __construct(
        private readonly string $rpId,
        public readonly string $credentialId,
        public readonly string $userHandle,
    ) {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => 'prime256v1',   // NIST P-256, COSE curve 1
        ]);
        if ($key === false) {
            throw new RuntimeException('could not generate a P-256 keypair: ' . openssl_error_string());
        }
        $this->key = $key;
    }

    /**
     * The public key as an authenticator would report it: a CBOR-encoded
     * COSE_Key. This is what `user_credentials.public_key` holds (base64url
     * of these bytes) and what `CheckSignature` decodes to verify with.
     */
    public function coseKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        if ($details === false || !isset($details['ec']['x'], $details['ec']['y'])) {
            throw new RuntimeException('could not read the EC public point');
        }

        return (string)MapObject::create()
            ->add(UnsignedIntegerObject::create(Key::TYPE), UnsignedIntegerObject::create(Key::TYPE_EC2))
            ->add(UnsignedIntegerObject::create(Key::ALG), NegativeIntegerObject::create(ES256::ID))
            ->add(NegativeIntegerObject::create(Ec2Key::DATA_CURVE), UnsignedIntegerObject::create(Ec2Key::CURVE_P256))
            ->add(NegativeIntegerObject::create(Ec2Key::DATA_X), ByteStringObject::create(self::coordinate($details['ec']['x'])))
            ->add(NegativeIntegerObject::create(Ec2Key::DATA_Y), ByteStringObject::create(self::coordinate($details['ec']['y'])));
    }

    /**
     * An assertion, as `navigator.credentials.get()` would hand it to the
     * page: the JSON envelope `finishLogin()` takes.
     *
     * @param string $challengeB64u the challenge the RP issued, base64url —
     *        i.e. `$_SESSION['passkey_challenge']` verbatim, which is how a
     *        browser would echo it back
     */
    public function assert(
        string $challengeB64u,
        string $origin = 'https://example.com',
        int $signCount = 0
    ): string {
        $clientDataJson = json_encode([
            'type'        => 'webauthn.get',
            'challenge'   => $challengeB64u,
            'origin'      => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);

        // rpIdHash (32) | flags (1) | signCount (4, big-endian). No attested
        // credential data and no extensions on an assertion, so it ends there.
        $authData = hash('sha256', $this->rpId, true)
            . chr(self::FLAG_USER_PRESENT | self::FLAG_USER_VERIFIED)
            . pack('N', $signCount);

        // What an authenticator signs: authenticatorData followed by the
        // SHA-256 of the client data, never the client data itself.
        $signature = $this->sign($authData . hash('sha256', $clientDataJson, true));

        return json_encode([
            'id'       => Passkeys::b64u($this->credentialId),
            'rawId'    => Passkeys::b64u($this->credentialId),
            'type'     => 'public-key',
            'response' => [
                'clientDataJSON'    => Passkeys::b64u($clientDataJson),
                'authenticatorData' => Passkeys::b64u($authData),
                'signature'         => Passkeys::b64u($signature),
                'userHandle'        => Passkeys::b64u($this->userHandle),
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * An attestation, as `navigator.credentials.create()` would hand it to
     * the page: the JSON envelope `finishRegistration()` takes.
     *
     * We ask for attestation `none`, so there is no attestation statement to
     * sign and none is produced — `attStmt` is an empty map and the AAGUID is
     * all zeroes, which is exactly what a platform authenticator sends under
     * that policy. The credential public key is carried inside `authData`,
     * which is where the relying party reads it from at enrolment.
     *
     * @param string $challengeB64u as for assert(): the issued challenge,
     *        base64url, i.e. `$_SESSION['passkey_challenge']` verbatim
     */
    public function attest(string $challengeB64u, string $origin = 'https://example.com'): string
    {
        $clientDataJson = json_encode([
            'type'        => 'webauthn.create',
            'challenge'   => $challengeB64u,
            'origin'      => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);

        // As for an assertion, but with the attested-credential-data flag
        // set and that data appended: AAGUID (16) | id length (2, big-endian)
        // | credential id | COSE public key.
        $authData = hash('sha256', $this->rpId, true)
            . chr(self::FLAG_USER_PRESENT | self::FLAG_USER_VERIFIED | self::FLAG_ATTESTED_CREDENTIAL_DATA)
            . pack('N', 0)
            . str_repeat("\x00", 16)
            . pack('n', strlen($this->credentialId))
            . $this->credentialId
            . $this->coseKey();

        $attestationObject = (string)MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create(AttestationStatement::TYPE_NONE))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return json_encode([
            'id'       => Passkeys::b64u($this->credentialId),
            'rawId'    => Passkeys::b64u($this->credentialId),
            'type'     => 'public-key',
            'response' => [
                'clientDataJSON'    => Passkeys::b64u($clientDataJson),
                'attestationObject' => Passkeys::b64u($attestationObject),
                'transports'        => ['internal'],
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * openssl_sign() emits an ASN.1 DER signature, which is the form
     * WebAuthn specifies for ES256; webauthn-lib's CoseSignatureFixer
     * converts it to the raw r||s pair its verifier wants.
     */
    private function sign(string $data): string
    {
        if (!openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('openssl_sign failed: ' . openssl_error_string());
        }
        return $signature;
    }

    /**
     * OpenSSL returns a public-point coordinate as a big-endian integer with
     * leading zero bytes stripped, but COSE wants a fixed-width field.
     */
    private static function coordinate(string $raw): string
    {
        return str_pad($raw, self::P256_COORDINATE_BYTES, "\x00", STR_PAD_LEFT);
    }
}
