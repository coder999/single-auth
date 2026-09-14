<?php

declare(strict_types=1);

namespace Coder999\SingleAuth\Tests;

use Coder999\SingleAuth\Auth;
use Coder999\SingleAuth\Passkeys;
use InvalidArgumentException;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;

final class PasskeysTest extends TestCase
{
    private PDO $pdo;
    private Passkeys $passkeys;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT NULL,
            webauthn_user_handle TEXT NULL UNIQUE
        )');
        $this->pdo->exec('CREATE TABLE user_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            transports TEXT NULL,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT NULL
        )');
        $this->pdo->exec('CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        )');

        $auth = new Auth($this->pdo, ['cookie_domain' => '.example.com']);
        $this->passkeys = new Passkeys($this->pdo, $auth, ['rp_id' => 'example.com']);

        // Same reset AuthTest::setUp does. Without it, session state leaks
        // between tests and the challenge assertions in Tasks 5 and 6
        // pass or fail depending on execution order.
        $auth->sessionStart();
        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    public function testConstructorRequiresRpId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Passkeys($this->pdo, new Auth($this->pdo), []);
    }

    public static function acceptedOrigins(): array
    {
        return [
            ['https://example.com'],
            ['https://sub.example.com'],
            ['https://deep.sub.example.com'],
            ['https://example.com:443'],
        ];
    }

    #[DataProvider('acceptedOrigins')]
    public function testOriginAccepted(string $origin): void
    {
        $this->assertTrue($this->passkeys->originMatchesRpId($origin));
    }

    public static function rejectedOrigins(): array
    {
        return [
            'plain http'          => ['http://example.com'],
            'suffix lookalike'    => ['https://notexample.com'],
            'prefix lookalike'    => ['https://example.com.evil.test'],
            'different domain'    => ['https://evil.test'],
            'no scheme'           => ['example.com'],
            'empty'               => [''],
            'embedded in path'    => ['https://evil.test/example.com'],
        ];
    }

    #[DataProvider('rejectedOrigins')]
    public function testOriginRejected(string $origin): void
    {
        $this->assertFalse($this->passkeys->originMatchesRpId($origin));
    }

    private function makeUser(int $id = 1, string $name = 'alice'): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)')
            ->execute([$id, $name, password_hash('pw', PASSWORD_DEFAULT)]);
    }

    #[RunInSeparateProcess]
    public function testBeginRegistrationGeneratesUserHandleWhenAbsent(): void
    {
        $this->makeUser();
        $this->assertNull($this->passkeys->userHandle(1));

        $this->passkeys->beginRegistration(1, 'Laptop');

        $handle = $this->passkeys->userHandle(1);
        $this->assertNotNull($handle);
        $this->assertNotSame('1', $handle, 'handle must not be the user id');
        $this->assertGreaterThanOrEqual(32, strlen($handle));
    }

    #[RunInSeparateProcess]
    public function testBeginRegistrationReusesExistingUserHandle(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $first = $this->passkeys->userHandle(1);

        $this->passkeys->beginRegistration(1, 'Phone');

        $this->assertSame($first, $this->passkeys->userHandle(1),
            'regenerating the handle would orphan enrolled credentials');
    }

    #[RunInSeparateProcess]
    public function testBeginRegistrationReturnsJsonWithRpIdAndChallenge(): void
    {
        $this->makeUser();

        $json = $this->passkeys->beginRegistration(1, 'Laptop');
        $options = json_decode($json, true);

        $this->assertIsArray($options);
        $this->assertSame('example.com', $options['rp']['id']);
        $this->assertNotEmpty($options['challenge']);
    }

    #[RunInSeparateProcess]
    public function testBeginRegistrationStoresSingleUseChallengeInSession(): void
    {
        $this->makeUser();

        $this->passkeys->beginRegistration(1, 'Laptop');

        $this->assertNotEmpty($_SESSION['passkey_challenge']);
        $this->assertSame('register', $_SESSION['passkey_purpose']);
        $this->assertSame(1, $_SESSION['passkey_user']);
        $this->assertSame('Laptop', $_SESSION['passkey_label']);
        $this->assertGreaterThan(time(), $_SESSION['passkey_expires']);
    }

    /**
     * Joins the real session written by beginRegistration() to the gate that
     * reads it, so the two cannot drift apart: the unit tests below prove the
     * gate, and this proves the gate is looking at what begin actually wrote.
     */
    #[RunInSeparateProcess]
    public function testBeginRegistrationStoresAChallengeTheGateAccepts(): void
    {
        $this->makeUser();
        $this->makeUser(2, 'bob');

        $this->passkeys->beginRegistration(1, 'Laptop');

        $this->assertTrue(Passkeys::challengeIsValid($_SESSION, 'register', 1, time()));
        $this->assertFalse(Passkeys::challengeIsValid($_SESSION, 'register', 2, time()),
            'a challenge issued for user 1 must not enrol a credential onto user 2');

        $this->passkeys->finishRegistration(1, '{}');

        $this->assertFalse(Passkeys::challengeIsValid($_SESSION, 'register', 1, time()),
            'the challenge must be single use');
    }

    // The next two tests document the public contract, but they cannot
    // prove the gate: '{}' is rejected further down finishRegistration()
    // whatever the session holds, and every rejection returns the same
    // false. The gate itself is covered by the challengeIsValid() tests
    // below, and joined to the real session by the bridging test above.

    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsWhenNoChallengeInSession(): void
    {
        $this->makeUser();
        $_SESSION = [];

        $this->assertFalse($this->passkeys->finishRegistration(1, '{}'));
    }

    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsExpiredChallenge(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $_SESSION['passkey_expires'] = time() - 1;

        $this->assertFalse($this->passkeys->finishRegistration(1, '{}'));
        $this->assertArrayNotHasKey('passkey_challenge', $_SESSION,
            'a consumed or expired challenge must be cleared, not left to retry');
    }

    /** A session as beginRegistration(1, ...) leaves it, expiring at t=2000. */
    private static function issuedSession(array $overrides = []): array
    {
        return $overrides + [
            'passkey_challenge' => 'Y2hhbGxlbmdl',
            'passkey_purpose'   => 'register',
            'passkey_user'      => 1,
            'passkey_expires'   => 2000,
        ];
    }

    public function testChallengeGateAcceptsAFreshChallengeForThisCeremony(): void
    {
        $this->assertTrue(Passkeys::challengeIsValid(self::issuedSession(), 'register', 1, 1999));
    }

    public function testChallengeGateRejectsAnAbsentChallenge(): void
    {
        $this->assertFalse(Passkeys::challengeIsValid([], 'register', 1, 1999));
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(['passkey_challenge' => null]), 'register', 1, 1999)
        );
    }

    public function testChallengeGateRejectsAChallengeIssuedForAnotherPurpose(): void
    {
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(['passkey_purpose' => 'login']), 'register', 1, 1999),
            'a login challenge must not be redeemable as a registration'
        );
    }

    public function testChallengeGateRejectsAChallengeIssuedForAnotherUser(): void
    {
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(['passkey_user' => 2]), 'register', 1, 1999)
        );
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(['passkey_user' => null]), 'register', 1, 1999),
            'an unattributed challenge must not enrol onto a named account'
        );
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(), 'register', null, 1999),
            "and a named account's challenge must not satisfy an unattributed ceremony"
        );
    }

    public function testChallengeGateRejectsAnExpiredChallenge(): void
    {
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(), 'register', 1, 2000),
            'expiry is exclusive: a challenge is dead on the second it expires'
        );
        $this->assertFalse(Passkeys::challengeIsValid(self::issuedSession(), 'register', 1, 2001));
        $this->assertFalse(
            Passkeys::challengeIsValid(self::issuedSession(['passkey_expires' => null]), 'register', 1, 1999),
            'a challenge with no expiry must not be treated as immortal'
        );
    }

    // `label` is VARCHAR(64) and `transports` VARCHAR(255). Both widths are
    // written out here rather than read from the class, so these tests
    // fail if the constants stop matching the columns.

    #[RunInSeparateProcess]
    public function testBeginRegistrationRejectsALabelWiderThanItsColumn(): void
    {
        $this->makeUser();

        $this->expectException(InvalidArgumentException::class);
        $this->passkeys->beginRegistration(1, str_repeat('a', 65));
    }

    #[RunInSeparateProcess]
    public function testBeginRegistrationAcceptsALabelExactlyAsWideAsItsColumn(): void
    {
        $this->makeUser();
        $label = str_repeat('a', 64);

        $this->passkeys->beginRegistration(1, $label);

        $this->assertSame($label, $_SESSION['passkey_label']);
    }

    #[RunInSeparateProcess]
    public function testLabelWidthIsCountedInCharactersNotBytes(): void
    {
        $this->makeUser();
        $label = str_repeat('é', 64);   // 64 characters, 128 bytes
        $this->assertSame(128, strlen($label), 'guard: this label must be multi-byte');

        $this->passkeys->beginRegistration(1, $label);

        $this->assertSame($label, $_SESSION['passkey_label'],
            'the column counts characters, so a byte count would reject a legal label');
    }

    public static function transportPackings(): array
    {
        return [
            'typical'                  => [['internal', 'hybrid'], 'internal,hybrid'],
            'unknown transports kept'  => [['a-future-transport'], 'a-future-transport'],
            'empty means unknown'      => [[], null],
            'a comma cannot round-trip so the value is dropped'
                                       => [['int,ernal', 'hybrid'], 'hybrid'],
            'packing stops at whole values'
                                       => [[str_repeat('a', 200), str_repeat('b', 200)], str_repeat('a', 200)],
            'a single over-wide value is dropped'
                                       => [[str_repeat('a', 300)], null],
        ];
    }

    #[DataProvider('transportPackings')]
    public function testTransportsArePackedToFitTheirColumn(array $transports, ?string $expected): void
    {
        $packed = Passkeys::packTransports($transports);

        $this->assertSame($expected, $packed);
        $this->assertLessThanOrEqual(255, strlen((string)$packed));
    }

    // ---------------------------------------------------------------- login

    private const TEST_USER_HANDLE = 'a-user-handle-that-is-32-bytes!!';

    /**
     * Enrols a credential the way a completed registration would, and gives
     * its owner the user handle a real beginRegistration() would have
     * written. The key material is junk: nothing in this file can produce a
     * signature that verifies, and nothing in this file tries to.
     */
    private function enrolCredential(string $credentialId, int $userId = 1, int $signCount = 0): void
    {
        $this->pdo->prepare('UPDATE users SET webauthn_user_handle = ? WHERE id = ?')
            ->execute([Passkeys::b64u(self::TEST_USER_HANDLE), $userId]);
        $this->pdo->prepare(
            'INSERT INTO user_credentials
                (user_id, credential_id, public_key, sign_count, transports, label, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $userId,
            Passkeys::b64u($credentialId),
            Passkeys::b64u('not a real COSE key'),
            $signCount,
            'internal',
            'Laptop',
            '2026-09-14 00:00:00',
        ]);
    }

    /**
     * A structurally valid assertion envelope with junk inside.
     *
     * It exists because the checks this file cares about live *after*
     * finishLogin()'s `instanceof PublicKeyCredential` guard, and a payload
     * that cannot get past that guard cannot exercise them. `'{}'`, and a
     * payload carrying only an `id` key, both die inside the serializer —
     * so a rejection test built on either would be green no matter what
     * finishLogin() did next. This one deserialises into a real
     * PublicKeyCredential wrapping a real AuthenticatorAssertionResponse,
     * which makes the credential lookup, the origin rule and the ceremony
     * reachable. The signature is not real and never verifies; that is the
     * point, not a shortcoming.
     */
    private static function assertionEnvelope(
        string $credentialId,
        string $origin = 'https://example.com',
        int $signCount = 0
    ): string {
        $clientData = json_encode([
            'type'        => 'webauthn.get',
            'challenge'   => Passkeys::b64u(random_bytes(32)),
            'origin'      => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);

        // 32-byte rpIdHash, then flags (user present | user verified), then
        // a big-endian 4-byte sign count. No attested credential data and no
        // extensions, so the structure ends there.
        $authData = str_repeat("\x00", 32) . chr(0x05) . pack('N', $signCount);

        return json_encode([
            'id'       => Passkeys::b64u($credentialId),
            'rawId'    => Passkeys::b64u($credentialId),
            'type'     => 'public-key',
            'response' => [
                'clientDataJSON'    => Passkeys::b64u($clientData),
                'authenticatorData' => Passkeys::b64u($authData),
                'signature'         => Passkeys::b64u('not a real signature'),
                'userHandle'        => Passkeys::b64u(self::TEST_USER_HANDLE),
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * A guard on the tests below, not on the library. Every rejection in
     * finishLogin() returns the same null, so if this envelope ever stopped
     * deserialising, every test that uses it would stay green while testing
     * only the `instanceof` guard. This fails loudly instead.
     */
    public function testTheAssertionEnvelopeGetsPastBothInstanceofGuards(): void
    {
        $serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();

        $credential = $serializer->deserialize(
            self::assertionEnvelope('credential-one'),
            PublicKeyCredential::class,
            'json'
        );

        $this->assertInstanceOf(PublicKeyCredential::class, $credential,
            'the denormalizer returns a bare array for a payload with no top-level id');
        $this->assertInstanceOf(AuthenticatorAssertionResponse::class, $credential->response);
        $this->assertSame('https://example.com', $credential->response->clientDataJSON->origin);
        $this->assertSame(Passkeys::b64u('credential-one'), Passkeys::b64u($credential->rawId));
    }

    public static function signCounts(): array
    {
        return [
            'both zero: authenticator does not count' => [0, 0, true],
            'normal increment'                        => [5, 6, true],
            'large jump forward'                      => [5, 500, true],
            'replay: same non-zero value'             => [5, 5, false],
            'clone: counter went backwards'           => [5, 4, false],
            'first use from zero'                     => [0, 1, true],
            'suspicious reset to zero'                => [5, 0, false],
        ];
    }

    #[DataProvider('signCounts')]
    public function testSignCountRule(int $stored, int $incoming, bool $expected): void
    {
        $this->assertSame($expected, $this->passkeys->signCountAcceptable($stored, $incoming));
    }

    #[RunInSeparateProcess]
    public function testBeginLoginStoresLoginChallengeAndAllowsAnyCredential(): void
    {
        $json = $this->passkeys->beginLogin();
        $options = json_decode($json, true);

        $this->assertIsArray($options);
        $this->assertSame('example.com', $options['rpId']);
        $this->assertNotEmpty($options['challenge']);
        $this->assertSame('login', $_SESSION['passkey_purpose']);
        $this->assertTrue(
            empty($options['allowCredentials']),
            'discoverable credentials: the browser picks, so no username is needed'
        );
    }

    /**
     * The mirror of testBeginRegistrationStoresAChallengeTheGateAccepts:
     * joins the session beginLogin() really writes to the gate that reads
     * it, so the two cannot drift.
     */
    #[RunInSeparateProcess]
    public function testBeginLoginStoresAChallengeTheGateAccepts(): void
    {
        $this->makeUser();
        $this->passkeys->beginLogin();

        $this->assertTrue(Passkeys::challengeIsValid($_SESSION, 'login', null, time()));
        $this->assertFalse(
            Passkeys::challengeIsValid($_SESSION, 'login', 1, time()),
            'a login challenge belongs to nobody until the assertion names its owner'
        );

        $this->passkeys->finishLogin(self::assertionEnvelope('no-such-credential'));

        $this->assertFalse(
            Passkeys::challengeIsValid($_SESSION, 'login', null, time()),
            'the challenge must be single use'
        );
    }

    /**
     * Ruling 2's pair. Each names a cross-purpose redemption, and each is
     * proved by the gate assertion, not by the ceremony call underneath it:
     * every rejection inside finishRegistration()/finishLogin() returns the
     * same false/null, so no black-box call can tell which check fired.
     */
    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsChallengeIssuedForLogin(): void
    {
        $this->makeUser();
        $this->passkeys->beginLogin();

        $this->assertFalse(
            Passkeys::challengeIsValid($_SESSION, 'register', 1, time()),
            'a login challenge must not be redeemable as a registration'
        );

        $this->assertFalse($this->passkeys->finishRegistration(1, '{}'));
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsChallengeIssuedForRegistration(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');
        $this->passkeys->beginRegistration(1, 'Laptop');

        $this->assertFalse(
            Passkeys::challengeIsValid($_SESSION, 'login', null, time()),
            'a registration challenge must not be redeemable as a login'
        );

        $this->assertNull($this->passkeys->finishLogin(self::assertionEnvelope('credential-one')));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    // The next three state the public contract and are worth having for
    // that, but they do not prove the check each is named after: every
    // rejection in finishLogin() returns the same null, so from outside,
    // "the challenge gate stopped it" and "it crashed two steps later" look
    // identical. Verified by mutation on a scratch copy, 2026-09-14 —
    // removing the challenge gate, the origin gate or the lookup's own null
    // guard leaves all three green. The checks themselves are proved by
    // challengeIsValid(), originMatchesRpId() and findCredential(), which
    // are tested directly; what these add is the session assertion, which
    // is the one property that must hold on every path regardless of which
    // check fired.

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsWhenNoChallenge(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');
        $_SESSION = [];

        $this->assertNull($this->passkeys->finishLogin(self::assertionEnvelope('credential-one')));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsUnknownCredentialId(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');
        $this->passkeys->beginLogin();

        $this->assertNull($this->passkeys->finishLogin(self::assertionEnvelope('no-such-credential')));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsAnAssertionFromADisallowedOrigin(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');
        $this->passkeys->beginLogin();

        $this->assertNull(
            $this->passkeys->finishLogin(self::assertionEnvelope('credential-one', 'https://evil.test'))
        );
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    /**
     * The most important test in this file.
     *
     * A zero sign count on both sides is the common case, not a corner: it
     * is what iCloud Keychain reports, and the sign-counter rule accepts it
     * by design. So for a credential like this one, the assertion
     * validation is the *only* thing between a forged envelope and a
     * session. Delete the validator call from finishLogin() and this test
     * fails with `user_id` in the session — confirmed by mutation, on a
     * scratch copy, 2026-09-14. The 5-then-6 variant below does not have
     * that property, because the sign-counter rule catches that mutant
     * first; this one has no second line of defence behind it.
     */
    #[RunInSeparateProcess]
    public function testFinishLoginRejectsAnUnverifiableAssertionForAZeroCounterCredential(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one', 1, 0);
        $this->passkeys->beginLogin();

        $this->assertNull(
            $this->passkeys->finishLogin(self::assertionEnvelope('credential-one', 'https://example.com', 0))
        );
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    /**
     * The same rejection with a counter in use. What this one discriminates
     * is the *ordering* of the write-back: move the sign_count / last_used_at
     * update ahead of the ceremony and it fails, because a rejected
     * assertion would have moved the counter.
     */
    #[RunInSeparateProcess]
    public function testARejectedAssertionDoesNotTouchTheStoredCredential(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one', 1, 5);
        $this->passkeys->beginLogin();

        $this->assertNull(
            $this->passkeys->finishLogin(self::assertionEnvelope('credential-one', 'https://example.com', 6))
        );

        $this->assertArrayNotHasKey('user_id', $_SESSION);
        $row = $this->pdo->query('SELECT sign_count, last_used_at FROM user_credentials')->fetch();
        $this->assertSame(5, (int)$row['sign_count'], 'a rejected assertion must not move the counter');
        $this->assertNull($row['last_used_at'], 'nor mark the credential as used');
    }

    #[RunInSeparateProcess]
    public function testFailedLoginEstablishesNoSession(): void
    {
        $this->makeUser();
        $this->passkeys->beginLogin();

        $this->passkeys->finishLogin('{}');

        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    // The credential lookup, tested directly. Through finishLogin() it
    // cannot be: an unknown id and a crash on a missing row both come back
    // as the same null, so removing the lookup's own guard would not fail
    // any black-box test.

    public function testCredentialLookupReturnsNullForAnUnknownId(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');

        $this->assertNull($this->passkeys->findCredential(Passkeys::b64u('no-such-credential')));
    }

    public function testCredentialLookupFindsAnEnrolledCredential(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one', 1, 7);

        $row = $this->passkeys->findCredential(Passkeys::b64u('credential-one'));

        $this->assertIsArray($row);
        $this->assertSame(1, (int)$row['user_id']);
        $this->assertSame(7, (int)$row['sign_count']);
        $this->assertSame(Passkeys::b64u(self::TEST_USER_HANDLE), $row['webauthn_user_handle']);
    }

    public function testCredentialLookupIgnoresACredentialWhoseOwnerIsGone(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');
        // Production has ON DELETE CASCADE, so this row cannot outlive its
        // user there. The join is what makes that true here as well, and an
        // ownerless credential must never authenticate anyone.
        $this->pdo->exec('DELETE FROM users WHERE id = 1');

        $this->assertNull($this->passkeys->findCredential(Passkeys::b64u('credential-one')));
    }

    public function testCredentialLookupIgnoresACredentialWhoseOwnerHasNoUserHandle(): void
    {
        $this->makeUser();
        $this->enrolCredential('credential-one');
        $this->pdo->exec('UPDATE users SET webauthn_user_handle = NULL WHERE id = 1');

        $this->assertNull(
            $this->passkeys->findCredential(Passkeys::b64u('credential-one')),
            'without a handle there is nothing for the library to match the assertion against'
        );
    }
}
