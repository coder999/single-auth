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

    /**
     * The registration happy path, which Task 5 could not reach either.
     * Without it nothing proves the row finishRegistration() writes is the
     * one a later login can actually use — and that is exactly what the
     * assertion on the last line checks, by logging in with it.
     */
    #[RunInSeparateProcess]
    public function testASuccessfulRegistrationEnrolsAUsableCredential(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $handle = (string)$this->passkeys->userHandle(1);
        $authenticator = new SoftwareAuthenticator('example.com', 'a-new-credential', Passkeys::b64uDecode($handle));

        $this->assertTrue($this->passkeys->finishRegistration(1, $authenticator->attest(self::issuedChallenge())));

        $row = $this->pdo->query('SELECT * FROM user_credentials')->fetch();
        $this->assertSame(1, (int)$row['user_id']);
        $this->assertSame(Passkeys::b64u('a-new-credential'), $row['credential_id']);
        $this->assertSame('Laptop', $row['label'], 'the label from beginRegistration, not from the browser');
        $this->assertSame('internal', $row['transports']);
        $this->assertSame(0, (int)$row['sign_count']);

        // The point of the whole exercise: the credential this enrolled is
        // one the login ceremony accepts.
        $this->passkeys->beginLogin();
        $user = $this->passkeys->finishLogin($authenticator->assert(self::issuedChallenge(), 'https://example.com', 1));
        $this->assertIsArray($user, 'a credential we enrolled must be one we can log in with');
        $this->assertSame('alice', $user['username']);
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

    /** A passkey holding a real P-256 keypair. See SoftwareAuthenticator. */
    private function authenticator(string $credentialId = 'credential-one'): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator('example.com', $credentialId, self::TEST_USER_HANDLE);
    }

    /**
     * Enrols a passkey the way a completed registration would: the stored
     * public key is that authenticator's real COSE key, so an assertion it
     * signs verifies and an assertion anything else signs does not.
     */
    private function enrolCredential(
        SoftwareAuthenticator $authenticator,
        int $userId = 1,
        int $signCount = 0
    ): void {
        $this->pdo->prepare('UPDATE users SET webauthn_user_handle = ? WHERE id = ?')
            ->execute([Passkeys::b64u($authenticator->userHandle), $userId]);
        $this->pdo->prepare(
            'INSERT INTO user_credentials
                (user_id, credential_id, public_key, sign_count, transports, label, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            $userId,
            Passkeys::b64u($authenticator->credentialId),
            Passkeys::b64u($authenticator->coseKey()),
            $signCount,
            'internal',
            'Laptop',
            '2026-09-14 00:00:00',
        ]);
    }

    /** The challenge beginLogin() just issued, as the browser would echo it. */
    private static function issuedChallenge(): string
    {
        return (string)$_SESSION['passkey_challenge'];
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
            $this->authenticator()->assert(Passkeys::b64u(random_bytes(32))),
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

        $this->passkeys->finishLogin($this->authenticator('no-such-credential')->assert(self::issuedChallenge()));

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
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator);
        $this->passkeys->beginRegistration(1, 'Laptop');

        $this->assertFalse(
            Passkeys::challengeIsValid($_SESSION, 'login', null, time()),
            'a registration challenge must not be redeemable as a login'
        );

        // Signed over the registration challenge, which is the only
        // challenge on offer -- so even a genuine authenticator cannot turn
        // a registration ceremony into a login.
        $this->assertNull($this->passkeys->finishLogin($authenticator->assert(self::issuedChallenge())));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    // Of the next three, only the origin one proves the check it is named
    // after. A genuine, correctly signed assertion from a disallowed origin
    // passes every other step of the ceremony, so removing the origin gate
    // logs it in and that test goes red.
    //
    // The other two cannot: every rejection in finishLogin() returns the
    // same null, so from outside, "the challenge gate stopped it" and "it
    // crashed two steps later" look identical. Verified by mutation on a
    // scratch copy, 2026-09-14 — removing the challenge gate, or the
    // lookup's own null guard, leaves both green. Those two checks are
    // proved by challengeIsValid() and findCredential(), which are tested
    // directly; what these tests add is the session assertion, the one
    // property that must hold on every path whichever check fired.

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsWhenNoChallenge(): void
    {
        $this->makeUser();
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator);
        $this->passkeys->beginLogin();
        $payload = $authenticator->assert(self::issuedChallenge());
        $_SESSION = [];

        $this->assertNull($this->passkeys->finishLogin($payload));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsUnknownCredentialId(): void
    {
        $this->makeUser();
        $this->enrolCredential($this->authenticator());
        $this->passkeys->beginLogin();

        // A genuine, correctly signed assertion from a passkey that was
        // simply never enrolled here.
        $stranger = $this->authenticator('no-such-credential');

        $this->assertNull($this->passkeys->finishLogin($stranger->assert(self::issuedChallenge())));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsAnAssertionFromADisallowedOrigin(): void
    {
        $this->makeUser();
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator);
        $this->passkeys->beginLogin();

        $this->assertNull(
            $this->passkeys->finishLogin($authenticator->assert(self::issuedChallenge(), 'https://evil.test'))
        );
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    /**
     * The most important rejection test in this file.
     *
     * An imposter holds the right credential id and the right user handle,
     * and builds a perfectly formed assertion over the challenge that was
     * actually issued, with the right rpId hash and the right flags — it
     * simply does not hold the private key. Everything in the ceremony
     * passes until CheckSignature, so this test covers the whole tail of
     * it: rpId hash, user presence, user verification, backup bits, and
     * the signature itself.
     *
     * A zero sign count on both sides is the common case, not a corner: it
     * is what iCloud Keychain reports, and the sign-counter rule accepts it
     * by design. So for a credential like this one there is nothing behind
     * the signature check at all — delete either it or the whole `check()`
     * call and this test fails with `user_id` in the session.
     */
    #[RunInSeparateProcess]
    public function testFinishLoginRejectsAnAssertionSignedByTheWrongKey(): void
    {
        $this->makeUser();
        $this->enrolCredential($this->authenticator(), 1, 0);
        // Same credential id, same user handle, different keypair.
        $imposter = $this->authenticator();
        $this->passkeys->beginLogin();

        $this->assertNull($this->passkeys->finishLogin($imposter->assert(self::issuedChallenge())));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    /**
     * The same rejection with a counter in use. What this one adds is the
     * *ordering* of the write-back: move the sign_count / last_used_at
     * update ahead of the ceremony and it fails, because a rejected
     * assertion would have moved the counter.
     */
    #[RunInSeparateProcess]
    public function testARejectedAssertionDoesNotTouchTheStoredCredential(): void
    {
        $this->makeUser();
        $this->enrolCredential($this->authenticator(), 1, 5);
        $imposter = $this->authenticator();
        $this->passkeys->beginLogin();

        $this->assertNull(
            $this->passkeys->finishLogin($imposter->assert(self::issuedChallenge(), 'https://example.com', 6))
        );

        $this->assertArrayNotHasKey('user_id', $_SESSION);
        $row = $this->pdo->query('SELECT sign_count, last_used_at FROM user_credentials')->fetch();
        $this->assertSame(5, (int)$row['sign_count'], 'a rejected assertion must not move the counter');
        $this->assertNull($row['last_used_at'], 'nor mark the credential as used');
    }

    // ------------------------------------------------------- the happy path

    /**
     * The only test in this file that reaches the end of finishLogin().
     *
     * Without it, everything after the ceremony — the sign_count write-back,
     * the last_used_at stamp, loginAs() and the returned row — is never
     * executed at all, and deleting any of it, or logging in the wrong
     * user id, breaks nothing.
     */
    #[RunInSeparateProcess]
    public function testASuccessfulLoginEstablishesASessionForTheCredentialsOwner(): void
    {
        $this->makeUser(1, 'alice');
        $this->makeUser(2, 'bob');
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator, 1, 5);
        $this->passkeys->beginLogin();

        $user = $this->passkeys->finishLogin($authenticator->assert(self::issuedChallenge(), 'https://example.com', 6));

        $this->assertIsArray($user, 'a verified assertion must log its owner in');
        $this->assertSame(1, $user['id']);
        $this->assertSame('alice', $user['username'],
            'the session belongs to the credential owner, not to whoever happens to be user 1');
        $this->assertSame(1, $_SESSION['user_id']);

        $row = $this->pdo->query('SELECT sign_count, last_used_at FROM user_credentials')->fetch();
        $this->assertSame(6, (int)$row['sign_count'],
            'without the write-back the replay check is inert on the next login');
        $this->assertNotNull($row['last_used_at']);
    }

    /** The credential's owner is whoever enrolled it, not a fixed user 1. */
    #[RunInSeparateProcess]
    public function testASuccessfulLoginLogsInTheCredentialsOwnerNotAnotherUser(): void
    {
        $this->makeUser(1, 'alice');
        $this->makeUser(2, 'bob');
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator, 2);
        $this->passkeys->beginLogin();

        $user = $this->passkeys->finishLogin($authenticator->assert(self::issuedChallenge(), 'https://example.com', 1));

        $this->assertIsArray($user);
        $this->assertSame('bob', $user['username']);
        $this->assertSame(2, $_SESSION['user_id']);
    }

    /**
     * Replaying a captured assertion is the attack the single-use challenge
     * exists to stop, and only a test that logs in first can show it being
     * stopped: the first call proves the payload is otherwise good, so the
     * second call's refusal cannot be blamed on anything else about it.
     */
    #[RunInSeparateProcess]
    public function testTheSameAssertionCannotBeReplayed(): void
    {
        $this->makeUser();
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator, 1, 5);
        $this->passkeys->beginLogin();
        $payload = $authenticator->assert(self::issuedChallenge(), 'https://example.com', 6);

        $this->assertIsArray($this->passkeys->finishLogin($payload), 'guard: the payload is good');

        $this->assertNull($this->passkeys->finishLogin($payload), 'a replayed assertion must be refused');
        $row = $this->pdo->query('SELECT sign_count FROM user_credentials')->fetch();
        $this->assertSame(6, (int)$row['sign_count'], 'and must not move the counter a second time');
    }

    /**
     * The same replay against a credential that does not count — and the
     * reason this is a separate test rather than a second data set.
     *
     * When a counter is in use, the replay above is refused by the counter
     * rule before the challenge is ever consulted, so it does not actually
     * prove the challenge is single use. With both counters at zero the
     * counter rule is skipped by design, and the consumed challenge is the
     * only thing left. Stop `consumeChallenge()` clearing the session and
     * this test — alone in the suite — fails with a second successful
     * login. Verified by mutation on a scratch copy, 2026-09-14.
     */
    #[RunInSeparateProcess]
    public function testAZeroCounterAssertionCannotBeReplayedEither(): void
    {
        $this->makeUser();
        $authenticator = $this->authenticator();
        $this->enrolCredential($authenticator, 1, 0);
        $this->passkeys->beginLogin();
        $payload = $authenticator->assert(self::issuedChallenge());

        $this->assertIsArray($this->passkeys->finishLogin($payload), 'guard: the payload is good');

        $this->assertNull(
            $this->passkeys->finishLogin($payload),
            'with no counter to rely on, the single-use challenge is the whole defence'
        );
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
        $this->enrolCredential($this->authenticator());

        $this->assertNull($this->passkeys->findCredential(Passkeys::b64u('no-such-credential')));
    }

    public function testCredentialLookupFindsAnEnrolledCredential(): void
    {
        $this->makeUser();
        $this->enrolCredential($this->authenticator(), 1, 7);

        $row = $this->passkeys->findCredential(Passkeys::b64u('credential-one'));

        $this->assertIsArray($row);
        $this->assertSame(1, (int)$row['user_id']);
        $this->assertSame(7, (int)$row['sign_count']);
        $this->assertSame(Passkeys::b64u(self::TEST_USER_HANDLE), $row['webauthn_user_handle']);
    }

    public function testCredentialLookupIgnoresACredentialWhoseOwnerIsGone(): void
    {
        $this->makeUser();
        $this->enrolCredential($this->authenticator());
        // Production has ON DELETE CASCADE, so this row cannot outlive its
        // user there. The join is what makes that true here as well, and an
        // ownerless credential must never authenticate anyone.
        $this->pdo->exec('DELETE FROM users WHERE id = 1');

        $this->assertNull($this->passkeys->findCredential(Passkeys::b64u('credential-one')));
    }

    public function testCredentialLookupIgnoresACredentialWhoseOwnerHasNoUserHandle(): void
    {
        $this->makeUser();
        $this->enrolCredential($this->authenticator());
        $this->pdo->exec('UPDATE users SET webauthn_user_handle = NULL WHERE id = 1');

        $this->assertNull(
            $this->passkeys->findCredential(Passkeys::b64u('credential-one')),
            'without a handle there is nothing for the library to match the assertion against'
        );
    }

    // -- Task 7: credential management -----------------------------------
    //
    // listCredentials/deleteCredential/hasCredentials are plain SQL over
    // rows in user_credentials; none of them run a ceremony or touch a
    // public key's contents, so enrolCredential()'s real COSE key and
    // software authenticator are unneeded machinery here. This helper is a
    // direct INSERT, matching what these methods actually read.

    private function makeCredential(int $userId, string $credId, string $label): int
    {
        $this->pdo->prepare('INSERT INTO user_credentials
            (user_id, credential_id, public_key, sign_count, label, created_at)
            VALUES (?, ?, ?, 0, ?, ?)')
            ->execute([$userId, $credId, 'PUBKEY', $label, '2026-09-13 00:00:00']);
        return (int)$this->pdo->lastInsertId();
    }

    public function testListCredentialsReturnsOnlyOwnAndNoPublicKey(): void
    {
        $this->makeUser(1, 'alice');
        $this->makeUser(2, 'mallory');
        $this->makeCredential(1, 'cred-a', 'Alice Laptop');
        $this->makeCredential(2, 'cred-m', 'Mallory Laptop');

        $rows = $this->passkeys->listCredentials(1);

        $this->assertCount(1, $rows);
        $this->assertSame('Alice Laptop', $rows[0]['label']);
        $this->assertArrayNotHasKey('public_key', $rows[0]);
    }

    public function testDeleteCredentialCannotDeleteAnotherUsersCredential(): void
    {
        $this->makeUser(1, 'alice');
        $this->makeUser(2, 'mallory');
        $victim = $this->makeCredential(1, 'cred-a', 'Alice Laptop');

        $this->assertFalse($this->passkeys->deleteCredential(2, $victim));
        $this->assertCount(1, $this->passkeys->listCredentials(1),
            'cross-user deletion is a silent privilege failure if unguarded');
    }

    public function testDeleteCredentialRemovesOwnCredential(): void
    {
        $this->makeUser(1, 'alice');
        $id = $this->makeCredential(1, 'cred-a', 'Alice Laptop');

        $this->assertTrue($this->passkeys->deleteCredential(1, $id));
        $this->assertCount(0, $this->passkeys->listCredentials(1));
    }

    public function testHasCredentials(): void
    {
        $this->makeUser(1, 'alice');
        $this->assertFalse($this->passkeys->hasCredentials(1));

        $this->makeCredential(1, 'cred-a', 'Alice Laptop');
        $this->assertTrue($this->passkeys->hasCredentials(1));
    }

    // ------------------------------------------- the gap after check()

    /**
     * Everything from here down covers the stretch between webauthn-lib's
     * check() returning and the row landing in the database. That stretch
     * sits outside finishRegistration()'s try block on purpose -- a database
     * error there must not be swallowed as "credential rejected" -- which
     * means anything it can throw escapes as a 500 *after* the user has
     * already touched their authenticator. The suite runs on SQLite, which
     * enforces neither column widths nor MariaDB's strict mode, so none of
     * these could surface as a plain assertion on stored data.
     */

    public function testPackTransportsSkipsNonStringElements(): void
    {
        $this->assertSame('usb', Passkeys::packTransports([123, 'usb']));
    }

    /**
     * `transports` is not covered by any signature -- attestation is `none`,
     * and the denormalizer passes the array through element-unchecked -- so
     * it is client input arriving at a `: bool` method under strict_types.
     */
    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsNonStringTransports(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $handle = (string)$this->passkeys->userHandle(1);
        $authenticator = new SoftwareAuthenticator('example.com', 'a-new-credential', Passkeys::b64uDecode($handle));

        $payload = json_decode($authenticator->attest(self::issuedChallenge()), true);
        $payload['response']['transports'] = [123];

        $this->assertTrue(
            $this->passkeys->finishRegistration(1, json_encode($payload)),
            'a junk transport hint must not abort an otherwise valid ceremony'
        );
        $this->assertNull(
            $this->pdo->query('SELECT transports FROM user_credentials')->fetch()['transports'],
            'the unusable hint is dropped rather than stored'
        );
    }

    /**
     * CheckCredentialId accepts a raw credential id up to 1023 bytes, but
     * the column holds 255 base64url characters -- 191 raw bytes. Above
     * that, MariaDB's strict mode throws a PDOException out of a method
     * documented to return false, and a relaxed sql_mode is worse: the row
     * enrols truncated and findCredential() can never match it again.
     */
    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsAnOversizedCredentialId(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $handle = (string)$this->passkeys->userHandle(1);
        $authenticator = new SoftwareAuthenticator('example.com', str_repeat('x', 192), Passkeys::b64uDecode($handle));

        $this->assertFalse($this->passkeys->finishRegistration(1, $authenticator->attest(self::issuedChallenge())));
        $this->assertCount(0, $this->passkeys->listCredentials(1));
    }

    #[RunInSeparateProcess]
    public function testFinishRegistrationAcceptsTheWidestCredentialIdTheColumnHolds(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $handle = (string)$this->passkeys->userHandle(1);
        $authenticator = new SoftwareAuthenticator('example.com', str_repeat('x', 191), Passkeys::b64uDecode($handle));

        $this->assertTrue($this->passkeys->finishRegistration(1, $authenticator->attest(self::issuedChallenge())));
        $stored = $this->pdo->query('SELECT credential_id FROM user_credentials')->fetch();
        $this->assertSame(255, strlen($stored['credential_id']), 'exactly fills the column');
    }

    /**
     * Re-enrolling an authenticator that returns a stable credential id
     * violates the UNIQUE index. Unguarded that is a PDOException, again
     * after a completed biometric.
     */
    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsAnAlreadyEnrolledCredential(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');
        $handle = (string)$this->passkeys->userHandle(1);
        $authenticator = new SoftwareAuthenticator('example.com', 'a-new-credential', Passkeys::b64uDecode($handle));
        $this->assertTrue($this->passkeys->finishRegistration(1, $authenticator->attest(self::issuedChallenge())));

        $this->passkeys->beginRegistration(1, 'Laptop again');

        $this->assertFalse($this->passkeys->finishRegistration(1, $authenticator->attest(self::issuedChallenge())));
        $this->assertCount(1, $this->passkeys->listCredentials(1), 'the first enrolment survives');
    }

    /**
     * The browser half already decodes `excludeCredentials`; until now the
     * server half never populated it, so nothing told the authenticator not
     * to re-enrol in the first place.
     */
    #[RunInSeparateProcess]
    public function testBeginRegistrationExcludesAlreadyEnrolledCredentials(): void
    {
        $this->makeUser();
        $this->makeCredential(1, Passkeys::b64u('credential-one'), 'Laptop');

        $options = json_decode($this->passkeys->beginRegistration(1, 'Phone'), true);

        $this->assertSame(
            [Passkeys::b64u('credential-one')],
            array_column($options['excludeCredentials'], 'id')
        );
    }

    /**
     * mb_strlen() counts invalid UTF-8 happily; a utf8mb4 column does not
     * accept it. Without this the length guard's docblock over-claims.
     */
    public function testBeginRegistrationRejectsAnInvalidUtf8Label(): void
    {
        $this->makeUser();

        $this->expectException(InvalidArgumentException::class);
        $this->passkeys->beginRegistration(1, "Laptop\xC3\x28");
    }

    /**
     * README tells consumers to derive rp_id as ltrim($cookieDomain, '.').
     * A cookie domain of '.Example.com' would then reject *every* origin,
     * indistinguishably from a dozen other rejections.
     */
    public function testRpIdMatchingIsCaseInsensitive(): void
    {
        $passkeys = new Passkeys($this->pdo, new Auth($this->pdo), ['rp_id' => 'Example.COM']);

        $this->assertTrue($passkeys->originMatchesRpId('https://example.com'));
        $this->assertTrue($passkeys->originMatchesRpId('https://sub.example.com'));

        // Hosts are case-insensitive per the URL spec. Browsers normalise
        // before we ever see the origin, so this is defence in depth on a
        // path that otherwise fails closed and silently.
        $this->assertTrue($this->passkeys->originMatchesRpId('https://EXAMPLE.com'));
        $this->assertFalse($this->passkeys->originMatchesRpId('https://NOTexample.com'));
    }
}
