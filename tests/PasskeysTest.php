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
}
