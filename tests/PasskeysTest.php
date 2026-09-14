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
        $this->assertSame('Laptop', $_SESSION['passkey_label']);
        $this->assertGreaterThan(time(), $_SESSION['passkey_expires']);
    }

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
}
