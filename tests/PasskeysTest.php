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
}
