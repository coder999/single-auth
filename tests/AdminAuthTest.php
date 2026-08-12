<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\AdminAuth;
use PDO;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class AdminAuthTest extends TestCase
{
    private PDO $pdo;
    private AdminAuth $auth;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT NULL
        )');
        $this->pdo->exec('CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        )');

        $this->auth = new AdminAuth($this->pdo, ['cookie_domain' => '.nexus.local']);
        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    #[RunInSeparateProcess]
    public function testCurrentAdminReturnsNullWithNoSession(): void
    {
        $this->assertNull($this->auth->currentAdmin());
    }

    #[RunInSeparateProcess]
    public function testCurrentAdminReturnsUserWhenSessionHasAdminId(): void
    {
        $this->pdo->prepare('INSERT INTO admin_users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);
        $_SESSION['admin_id'] = 1;

        $user = $this->auth->currentAdmin();

        $this->assertNotNull($user);
        $this->assertSame('alice', $user['username']);
    }

    #[RunInSeparateProcess]
    public function testCurrentAdminReturnsNullWhenSessionUserWasDeleted(): void
    {
        $_SESSION['admin_id'] = 999;

        $this->assertNull($this->auth->currentAdmin());
    }
}
