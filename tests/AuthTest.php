<?php

declare(strict_types=1);

namespace Coder999\SingleAuth\Tests;

use Coder999\SingleAuth\Auth;
use PDO;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class AuthTest extends TestCase
{
    private PDO $pdo;
    private Auth $auth;

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
            last_login TEXT NULL
        )');
        $this->pdo->exec('CREATE TABLE login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        )');

        $this->auth = new Auth($this->pdo, ['cookie_domain' => '.nexus.local']);
        $this->auth->sessionStart();
        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    #[RunInSeparateProcess]
    public function testCurrentUserReturnsNullWithNoSession(): void
    {
        $this->assertNull($this->auth->currentUser());
    }

    #[RunInSeparateProcess]
    public function testDefaultCookieNameIsIdentitySession(): void
    {
        $auth = new Auth($this->pdo, ['cookie_domain' => '.nexus.local']);
        $auth->sessionStart();

        $this->assertSame('identity_session', session_name());
    }

    #[RunInSeparateProcess]
    public function testCurrentUserReturnsUserWhenSessionHasUserId(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);
        $_SESSION['user_id'] = 1;

        $user = $this->auth->currentUser();

        $this->assertNotNull($user);
        $this->assertSame('alice', $user['username']);
        $this->assertIsInt($user['id']);
        $this->assertSame(1, $user['id']);
    }

    #[RunInSeparateProcess]
    public function testCurrentUserReturnsNullWhenSessionUserWasDeleted(): void
    {
        $_SESSION['user_id'] = 999;

        $this->assertNull($this->auth->currentUser());
    }

    #[RunInSeparateProcess]
    public function testCsrfTokenIsGeneratedAndStable(): void
    {
        $first = $this->auth->csrfToken();
        $second = $this->auth->csrfToken();

        $this->assertSame(64, strlen($first)); // bin2hex(random_bytes(32))
        $this->assertSame($first, $second);
    }

    #[RunInSeparateProcess]
    public function testCsrfFieldEmbedsTheToken(): void
    {
        $field = $this->auth->csrfField();

        $this->assertStringContainsString($this->auth->csrfToken(), $field);
        $this->assertStringContainsString('name="csrf"', $field);
    }

    #[RunInSeparateProcess]
    public function testCsrfCheckPassesWithMatchingToken(): void
    {
        $token = $this->auth->csrfToken();
        $_POST['csrf'] = $token;

        $this->auth->csrfCheck(); // no exception/exit means success

        $this->assertTrue(true);
    }

    #[RunInSeparateProcess]
    public function testAttemptLoginSucceedsWithCorrectPassword(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);

        $result = $this->auth->attemptLogin('alice', 'secret');

        $this->assertTrue($result);
        $this->assertSame(1, $_SESSION['user_id']);
    }

    #[RunInSeparateProcess]
    public function testAttemptLoginFailsWithWrongPasswordAndRecordsAttempt(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);

        $result = $this->auth->attemptLogin('alice', 'wrong');

        $this->assertFalse($result);
        $this->assertArrayNotHasKey('user_id', $_SESSION);
        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM login_attempts')->fetch()['n'];
        $this->assertSame(1, $count);
    }

    #[RunInSeparateProcess]
    public function testAttemptLoginClearsPriorAttemptsOnSuccess(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);
        $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)')
            ->execute(['127.0.0.1', (new \DateTimeImmutable())->format('Y-m-d H:i:s')]);

        $this->auth->attemptLogin('alice', 'secret');

        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM login_attempts')->fetch()['n'];
        $this->assertSame(0, $count);
    }

    #[RunInSeparateProcess]
    public function testLoginThrottledAfterMaxAttempts(): void
    {
        $auth = new Auth($this->pdo, ['cookie_domain' => '.nexus.local', 'login_max_attempts' => 3]);
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)');
        for ($i = 0; $i < 3; $i++) {
            $stmt->execute(['127.0.0.1', $now]);
        }

        $this->assertTrue($auth->loginThrottled());
    }

    #[RunInSeparateProcess]
    public function testLoginNotThrottledWhenAttemptsAreOld(): void
    {
        $auth = new Auth($this->pdo, ['cookie_domain' => '.nexus.local', 'login_max_attempts' => 1, 'login_window_seconds' => 60]);
        $old = (new \DateTimeImmutable('-2 hours'))->format('Y-m-d H:i:s');
        $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)')
            ->execute(['127.0.0.1', $old]);

        $this->assertFalse($auth->loginThrottled());
    }

    #[RunInSeparateProcess]
    public function testLogoutClearsSession(): void
    {
        $_SESSION['user_id'] = 1;
        $_SESSION['csrf'] = 'token';

        $this->auth->logout();

        $this->assertSame([], $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testLoginAsEstablishesSessionForExistingUser(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (7, ?, ?)')
            ->execute(['carol', password_hash('pw', PASSWORD_DEFAULT)]);

        $this->assertTrue($this->auth->loginAs(7));
        $this->assertSame(7, $_SESSION['user_id']);

        $user = $this->auth->currentUser();
        $this->assertNotNull($user);
        $this->assertSame('carol', $user['username']);
    }

    #[RunInSeparateProcess]
    public function testLoginAsReturnsFalseForUnknownUserAndSetsNoSession(): void
    {
        $this->assertFalse($this->auth->loginAs(999));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testLoginAsStampsLastLogin(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (8, ?, ?)')
            ->execute(['dave', password_hash('pw', PASSWORD_DEFAULT)]);

        $this->auth->loginAs(8);

        $st = $this->pdo->query('SELECT last_login FROM users WHERE id = 8');
        $this->assertNotNull($st->fetch(PDO::FETCH_ASSOC)['last_login']);
    }

    /**
     * attemptLogin() delegates the whole "establish a session" step to
     * loginAs(), which returns false when the user row is gone. Reporting
     * success anyway hands the caller a logged-in user that has no session.
     *
     * The race is real but narrow -- the row must vanish between
     * attemptLogin()'s SELECT and loginAs()'s -- so it is reproduced here
     * by deleting through a second handle to the same database at exactly
     * that point, rather than by stubbing Auth.
     */
    #[RunInSeparateProcess]
    public function testAttemptLoginReportsFailureWhenTheUserVanishesMidLogin(): void
    {
        $this->pdo->prepare('INSERT INTO users (id, username, password_hash) VALUES (9, ?, ?)')
            ->execute(['eve', password_hash('pw', PASSWORD_DEFAULT)]);

        $pdo = new class ('sqlite::memory:') extends PDO {
            public ?PDO $real = null;
            public function prepare(string $query, array $options = []): \PDOStatement|false
            {
                // The DELETE lands after the credential check has passed and
                // before loginAs() looks the user up again.
                if (str_starts_with($query, 'DELETE FROM login_attempts')) {
                    $this->real->exec('DELETE FROM users WHERE id = 9');
                }
                return $this->real->prepare($query, $options);
            }
            public function query(string $query, ?int $fetchMode = null, mixed ...$args): \PDOStatement|false
            {
                return $this->real->query($query);
            }
        };
        $pdo->real = $this->pdo;

        $auth = new Auth($pdo, ['cookie_domain' => '.nexus.local']);

        $this->assertFalse($auth->attemptLogin('eve', 'pw'));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }
}
