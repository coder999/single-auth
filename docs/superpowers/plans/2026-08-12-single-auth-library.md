# single-auth Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and tag v0.1.0 of `coder999/single-auth`, a standalone Composer
package providing shared PHP-session-based admin authentication
(`AdminAuth`) and DB-backed session storage (`DbSessionHandler`), plus its
own database schema and a production migrate-only CI workflow.

**Architecture:** A small PSR-4 library with two classes, each independently
unit-testable against an in-memory SQLite PDO (no live MySQL needed for
tests — the SQL surface is deliberately kept portable). Schema lives in this
repo's own `db/migrations/` (dbmate), applied to a dedicated `single_auth`
database via a manual-trigger GitHub Actions workflow, never from a dev
machine directly. This plan does **not** touch marktuttlemd or
mdproductivity — that's the next two plans, which depend on this one being
tagged first.

**Tech Stack:** PHP 8.1+, Composer, PHPUnit 10, dbmate, MariaDB (local),
GitHub Actions.

## Global Constraints

- Composer package name: `coder999/single-auth`. PSR-4 namespace:
  `Mtmd\SingleAuth\` → `src/`.
- PHP `>=8.1`.
- Session cookie name stays `mtmd_admin` (default in `AdminAuth`).
- Identity tables (`admin_users`, `login_attempts`, `admin_sessions`) live
  in their own `single_auth` database — never `marktuttlemd`'s database.
  Schema for `admin_users`/`login_attempts` must exactly match
  `marktuttlemd/db/migrations/20260728020000_baseline_schema.sql` (needed
  so the later data migration is a straight copy, no transformation).
- Dedicated MySQL user `identity_auth`, scoped to `single_auth.*` only —
  this library never assumes it has access to any other database.
- No SQL dialect-specific syntax (no `NOW()`, `INTERVAL`, or
  `ON DUPLICATE KEY UPDATE`) — all "current time" values are computed in
  PHP and passed as bound parameters, and writes use
  select-then-insert-or-update instead of upsert syntax. This is what
  makes the whole library testable against SQLite without a live MySQL,
  and is a deliberate, permanent property of this codebase, not a
  shortcut to remove later.
- No login-page HTML, no authorization/roles — this library only answers
  "who is this," never "what can they do" (see spec, "Authn vs authz").
- Production database schema changes only ever happen via this repo's own
  CI workflow (`dbmate up` run over SSH on the IONOS host) — never by
  connecting to the production database directly from a dev machine.

---

### Task 1: Composer + PHPUnit scaffold

**Files:**
- Create: `composer.json`
- Create: `.gitignore`
- Create: `phpunit.xml`

**Interfaces:**
- Produces: an autoloadable `Mtmd\SingleAuth\` namespace rooted at `src/`,
  and a working `vendor/bin/phpunit` for every later task's tests.

- [ ] **Step 1: Write `composer.json`**

```json
{
    "name": "coder999/single-auth",
    "description": "Shared PHP identity/session library for marktuttlemd.com and its subdomain apps",
    "type": "library",
    "license": "proprietary",
    "require": {
        "php": ">=8.1",
        "ext-pdo": "*"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.5"
    },
    "autoload": {
        "psr-4": {
            "Mtmd\\SingleAuth\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Mtmd\\SingleAuth\\Tests\\": "tests/"
        }
    }
}
```

- [ ] **Step 2: Write `.gitignore`**

```
/vendor/
composer.lock
.phpunit.result.cache
```

- [ ] **Step 3: Write `phpunit.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true">
    <testsuites>
        <testsuite name="single-auth">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
</phpunit>
```

- [ ] **Step 4: Install dependencies**

```bash
mkdir -p src tests
docker exec -w /var/www/html-local/single-auth php composer install
```

Expected: `vendor/` is created, `composer.lock` is written, no errors.

- [ ] **Step 5: Verify PHPUnit runs with zero tests**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit
```

Expected: `No tests executed!` (not an error — confirms the harness itself
works before any test exists).

- [ ] **Step 6: Commit**

```bash
git add composer.json .gitignore phpunit.xml
git commit -m "Scaffold Composer package and PHPUnit harness"
```

(`vendor/` and `composer.lock` stay untracked per `.gitignore` — this is a
library other projects will pin by tag, not an app that ships its own lock
file.)

---

### Task 2: `AdminAuth` — identity lookup (`currentAdmin`/`requireAdmin`)

**Files:**
- Create: `src/AdminAuth.php`
- Test: `tests/AdminAuthTest.php`

**Interfaces:**
- Produces: `Mtmd\SingleAuth\AdminAuth::__construct(PDO $pdo, array $options = [])`
  where `$options` may set `cookie_name` (default `'mtmd_admin'`),
  `cookie_domain` (default `''`, meaning host-only — matches
  marktuttlemd's current live cookie behavior until a later plan flips it),
  `cookie_secure` (default `true`), `login_max_attempts` (default `8`),
  `login_window_seconds` (default `900`).
- Produces: `currentAdmin(): ?array` — returns `['id' => int, 'username' =>
  string, 'last_login' => ?string]` or `null`.
- Produces: `requireAdmin(string $loginUrl = 'login.php'): array` — same
  shape as `currentAdmin()`, but redirects and exits instead of returning
  `null`.

Every test in this file needs its own PHP process, because
`AdminAuth::sessionStart()` calls PHP's real `session_start()`, and PHP
sessions are process-global state — the second test in a shared process
would silently inherit the first test's already-active session instead of
exercising a fresh one. `#[RunInSeparateProcess]` on the class fixes this
at the cost of test speed, which is fine for a suite this small.

- [ ] **Step 1: Write the failing tests**

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\AdminAuth;
use PDO;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

#[RunInSeparateProcess]
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

    public function testCurrentAdminReturnsNullWithNoSession(): void
    {
        $this->assertNull($this->auth->currentAdmin());
    }

    public function testCurrentAdminReturnsUserWhenSessionHasAdminId(): void
    {
        $this->pdo->prepare('INSERT INTO admin_users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);
        $_SESSION['admin_id'] = 1;

        $user = $this->auth->currentAdmin();

        $this->assertNotNull($user);
        $this->assertSame('alice', $user['username']);
    }

    public function testCurrentAdminReturnsNullWhenSessionUserWasDeleted(): void
    {
        $_SESSION['admin_id'] = 999;

        $this->assertNull($this->auth->currentAdmin());
    }
}
```

- [ ] **Step 2: Run and verify it fails**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AdminAuthTest.php
```

Expected: FAIL — `Class "Mtmd\SingleAuth\AdminAuth" not found`.

- [ ] **Step 3: Implement `AdminAuth` (identity lookup only so far)**

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth;

use PDO;

final class AdminAuth
{
    private PDO $pdo;
    private string $cookieName;
    private string $cookieDomain;
    private bool $cookieSecure;
    private int $loginMaxAttempts;
    private int $loginWindowSeconds;

    public function __construct(PDO $pdo, array $options = [])
    {
        $this->pdo = $pdo;
        $this->cookieName = $options['cookie_name'] ?? 'mtmd_admin';
        // '' (host-only) matches marktuttlemd's current live cookie
        // behavior — callers pass '.marktuttlemd.com' / '.nexus.local'
        // only once they're ready for cross-subdomain sharing.
        $this->cookieDomain = $options['cookie_domain'] ?? '';
        $this->cookieSecure = $options['cookie_secure'] ?? true;
        $this->loginMaxAttempts = $options['login_max_attempts'] ?? 8;
        $this->loginWindowSeconds = $options['login_window_seconds'] ?? 900;
    }

    public function sessionStart(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        session_name($this->cookieName);
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => $this->cookieDomain,
            'secure'   => $this->cookieSecure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }

    public function currentAdmin(): ?array
    {
        $this->sessionStart();
        if (empty($_SESSION['admin_id'])) {
            return null;
        }
        $st = $this->pdo->prepare('SELECT id, username, last_login FROM admin_users WHERE id = ?');
        $st->execute([$_SESSION['admin_id']]);
        $user = $st->fetch();
        return $user === false ? null : $user;
    }

    public function requireAdmin(string $loginUrl = 'login.php'): array
    {
        $user = $this->currentAdmin();
        if ($user === null) {
            header('Location: ' . $loginUrl);
            exit;
        }
        return $user;
    }
}
```

- [ ] **Step 4: Run and verify it passes**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AdminAuthTest.php
```

Expected: 3 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add src/AdminAuth.php tests/AdminAuthTest.php
git commit -m "AdminAuth: session bootstrap and identity lookup"
```

---

### Task 3: `AdminAuth` — CSRF helpers

**Files:**
- Modify: `src/AdminAuth.php`
- Modify: `tests/AdminAuthTest.php`

**Interfaces:**
- Consumes: the `AdminAuth` class and `$this->auth`/`$this->pdo` fixture
  from Task 2.
- Produces: `csrfToken(): string`, `csrfField(): string`,
  `csrfCheck(): void` (calls `exit` with HTTP 400 on mismatch — the
  failure path is intentionally not unit tested, since it terminates the
  process by design; it's covered by manual verification once a
  consuming app's login form exists).

- [ ] **Step 1: Add the failing tests**

```php
    public function testCsrfTokenIsGeneratedAndStable(): void
    {
        $first = $this->auth->csrfToken();
        $second = $this->auth->csrfToken();

        $this->assertSame(64, strlen($first)); // bin2hex(random_bytes(32))
        $this->assertSame($first, $second);
    }

    public function testCsrfFieldEmbedsTheToken(): void
    {
        $field = $this->auth->csrfField();

        $this->assertStringContainsString($this->auth->csrfToken(), $field);
        $this->assertStringContainsString('name="csrf"', $field);
    }

    public function testCsrfCheckPassesWithMatchingToken(): void
    {
        $token = $this->auth->csrfToken();
        $_POST['csrf'] = $token;

        $this->auth->csrfCheck(); // no exception/exit means success

        $this->assertTrue(true);
    }
```

- [ ] **Step 2: Run and verify these three fail**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AdminAuthTest.php
```

Expected: FAIL — `Call to undefined method Mtmd\SingleAuth\AdminAuth::csrfToken()`.

- [ ] **Step 3: Add the CSRF methods**

```php
    public function csrfToken(): string
    {
        $this->sessionStart();
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf'];
    }

    public function csrfField(): string
    {
        return '<input type="hidden" name="csrf" value="' . htmlspecialchars($this->csrfToken()) . '">';
    }

    public function csrfCheck(): void
    {
        $this->sessionStart();
        $sent = $_POST['csrf'] ?? '';
        if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], (string)$sent)) {
            http_response_code(400);
            exit('Invalid or expired form token. Go back, reload the page, and try again.');
        }
    }
```

(Insert these methods into the `AdminAuth` class body from Task 2, after
`requireAdmin()`.)

- [ ] **Step 4: Run and verify it passes**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AdminAuthTest.php
```

Expected: 6 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add src/AdminAuth.php tests/AdminAuthTest.php
git commit -m "AdminAuth: CSRF token helpers"
```

---

### Task 4: `AdminAuth` — login throttling, `attemptLogin`, `logout`

**Files:**
- Modify: `src/AdminAuth.php`
- Modify: `tests/AdminAuthTest.php`

**Interfaces:**
- Produces: `loginThrottled(): bool`, `attemptLogin(string $username,
  string $password): bool`, `logout(): void`, `clientIp(): string`.
- Uses PHP-computed timestamps (`\DateTimeImmutable`), never SQL
  `NOW()`/`INTERVAL` — see Global Constraints.

- [ ] **Step 1: Add the failing tests**

```php
    public function testAttemptLoginSucceedsWithCorrectPassword(): void
    {
        $this->pdo->prepare('INSERT INTO admin_users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);

        $result = $this->auth->attemptLogin('alice', 'secret');

        $this->assertTrue($result);
        $this->assertSame(1, $_SESSION['admin_id']);
    }

    public function testAttemptLoginFailsWithWrongPasswordAndRecordsAttempt(): void
    {
        $this->pdo->prepare('INSERT INTO admin_users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);

        $result = $this->auth->attemptLogin('alice', 'wrong');

        $this->assertFalse($result);
        $this->assertArrayNotHasKey('admin_id', $_SESSION);
        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM login_attempts')->fetch()['n'];
        $this->assertSame(1, $count);
    }

    public function testAttemptLoginClearsPriorAttemptsOnSuccess(): void
    {
        $this->pdo->prepare('INSERT INTO admin_users (id, username, password_hash) VALUES (1, ?, ?)')
            ->execute(['alice', password_hash('secret', PASSWORD_DEFAULT)]);
        $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)')
            ->execute(['127.0.0.1', (new \DateTimeImmutable())->format('Y-m-d H:i:s')]);

        $this->auth->attemptLogin('alice', 'secret');

        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM login_attempts')->fetch()['n'];
        $this->assertSame(0, $count);
    }

    public function testLoginThrottledAfterMaxAttempts(): void
    {
        $auth = new AdminAuth($this->pdo, ['cookie_domain' => '.nexus.local', 'login_max_attempts' => 3]);
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)');
        for ($i = 0; $i < 3; $i++) {
            $stmt->execute(['127.0.0.1', $now]);
        }

        $this->assertTrue($auth->loginThrottled());
    }

    public function testLoginNotThrottledWhenAttemptsAreOld(): void
    {
        $auth = new AdminAuth($this->pdo, ['cookie_domain' => '.nexus.local', 'login_max_attempts' => 1, 'login_window_seconds' => 60]);
        $old = (new \DateTimeImmutable('-2 hours'))->format('Y-m-d H:i:s');
        $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)')
            ->execute(['127.0.0.1', $old]);

        $this->assertFalse($auth->loginThrottled());
    }

    public function testLogoutClearsSession(): void
    {
        $_SESSION['admin_id'] = 1;
        $_SESSION['csrf'] = 'token';

        $this->auth->logout();

        $this->assertSame([], $_SESSION);
    }
```

- [ ] **Step 2: Run and verify these fail**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AdminAuthTest.php
```

Expected: FAIL — `Call to undefined method Mtmd\SingleAuth\AdminAuth::attemptLogin()`.

- [ ] **Step 3: Add the methods**

```php
    public function clientIp(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    public function loginThrottled(): bool
    {
        $cutoff = (new \DateTimeImmutable('now'))
            ->modify("-{$this->loginWindowSeconds} seconds")
            ->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND attempted_at > ?');
        $st->execute([$this->clientIp(), $cutoff]);
        return (int)$st->fetch()['n'] >= $this->loginMaxAttempts;
    }

    public function attemptLogin(string $username, string $password): bool
    {
        $this->sessionStart();
        $st = $this->pdo->prepare('SELECT * FROM admin_users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch();

        if ($user !== false && password_verify($password, $user['password_hash'])) {
            $this->pdo->prepare('DELETE FROM login_attempts WHERE ip = ?')->execute([$this->clientIp()]);
            session_regenerate_id(true);
            $_SESSION['admin_id'] = (int)$user['id'];
            $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
            $this->pdo->prepare('UPDATE admin_users SET last_login = ? WHERE id = ?')->execute([$now, $user['id']]);
            return true;
        }

        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $this->pdo->prepare('INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)')->execute([$this->clientIp(), $now]);
        return false;
    }

    public function logout(): void
    {
        $this->sessionStart();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
    }
```

- [ ] **Step 4: Run and verify it passes**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AdminAuthTest.php
```

Expected: 12 tests, 0 failures.

- [ ] **Step 5: Commit**

```bash
git add src/AdminAuth.php tests/AdminAuthTest.php
git commit -m "AdminAuth: login throttling, attemptLogin, logout"
```

---

### Task 5: `DbSessionHandler`

**Files:**
- Create: `src/DbSessionHandler.php`
- Test: `tests/DbSessionHandlerTest.php`

**Interfaces:**
- Produces: `Mtmd\SingleAuth\DbSessionHandler implements SessionHandlerInterface`,
  constructed with `__construct(PDO $pdo)`. Backs PHP sessions with an
  `admin_sessions(id VARCHAR PRIMARY KEY, data MEDIUMTEXT, last_activity DATETIME)`
  table. Writes use select-then-insert-or-update (no `ON DUPLICATE KEY
  UPDATE`) so the exact same class works against both MySQL (production)
  and SQLite (tests) — see Global Constraints.
- This class is tested by calling its `SessionHandlerInterface` methods
  directly, not through a real `session_start()` — no `RunInSeparateProcess`
  needed here, unlike `AdminAuthTest`.

- [ ] **Step 1: Write the failing tests**

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\DbSessionHandler;
use PDO;
use PHPUnit\Framework\TestCase;

final class DbSessionHandlerTest extends TestCase
{
    private PDO $pdo;
    private DbSessionHandler $handler;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE admin_sessions (
            id TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            last_activity TEXT NOT NULL
        )');
        $this->handler = new DbSessionHandler($this->pdo);
    }

    public function testReadReturnsEmptyStringForUnknownId(): void
    {
        $this->assertSame('', $this->handler->read('nonexistent'));
    }

    public function testWriteThenReadRoundTrips(): void
    {
        $this->handler->write('sess1', 'admin_id|i:1;');

        $this->assertSame('admin_id|i:1;', $this->handler->read('sess1'));
    }

    public function testWriteTwiceUpdatesInPlace(): void
    {
        $this->handler->write('sess1', 'first');
        $this->handler->write('sess1', 'second');

        $this->assertSame('second', $this->handler->read('sess1'));
        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM admin_sessions')->fetch()['n'];
        $this->assertSame(1, $count);
    }

    public function testDestroyRemovesTheRow(): void
    {
        $this->handler->write('sess1', 'data');

        $this->handler->destroy('sess1');

        $this->assertSame('', $this->handler->read('sess1'));
    }

    public function testGcRemovesOnlyExpiredRows(): void
    {
        $fresh = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stale = (new \DateTimeImmutable('-2 hours'))->format('Y-m-d H:i:s');
        $this->pdo->prepare('INSERT INTO admin_sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['fresh', 'a', $fresh]);
        $this->pdo->prepare('INSERT INTO admin_sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['stale', 'b', $stale]);

        $this->handler->gc(3600); // 1 hour max lifetime

        $this->assertSame('a', $this->handler->read('fresh'));
        $this->assertSame('', $this->handler->read('stale'));
    }
}
```

- [ ] **Step 2: Run and verify it fails**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/DbSessionHandlerTest.php
```

Expected: FAIL — `Class "Mtmd\SingleAuth\DbSessionHandler" not found`.

- [ ] **Step 3: Implement `DbSessionHandler`**

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth;

use PDO;
use SessionHandlerInterface;

final class DbSessionHandler implements SessionHandlerInterface
{
    public function __construct(private PDO $pdo)
    {
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        $st = $this->pdo->prepare('SELECT data FROM admin_sessions WHERE id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        return $row === false ? '' : $row['data'];
    }

    public function write(string $id, string $data): bool
    {
        $now = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');

        $exists = $this->pdo->prepare('SELECT 1 FROM admin_sessions WHERE id = ?');
        $exists->execute([$id]);

        if ($exists->fetch() !== false) {
            $st = $this->pdo->prepare('UPDATE admin_sessions SET data = ?, last_activity = ? WHERE id = ?');
            return $st->execute([$data, $now, $id]);
        }

        $st = $this->pdo->prepare('INSERT INTO admin_sessions (id, data, last_activity) VALUES (?, ?, ?)');
        return $st->execute([$id, $data, $now]);
    }

    public function destroy(string $id): bool
    {
        $st = $this->pdo->prepare('DELETE FROM admin_sessions WHERE id = ?');
        return $st->execute([$id]);
    }

    public function gc(int $max_lifetime): int|false
    {
        $cutoff = (new \DateTimeImmutable('now'))
            ->modify("-{$max_lifetime} seconds")
            ->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('DELETE FROM admin_sessions WHERE last_activity < ?');
        $st->execute([$cutoff]);
        return $st->rowCount();
    }
}
```

- [ ] **Step 4: Run and verify it passes**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit
```

Expected: all tests across both files pass (17 total).

- [ ] **Step 5: Commit**

```bash
git add src/DbSessionHandler.php tests/DbSessionHandlerTest.php
git commit -m "DbSessionHandler: DB-backed PHP session storage"
```

---

### Task 6: dbmate migrations for `single_auth`

**Files:**
- Create: `db/migrations/<timestamp>_baseline_schema.sql` (timestamp
  generated by `dbmate new`, do not hand-pick one)
- Generate: `db/schema.sql` (dbmate writes this automatically on `up`)

**Interfaces:**
- Produces: the `admin_users`, `login_attempts`, `admin_sessions` tables
  that `AdminAuth`/`DbSessionHandler` query against in real MySQL.
- `admin_users`/`login_attempts` column definitions are copied verbatim
  from `marktuttlemd/db/migrations/20260728020000_baseline_schema.sql`
  (lines 14–27) so the later data migration needs no transformation.

- [ ] **Step 1: Generate the migration file**

```bash
dbmate --migrations-dir db/migrations new baseline_schema
```

Expected: creates `db/migrations/<timestamp>_baseline_schema.sql` with
empty `-- migrate:up` / `-- migrate:down` sections.

- [ ] **Step 2: Write the migration**

```sql
-- migrate:up
CREATE TABLE IF NOT EXISTS admin_users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    attempted_at DATETIME NOT NULL,
    KEY idx_ip_time (ip, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS admin_sessions (
    id VARCHAR(128) NOT NULL PRIMARY KEY,
    data MEDIUMTEXT NOT NULL,
    last_activity DATETIME NOT NULL,
    KEY idx_last_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- migrate:down
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS admin_users;
```

- [ ] **Step 3: Provision the local `single_auth` database and user**

```bash
docker exec mariadb mysql -uroot -pChangeThisRootPassword -e "
  CREATE DATABASE IF NOT EXISTS single_auth CHARACTER SET utf8mb4;
  CREATE USER IF NOT EXISTS 'identity_auth'@'%' IDENTIFIED BY 'ChangeThisIdentityAuthPassword';
  GRANT ALL ON single_auth.* TO 'identity_auth'@'%';
  FLUSH PRIVILEGES;
"
```

Expected: no errors. (This mirrors how the container's other per-project
databases — `marktuttlemd`, `mdproductivity`, etc. — already got created;
same manual, one-time step, now for `single_auth`.)

- [ ] **Step 4: Apply the migration locally and verify**

```bash
DATABASE_URL="mysql://root:ChangeThisRootPassword@127.0.0.1:3306/single_auth" \
  dbmate --migrations-dir db/migrations up
docker exec mariadb mysql -uroot -pChangeThisRootPassword single_auth -e "SHOW TABLES;"
```

Expected: `admin_sessions`, `admin_users`, `login_attempts`,
`schema_migrations` listed. Confirm `db/schema.sql` was generated/updated
by the `up` command.

- [ ] **Step 5: Commit**

```bash
git add db/migrations db/schema.sql
git commit -m "Add baseline schema: admin_users, login_attempts, admin_sessions"
```

---

### Task 7: README and CLAUDE.md

**Files:**
- Create: `README.md`
- Create: `CLAUDE.md`

**Interfaces:**
- None — documentation only, but required before tagging a release
  someone else (a consuming project) will depend on without this
  repo's context loaded.

- [ ] **Step 1: Write `README.md`**

```markdown
# single-auth

Shared PHP identity/session library for `marktuttlemd.com` and its
subdomain apps (`mdproductivity.marktuttlemd.com`, and future ones). One
login, one session, shared across every consuming app via a cookie scoped
to `.marktuttlemd.com` and a dedicated `single_auth` database.

See `docs/superpowers/specs/2026-08-12-single-auth-design.md` for the full
design, and `docs/superpowers/plans/` for how this and its two consuming
projects were built.

## What this is

- `Mtmd\SingleAuth\AdminAuth` — session bootstrap, identity lookup, CSRF
  helpers, login/logout, login throttling.
- `Mtmd\SingleAuth\DbSessionHandler` — a `SessionHandlerInterface`
  implementation backing PHP sessions with a database table instead of
  local disk, so session state doesn't depend on consuming apps sharing a
  filesystem.

This package ships no login-page HTML and no authorization/roles system —
see the design doc's "Authn vs authz" section for why.

## Using this in a consuming app

```php
$pdo = new PDO($identityDsn, $identityUser, $identityPass, [...]);
$auth = new \Mtmd\SingleAuth\AdminAuth($pdo, [
    'cookie_domain' => $isLocal ? '.nexus.local' : '.marktuttlemd.com',
]);

session_set_save_handler(new \Mtmd\SingleAuth\DbSessionHandler($pdo), true);

$user = $auth->requireAdmin(); // redirects to login.php if not logged in
```

## Database Migrations (dbmate)

Same convention as `marktuttlemd`/`mdproductivity`. See `CLAUDE.md`.
```

- [ ] **Step 2: Write `CLAUDE.md`**

```markdown
# single-auth — Claude instructions

## Database schema changes

This project uses [dbmate](https://github.com/amacneil/dbmate), same
convention as `marktuttlemd`/`mdproductivity`. This repo's database
(`single_auth`) is production identity data used by every consuming app —
treat schema changes here with more care than an ordinary app's own
tables, since a mistake affects every consumer at once, not just this repo.

1. Never hand-edit `db/schema.sql` and never run ad-hoc `ALTER TABLE` /
   `CREATE TABLE` directly against any database outside of a migration.
2. Generate a migration file first:
   `dbmate --migrations-dir db/migrations new <descriptive_name>`
3. Write the DDL in `-- migrate:up` (and `-- migrate:down` to reverse it).
   Keep `admin_users`/`login_attempts` column-compatible with what
   `marktuttlemd`'s original schema had, unless a migration is
   deliberately evolving them — every consuming app's `AdminAuth` usage
   assumes these shapes.
4. Apply locally to verify:
   `DATABASE_URL="mysql://root:ChangeThisRootPassword@127.0.0.1:3306/single_auth" dbmate --migrations-dir db/migrations up`
5. Confirm the `db/schema.sql` diff matches intent; stage both files.
6. Production schema changes **only** happen via
   `.github/workflows/migrate.yml` (manually triggered), which runs
   `dbmate up` over SSH on the IONOS host itself — never by connecting to
   the production database directly from a dev machine.

## No SQL dialect-specific syntax in `src/`

`AdminAuth` and `DbSessionHandler` deliberately avoid `NOW()`, `INTERVAL`,
and `ON DUPLICATE KEY UPDATE` — "current time" is computed in PHP and
passed as a bound parameter, and writes use select-then-insert-or-update.
This is what lets the whole test suite run against an in-memory SQLite PDO
instead of needing a live MySQL for every test run. Keep any new code in
`src/` to this same portable SQL subset.

## Consumers

`marktuttlemd` and `mdproductivity` both require this package via a
Composer VCS repository entry pointing at this (private) GitHub repo, and
each holds its own `identity_auth` database credentials (scoped to
`single_auth.*` only) alongside its own app-database credentials. See
`docs/superpowers/specs/2026-08-12-single-auth-design.md` for the full
authn/authz split rationale.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "Add README and CLAUDE.md"
```

---

### Task 8: Production migrate-only GitHub Actions workflow

**Files:**
- Create: `.github/workflows/migrate.yml`

**Interfaces:**
- Consumes: `secrets.IONOS_HOST`, `secrets.IONOS_USER`,
  `secrets.IONOS_SSH_KEY`, `secrets.IONOS_PORT` (optional),
  `secrets.IONOS_TARGET`, `secrets.DB_HOST`, `secrets.DB_PORT`,
  `secrets.DB_NAME`, `secrets.DB_USER`, `secrets.DB_PASS` — bare `DB_*`
  names, matching the convention every other repo uses for its own
  database, since this repo only ever touches one database
  (`single_auth`) and there's no second `DB_*` set to collide with (unlike
  `marktuttlemd`/`mdproductivity`, which each already have their own
  `DB_*` secrets for their own app database and so need the identity DB's
  credentials under a different name, `SINGLE_AUTH_DB_*`, to avoid a
  collision). All set manually in this repo's GitHub settings before first
  use (Step 3 below; **do not** run this workflow until they're set).

This workflow ships only `db/migrations/` and a `dbmate` binary to a
sibling directory on the IONOS account (this repo has no webroot — nothing
else needs to reach the server), then runs `dbmate up` over SSH. Modeled
directly on the DB-migration half of `marktuttlemd/.github/workflows/deploy.yml`.

- [ ] **Step 1: Write the workflow**

```yaml
name: Migrate single_auth (production)

on:
  workflow_dispatch:

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download dbmate
        run: |
          set -euo pipefail
          mkdir -p "$GITHUB_WORKSPACE/bin"
          curl -fsSL -o "$GITHUB_WORKSPACE/bin/dbmate" \
            https://github.com/amacneil/dbmate/releases/latest/download/dbmate-linux-amd64
          chmod +x "$GITHUB_WORKSPACE/bin/dbmate"

      - name: Set up SSH
        run: |
          mkdir -p ~/.ssh
          printf '%s' "${{ secrets.IONOS_SSH_KEY }}" > ~/.ssh/ionos_deploy_key
          chmod 600 ~/.ssh/ionos_deploy_key
          ssh-keyscan -p "${{ secrets.IONOS_PORT || 22 }}" "${{ secrets.IONOS_HOST }}" >> ~/.ssh/known_hosts

      - name: Ship dbmate + migrations to IONOS
        run: |
          rsync -az --delete \
            --exclude '.git/' --exclude '.github/' --exclude 'src/' \
            --exclude 'tests/' --exclude 'vendor/' --exclude 'composer.*' \
            --exclude 'README.md' --exclude 'phpunit.xml' \
            -e "ssh -i ~/.ssh/ionos_deploy_key -o IdentitiesOnly=yes -p ${{ secrets.IONOS_PORT || 22 }}" \
            ./ "${{ secrets.IONOS_USER }}@${{ secrets.IONOS_HOST }}:${{ secrets.IONOS_TARGET }}/"

      - name: Run migrations
        env:
          DB_HOST: ${{ secrets.DB_HOST }}
          DB_PORT: ${{ secrets.DB_PORT }}
          DB_NAME: ${{ secrets.DB_NAME }}
          DB_USER: ${{ secrets.DB_USER }}
          DB_PASS: ${{ secrets.DB_PASS }}
          IONOS_TARGET: ${{ secrets.IONOS_TARGET }}
        run: |
          set -euo pipefail
          DB_USER_ENC=$(jq -rn --arg v "$DB_USER" '$v|@uri')
          DB_PASS_ENC=$(jq -rn --arg v "$DB_PASS" '$v|@uri')
          DATABASE_URL="mysql://${DB_USER_ENC}:${DB_PASS_ENC}@${DB_HOST}:${DB_PORT:-3306}/${DB_NAME}"
          ssh -i ~/.ssh/ionos_deploy_key -o IdentitiesOnly=yes -o BatchMode=yes \
            -p "${{ secrets.IONOS_PORT || 22 }}" \
            "${{ secrets.IONOS_USER }}@${{ secrets.IONOS_HOST }}" \
            "DATABASE_URL='$DATABASE_URL' '$IONOS_TARGET/bin/dbmate' --migrations-dir '$IONOS_TARGET/db/migrations' up"
```

- [ ] **Step 2: Commit (do not trigger yet)**

```bash
git add .github/workflows/migrate.yml
git commit -m "Add production migrate-only workflow"
```

- [ ] **Step 3: [MANUAL — you, not this plan] Provision production and set secrets**

Before ever running this workflow, on the IONOS side:
1. Create the `single_auth` database and an `identity_auth` MySQL user
   scoped to it (same shape as the local commands in Task 6 Step 3, run
   via whatever DB admin tool your IONOS plan provides — phpMyAdmin,
   IONOS's own DB manager, or SSH + `mysql` client on the host itself).
2. In this repo's GitHub settings, add secrets (values from your existing
   `marktuttlemd` IONOS setup for the `IONOS_*` ones, since it's the same
   account):

```bash
gh secret set IONOS_HOST -R coder999/single-auth
gh secret set IONOS_USER -R coder999/single-auth
gh secret set IONOS_SSH_KEY -R coder999/single-auth < /path/to/deploy_key
gh secret set IONOS_TARGET -R coder999/single-auth   # NEW sibling path, distinct from marktuttlemd's target — see note below
gh secret set DB_HOST -R coder999/single-auth
gh secret set DB_PORT -R coder999/single-auth
gh secret set DB_NAME -R coder999/single-auth
gh secret set DB_USER -R coder999/single-auth
gh secret set DB_PASS -R coder999/single-auth
```

These are named `DB_*` (not `SINGLE_AUTH_DB_*`) here — this repo only
ever touches its own one database, so the bare convention every other repo
uses applies unchanged. `marktuttlemd` and `mdproductivity` each need
these same credential values under `SINGLE_AUTH_DB_*` instead, since they
already have their own `DB_*` secrets for their own app database and a
second database needs a different name to avoid colliding.

The IONOS shared-hosting account root is `/kunden/homepages/26/d193370434/htdocs` — every project (`marktuttlemd`, `mdproductivity`, etc.) is a sibling directory directly under that root, each with its own `htdocs/` inside (e.g. `marktuttlemd`'s webroot is `/kunden/homepages/26/d193370434/htdocs/marktuttlemd/htdocs`), matching this workflow's sibling-directory assumption. `single-auth` has no webroot of its own — set `IONOS_TARGET` to the absolute path `/kunden/homepages/26/d193370434/htdocs/single-auth` (a new sibling directory that will hold only `db/migrations/` and `bin/dbmate`, nothing web-served). Using the full absolute path here — rather than a bare relative name like `single-auth` — avoids depending on whether the SSH migration step's shell lands in the same working directory the SFTP/rsync step does; it's unambiguous either way.

3. Trigger the workflow manually (`gh workflow run migrate.yml -R
   coder999/single-auth`, or via the Actions tab) and confirm it succeeds.
4. Verify: connect to the production `single_auth` database and confirm
   `admin_users`, `login_attempts`, `admin_sessions` exist.

This step is deliberately not something this plan executes automatically —
it's the first thing in the whole project that touches production
infrastructure, worth doing by hand and watching.

---

### Task 9: Tag v0.1.0

**Files:** none (git tag only)

- [ ] **Step 1: Confirm the full local test suite passes**

```bash
docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit
```

Expected: all tests pass, zero failures/errors.

- [ ] **Step 2: Push and tag**

```bash
git push origin main
git tag v0.1.0
git push origin v0.1.0
```

- [ ] **Step 3: Confirm the tag is visible on GitHub**

```bash
gh release view v0.1.0 -R coder999/single-auth 2>&1 || gh api repos/coder999/single-auth/tags --jq '.[].name'
```

Expected: `v0.1.0` listed. This is the version the next two plans
(`marktuttlemd` and `mdproductivity` integration) will require in their
`composer.json`.
