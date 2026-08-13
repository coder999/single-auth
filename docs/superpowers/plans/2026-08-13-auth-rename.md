# single-auth: rename admin_* vocabulary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename `single-auth`'s `admin_*` vocabulary (table names, class
name, method names, session key, default cookie name) to identity-neutral
names, with zero behavior change — this library only ever asserted "who is
this," never "this identity is an admin," and the naming should stop
implying otherwise.

**Architecture:** Pure rename across `src/`, `tests/`, `db/migrations/`,
and docs. `src/AdminAuth.php` becomes `src/Auth.php` (class `Auth`,
methods `requireLogin()`/`currentUser()`), `src/DbSessionHandler.php`'s
table reference changes, and a new dbmate migration renames the live
tables. No new files beyond the migration; no logic changes anywhere.

**Tech Stack:** PHP 8.1+, PHPUnit 10.5 (in-memory SQLite), dbmate
(MySQL/MariaDB in production).

**Spec:** `docs/superpowers/specs/2026-08-13-auth-rename.md`

## Global Constraints

- Pure rename, zero behavior change — every method's internal logic stays
  byte-identical except for the identifiers being renamed. Do not "improve"
  anything else while in these files.
- `csrfToken()`, `csrfField()`, `csrfCheck()`, `attemptLogin()`, `logout()`,
  `loginThrottled()`, `clientIp()`, `sessionStart()` are NOT renamed —
  already generic.
- `login_attempts` table, `identity_auth` DB user, `single_auth` database
  are NOT renamed — out of scope per the spec's non-goals.
- This repo's own tests must keep passing against in-memory SQLite with no
  `NOW()`/`INTERVAL`/`ON DUPLICATE KEY UPDATE` (see this repo's
  `CLAUDE.md`) — the rename must not introduce any of these.
- Default cookie name changes from `'mtmd_admin'` to `'identity_session'`
  (this is a behavior change, but an explicitly agreed one — see spec).

---

### Task 1: Rename `AdminAuth` to `Auth`

**Files:**
- Create: `src/Auth.php` (renamed from `src/AdminAuth.php`)
- Delete: `src/AdminAuth.php`
- Create: `tests/AuthTest.php` (renamed from `tests/AdminAuthTest.php`)
- Delete: `tests/AdminAuthTest.php`

**Interfaces:**
- Produces: class `Mtmd\SingleAuth\Auth`, constructed the same way as the
  old `AdminAuth` (`new Auth(PDO $pdo, array $options = [])`). Methods:
  `sessionStart(): void` (unchanged), `currentUser(): ?array` (was
  `currentAdmin()`), `requireLogin(string $loginUrl = 'login.php'): array`
  (was `requireAdmin()`), `csrfToken()`/`csrfField()`/`csrfCheck()`
  (unchanged), `clientIp()` (unchanged), `loginThrottled()` (unchanged),
  `attemptLogin(string $username, string $password): bool` (unchanged
  signature, now reads/writes the `users` table), `logout()` (unchanged).
  This is what Task 3 (migration) and every consuming app depend on.

- [ ] **Step 1: Write the new test file (this will fail — `Auth` doesn't exist yet)**

Write `tests/AuthTest.php`:

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\Auth;
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
}
```

Delete the old `tests/AdminAuthTest.php` (`git rm tests/AdminAuthTest.php`).

- [ ] **Step 2: Run tests to verify the new file fails**

Run: `docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AuthTest.php`
Expected: FAIL — `Class "Mtmd\SingleAuth\Auth" not found` (or similar autoload error), since `src/Auth.php` doesn't exist yet.

- [ ] **Step 3: Write `src/Auth.php`, delete `src/AdminAuth.php`**

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth;

use PDO;

final class Auth
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
        $this->cookieName = $options['cookie_name'] ?? 'identity_session';
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

    public function currentUser(): ?array
    {
        $this->sessionStart();
        if (empty($_SESSION['user_id'])) {
            return null;
        }
        $st = $this->pdo->prepare('SELECT id, username, last_login FROM users WHERE id = ?');
        $st->execute([$_SESSION['user_id']]);
        $user = $st->fetch(PDO::FETCH_ASSOC);
        if ($user === false) {
            return null;
        }
        $user['id'] = (int)$user['id'];
        return $user;
    }

    public function requireLogin(string $loginUrl = 'login.php'): array
    {
        $user = $this->currentUser();
        if ($user === null) {
            header('Location: ' . $loginUrl);
            exit;
        }
        return $user;
    }

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

    public function clientIp(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    public function loginThrottled(): bool
    {
        $cutoff = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify("-{$this->loginWindowSeconds} seconds")
            ->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND attempted_at > ?');
        $st->execute([$this->clientIp(), $cutoff]);
        return (int)$st->fetch(PDO::FETCH_ASSOC)['n'] >= $this->loginMaxAttempts;
    }

    public function attemptLogin(string $username, string $password): bool
    {
        $this->sessionStart();
        $st = $this->pdo->prepare('SELECT * FROM users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch(PDO::FETCH_ASSOC);

        if ($user !== false && password_verify($password, $user['password_hash'])) {
            $this->pdo->prepare('DELETE FROM login_attempts WHERE ip = ?')->execute([$this->clientIp()]);
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int)$user['id'];
            $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
            $this->pdo->prepare('UPDATE users SET last_login = ? WHERE id = ?')->execute([$now, $user['id']]);
            return true;
        }

        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
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
}
```

Delete the old `src/AdminAuth.php` (`git rm src/AdminAuth.php`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/AuthTest.php`
Expected: PASS — 13 tests, 0 failures, output pristine (no warnings).

- [ ] **Step 5: Commit**

```bash
git add src/Auth.php tests/AuthTest.php
git rm src/AdminAuth.php tests/AdminAuthTest.php
git commit -m "Rename AdminAuth to Auth: requireLogin/currentUser, users table, identity_session cookie"
```

---

### Task 2: Rename `DbSessionHandler`'s table reference

**Files:**
- Modify: `src/DbSessionHandler.php`
- Modify: `tests/DbSessionHandlerTest.php`

**Interfaces:**
- Consumes: nothing from Task 1 (independent class, unaffected by the
  `Auth` rename).
- Produces: `Mtmd\SingleAuth\DbSessionHandler` (class name unchanged —
  never admin-specific), now reading/writing the `sessions` table instead
  of `admin_sessions`. Task 3's migration renames the table this depends
  on; Task 1's `Auth::sessionStart()` is what actually registers this
  handler via PHP's `session_set_save_handler()`, but that wiring lives in
  each consuming app, not here.

- [ ] **Step 1: Update the test file to expect the new table name (this will fail against the current source)**

Rewrite `tests/DbSessionHandlerTest.php`:

```php
<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\DbSessionHandler;
use PDO;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;
use DateTimeZone;

final class DbSessionHandlerTest extends TestCase
{
    private PDO $pdo;
    private DbSessionHandler $handler;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE sessions (
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
        $this->handler->write('sess1', 'user_id|i:1;');

        $this->assertSame('user_id|i:1;', $this->handler->read('sess1'));
    }

    public function testWriteTwiceUpdatesInPlace(): void
    {
        $this->handler->write('sess1', 'first');
        $this->handler->write('sess1', 'second');

        $this->assertSame('second', $this->handler->read('sess1'));
        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM sessions')->fetch()['n'];
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
        $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['fresh', 'a', $fresh]);
        $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['stale', 'b', $stale]);

        $this->handler->gc(3600); // 1 hour max lifetime

        $this->assertSame('a', $this->handler->read('fresh'));
        $this->assertSame('', $this->handler->read('stale'));
    }

    public function testTimestampsAreAnchoredToUtcRegardlessOfAmbientTimezone(): void
    {
        date_default_timezone_set('America/Denver');
        try {
            // write() must store last_activity in UTC even though the
            // process-wide default timezone is Denver.
            $this->handler->write('denver-sess', 'data');

            $row = $this->pdo->query("SELECT last_activity FROM sessions WHERE id = 'denver-sess'")
                ->fetch(PDO::FETCH_ASSOC);
            $stored = new DateTimeImmutable($row['last_activity'], new DateTimeZone('UTC'));
            $trueUtcNow = new DateTimeImmutable('now', new DateTimeZone('UTC'));
            $this->assertLessThan(
                5,
                abs($trueUtcNow->getTimestamp() - $stored->getTimestamp()),
                'write() must anchor last_activity to UTC, not the ambient default timezone'
            );

            // A session that is genuinely stale in UTC terms (2 hours old)
            // must still be collected by gc(3600) even though gc() is
            // invoked while the ambient timezone is Denver.
            $staleUtc = (new DateTimeImmutable('-2 hours', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
            $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)')
                ->execute(['denver-stale', 'x', $staleUtc]);

            $this->handler->gc(3600); // 1 hour max lifetime

            $this->assertSame(
                '',
                $this->handler->read('denver-stale'),
                'gc() cutoff must be computed in UTC so genuinely stale sessions are collected under any ambient timezone'
            );
            $this->assertSame(
                'data',
                $this->handler->read('denver-sess'),
                'a freshly written session must survive gc() regardless of ambient timezone'
            );
        } finally {
            date_default_timezone_set('UTC');
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/DbSessionHandlerTest.php`
Expected: FAIL — SQL errors referencing `admin_sessions` not existing (the test now creates a `sessions` table, but the source still queries `admin_sessions`).

- [ ] **Step 3: Update `src/DbSessionHandler.php`**

Replace every `admin_sessions` with `sessions` (5 occurrences: `read()`,
`write()` ×3, `destroy()`, `gc()`). Full resulting file:

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
        $st = $this->pdo->prepare('SELECT data FROM sessions WHERE id = ?');
        $st->execute([$id]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? '' : $row['data'];
    }

    public function write(string $id, string $data): bool
    {
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        $exists = $this->pdo->prepare('SELECT 1 FROM sessions WHERE id = ?');
        $exists->execute([$id]);

        if ($exists->fetch(PDO::FETCH_ASSOC) !== false) {
            $st = $this->pdo->prepare('UPDATE sessions SET data = ?, last_activity = ? WHERE id = ?');
            return $st->execute([$data, $now, $id]);
        }

        $st = $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)');
        return $st->execute([$id, $data, $now]);
    }

    public function destroy(string $id): bool
    {
        $st = $this->pdo->prepare('DELETE FROM sessions WHERE id = ?');
        return $st->execute([$id]);
    }

    public function gc(int $max_lifetime): int|false
    {
        $cutoff = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify("-{$max_lifetime} seconds")
            ->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('DELETE FROM sessions WHERE last_activity < ?');
        $st->execute([$cutoff]);
        return $st->rowCount();
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit tests/DbSessionHandlerTest.php`
Expected: PASS — 6 tests, 0 failures, output pristine.

- [ ] **Step 5: Run the full suite together**

Run: `docker exec -w /var/www/html-local/single-auth php vendor/bin/phpunit`
Expected: PASS — 19 tests total (13 from `AuthTest` + 6 from
`DbSessionHandlerTest`), 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/DbSessionHandler.php tests/DbSessionHandlerTest.php
git commit -m "Rename admin_sessions table reference to sessions in DbSessionHandler"
```

---

### Task 3: Write and locally verify the rename migration

**Files:**
- Create: `db/migrations/<timestamp>_rename_admin_tables.sql`
- Modify: `db/schema.sql` (auto-regenerated by `dbmate up` — do not
  hand-edit)

**Interfaces:**
- Consumes: nothing from Tasks 1-2 (schema change is independent of the
  PHP code change — both must land before the production cutover, but
  neither depends on the other to be written).
- Produces: the `users`/`sessions` tables that Task 1's `Auth` and Task
  2's `DbSessionHandler` now query. This migration is NOT run against
  production as part of this task — only applied locally to verify it
  works. Production application happens during the coordinated cutover
  (see this repo's README "Rollout" note, added in Task 4), via this
  repo's existing `.github/workflows/migrate.yml`.

- [ ] **Step 1: Generate the migration file**

```bash
docker exec -w /var/www/html-local/single-auth php dbmate --migrations-dir db/migrations new rename_admin_tables
```

This creates `db/migrations/<timestamp>_rename_admin_tables.sql` with
empty `-- migrate:up` / `-- migrate:down` sections. Note the generated
timestamp for the next step.

- [ ] **Step 2: Write the migration**

Replace the generated file's contents with:

```sql
-- migrate:up
RENAME TABLE admin_users TO users, admin_sessions TO sessions;

-- migrate:down
RENAME TABLE users TO admin_users, sessions TO admin_sessions;
```

A single comma-separated `RENAME TABLE` statement — MySQL/MariaDB
executes a multi-table rename as one atomic DDL operation, so there's no
window where one table is renamed and the other isn't.

- [ ] **Step 3: Apply it to the local database and verify**

```bash
DATABASE_URL="mysql://root:ChangeThisRootPassword@127.0.0.1:3306/single_auth" docker exec -w /var/www/html-local/single-auth -e DATABASE_URL php dbmate --migrations-dir db/migrations up
```

Expected output includes `Applying: <timestamp>_rename_admin_tables.sql`.

Then confirm the rename actually happened and preserved data — if there's
existing local dev data in `admin_users`/`admin_sessions`, this proves
`RENAME TABLE` didn't drop anything:

```bash
docker exec php mysql -h 127.0.0.1 -u root -pChangeThisRootPassword single_auth -e "SHOW TABLES; SELECT COUNT(*) FROM users;"
```

Expected: `SHOW TABLES` lists `users`/`sessions` (not
`admin_users`/`admin_sessions`), and the row count matches whatever was in
`admin_users` before (0 if the local dev DB has no seeded admin yet — that
is fine, this is just confirming the table exists and is queryable, not
asserting a specific count).

- [ ] **Step 4: Confirm `db/schema.sql` was regenerated correctly**

```bash
git diff db/schema.sql
```

Expected: the diff shows `admin_users`/`admin_sessions` replaced by
`users`/`sessions` (table definitions unchanged otherwise), and a new
`schema_migrations` row for this migration's version.

- [ ] **Step 5: Commit**

```bash
git add db/migrations/ db/schema.sql
git commit -m "Add migration renaming admin_users/admin_sessions to users/sessions"
```

---

### Task 4: Update docs and tag the release

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-08-12-single-auth-design.md`

**Interfaces:**
- Consumes: nothing — pure documentation, no code dependency.
- Produces: nothing consumed by later tasks — this is the last task in
  this repo before the coordinated cutover (which is `mdproductivity`'s
  plan's final section, since it deploys last in the sequence).

- [ ] **Step 1: Update `README.md`**

Replace every `AdminAuth` with `Auth`, `admin_users`/`admin_sessions` with
`users`/`sessions`, `requireAdmin()` with `requireLogin()`, `'mtmd_admin'`
with `'identity_session'` throughout. Specifically:

- The "What this is" section: `Mtmd\SingleAuth\AdminAuth` → `Mtmd\SingleAuth\Auth`.
- The usage example:
  ```php
  $auth = new \Mtmd\SingleAuth\Auth($pdo, [
      'cookie_domain' => $isLocal ? '.nexus.local' : '.marktuttlemd.com',
      'cookie_secure' => !$isLocal,
  ]);

  session_set_save_handler(new \Mtmd\SingleAuth\DbSessionHandler($pdo), true);

  $user = $auth->requireLogin(); // redirects to login.php if not logged in
  ```
- The throttling example: `$auth->loginThrottled()` / `$auth->attemptLogin(...)` stay as-is (unchanged method names).
- The options table's `cookie_name` row: default `'mtmd_admin'` → `'identity_session'`.

- [ ] **Step 2: Update `CLAUDE.md`**

In the "Database schema changes" section, replace:

> Keep `admin_users`/`login_attempts` column-compatible with what
> `marktuttlemd`'s original schema had, unless a migration is
> deliberately evolving them — every consuming app's `AdminAuth` usage
> assumes these shapes.

with:

> Keep `users`/`login_attempts` column-compatible with what they already
> have, unless a migration is deliberately evolving them — every
> consuming app's `Auth` usage assumes these shapes. (`users` was renamed
> from `admin_users` in the `2026-08-13-auth-rename` migration — see
> `docs/superpowers/specs/2026-08-13-auth-rename.md`.)

- [ ] **Step 3: Update the "Authn vs authz" section of `docs/superpowers/specs/2026-08-12-single-auth-design.md`**

Replace the section (lines under `## Authn vs authz`) so every
`admin_users`/`admin_sessions`/`admin_id`/`AdminAuth` reference reads
`users`/`sessions`/`user_id`/`Auth`, and add one sentence at the end of
the section:

> This vocabulary itself was renamed from `admin_*` to identity-neutral
> names on 2026-08-13 — see
> `docs/superpowers/specs/2026-08-13-auth-rename.md` for why: the naming
> was asserting exactly the guarantee this section says the library
> doesn't provide.

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md docs/superpowers/specs/2026-08-12-single-auth-design.md
git commit -m "Update docs for the admin_* -> identity-neutral rename"
```

- [ ] **Step 5: Tag the release**

```bash
git tag v0.2.0
git push origin main --tags
```

`v0.2.0`, not a patch bump: breaking API (class/method names) and schema
(table names) change, but still pre-1.0 so a minor bump is the correct
semver signal (same reasoning as this project's own `CLAUDE.md`/history —
`v0.1.0`→`v0.1.1` was a same-day patch for a bug fix, not a rename).

**Do not run the production migration yet.** That happens during the
coordinated cutover, the final section of `mdproductivity`'s
`2026-08-13-auth-rename.md` plan — after both `marktuttlemd`'s and
`mdproductivity`'s code changes (their own plans, same filename in their
own repos) are merged and this tag exists for them to require.
