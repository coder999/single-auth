# Passkeys (single-auth library) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add passkey (WebAuthn) registration and login to the `single-auth` library, alongside the existing password path, and release it.

**Architecture:** A new `Passkeys` class composed with the existing `Auth`. Both login paths converge on one new `Auth::loginAs()`. Credentials live in a new `user_credentials` table; challenges live in the existing database-backed session. No consumer app is touched by this plan.

**Tech Stack:** PHP 8.2+, PDO, `web-auth/webauthn-lib` ^5.3, PHPUnit 10.5, dbmate, SQLite (tests) / MariaDB (production).

**Spec:** `docs/superpowers/specs/2026-09-13-passkeys-design.md`

## Global Constraints

- **PHP floor moves `>=8.1` → `>=8.2`** (required by `web-auth/webauthn-lib`). Every consumer already runs 8.4.
- **Portable SQL only in `src/`.** No `NOW()`, no `INTERVAL`, no `ON DUPLICATE KEY UPDATE`. Compute "now" in PHP and bind it. This is what lets the suite run on in-memory SQLite. (`CLAUDE.md`)
- **Never hand-edit `db/schema.sql`.** Regenerate it with dbmate.
- **Binary values are stored as base64url TEXT, never `VARBINARY`.** SQLite has no `VARBINARY`.
- **This repo is public.** No production hostnames, database usernames, infrastructure paths, or credentials in code, comments, tests, or commit messages.
- **Origin validation has no escape hatch.** There is no option, constant, or environment check that relaxes it. If a task seems to need one, the task is wrong.
- **Passwords keep working.** Every existing test in `tests/AuthTest.php` must still pass, unmodified, at every commit.
- Run tests with:
  `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
  (There is no PHP on the nexus host.)

---

### Task 1: Migration and schema

**Files:**
- Create: `db/migrations/<timestamp>_add_passkey_credentials.sql`
- Modify: `db/schema.sql` (regenerated, never hand-edited)
- Modify: `CLAUDE.md` (the local dbmate command is stale — see Step 1)

**Interfaces:**
- Consumes: nothing.
- Produces: table `user_credentials`; column `users.webauthn_user_handle`.

- [ ] **Step 1: Fix the stale local migration command in `CLAUDE.md`**

`CLAUDE.md` step 4 currently says to run dbmate against `127.0.0.1:3306`. That cannot work: `single-auth-mariadb` on nexus publishes nothing to the host (`docker inspect` reports `{"3306/tcp":null}`, and nothing listens on 3306). Verified 2026-09-13.

Replace that command with one that joins the container's network:

```bash
docker run --rm --network identity -v "$PWD/db:/db" \
  ghcr.io/amacneil/dbmate:v2.35.0 \
  -u "mysql://root:ChangeThisRootPassword@single-auth-mariadb:3306/single_auth" \
  --migrations-dir /db/migrations --schema-file /db/schema.sql up
```

(`ChangeThisRootPassword` is the local-dev placeholder already published in this repo, not a secret.)

- [ ] **Step 2: Create the migration**

```bash
dbmate --migrations-dir db/migrations new add_passkey_credentials
```

Write into the generated file:

```sql
-- migrate:up
CREATE TABLE user_credentials (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id       INT UNSIGNED NOT NULL,
  credential_id VARCHAR(255) NOT NULL,
  public_key    TEXT NOT NULL,
  sign_count    INT UNSIGNED NOT NULL DEFAULT 0,
  transports    VARCHAR(255) NULL,
  label         VARCHAR(64) NOT NULL,
  created_at    DATETIME NOT NULL,
  last_used_at  DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_credential_id (credential_id),
  KEY idx_user (user_id),
  CONSTRAINT fk_user_credentials_user FOREIGN KEY (user_id)
    REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

ALTER TABLE users ADD COLUMN webauthn_user_handle VARCHAR(64) NULL,
  ADD UNIQUE KEY uniq_webauthn_user_handle (webauthn_user_handle);

-- migrate:down
ALTER TABLE users DROP INDEX uniq_webauthn_user_handle,
  DROP COLUMN webauthn_user_handle;
DROP TABLE user_credentials;
```

`credential_id` is `VARCHAR(255)` holding base64url text, not `VARBINARY` — see Global Constraints.

- [ ] **Step 3: Apply locally and regenerate the schema**

Run the Step 1 command. Expected: the migration applies and `db/schema.sql` is rewritten to include `user_credentials` and the new column.

- [ ] **Step 4: Confirm the schema diff matches intent**

Run: `git diff db/schema.sql`
Expected: only the new table, the new column, its unique index, and a new row in the `schema_migrations` insert. Nothing else. If other tables moved, stop — the dump was taken against the wrong database.

- [ ] **Step 5: Confirm the existing suite still passes**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: `OK (19 tests, 31 assertions)` — this task changes no PHP.

- [ ] **Step 6: Commit**

```bash
git add db/migrations db/schema.sql CLAUDE.md
git commit -m "Add user_credentials table and WebAuthn user handle

Safe to apply standalone: a new table plus a nullable column breaks no
deployed code. Also fixes CLAUDE.md's local dbmate command, which pointed
at 127.0.0.1:3306 — single-auth-mariadb publishes nothing to the host, so
that command could not have worked."
```

---

### Task 2: Add the dependency and pin its real API

**Files:**
- Modify: `composer.json`
- Modify: `composer.lock`
- Create: `docs/superpowers/notes/webauthn-lib-api.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `docs/superpowers/notes/webauthn-lib-api.md`, which every later task reads before writing library-facing code.

**Why this task exists:** the plan author had not used `web-auth/webauthn-lib` 5.x. Writing guessed class names and method signatures into later tasks would produce code that looks right and does not run. This task replaces guesses with the installed source of truth. **Do not skip it, and do not write library-facing code from memory in any later task.**

- [ ] **Step 1: Require the library and raise the PHP floor**

```bash
composer require web-auth/webauthn-lib:^5.3
```

Then edit `composer.json` so `"php"` reads `">=8.2"`, and run `composer update --lock`.

- [ ] **Step 2: Verify it installed and the suite still passes**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: `OK (19 tests, ...)`. A failure here means the dependency broke autoloading, not that a test is wrong.

- [ ] **Step 3: Record the real API**

Read the installed source under `vendor/web-auth/webauthn-lib/src/`. Write `docs/superpowers/notes/webauthn-lib-api.md` capturing, with exact namespaces and signatures:

1. How to build creation options for a registration ceremony (the class, its constructor or factory, and where RP id/name, user entity, challenge, `residentKey`, `userVerification` and `attestation: none` are set).
2. How to build request options for a login ceremony.
3. How to validate an attestation response, and what object comes back — specifically where to read the credential id, public key, sign count and transports.
4. How to validate an assertion response, and how the stored credential is supplied to it.
5. Which value types are raw binary vs already-encoded, since everything we persist is base64url TEXT.
6. Whether it requires a PSR-3 logger, PSR-20 clock, or serializer to be constructed, and if so which concrete classes ship with it.

For each, note the file and line you read it from.

- [ ] **Step 4: Commit**

```bash
git add composer.json composer.lock docs/superpowers/notes/webauthn-lib-api.md
git commit -m "Add web-auth/webauthn-lib, pin its API surface

PHP floor 8.1 -> 8.2 as the library requires; every consumer runs 8.4.
The notes file records the real signatures read from vendor/, so later
work is not written against a remembered API."
```

---

### Task 3: `Auth::loginAs()`

**Files:**
- Modify: `src/Auth.php`
- Test: `tests/AuthTest.php`

**Interfaces:**
- Consumes: nothing.
- Produces: `Auth::loginAs(int $userId): bool` — regenerates the session id, sets `$_SESSION['user_id']`, stamps `last_login`, returns `false` if no such user. `Auth::attemptLogin()` is refactored to call it; its behaviour is unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `tests/AuthTest.php`:

```php
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit --filter LoginAs`
Expected: FAIL — `Call to undefined method ... ::loginAs()`.

- [ ] **Step 3: Implement**

Add to `src/Auth.php`:

```php
    /**
     * Establish a logged-in session for a user id.
     *
     * DANGER: this verifies NO credential. It is the shared tail of every
     * authentication path (password, passkey), and calling it directly
     * from application code is an authentication bypass. Only call it
     * after you have actually authenticated the user by some means.
     */
    public function loginAs(int $userId): bool
    {
        $this->sessionStart();
        $st = $this->pdo->prepare('SELECT id FROM users WHERE id = ?');
        $st->execute([$userId]);
        if ($st->fetch(PDO::FETCH_ASSOC) === false) {
            return false;
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $this->pdo->prepare('UPDATE users SET last_login = ? WHERE id = ?')->execute([$now, $userId]);
        return true;
    }
```

Then refactor `attemptLogin()`: on a successful `password_verify`, replace the inline session-regenerate / `$_SESSION['user_id']` / `last_login` block with `$this->loginAs((int)$user['id']);` and keep the `DELETE FROM login_attempts` call before it.

- [ ] **Step 4: Run the whole suite**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS, including every pre-existing `attemptLogin` test unmodified. Those tests are the proof the refactor preserved behaviour — if one fails, the refactor is wrong, not the test.

- [ ] **Step 5: Commit**

```bash
git add src/Auth.php tests/AuthTest.php
git commit -m "Add Auth::loginAs and route attemptLogin through it

One implementation of 'establish a logged-in session', so the passkey
path cannot drift from the password path. loginAs verifies no credential
and says so loudly in its doc block."
```

---

### Task 4: `Passkeys` scaffold and origin validation

**Files:**
- Create: `src/Passkeys.php`
- Test: `tests/PasskeysTest.php`

**Interfaces:**
- Consumes: `Auth` (Task 3), `web-auth/webauthn-lib` (Task 2).
- Produces: `Passkeys::__construct(PDO $pdo, Auth $auth, array $options)` with options `rp_id` (required, throws `InvalidArgumentException` if absent), `rp_name` (default `'single-auth'`), `challenge_ttl` (default `120`). Also `Passkeys::originMatchesRpId(string $origin): bool`, public so it is directly testable.

- [ ] **Step 1: Write the failing tests**

Create `tests/PasskeysTest.php`:

```php
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
```

The lookalike cases are the point of this task. `notexample.com` and `example.com.evil.test` are exactly what a naive `str_ends_with` or `str_contains` check would wrongly accept.

- [ ] **Step 2: Run to verify they fail**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit --filter PasskeysTest`
Expected: FAIL — `Class "Coder999\SingleAuth\Passkeys" not found`.

- [ ] **Step 3: Implement**

Create `src/Passkeys.php`:

```php
<?php

declare(strict_types=1);

namespace Coder999\SingleAuth;

use InvalidArgumentException;
use PDO;

final class Passkeys
{
    private PDO $pdo;
    private Auth $auth;
    private string $rpId;
    private string $rpName;
    private int $challengeTtl;

    public function __construct(PDO $pdo, Auth $auth, array $options = [])
    {
        if (empty($options['rp_id'])) {
            throw new InvalidArgumentException('Passkeys requires an rp_id option.');
        }
        $this->pdo = $pdo;
        $this->auth = $auth;
        $this->rpId = (string)$options['rp_id'];
        $this->rpName = (string)($options['rp_name'] ?? 'single-auth');
        $this->challengeTtl = (int)($options['challenge_ttl'] ?? 120);
    }

    /**
     * The WebAuthn spec's own RP ID rule: an origin is valid when it is
     * https and its host is the RP ID or a subdomain of it.
     *
     * There is deliberately no way to relax this. Local development is
     * plain HTTP and therefore cannot use passkeys at all; that is a
     * known, accepted consequence, not a bug to work around.
     */
    public function originMatchesRpId(string $origin): bool
    {
        $parts = parse_url($origin);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https') {
            return false;
        }
        $host = $parts['host'] ?? '';
        if ($host === '') {
            return false;
        }
        return $host === $this->rpId || str_ends_with($host, '.' . $this->rpId);
    }
}
```

Note the `'.' . $this->rpId` concatenation — without the leading dot, `notexample.com` would pass.

- [ ] **Step 4: Run to verify they pass**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add src/Passkeys.php tests/PasskeysTest.php
git commit -m "Add Passkeys scaffold with origin validation

Origin validation is the spec's own RP ID rule, so no allowlist can drift
from the cookie scope, and there is no option to relax it. Table-driven
tests cover the lookalike hosts a naive suffix check would accept."
```

---

### Task 5: Registration ceremony

**Files:**
- Modify: `src/Passkeys.php`
- Test: `tests/PasskeysTest.php`

**Interfaces:**
- Consumes: Task 4's constructor; Task 2's API notes.
- Produces:
  - `beginRegistration(int $userId, string $label): string` — returns JSON creation options; generates `users.webauthn_user_handle` if absent; stores challenge, label, purpose and expiry in `$_SESSION`.
  - `finishRegistration(int $userId, string $clientJson): bool` — validates, inserts into `user_credentials`, clears the challenge.
  - `userHandle(int $userId): ?string` — reads the stored handle; used by tests and by login.

- [ ] **Step 1: Read the API notes**

Open `docs/superpowers/notes/webauthn-lib-api.md` (Task 2). Library-facing code below must use the signatures recorded there, not remembered ones.

- [ ] **Step 2: Write the failing tests**

Add to `tests/PasskeysTest.php`:

```php
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

    #[RunInSeparateProcess]
    public function testFinishRegistrationRejectsChallengeIssuedForLogin(): void
    {
        $this->makeUser();
        $this->passkeys->beginLogin();

        $this->assertFalse($this->passkeys->finishRegistration(1, '{}'));
    }
```

- [ ] **Step 3: Run to verify they fail**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit --filter Registration`
Expected: FAIL — undefined methods.

- [ ] **Step 4: Implement**

Add to `src/Passkeys.php`. The session/challenge/persistence half is fixed; build the creation options and run validation using the classes recorded in the Task 2 notes.

```php
    public function userHandle(int $userId): ?string
    {
        $st = $this->pdo->prepare('SELECT webauthn_user_handle FROM users WHERE id = ?');
        $st->execute([$userId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return ($row === false || $row['webauthn_user_handle'] === null)
            ? null
            : (string)$row['webauthn_user_handle'];
    }

    private function ensureUserHandle(int $userId): string
    {
        $existing = $this->userHandle($userId);
        if ($existing !== null) {
            return $existing;
        }
        $handle = self::b64u(random_bytes(32));
        $this->pdo->prepare('UPDATE users SET webauthn_user_handle = ? WHERE id = ?')
            ->execute([$handle, $userId]);
        return $handle;
    }

    public static function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public static function b64uDecode(string $encoded): string
    {
        return (string)base64_decode(strtr($encoded, '-_', '+/'), true);
    }

    private function storeChallenge(string $challenge, string $purpose, ?string $label = null): void
    {
        $this->auth->sessionStart();
        $_SESSION['passkey_challenge'] = $challenge;
        $_SESSION['passkey_purpose']   = $purpose;
        $_SESSION['passkey_expires']   = time() + $this->challengeTtl;
        $_SESSION['passkey_label']     = $label;
    }

    /** Returns the challenge if valid for $purpose, and always clears it. */
    private function consumeChallenge(string $purpose): ?string
    {
        $this->auth->sessionStart();
        $challenge = $_SESSION['passkey_challenge'] ?? null;
        $ok = $challenge !== null
            && ($_SESSION['passkey_purpose'] ?? null) === $purpose
            && (int)($_SESSION['passkey_expires'] ?? 0) > time();

        // Cleared whether or not it was valid: single use, no retries.
        unset($_SESSION['passkey_challenge'], $_SESSION['passkey_purpose'], $_SESSION['passkey_expires']);

        return $ok ? (string)$challenge : null;
    }
```

`beginRegistration()` must: call `ensureUserHandle()`, generate a 32-byte random challenge, build creation options with `rp.id = $this->rpId`, `rp.name = $this->rpName`, the user entity keyed on the handle, `residentKey: 'required'`, `userVerification: 'required'`, `attestation: 'none'`, call `storeChallenge($challenge, 'register', $label)`, and return the options as JSON.

`finishRegistration()` must: `consumeChallenge('register')` and return `false` if null; validate the attestation response against that challenge, `$this->rpId`, and an origin accepted by `originMatchesRpId()`; then insert `credential_id` and `public_key` base64url-encoded via `b64u()`, `sign_count`, comma-joined `transports`, the label from `$_SESSION['passkey_label']`, and `created_at` computed in PHP. Return `false` on any validation exception rather than letting it escape.

- [ ] **Step 5: Run the whole suite**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/Passkeys.php tests/PasskeysTest.php
git commit -m "Add passkey registration ceremony

The user handle is random and generated at begin time, because it forms
part of the creation options; it is stable for the account's life, since
regenerating it would orphan every enrolled credential. Challenges are
single-use and cleared even on failure."
```

---

### Task 6: Login ceremony and sign-counter rule

**Files:**
- Modify: `src/Passkeys.php`
- Test: `tests/PasskeysTest.php`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces:
  - `beginLogin(): string` — JSON request options, stores a `login` challenge.
  - `finishLogin(string $clientJson): ?array` — on success calls `Auth::loginAs()` and returns the user row; `null` otherwise.
  - `signCountAcceptable(int $stored, int $incoming): bool` — public so the rule is directly testable.

- [ ] **Step 1: Write the failing tests**

Add to `tests/PasskeysTest.php`:

```php
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

        $this->assertSame('example.com', $options['rpId']);
        $this->assertNotEmpty($options['challenge']);
        $this->assertSame('login', $_SESSION['passkey_purpose']);
        $this->assertTrue(
            empty($options['allowCredentials']),
            'discoverable credentials: the browser picks, so no username is needed'
        );
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsWhenNoChallenge(): void
    {
        $_SESSION = [];
        $this->assertNull($this->passkeys->finishLogin('{}'));
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsChallengeIssuedForRegistration(): void
    {
        $this->makeUser();
        $this->passkeys->beginRegistration(1, 'Laptop');

        $this->assertNull($this->passkeys->finishLogin('{}'));
    }

    #[RunInSeparateProcess]
    public function testFinishLoginRejectsUnknownCredentialId(): void
    {
        $this->makeUser();
        $this->passkeys->beginLogin();

        $payload = json_encode(['id' => Passkeys::b64u('no-such-credential')]);

        $this->assertNull($this->passkeys->finishLogin($payload));
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    #[RunInSeparateProcess]
    public function testFailedLoginEstablishesNoSession(): void
    {
        $this->makeUser();
        $this->passkeys->beginLogin();

        $this->passkeys->finishLogin('{}');

        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit --filter "Login|SignCount"`
Expected: FAIL — undefined methods.

- [ ] **Step 3: Implement**

```php
    /**
     * Many authenticators (notably iCloud Keychain) always report 0. A
     * pair of zeroes therefore means "this authenticator does not count"
     * and is accepted. Once a counter is in use, it must strictly
     * increase: equal means a replayed assertion, lower means a possible
     * cloned credential.
     */
    public function signCountAcceptable(int $stored, int $incoming): bool
    {
        if ($stored === 0 && $incoming === 0) {
            return true;
        }
        return $incoming > $stored;
    }
```

`beginLogin()` must: generate a 32-byte random challenge, build request options with `rpId = $this->rpId`, `userVerification: 'required'`, and an **empty** `allowCredentials`, call `storeChallenge($challenge, 'login')`, and return JSON.

`finishLogin()` must, in order: `consumeChallenge('login')`, returning `null` if invalid; base64url-encode the returned credential id and look it up in `user_credentials`, returning `null` if absent; validate the assertion against the stored public key, the challenge, `$this->rpId` and an origin accepted by `originMatchesRpId()`; check `signCountAcceptable()` against the stored count and return `null` if it fails; on success update `sign_count` and `last_used_at`, call `$this->auth->loginAs((int)$row['user_id'])`, and return `$this->auth->currentUser()`. Any validation exception returns `null`.

**Every `null` return path must leave no session behind** — `loginAs()` is the last step, reached only after all checks pass.

- [ ] **Step 4: Run the whole suite**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Passkeys.php tests/PasskeysTest.php
git commit -m "Add passkey login ceremony and sign-counter rule

Discoverable credentials, so no username is typed. loginAs is the last
step and is reached only after every check passes, so no failure path can
leave a session behind."
```

---

### Task 7: Credential management

**Files:**
- Modify: `src/Passkeys.php`
- Test: `tests/PasskeysTest.php`

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  - `listCredentials(int $userId): array` — rows of `id`, `label`, `created_at`, `last_used_at`, ordered by `created_at`. Never returns `public_key`.
  - `deleteCredential(int $userId, int $credentialId): bool`
  - `hasCredentials(int $userId): bool`

- [ ] **Step 1: Write the failing tests**

```php
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit --filter "Credential"`
Expected: FAIL — undefined methods.

- [ ] **Step 3: Implement**

```php
    public function listCredentials(int $userId): array
    {
        $st = $this->pdo->prepare(
            'SELECT id, label, created_at, last_used_at
               FROM user_credentials WHERE user_id = ? ORDER BY created_at'
        );
        $st->execute([$userId]);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    }

    /** user_id is in the WHERE clause on purpose: ownership is enforced in SQL. */
    public function deleteCredential(int $userId, int $credentialId): bool
    {
        $st = $this->pdo->prepare('DELETE FROM user_credentials WHERE id = ? AND user_id = ?');
        $st->execute([$credentialId, $userId]);
        return $st->rowCount() > 0;
    }

    public function hasCredentials(int $userId): bool
    {
        $st = $this->pdo->prepare('SELECT COUNT(*) AS n FROM user_credentials WHERE user_id = ?');
        $st->execute([$userId]);
        return (int)$st->fetch(PDO::FETCH_ASSOC)['n'] > 0;
    }
```

- [ ] **Step 4: Run the whole suite**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Passkeys.php tests/PasskeysTest.php
git commit -m "Add credential listing, deletion and presence check

Ownership is enforced in the WHERE clause rather than by a prior read, so
there is no window between check and delete. listCredentials never
returns public_key."
```

---

### Task 8: Browser JS asset

**Files:**
- Create: `assets/passkey.js`
- Modify: `composer.json` (ensure `assets/` is not excluded from the package)

**Interfaces:**
- Consumes: the JSON shapes produced by Tasks 5 and 6.
- Produces: `assets/passkey.js`, an ES module exporting `registerPasskey(beginUrl, finishUrl, csrfToken, label)` and `loginWithPasskey(beginUrl, finishUrl)`, each resolving to `{ok: boolean, error?: string}`. Consumers serve this file through their own PHP passthrough — see the spec.

- [ ] **Step 1: Write the asset**

```javascript
// Browser half of the WebAuthn ceremonies. Protocol plumbing only: it
// renders nothing and styles nothing, so it does not contradict
// single-auth shipping no login-page HTML.
//
// Consumers cannot serve this file directly -- every site's nginx denies
// /vendor/ -- so each one serves it through a small PHP passthrough.

const b64uToBytes = (s) => {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const bytesToB64u = (buf) => {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const isSupported = () =>
  typeof window.PublicKeyCredential === 'function';

const postJson = async (url, body, csrfToken) => {
  const headers = { 'Content-Type': 'application/json' };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok) return { ok: false, error: data.error || `HTTP ${res.status}` };
  return data;
};

export async function registerPasskey(beginUrl, finishUrl, csrfToken, label) {
  if (!isSupported()) return { ok: false, error: 'This browser does not support passkeys.' };
  try {
    const options = await postJson(beginUrl, { label }, csrfToken);
    if (options.ok === false) return options;

    options.challenge = b64uToBytes(options.challenge);
    options.user.id = b64uToBytes(options.user.id);
    (options.excludeCredentials || []).forEach((c) => { c.id = b64uToBytes(c.id); });

    const cred = await navigator.credentials.create({ publicKey: options });
    return await postJson(finishUrl, {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        attestationObject: bytesToB64u(cred.response.attestationObject),
      },
    }, csrfToken);
  } catch (e) {
    // NotAllowedError is the user cancelling or timing out, not a fault.
    if (e.name === 'NotAllowedError') return { ok: false, error: 'Cancelled.' };
    return { ok: false, error: e.message || 'Passkey registration failed.' };
  }
}

export async function loginWithPasskey(beginUrl, finishUrl) {
  if (!isSupported()) return { ok: false, error: 'This browser does not support passkeys.' };
  try {
    const options = await postJson(beginUrl, {});
    if (options.ok === false) return options;

    options.challenge = b64uToBytes(options.challenge);
    (options.allowCredentials || []).forEach((c) => { c.id = b64uToBytes(c.id); });

    const cred = await navigator.credentials.get({ publicKey: options });
    return await postJson(finishUrl, {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        authenticatorData: bytesToB64u(cred.response.authenticatorData),
        signature: bytesToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bytesToB64u(cred.response.userHandle) : null,
      },
    });
  } catch (e) {
    if (e.name === 'NotAllowedError') return { ok: false, error: 'Cancelled.' };
    return { ok: false, error: e.message || 'Passkey login failed.' };
  }
}
```

- [ ] **Step 2: Syntax-check it**

Run: `docker run --rm -v "$PWD:/app" -w /app node:22-alpine node --check assets/passkey.js`
Expected: no output, exit 0.

- [ ] **Step 3: Confirm the package ships it**

Run: `git check-ignore -v assets/passkey.js || echo "not ignored"`
Expected: `not ignored`. Also confirm `composer.json` has no `archive.exclude` entry that would drop `assets/`.

- [ ] **Step 4: Run the whole suite**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS (unchanged — this task adds no PHP).

- [ ] **Step 5: Commit**

```bash
git add assets/passkey.js composer.json
git commit -m "Add browser half of the WebAuthn ceremonies

Ships from the library so four consumers do not each keep their own copy
of base64url and ArrayBuffer plumbing. Renders nothing, so the 'no
login-page HTML' rule is intact."
```

---

### Task 9: Documentation and release

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a tagged release consumers can require.

- [ ] **Step 1: Document usage in `README.md`**

Add a "Passkeys" section covering: constructing `Passkeys` alongside `Auth`; that `rp_id` is the cookie domain without its leading dot; the four ceremony methods and their return types; that `finishLogin()` returns the user row and **that consumers applying authorization after `attemptLogin()` must apply the same check after `finishLogin()` or the passkey path is an authorization bypass**; that `assets/passkey.js` cannot be served from `vendor/` and needs a PHP passthrough; and that passkeys cannot work over plain HTTP, so local development uses the password path.

- [ ] **Step 2: Note the new invariants in `CLAUDE.md`**

Add: base64url TEXT rather than `VARBINARY`, and why (SQLite); that origin validation has no escape hatch and must not gain one; and that `Auth::loginAs()` verifies no credential and must never be called from application code.

- [ ] **Step 3: Verify the full suite one final time**

Run: `docker run --rm -v "$PWD:/app" -w /app php:8.4-cli php vendor/bin/phpunit`
Expected: PASS, with every pre-existing `AuthTest` test among them.

- [ ] **Step 4: Commit and tag**

```bash
git add README.md CLAUDE.md
git commit -m "Document passkey support"
git tag -a v0.4.0 -m "Passkey (WebAuthn) support alongside passwords"
git push origin main --follow-tags
```

- [ ] **Step 5: Apply the migration to production**

Follow the procedure in `CLAUDE.md` step 6 — staged via `vps-infra`'s `sites/single-auth/bin/migrate.sh`. Run `status` first and confirm the new migration is listed as pending, then `up`, then remove the staged copy.

Expected after `up`: `Applied: 3, Pending: 0`.

**No consumer changes yet.** Composer pins exact commits, so nothing moves onto v0.4.0 until a consumer bumps its constraint. Console integration is a separate plan.

---

## Notes for the executor

- **Task 2 is not optional ceremony.** Later tasks deliberately specify behaviour and leave library-facing calls to the recorded API. If you find yourself writing a `web-auth` class name from memory, stop and read `vendor/`.
- **The pre-existing `AuthTest` suite is the regression harness for Task 3.** Do not modify those tests to make a refactor pass.
- If a test seems to require relaxing origin validation, the test is wrong. See Global Constraints.
