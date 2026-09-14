# single-auth

Shared PHP identity/session library for a primary domain and its
subdomain apps. One login, one session, shared across every consuming
app via a cookie scoped to your chosen domain and a dedicated identity
database.

See `docs/superpowers/specs/2026-08-12-single-auth-design.md` for the full
design, and `docs/superpowers/plans/` for how this and its two consuming
projects were built.

## What this is

- `Coder999\SingleAuth\Auth` — session bootstrap, identity lookup, CSRF
  helpers, login/logout, login throttling.
- `Coder999\SingleAuth\DbSessionHandler` — a `SessionHandlerInterface`
  implementation backing PHP sessions with a database table instead of
  local disk, so session state doesn't depend on consuming apps sharing a
  filesystem.

This package ships no login-page HTML and no authorization/roles system —
see the design doc's "Authn vs authz" section for why.

## Using this in a consuming app

```php
$pdo = new PDO($identityDsn, $identityUser, $identityPass, [...]);
$auth = new \Coder999\SingleAuth\Auth($pdo, [
    'cookie_domain' => $isLocal ? '.yourdomain.local' : '.yourdomain.com',
    'cookie_secure' => !$isLocal,
]);

session_set_save_handler(new \Coder999\SingleAuth\DbSessionHandler($pdo), true);

$user = $auth->requireLogin(); // redirects to login.php if not logged in
```

On the login form, `attemptLogin()` does **not** consult `loginThrottled()`
itself — enforcing the lockout is the calling app's responsibility. Check
throttling before attempting the login:

```php
if ($auth->loginThrottled()) {
    $error = 'Too many failed attempts. Please wait 15 minutes and try again.';
} elseif ($auth->attemptLogin($username, $password)) {
    // success
} else {
    $error = 'Incorrect username or password.';
}
```

`csrfCheck()` terminates the request itself (calls `exit`) when the token
is missing or invalid, so callers should not expect a return value to
check — just call it and continue if it returns.

### `Auth` constructor options

| Option                 | Default        | Notes                                                            |
|-------------------------|----------------|-------------------------------------------------------------------|
| `cookie_name`           | `'identity_session'` | Session cookie / `session_name()`.                                |
| `cookie_domain`         | `''`           | Host-only by default; set to your production/local domains (e.g. `.yourdomain.com` / `.yourdomain.local`) for cross-subdomain sharing. |
| `cookie_secure`         | `true`         | Requires HTTPS to persist the cookie — set to `false` (or conditionally, as above) for plain-HTTP local dev. |
| `login_max_attempts`    | `8`            | Failed attempts allowed per IP within `login_window_seconds` before `loginThrottled()` returns `true`. |
| `login_window_seconds`  | `900`          | Rolling window (seconds) that `login_max_attempts` is counted over. |

### Sharing the login throttle

`attemptLogin()` maintains an IP-keyed failure budget and `loginThrottled()`
reports it. A consumer that authenticates by some other means — a passkey
assertion, say — can join the same budget rather than keeping its own:

```php
if ($auth->loginThrottled()) { /* refuse */ }
$user = $passkeys->finishLogin($json);
if ($user === null) { $auth->noteLoginFailure(); }
else { $auth->clearLoginFailures(); }
```

The budget is keyed on IP alone, not on the credential type, so every
credential on one address shares a single lockout: enough failed passkey
attempts will also lock out password login from that address.

## Passkeys

Passkeys are an additional login path alongside passwords. Construct
`Passkeys` with the same identity-database PDO and `Auth` instance. The
required `rp_id` is the configured cookie domain with its leading dot
removed:

```php
use Coder999\SingleAuth\Auth;
use Coder999\SingleAuth\Passkeys;

$cookieDomain = $isLocal ? '.yourdomain.local' : '.yourdomain.com';
$auth = new Auth($pdo, [
    'cookie_domain' => $cookieDomain,
    'cookie_secure' => !$isLocal,
]);
$passkeys = new Passkeys($pdo, $auth, [
    'rp_id' => ltrim($cookieDomain, '.'),
    'rp_name' => 'Your application', // optional; defaults to single-auth
]);
```

The four ceremony methods are:

| Method | Return value |
|---|---|
| `beginRegistration(int $userId, string $label)` | Raw WebAuthn creation-options JSON (`string`) |
| `finishRegistration(int $userId, string $clientJson)` | `bool`; `true` when the credential was enrolled |
| `beginLogin()` | Raw WebAuthn request-options JSON (`string`) |
| `finishLogin(string $clientJson)` | The authenticated user row (`array`) or `null` |

`beginRegistration()` throws `InvalidArgumentException` on an unknown user
or a label that is over 64 characters or not valid UTF-8 — validate and
report those before starting a ceremony. `finishRegistration()` returns
`false` rather than throwing for anything the authenticator itself produces,
including a credential id too wide for the column and a credential that is
already enrolled.

Registration must use the ID of the currently authenticated user; never
accept a user ID supplied by the browser. Protect registration begin,
registration finish, and credential deletion with CSRF checks. The supplied
ES module sends the registration token in `X-CSRF-Token`, while
`Auth::csrfCheck()` reads `$_POST['csrf']` and exits. A JSON endpoint must
therefore validate the header explicitly (as below), or deliberately adapt it
into `$_POST['csrf']` before calling `csrfCheck()`.

The endpoint contract expected by `assets/passkey.js` is simple: each begin
action responds with the raw options JSON returned by `Passkeys`; each finish
action responds with `{"ok":true}` or `{"ok":false,"error":"..."}`.
Here is the core of a registration endpoint:

```php
header('Content-Type: application/json');

function requireJsonCsrf(Auth $auth): void
{
    $sent = (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if ($sent === '' || !hash_equals($auth->csrfToken(), $sent)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid or expired form token.']);
        exit;
    }
}

$user = $auth->requireLogin();
requireJsonCsrf($auth);

// Decode after the CSRF check, and catch: JSON_THROW_ON_ERROR on unchecked
// input is an uncaught JsonException, i.e. a 500 on malformed input.
try {
    $body = json_decode(file_get_contents('php://input'), true, 512, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Malformed request.']);
    exit;
}
$action = (string)($_GET['action'] ?? '');

if ($action === 'register-begin') {
    echo $passkeys->beginRegistration((int)$user['id'], (string)($body['label'] ?? ''));
} elseif ($action === 'register-finish') {
    $ok = $passkeys->finishRegistration((int)$user['id'], json_encode($body, JSON_THROW_ON_ERROR));
    echo json_encode(['ok' => $ok] + ($ok ? [] : ['error' => 'Passkey registration failed.']));
}
```

Login endpoints use the same wire contract. A successful `finishLogin()` has
already established the shared session. If a consumer applies an allowlist,
role, or any other authorization check after `attemptLogin()`, it **must apply
the same check to the user returned by `finishLogin()`**. Otherwise passkey
login bypasses that authorization. Clear the newly established session when
authorization denies the user:

```php
if ($action === 'login-begin') {
    echo $passkeys->beginLogin();
} elseif ($action === 'login-finish') {
    $user = $passkeys->finishLogin(json_encode($body, JSON_THROW_ON_ERROR));
    $ok = $user !== null && consumerUserAllowed($user);
    if ($user !== null && !$ok) {
        $auth->logout();
    }
    echo json_encode(['ok' => $ok] + ($ok ? [] : ['error' => 'Passkey login failed.']));
}
```

Serve the browser helper through a public PHP endpoint because consumers
cannot expose files below `vendor/` directly:

```php
<?php
declare(strict_types=1);

header('Content-Type: text/javascript; charset=utf-8');
readfile(__DIR__ . '/vendor/coder999/single-auth/assets/passkey.js');
```

Import that endpoint as an ES module and call `registerPasskey()` or
`loginWithPasskey()`. Passkeys require a secure browser context and this
library accepts only HTTPS origins. Plain-HTTP local development therefore
uses the existing password login path.

## Database Migrations (dbmate)

Standard dbmate migration workflow — see `CLAUDE.md`.

Production migrations are applied by hand on the VPS, using `vps-infra`'s
`sites/single-auth/bin/migrate.sh`. This repo deliberately ships no
migration CI: the procedure lives in that script, which is the only copy
of it (verified against production 2026-09-13).

**Migration `20260813020513_rename_admin_tables` is not safe to run in
isolation against a database whose consumers are still on `v0.1.x`** —
it renames `admin_users`/`admin_sessions` to `users`/`sessions`, so any
consumer whose deployed code still queries the old names breaks the
moment it lands. See `docs/superpowers/specs/2026-08-13-auth-rename.md`
for the coordinated cutover this was originally part of. This is now only
a concern when bootstrapping a fresh database (local dev, or a rebuilt
production instance); both migrations have been applied in production
since the 2026-08-13 cutover, confirmed 2026-09-13.
