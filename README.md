# single-auth

Shared PHP identity/session library for `marktuttlemd.com` and its
subdomain apps (`mdproductivity.marktuttlemd.com`, and future ones). One
login, one session, shared across every consuming app via a cookie scoped
to `.marktuttlemd.com` and a dedicated `single_auth` database.

See `docs/superpowers/specs/2026-08-12-single-auth-design.md` for the full
design, and `docs/superpowers/plans/` for how this and its two consuming
projects were built.

## What this is

- `Mtmd\SingleAuth\Auth` — session bootstrap, identity lookup, CSRF
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
$auth = new \Mtmd\SingleAuth\Auth($pdo, [
    'cookie_domain' => $isLocal ? '.nexus.local' : '.marktuttlemd.com',
    'cookie_secure' => !$isLocal,
]);

session_set_save_handler(new \Mtmd\SingleAuth\DbSessionHandler($pdo), true);

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
| `cookie_domain`         | `''`           | Host-only by default; set to `.marktuttlemd.com` / `.nexus.local` for cross-subdomain sharing. |
| `cookie_secure`         | `true`         | Requires HTTPS to persist the cookie — set to `false` (or conditionally, as above) for plain-HTTP local dev. |
| `login_max_attempts`    | `8`            | Failed attempts allowed per IP within `login_window_seconds` before `loginThrottled()` returns `true`. |
| `login_window_seconds`  | `900`          | Rolling window (seconds) that `login_max_attempts` is counted over. |

## Database Migrations (dbmate)

Same convention as `marktuttlemd`/`mdproductivity`. See `CLAUDE.md`.

**Migration `20260813020513_rename_admin_tables` is not safe to run in
isolation** — running it via `.github/workflows/migrate.yml` outside the
coordinated 3-repo cutover documented in
`docs/superpowers/specs/2026-08-13-auth-rename.md` breaks both consuming
sites (`marktuttlemd`, `mdproductivity`) immediately, since their
currently-deployed code queries the old `admin_users`/`admin_sessions`
table names until they're redeployed on `single-auth` `v0.2.0`.
