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
