# Onboarding a new single-auth site

This checklist targets the v0.5.0 API and was checked against the library
and a working consumer on 2026-09-14. Infrastructure configuration belongs
in the private `vps-infra` repository; keep real credentials, database
usernames, and production topology there.

## 1. Decide identity scope and provision access

- Decide whether this app joins an existing identity database or needs an
  independent one. Sharing this database shares identities, credentials,
  and the IP-based login-failure budget; it does not define app permissions.
- Define the app's authorization policy (allowlist, roles, or membership).
  A valid identity is not automatically permission to use the new app.
- Decide cookie scope. Trusted sibling apps can share `identity_session`
  under a common parent domain, using the same identity database and
  session handler. Unrelated domains do not share a browser cookie merely
  because they use the same database. This library is not an OIDC provider.
- Choose a stable passkey relying-party ID (`rp_id`), the domain to which
  credentials belong. For the shared-parent-domain pattern, derive it from
  the cookie domain with its leading dot removed. Do not derive it from an
  unchecked request Host header. Host-only cookies need an explicit RP ID;
  an empty cookie-domain option is not a usable RP ID.
- Existing passkeys must match the RP ID used at registration. HTTPS and an
  origin at that RP ID or one of its subdomains are required by the library.
  Do not relax origin checks for local development; use passwords over HTTP.
- Provision a dedicated database user for the app, scoped to the identity
  database with the required SELECT/INSERT/UPDATE/DELETE access. Keep schema
  migration privileges separate. The app may also have its own database.
- In `vps-infra`, connect the app's PHP service to the identity network,
  provide its credentials through the site's secret mechanism, and mount
  the trusted database CA outside the public web root. Validate TLS with
  server-certificate verification enabled. Read current site configurations
  for paths and network names; copying a historical migration is insufficient.
- Check migration status using the procedure in [CLAUDE.md](../CLAUDE.md).
  The shared database is migrated centrally, not once per new consumer.
  Passkeys require `user_credentials` and `users.webauthn_user_handle`.
  Use the release's migrations to initialize a fresh database; never paste
  schema DDL into an app's startup code.
- Account provisioning, account recovery, email verification, and public
  signup are app responsibilities. The library provides no public signup
  flow. Enrolling a passkey attaches a credential to an existing account.

## 2. Install and bootstrap

Merge this into the app's Composer configuration:

```json
{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/coder999/single-auth" }
  ],
  "require": { "php": ">=8.2", "ext-pdo": "*", "coder999/single-auth": "^0.5.0" }
}
```

Resolve dependencies in development and commit `composer.json` and
`composer.lock`. Deploy with `composer install` from the lockfile, not a
production `composer update`. Confirm the runtime has PDO's MySQL driver
and all resolved dependencies' platform requirements. The package is public;
consumers do not need credentials to access its source repository.

In the app's bootstrap, before output or any session access:

```php
use Coder999\SingleAuth\Auth;
use Coder999\SingleAuth\DbSessionHandler;
use Coder999\SingleAuth\Passkeys;

// These values come from validated app configuration, not request input.
$pdo = new PDO($identityDsn, $identityUser, $identityPassword, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::MYSQL_ATTR_SSL_CA => $identityCaPath,
    PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
]);
session_set_save_handler(new DbSessionHandler($pdo), true);
$auth = new Auth($pdo, [
    'cookie_domain' => $cookieDomain,
    'cookie_secure' => $isProductionHttps,
]);
$passkeys = new Passkeys($pdo, $auth, [
    'rp_id' => $rpId,
    'rp_name' => 'Your application',
]);
```

Production cookies must be secure. Reuse these instances for each request.
Do not call `session_start()` before installing the database handler. Keep
session writes active through login and registration: the library stores
ceremony challenges in the session. Read-only polling optimizations must
not abort or close a session before a ceremony changes it.

If `vendor/` lives below the web root, deny HTTP access to it in the web
server. Serve only the browser helper through a dedicated public endpoint;
see [README](../README.md#passkeys). Check the production autoloader against
the actual deployed directory layout, not just the repository layout.

## 3. Implement password login and shared authorization

- Render `$auth->csrfField()` in the password form and run
  `$auth->csrfCheck()` before attempting a password login.
- Check `$auth->loginThrottled()` before `$auth->attemptLogin(...)`.
  `attemptLogin()` records failures but does not enforce the lockout itself.
- After either credential succeeds, call one shared app authorization
  function. If it denies access, call `$auth->logout()` and return an error.
  Never call `Auth::loginAs()` from the app: it verifies no credential.
- Apply authorization to every protected page and API, including visitors
  who already have a shared session from another app. APIs should return
  JSON 401/403 responses, not redirect to an HTML login page.
- Validate post-login destinations against a configured same-origin base.
  Use the same validated destination for password and passkey login.
- The failure budget uses `REMOTE_ADDR`. Configure trusted proxies to supply
  the real client IP through the web server; do not trust arbitrary incoming
  forwarded headers in application code.

## 4. Wire passkey endpoints

Use POST for each action. Send `Content-Type: application/json` and
`Cache-Control: no-store`, including on the raw begin-options responses.
Do not wrap begin options in an extra `ok` or `options` object.

| Action | Required checks | Library call / result |
|---|---|---|
| Registration begin | Signed-in authorized user, CSRF, valid label | `beginRegistration($userId, $label)` → raw JSON |
| Registration finish | Signed-in authorized user, CSRF | `finishRegistration($userId, $raw)` → boolean |
| Delete | Signed-in authorized user, CSRF, valid credential ID | `deleteCredential($userId, $credentialId)` → boolean |
| Login begin | Shared throttle; no existing login required | `beginLogin()` → raw JSON |
| Login finish | Shared throttle; no existing login required | `finishLogin($raw)` → user or null, then shared app authorization |

For authenticated actions, obtain the user ID from the session, never the
request body. `deleteCredential()` scopes the deletion to that user.
The browser helper sends registration CSRF in `X-CSRF-Token`;
`Auth::csrfCheck()` expects a form field, so JSON endpoints must explicitly
validate the header against `$auth->csrfToken()` using `hash_equals()`.
The login helper sends no CSRF token: do not put registration's session or
CSRF gate in front of anonymous login actions. The library validates the
login assertion against its session challenge and origin.

### Parse once; preserve the original JSON

This example supplies reusable request helpers, not a complete application
endpoint. The app must apply the action-specific checks above.

```php
function reply(array $body, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode($body, JSON_THROW_ON_ERROR);
    exit;
}

function readClientBody(string $raw): array
{
    try {
        $body = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        reply(['ok' => false, 'error' => 'Malformed request.'], 400);
    }
    if (!$body instanceof stdClass) {
        reply(['ok' => false, 'error' => 'Expected a JSON object.'], 400);
    }
    return get_object_vars($body);
}

$raw = (string) file_get_contents('php://input');
$body = readClientBody($raw);
// For finish actions, pass $raw unchanged to the library. Do not re-encode $body.
```

Validate label and credential-ID types before calling the library. Catch
`InvalidArgumentException` from registration begin and report a controlled
400. Do not reflect arbitrary request values or exception details in errors.
Convert infrastructure failures to generic JSON 503 responses and log
server-side diagnostics without credentials or assertion payloads.

Login finish follows this sequence (the app defines `consumerUserAllowed`):

```php
if ($auth->loginThrottled()) {
    reply(['ok' => false, 'error' => 'Too many failed attempts. Try again later.'], 429);
}
$user = $passkeys->finishLogin($raw);
if ($user === null) {
    $auth->noteLoginFailure();
    reply(['ok' => false, 'error' => 'Login incorrect']);
}
$auth->clearLoginFailures();
if (!consumerUserAllowed($user)) {
    $auth->logout();
    reply(['ok' => false, 'error' => 'This account may not use this site.'], 403);
}
reply(['ok' => true]);
```

Registration finish also uses the original `$raw` and returns
`{"ok":true}` or `{"ok":false,"error":"..."}`. A malformed assertion must
never establish a session. A cancelled browser prompt does not reach finish
and therefore does not itself add a server-side login failure.

Import `registerPasskey()` and `loginWithPasskey()` from the publicly served
library helper. Show failures and re-enable buttons after cancellation or
errors; prevent overlapping ceremonies. In ES modules, `document.currentScript`
is null: read a destination data attribute through an explicit selector.

## 5. Preferred public-site enrollment flow

User preference recorded 2026-09-14:

1. After successful password authentication and app authorization, check
   `$passkeys->hasCredentials($userId)` and the app's prompt preference.
2. If the account has no passkeys and has not opted out, offer **Create a
   passkey for faster sign-in**.
3. Provide **Create passkey**, **Not now**, and **Don't ask again**.
   **Not now** dismisses the current offer; **Don't ask again** persists an
   account-level preference suppressing future offers.
4. After creating or dismissing the offer, continue to the validated
   post-login destination. Keep password login available.
5. Retain a management page for listing, adding, and deleting the signed-in
   user's passkeys, even after opting out of prompts.

Prompt UI and the opt-out preference are app-owned features; single-auth
v0.5.0 does not implement their storage or rendering. Store the preference
in the app's own account settings, using that app's migration process, and
protect changes with authentication, authorization, and CSRF. Do not silently
add a column to the shared identity schema for one app's preference.
A single-user administrative site may use management-page-only enrollment.

## 6. Validate and deploy

- [ ] Password success, wrong password, throttling, and denied-account
  session teardown pass automated tests.
- [ ] Both login methods use the same authorization policy. Protected APIs
  still reject anonymous and disallowed shared-session users.
- [ ] Registration/deletion require CSRF and session ownership. Anonymous
  users cannot enroll; one user cannot delete another's credential.
- [ ] Malformed JSON, scalar/array bodies, and extreme numbers such as
  `1e400` yield controlled failures rather than uncaught encoding errors.
- [ ] Browser tests exercise the real handlers with success, cancellation,
  and failures, and verify page/JS selectors and return destinations.
- [ ] Production dependencies and autoloading work in the deployed layout;
  the deployment CI actually runs the relevant PHP and browser checks.
- [ ] Database schema, TLS, domain/RP ID, and secrets are ready before the
  app deploy. Updating this library does not automatically update consumers:
  commit each consumer's lockfile change and deploy it explicitly.
- [ ] Follow the site's infra/deploy procedure. Recreate affected containers
  when environment variables or bind mounts change; restarting alone does
  not load a changed container environment.
- [ ] Deploy enrollment first and enroll a real passkey over HTTPS. Then
  enable passkey login and verify password fallback, passkey success,
  cancellation, last-used timestamp, and the validated return destination.
- [ ] For public sites, verify all three prompt choices, persistence of
  **Don't ask again**, and manual enrollment after opting out.

Keep a known-working password path while verifying the new login method.
Record the deployment and real-browser results in the consumer repository.
