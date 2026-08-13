# single-auth: rename admin_* vocabulary to identity-neutral names — design

**Date:** 2026-08-13
**Status:** Approved, pending implementation plan

## Problem

`single-auth`'s own design doc
(`docs/superpowers/specs/2026-08-12-single-auth-design.md`, "Authn vs
authz") already states the intended split: this library only answers
"who is this?" — authorization ("what can this identity do *here*?") is
deliberately left to each consuming app. But the actual vocabulary
throughout the library and both its consumers says otherwise: the table
is `admin_users`, the class is `AdminAuth`, the gate method is
`requireAdmin()`, the session cookie is `mtmd_admin`. Every name asserts
that anyone who can authenticate is an admin — an assumption the design
doc explicitly disclaims, and one that stops being true the moment a
second, non-admin authenticated user ever exists on any consuming app.

This spec renames the vocabulary to be identity-neutral, with **no
behavior change**: today's single user keeps working exactly as before;
every consuming app still decides for itself whether an authenticated
identity is allowed in. This is not adding authorization — it's making
the naming stop implying a guarantee the library was already explicit
about not providing.

## Non-goals

- No roles, scopes, or per-app authorization table. Still one human user
  across every app, same as the original design.
- No zero-downtime staged rollout. Single coordinated cutover: DB rename,
  library version bump, and both consumers' redeploys happen back-to-back
  in one sitting. The one user re-logs in once afterward (the cookie name
  itself is changing, which invalidates any live session by design,
  independent of the DB rename).
- No change to `marktuttlemd`'s `/admin` URL path or its admin-panel
  branding — the complaint is about identity vocabulary implying a
  guarantee it doesn't make, not about the admin panel's own naming.
- No change to the `single-auth` repo name, the `single_auth` database
  name, or the `identity_auth` MySQL user — none of these assert
  "admin-only," all already describe "one shared identity system," and
  renaming them would be pure churn (git remotes, deploy secrets) for no
  benefit.
- `login_attempts` is not renamed — it was never admin-specific.

## Naming scheme

| Current | New |
|---|---|
| `admin_users` table | `users` |
| `admin_sessions` table | `sessions` |
| `AdminAuth` class (`src/AdminAuth.php`) | `Auth` (`src/Auth.php`) |
| `requireAdmin(): array` | `requireLogin(): array` |
| `currentAdmin(): ?array` | `currentUser(): ?array` |
| `mtmd_admin` cookie | `identity_session` |
| Each consumer's `admin_auth()` wrapper fn | `auth()` |
| Each consumer's `current_admin()` wrapper fn | `current_user()` |
| Each consumer's `require_admin()` wrapper fn | `require_login()` |
| `$_SESSION['admin_id']` (internal only) | `$_SESSION['user_id']` |
| marktuttlemd's `admin_session_start()` wrapper fn | `start_session()` |

Unchanged (already generic, nothing admin-specific about them):
`csrfToken()`, `csrfField()`, `csrfCheck()`, `attemptLogin()`, `logout()`,
`loginThrottled()`, `clientIp()`, `sessionStart()`, `identity_pdo()` (each
consumer's PDO-factory wrapper function), `login_attempts` table,
`identity_auth` DB user, `single_auth` database, `IDENTITY_DB_*` /
`IDENTITY_COOKIE_*` constants (already identity-neutral).

`$_SESSION['admin_id']` is internal to `Auth`/`currentUser()`/
`attemptLogin()` — confirmed (grep, both consumer repos) that no consumer
reads or writes it directly, only through the class's own methods, so
renaming it has zero external surface.

The returned identity array's own keys (`id`, `username`) don't change —
only the method name that returns it does. Anywhere existing docs
describe authorization as "keyed by the `admin_id` this library returns"
(the original design doc's "Authn vs authz" section) gets reworded to
"the `id` this library returns," since that's now the accurate name.

## `single-auth` (library) changes

- `src/AdminAuth.php` → `src/Auth.php`: class `AdminAuth` → `Auth`,
  `requireAdmin()` → `requireLogin()`, `currentAdmin()` → `currentUser()`,
  internal SQL updated to the new table names, default cookie name
  updated to `identity_session`. Every other method body is otherwise
  unchanged.
- `src/DbSessionHandler.php`: update its `admin_sessions` reference to
  `sessions`. Class name unchanged (never admin-specific).
- `tests/AdminAuthTest.php` → `tests/AuthTest.php`: update to the new
  class/method/table names throughout.
- `tests/DbSessionHandlerTest.php`: update its table reference.
- New dbmate migration (`db/migrations/`):
  ```sql
  -- migrate:up
  RENAME TABLE admin_users TO users, admin_sessions TO sessions;

  -- migrate:down
  RENAME TABLE users TO admin_users, sessions TO admin_sessions;
  ```
  A single comma-separated `RENAME TABLE` statement, not two separate
  ones — MySQL/MariaDB executes a multi-table rename as one atomic DDL
  operation, so there's no window where one table is renamed and the
  other isn't. Preserves all data (including any live session rows) — no
  data migration step needed, unlike the original marktuttlemd →
  single_auth migration.
- Update `README.md` and `CLAUDE.md` to the new names throughout,
  including `CLAUDE.md`'s "Keep `admin_users`/`login_attempts`
  column-compatible..." line (this migration is exactly the deliberate
  exception that line already carves out).
- Update `docs/superpowers/specs/2026-08-12-single-auth-design.md`'s
  "Authn vs authz" section: replace `admin_users`/`admin_sessions`/
  `admin_id`/`AdminAuth` references with the new names, and add a short
  note pointing forward to this spec so the design doc's history reads
  coherently (the original doc chose `admin_*` names deliberately at the
  time; this spec is the record of why that changed).
- Tag `v0.2.0` after merge — breaking API and schema change, still pre-1.0
  so a minor bump is the correct semver signal (matches how `v0.1.0`
  received a same-day patch bump for its timezone bug rather than a major
  one).

## `marktuttlemd` changes

- Bump `composer.json`'s `coder999/single-auth` constraint to `^0.2.0`.
- `admin/lib/auth.php`: update the `Mtmd\SingleAuth\AdminAuth` import to
  `Auth`, rename the `admin_auth()`/`current_admin()`/`require_admin()`
  wrapper functions to `auth()`/`current_user()`/`require_login()`,
  update their bodies to call `currentUser()`/`requireLogin()`. This file
  also has a wrapper `mdproductivity` doesn't: `admin_session_start()`
  (calls the unchanged `sessionStart()`) — rename to `start_session()`
  (not `session_start()`, which collides with PHP's own built-in
  function of that exact name). It has two direct callers outside
  `auth.php` itself: `admin/login.php:4` and `admin/lib/ui.php:52,58`.
- `admin/setup.php`: delete the dead `CREATE TABLE IF NOT EXISTS
  admin_users (...)` block (leftover from before the table moved into
  `single_auth` — the line directly above it already says so in a
  comment; `single-auth`'s own migrations own this table now). Update the
  `SELECT COUNT(*) FROM admin_users` / `INSERT INTO admin_users` calls to
  `users`.
- `admin/settings.php`: update all four direct `admin_users` references
  (`SELECT`/`UPDATE`/`INSERT`/the admin-listing query) to `users`, and
  rename the `$admins` display variable to `$users`.
- Every other file that calls the wrapper functions needs its call sites
  updated to the new names (unlike the original integration, where
  wrapper names stayed identical to what callers already used — this
  rename changes the names themselves, so every call site changes too,
  even though the *behavior* at each site doesn't). Confirmed full list
  via grep, each just a function-name swap, no logic change:
  - `admin/login.php:4` — `admin_session_start();` → `start_session();`
  - `admin/login.php:5` — `if (current_admin() !== null) {` → `if (current_user() !== null) {`
  - `admin/lib/ui.php:12` — `$user = current_admin();` → `$user = current_user();`
  - `admin/lib/ui.php:52,58` — `admin_session_start();` → `start_session();` (two call sites)
  - `admin/content.php:4` — `require_admin();` → `require_login();`
  - `admin/items.php:4` — `require_admin();` → `require_login();`
  - `admin/index.php:5` — `$user = require_admin();` → `$user = require_login();`
  - `admin/settings.php:5` — `$user = require_admin();` → `$user = require_login();`

## `mdproductivity` changes

- Bump `composer.json`'s `coder999/single-auth` constraint to `^0.2.0`.
- `htdocs/lib/auth.php`: same treatment as marktuttlemd's — import,
  wrapper function renames, body updates. No direct SQL here (this app
  never queried `admin_users` itself) and no `admin_session_start()`
  equivalent (this app doesn't have that wrapper), so nothing else in
  this file.
- Call sites needing the function-name swap (confirmed via grep, same
  "name changes, behavior doesn't" pattern as marktuttlemd's list above):
  - `htdocs/index.php:4` — `require_admin();` → `require_login();`
  - `htdocs/import.php:6` — `require_admin();` → `require_login();`
  - `htdocs/api/summary.php:4` — `require_admin();` → `require_login();`
  - `htdocs/login.php:5` — `if (current_admin() !== null) {` → `if (current_user() !== null) {`

## Cutover sequencing

Because this is a single coordinated cutover, order matters: the moment
the DB migration runs, any *currently-deployed* consumer code (still
saying `admin_users`) breaks immediately, since the table it queries no
longer exists under that name. So all code changes across all three
repos are built, reviewed, and merged **before** anything touches
production, then the actual cutover runs as one tight sequence:

1. Merge and tag `single-auth` `v0.2.0` (tagging alone changes nothing
   live — no consumer has bumped its constraint yet).
2. Merge `marktuttlemd`'s and `mdproductivity`'s updated code to their own
   `main` branches (merging ≠ deploying — nothing live changes yet).
3. **The cutover itself, done back-to-back with no unrelated work in
   between:**
   1. Run `single-auth`'s migration against production
      (`RENAME TABLE` — fast and atomic, but breaks both sites'
      *currently-deployed* code the instant it runs).
   2. Deploy `marktuttlemd` (picks up `v0.2.0` + the updated wrapper).
   3. Deploy `mdproductivity` (same).
   4. Verify: fresh login at `marktuttlemd.com/admin`, confirm
      `mdproductivity.marktuttlemd.com` still needs no second login
      (same SSO check as the original rollout, just re-run against the
      new names) — existing session cookies are invalidated by the
      cookie-name change regardless of the DB rename, so this must be a
      fresh login, not a reused session.

Expected impact: a few minutes of broken login between step 3.1 and 3.3
finishing. Accepted — single user, low-traffic sites, already agreed to
in favor of avoiding transition-shim complexity for a purely cosmetic
rename.

## Testing

- `single-auth`: full existing test suite (`AuthTest`,
  `DbSessionHandlerTest`) continues running against in-memory SQLite,
  updated to the new names — same portable-SQL constraint as today, no
  new testing infrastructure needed.
- Local dev: apply the migration locally first (`dbmate up` against the
  local `single_auth` DB), confirm both apps' local login still works
  end-to-end before touching production, same discipline as every other
  schema change in this family of projects.
- Production: after the cutover sequence's final step, confirm login
  works end-to-end (marktuttlemd login → mdproductivity SSO check) before
  considering this done — this is a login system, verify it working, not
  just the deploys succeeding.
- Regression: confirm marktuttlemd's CSRF-protected admin forms
  (`content.php`, `items.php`, `settings.php`) still work unchanged, and
  that `settings.php`'s password-change/user-listing functionality (now
  reading/writing `users` instead of `admin_users`) still works —
  directly re-testing the exact code path the original design doc's
  "Authn vs authz" section flagged as having drifted once already.
