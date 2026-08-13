# single-auth: shared identity library — design

**Date:** 2026-08-12
**Status:** Approved, pending implementation plan

## Problem

`marktuttlemd.com/admin` has a working PHP session-based admin login
(`admin_users` table, `mtmd_admin` session cookie, CSRF helpers — see
`marktuttlemd/htdocs/admin/lib/auth.php`). `mdproductivity` will move to
`mdproductivity.marktuttlemd.com` with its own webroot, and currently has no
login at all. The goal: log in once at `marktuttlemd.com/admin`, and
`mdproductivity` (plus future subdomain projects) recognizes the same
session — same credentials, same session, no second login.

Both apps are deployed independently (separate GitHub repos, separate CI,
separate rsync targets on the same shared IONOS hosting account) and are
expected to stay that way. `mdproductivity.marktuttlemd.com` and
`marktuttlemd.com` share a registrable domain, so they are same-site for
cookie purposes — this makes cross-subdomain cookie sharing straightforward
(no CORS, `SameSite=Lax` works fine) but session **storage** and the
**credential store** still need a real design.

## Non-goals

- No OAuth/OIDC flow, no tokens, no network auth service. This stays a
  first-party cookie + shared database, not a "real" SSO protocol — that
  level of infrastructure isn't justified for a handful of personal
  projects on one shared-hosting account.
- No per-app authorization/roles system. There is one human admin today.
  Authorization ("what can this identity do *here*") is deliberately left
  out of scope for this library — see "Authn vs authz" below.

## Architecture

- **New private repo, `single-auth`** (`coder999/single-auth`), a Composer
  package (`coder999/single-auth`, PSR-4 namespace `Mtmd\SingleAuth`,
  PHP 8.1+). Consumed by every app (including marktuttlemd) as an ordinary
  Composer dependency via a VCS repository entry pointing at this private
  GitHub repo. Composer needs a GitHub token (`COMPOSER_AUTH`) to fetch it,
  both in each consumer's CI and in local dev.
- **Its own database, `single_auth`**, on the same shared IONOS MySQL
  server as every other project's database. Holds `admin_users`,
  `admin_sessions`, `login_attempts`. This is a deliberate choice over
  reusing `marktuttlemd`'s existing database: putting identity data inside
  `marktuttlemd.*` would leave the same asymmetry the separate-repo
  decision was meant to avoid — code decoupled, but data still "owned" by
  one particular consumer. `admin_users`/`login_attempts` already exist in
  `marktuttlemd`'s database today and get migrated over once (see
  Migration below).
- **`single-auth` owns its own dbmate migrations** (`db/migrations/` in
  this repo) and its own minimal migrate-only GitHub Actions workflow — SSH
  + `dbmate up` against production, same pattern as the DB-migration half
  of `marktuttlemd`'s `deploy.yml`, but with no rsync step (this repo ships
  no webroot, just a Composer package and a schema).
- **Dedicated MySQL user, `identity_auth`**, granted access to
  `single_auth.*` only (`GRANT ALL ON single_auth.* TO 'identity_auth'@'%'`
  — database-level, so new tables added later don't need a new grant).
  Every consuming app gets this credential in addition to its own app-DB
  user; the two are never the same user.
- Local dev and production get **separate instances** of all of this —
  same convention already used everywhere else in these projects
  (`marktuttlemd`'s `CLAUDE.md`: "production and local dev are separate
  MySQL instances"). The local Docker MariaDB container gets its own
  `single_auth` database and its own `identity_auth` user, provisioned the
  same manual way the container's existing per-project databases were
  (`marktuttlemd`, `mdproductivity`, etc. in `mariadb_data/` today).

## What's in the package

- `src/AdminAuth.php` — class `AdminAuth`. Constructed with a PDO (already
  connected via `identity_auth`) plus an options array (cookie name,
  cookie domain). Methods mirror what `marktuttlemd`'s `auth.php` does
  today almost 1:1:
  - `currentAdmin(): ?array`
  - `requireAdmin(): array` (redirects to a caller-supplied login URL)
  - `csrfToken()` / `csrfField()` / `csrfCheck()`
  - `attemptLogin(string $username, string $password): bool`
  - `logout(): void`
  - `loginThrottled(): bool`
- `src/DbSessionHandler.php` — implements `SessionHandlerInterface`,
  backing PHP sessions with the `admin_sessions` table instead of local
  disk. Removes any dependency on IONOS sharing file-based session storage
  across subdomains/accounts — session data lives in the same database
  every consumer already needs to reach for identity lookups.
- No login-page HTML/branding ships in this package — each consuming app
  keeps its own `login.php` view and calls into `AdminAuth` for the logic.

## Cookie / session behavior

- Cookie name stays `mtmd_admin` — continuity with marktuttlemd's existing
  sessions.
- Cookie **domain is environment-aware**, not hardcoded: each consuming
  app's wrapper computes it via a `local.marker`-file check (present in the
  git checkout, excluded from the deploy rsync) — same convention already
  used by `mdproductivity`, `dash`, and `diaslab` — giving
  `.marktuttlemd.com` in production and `.nexus.local`/`.odroid.local`
  locally. This means SSO works in local dev too, not just production.
  Note: marktuttlemd's *existing* `admin/config.php` actually uses a
  Host-header check today (`str_ends_with($host, '.odroid.local')`, which
  doesn't even recognize `.nexus.local`) rather than `local.marker` — that
  file is left as-is; the new single-auth wrapper does its own independent
  `local.marker` check rather than reusing or fixing that existing logic.
- `secure` and `httponly` stay `true`. `SameSite=Lax` stays — cross-
  subdomain sharing needs neither CORS nor `SameSite=None` since
  `mdproductivity.marktuttlemd.com` and `marktuttlemd.com` share a
  registrable domain.

## Authn vs authz

Authentication (who is this?) is centralized in this library — it's the
only thing with an `identity_auth` DB credential and it's meant to be the
only code that ever touches `users`/`sessions` directly.
`currentUser()` returns the identity (`{id, username}`), not just a
boolean, specifically so that authorization stays out of this library:

**This is a design intent, not something enforced anywhere — verify it on
every consuming app, don't assume it.** `marktuttlemd`'s integration
initially violated it: `settings.php` (password change, new-admin
creation, admin listing) predated this migration and kept reading/writing
`users` through the app's own database connection instead of
`identity_pdo()`, discovered only by a final whole-branch review after
all of that project's individually-reviewed tasks had shipped — none of
which touched `settings.php`, so none of them could catch it. Concretely:
grep any consuming app for `users`/`sessions`/`login_attempts`
outside of `single-auth`'s own code before considering an integration
done, not just the files the integration plan intended to touch.

Authorization (what can this identity do *here*?) is deliberately left to
each consuming app's own database, keyed by the `id` this library
returns — e.g. a future `productivity_admins` table living entirely inside
`mdproductivity`'s own database, unrelated to and unknown by `single-auth`.
Today there is one admin across every app, so no app needs to build this
yet; the design just needs to not foreclose it, which returning a full
identity (not a bool) accomplishes.

This vocabulary itself was renamed from `admin_*` to identity-neutral
names on 2026-08-13 — see
`docs/superpowers/specs/2026-08-13-auth-rename.md` for why: the naming
was asserting exactly the guarantee this section says the library
doesn't provide.

## Data migration (marktuttlemd → single_auth)

One-time, done as part of rollout, not an ongoing sync:

1. Provision the `single_auth` database and `identity_auth` MySQL user on
   the shared IONOS server.
2. Run `single-auth`'s dbmate migrations against it to create
   `admin_users`, `admin_sessions`, `login_attempts`.
3. Dump `admin_users` and `login_attempts` data out of `marktuttlemd`'s
   production database, restore into `single_auth`. This carries real
   production login credentials — verify row counts and a successful login
   against the new location before anything depends on it.
4. Only after verification: point marktuttlemd's `auth.php` wrapper at
   `single_auth` / `identity_auth`, and stop reading `admin_users`/
   `login_attempts` from `marktuttlemd`'s own database. Leave the old
   tables in place (not dropped) until the cutover has been running
   cleanly for a while.

The same four steps apply to local dev too (migrate the local `marktuttlemd`
DB's `admin_users`/`login_attempts` into a new local `single_auth` DB) —
lower stakes than production, but keeping the environments structurally
identical avoids local dev silently testing a different shape than what
ships.

## marktuttlemd integration

- Add `composer.json` requiring `coder999/single-auth` via a VCS
  repository entry.
- `admin/lib/auth.php` becomes a thin wrapper: builds the `identity_auth`
  PDO, instantiates `AdminAuth`, re-exposes the same function names
  (`current_admin()`, `require_admin()`, `csrf_field()`, etc.) it exposes
  today — **zero changes** to `login.php`, `content.php`, `items.php`,
  `settings.php`, or anything else that calls them.
- `deploy.yml` gains its first-ever `composer install --no-dev` step
  (build `vendor/` fresh in CI, don't commit it) and a `COMPOSER_AUTH`
  secret for the private package.
- Cookie domain flips to `.marktuttlemd.com` only after the data migration
  above is verified. This is the one user-visible change in the whole
  project: it invalidates any live admin session at the moment it ships,
  requiring one re-login.

## mdproductivity integration

- Composer already exists here (`phpoffice/phpspreadsheet`), so adding
  `coder999/single-auth` is a non-event dependency-wise.
- Same thin-wrapper pattern as marktuttlemd, using its own `identity_auth`
  credentials (new secrets, additive to its existing app-DB connection).
- New small `login.php` / `logout.php`, mdproductivity-branded.
- `require_admin()` gate added at the top of `index.php`, `import.php`,
  and `api/summary.php` — the entire app is protected (matches "personal
  billing data, nothing should be public").
- mdproductivity's first-ever `deploy.yml`, modeled on marktuttlemd's
  (IONOS rsync + its own `dbmate` for its own business schema + composer
  install).

## Rollout order

1. Build `single-auth` v0.1.0: `AdminAuth`, `DbSessionHandler`, dbmate
   migrations, migrate-only workflow. Tag a release.
2. Provision `single_auth` DB + `identity_auth` user; run migrations;
   migrate `admin_users`/`login_attempts` data from `marktuttlemd`; verify.
3. Swap marktuttlemd's `auth.php` to the wrapper (still on the old cookie
   domain), deploy, confirm existing admin login behaves identically.
4. Flip marktuttlemd's cookie domain to `.marktuttlemd.com`, redeploy,
   re-login once, confirm nothing else broke.
5. Wire up mdproductivity end to end (composer dep, wrapper, login page,
   deploy pipeline, DB grants), deploy.
6. Verify SSO: log in at `marktuttlemd.com/admin`, visit
   `mdproductivity.marktuttlemd.com`, confirm no login prompt.

## Testing

- Local: verify login at `marktuttlemd.nexus.local` sets a cookie scoped
  to `.nexus.local`, then confirm `mdproductivity.nexus.local` (once its
  gate exists) sees the same session, backed by the local `single_auth`
  database (same MariaDB container, trivial cross-DB access locally).
- Production: after each deploy step in the rollout order, confirm the
  specific behavior that step changed before moving to the next step —
  this is a login system, roll it out one verified step at a time rather
  than all at once.
- Regression: confirm marktuttlemd's existing CSRF-protected admin forms
  (`content.php`, `items.php`, `settings.php`) still work unchanged once
  `auth.php` is a thin wrapper.
