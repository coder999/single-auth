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
   Keep `users`/`login_attempts` column-compatible with what they already
   have, unless a migration is deliberately evolving them — every
   consuming app's `Auth` usage assumes these shapes. (`users` was renamed
   from `admin_users` in the `2026-08-13-auth-rename` migration — see
   `docs/superpowers/specs/2026-08-13-auth-rename.md`.)
4. Apply locally to verify:
   `DATABASE_URL="mysql://root:ChangeThisRootPassword@127.0.0.1:3306/single_auth" dbmate --migrations-dir db/migrations up`
5. Confirm the `db/schema.sql` diff matches intent; stage both files.
6. Production schema changes **only** happen via
   `.github/workflows/migrate.yml` (manually triggered), which runs
   `dbmate up` over SSH on the IONOS host itself — never by connecting to
   the production database directly from a dev machine.

## No SQL dialect-specific syntax in `src/`

`Auth` and `DbSessionHandler` deliberately avoid `NOW()`, `INTERVAL`,
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
