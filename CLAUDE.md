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
4. Apply locally to verify. `single-auth-mariadb` publishes nothing to
   the host (`docker inspect` reports `{"3306/tcp":null}`) — verified
   2026-09-13 — so run dbmate in a container joined to the `identity`
   network instead of pointing it at `127.0.0.1:3306`. The container also
   enforces `--require-secure-transport=ON` with a self-signed local cert
   (`tls=skip-verify`), and its root password is not a fixed placeholder —
   read it from the running container at invocation time rather than
   hardcoding it, since a hardcoded value in this **public** repo would
   both leak and go stale the moment local dev credentials rotate:
   ```bash
   DBPW="$(docker inspect single-auth-mariadb \
     --format '{{range .Config.Env}}{{println .}}{{end}}' \
     | sed -n 's/^MYSQL_ROOT_PASSWORD=//p')"

   docker run --rm --network identity -v "$PWD/db:/db" \
     -e DATABASE_URL="mysql://root:${DBPW}@single-auth-mariadb:3306/single_auth?tls=skip-verify" \
     ghcr.io/amacneil/dbmate:2.35.0 \
     --migrations-dir /db/migrations --schema-file /db/schema.sql up
   ```
   If the password ever contains `@`, `:`, `/` or `#`, it needs
   URL-encoding before going into the DSN — an un-encoded special
   character there is a silent corruption (dbmate parses the DSN wrong),
   not a clean failure, so it's easy to miss.
5. Confirm the `db/schema.sql` diff matches intent; stage both files.
6. Production schema changes happen **only** on the VPS, by hand, via
   `vps-infra`'s `sites/single-auth/bin/migrate.sh` — never by connecting
   to the production database directly from a dev machine. That script
   owns the whole procedure (staging the migrations, credentials, TLS);
   read it rather than reconstructing the commands from here. Verified
   end-to-end against production 2026-09-13: `migrate.sh status` reported
   both migrations applied, 0 pending.

   There used to be a `.github/workflows/migrate.yml` in this repo that
   ran `dbmate up` over SSH against **IONOS**. It was deleted 2026-09-13.
   `single_auth` moved onto the VPS on 2026-08-21 and that workflow was
   never repointed, so triggering it would have migrated the abandoned
   IONOS database while production read a different one — going green
   while changing nothing that matters. Git remembers it; do not
   resurrect it.

## No SQL dialect-specific syntax in `src/`

`Auth` and `DbSessionHandler` deliberately avoid `NOW()`, `INTERVAL`,
and `ON DUPLICATE KEY UPDATE` — "current time" is computed in PHP and
passed as a bound parameter, and writes use select-then-insert-or-update.
This is what lets the whole test suite run against an in-memory SQLite PDO
instead of needing a live MySQL for every test run. Keep any new code in
`src/` to this same portable SQL subset.

## Passkey security invariants

WebAuthn credential IDs, user handles, and credential public keys are stored
as base64url text. In particular, `user_credentials.public_key` contains the
base64url-encoded COSE public-key bytes, not PEM. Do not change these fields to
`VARBINARY`: SQLite has no equivalent, and the in-memory SQLite suite depends
on a text-compatible schema.

`Passkeys::originMatchesRpId()` deliberately requires HTTPS and permits only
the RP ID itself or its subdomains. There is no development or configuration
escape hatch, and one must not be added. Plain-HTTP local development uses the
password path.

`Auth::loginAs()` verifies no credential. It exists only as the shared tail of
the password and passkey implementations and must never be called from
application code. Consumers authenticate through `attemptLogin()` or
`Passkeys::finishLogin()` and then apply their own authorization checks.

## Consumers

Four apps require this package via a Composer VCS repository entry
pointing at this (public) GitHub repo — no Composer auth token needed to
fetch it: `marktuttlemd`, `mdproductivity`, `console` and
`3mensioxmlparser`. Don't trust that list without re-deriving it; from
`~/docker/html-local`:

```bash
for d in */; do d=${d%/}; [ -f "$d/composer.json" ] || continue
  grep -q 'coder999/single-auth' "$d/composer.json" && echo "$d"
done
```

Each holds its own dedicated MySQL user scoped to `single_auth.*`,
alongside its own app-database credentials. The design doc
(`docs/superpowers/specs/2026-08-12-single-auth-design.md`) describes a
single shared `identity_auth` user for this — that is **not** what was
built. Production gives each consumer its own user, which is the better
arrangement; the doc is stale on this point. Confirmed 2026-09-13.

This repo is **public**, so the actual usernames and grants are
deliberately not written down here — see `vps-infra` (private) for the
identity database's real user inventory, and note that
`single-auth-mariadb` publishes 3306 for a remote consumer, which is why
enumerating valid usernames in public would be doing an attacker's
reconnaissance for them.

At least one non-Composer consumer also reaches `single-auth-mariadb`
directly via a `vps-infra` nginx/PHP gate rather than through this
library. `vps-infra/sites/` is authoritative for who talks to that
database; this file is only authoritative for who uses this package.

See the design doc for the full authn/authz split rationale.

## Preferred passkey experience for public-facing consumers

User preference, recorded 2026-09-14: offer passkey enrollment as part of
sign-in for public-facing sites. After a successful password sign-in, if
that account has no registered passkeys, offer **Create a passkey for
faster sign-in**, with **Create passkey** and **Not now** actions. Enrollment
is optional and attaches to the authenticated account; it must never let
an anonymous visitor create a credential for an existing account.

Keep password sign-in available and retain a separate passkey management
page for adding or deleting credentials later. This is the preferred flow
for future public-facing consumer work, not a claim that every consumer
already implements it. A single-user admin site may use management-page
only enrollment.
