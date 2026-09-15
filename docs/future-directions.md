# Future directions

**Status: open question, deliberately tabled 2026-09-14. No decision has been
made and none is pending.**

This document exists so the architecture question below is not rediscovered
and re-argued from scratch every time someone reads the onboarding guide and
finds it long. If you are about to propose replacing this library, read this
first — the tradeoffs are already mapped, and the reason nothing was chosen is
that the deciding question is a product question, not a technical one.

## The question

Should this remain a library that each site embeds, or should authentication
move to a central service that sites delegate to over OpenID Connect (OIDC)?

An external architecture review recommended the OIDC path in September 2026,
estimating several weeks of work across the current consumers. That review is
held privately, outside this public repository. Its direction was judged sound;
its urgency was not, and the decision was deferred.

## This library is currently two things at once

That is the root of the tension, and it is worth naming plainly.

**A login kit.** Password verification, CSRF helpers, login-failure
throttling, database-backed sessions, and WebAuthn passkey ceremonies — the
parts of a login page nobody should write twice. This is sections 3–5 of
[onboarding.md](onboarding.md).

**A shared-identity system.** One identity database that several apps connect
to, plus a cookie scoped to a shared parent domain, so sibling sites recognize
one session. This is essentially all of onboarding section 1: deciding identity
scope, deciding cookie scope, coordinating a passkey relying-party ID across
domains, provisioning a scoped database user, joining a shared container
network, and mounting a database CA certificate.

None of section 1 helps a site log a user in. It exists only so that two sites
can share a session. It is also where the blast radius comes from: every app
holding read access to the shared credential tables can read every stored
password hash. Separate database users per consumer are useful for rotation
and audit, but they are not an isolation boundary.

**So the cost of onboarding a new site is mostly the cost of the feature you
may not need.**

## What OIDC is, and what it would change

OIDC is a standard for one site to ask another "who is this person?" and get a
signed, verifiable answer. The flow:

1. The app redirects the browser to the accounts service.
2. The user authenticates there. That service owns the credentials.
3. The browser comes back to the app's callback with a short-lived code.
4. The app's server exchanges that code directly for a signed ID token.
5. The app verifies the signature and creates its own ordinary local session.

Two consequences matter here. The apps never see a password or touch a
credential store — an app learns a subject identifier and nothing more. And it
works across unrelated domains, because the browser physically visits the
accounts service rather than relying on a shared cookie.

If this is ever built: use the authorization-code flow with PKCE through a
maintained client library, and validate issuer, audience, signature, and the
`state`/`nonce` binding. Do not hand-roll the protocol. Writing an OIDC
provider is a separate security product, not a feature of this package.

## The three models

| | Credentials live | SSO reach | Cost to add a site |
|---|---|---|---|
| Library only | Each site's own database | None; separate login per site | Install, run the migrations into your own database |
| Shared identity database | One identity database, all apps connect | Sites under one shared parent domain | Everything in onboarding section 1 |
| Central service over OIDC | One accounts service | Any domain | Register a client, implement a callback |

The middle row is what the current onboarding guide describes. The top row is
already supported and undocumented. The bottom row does not exist.

## Library-only mode already works — verified 2026-09-14

No code change is required to use this package standalone, with no shared
database and no cross-site session. Checked against the source at the time of
writing:

- `Auth::__construct` takes an injected `PDO` (`src/Auth.php`). It is never
  constructed internally and no database name is hardcoded anywhere in `src/`.
- `cookie_domain` defaults to `''`, which is a host-only cookie — sharing is
  opt-in, not the default (`src/Auth.php`).
- The schema is four self-contained tables: `users`, `sessions`,
  `login_attempts`, `user_credentials` (`db/schema.sql`).

So a standalone site points the PDO at its own application database, applies
this repo's migrations there, and sets `rp_id` to its own hostname. It gets
password login, throttling, sessions and passkeys, sharing nothing with any
other site — and with no identity network, no CA mount, and no cross-app
database grants to provision.

Should this become the documented default, the work is a rewritten onboarding
path and a migration bundle, not a rewrite of `src/`.

## The one thing only a central login host can give you

Passkeys are bound to a **relying-party ID**, which is a domain. Credentials
registered under one apex domain can never be used at a different apex domain.
That is a WebAuthn constraint, not a limitation of this library, and no amount
of shared database or shared cookie changes it.

Consequently, a deployment spanning two apex domains maintains two separate
passkey enrollments permanently. The cost of that grows with every credential
enrolled, and only a single central login host removes it. This is the
strongest argument for the OIDC path, and it gets more expensive to ignore
over time rather than less.

## What would actually decide this

**Will any consuming site have users who are not the operator?**

If yes, a central accounts service eventually wins: public signup, account
recovery, and one place to disable an account are real features, and building
them once beats building them per site. If no, the login kit is the whole
answer and the shared-identity machinery is overhead.

Note that this is not a one-way door. Migrating a standalone site to OIDC
later is a contained change: the callback replaces the login form, and the
rest of the app keeps using its own local session exactly as before.

## Meanwhile

- **Do not add another consumer to a shared identity database** without
  deciding this first. Each one makes both futures more expensive.
- **Do not add per-site authentication features to consuming apps.** If a
  login capability is worth having, it belongs in this library.
- **Do not build an OIDC provider here.** If the OIDC path is chosen, adopt an
  established provider or protocol engine.

## Deployment inventory

Deployed versions, cookie scopes, database grants, container networks and
per-consumer topology are **not** recorded here — this repository is public,
and a copy would go stale. `vps-infra` is authoritative for all of it. Derive
the current consumer list from source rather than trusting any written list;
[CLAUDE.md](../CLAUDE.md) gives the command, and notes that a consumer may
exist outside the locally checked-out repositories.
