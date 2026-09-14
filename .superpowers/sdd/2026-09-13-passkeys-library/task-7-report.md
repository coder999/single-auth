# Task 7: Credential management report

## Implementation

Implemented the three credential-management methods in `src/Passkeys.php`:

- `listCredentials(int $userId): array` selects only `id`, `label`, `created_at`, and `last_used_at`, scoped to the requested user and ordered by `created_at`; `public_key` is not selected.
- `deleteCredential(int $userId, int $credentialId): bool` performs an ownership-scoped `DELETE` and reports whether a row was removed.
- `hasCredentials(int $userId): bool` checks whether the requested user has at least one credential.

Added the four specified behavior tests and their direct SQLite fixture helper in `tests/PasskeysTest.php`.

All SQL uses the existing portable parameterized subset; no schema or migration files were changed.

## Testing

Focused run:

```text
docker run --rm -v "$PWD:/app:ro" -w /app php:8.4-cli php vendor/bin/phpunit --filter 'Credential' --do-not-cache-result
```

Result: `OK (14 tests, 44 assertions)`; output was pristine.

Full suite:

```text
docker run --rm -v "$PWD:/app:ro" -w /app php:8.4-cli php vendor/bin/phpunit --do-not-cache-result
```

Result: `OK (86 tests, 177 assertions)`; output was pristine.

`git diff --check` also passed.

## TDD evidence

The Task 7 draft, including its tests, was already present as uncommitted work when I took ownership. The historical RED run against the pre-implementation code was therefore not available to reproduce from the working tree. The focused and full GREEN runs above were executed against the completed implementation and pass. I have not claimed a RED output that was not observed.

## Files changed

- `src/Passkeys.php`
- `tests/PasskeysTest.php`
- This report file.

## Self-review

The implementation is scoped to the task, follows the existing PDO and fetch-mode patterns, explicitly protects credential ownership in SQL, and does not expose the stored public key. No concerns remain.
