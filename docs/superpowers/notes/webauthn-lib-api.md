# `web-auth/webauthn-lib` 5.x — the real API

Read from the installed source of **web-auth/webauthn-lib 5.3.9** on 2026-09-14.
Every signature below was copied out of `vendor/web-auth/webauthn-lib/src/...`;
none of it is recalled from memory. Line numbers are as installed at that
version — if the version moves, re-read before trusting them.

All paths in this file are relative to `vendor/web-auth/webauthn-lib/`.
Everything lives in the `Webauthn\` namespace unless stated otherwise.

Where a snippet appears here, it was executed against the installed library on
PHP 8.4 (see "Verified end to end" at the bottom) — the JSON shown is real
output, not illustrative.

---

## 0. The four objects you construct once

The library has no container and no bundle. For a "passkeys only, attestation
none" relying party you need exactly these, and nothing else:

```php
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;

// 1. attestation formats we accept. The constructor ALREADY adds
//    NoneAttestationStatementSupport, so an empty manager is the "none" policy.
$asm = AttestationStatementSupportManager::create();   // src/AttestationStatement/AttestationStatementSupportManager.php:31, adds None at :19

// 2. the serializer (browser JSON <-> objects). Needs the manager above.
$serializer = (new WebauthnSerializerFactory($asm))->create();  // src/Denormalizer/WebauthnSerializerFactory.php:29,34 -> Symfony\Component\Serializer\SerializerInterface

// 3. the ceremony rule sets
$factory = new CeremonyStepManagerFactory();            // src/CeremonyStep/CeremonyStepManagerFactory.php:49
$factory->setAllowedOrigins(['https://auth.example']);  // :76  — see the warning below
$factory->setAttestationStatementSupportManager($asm);  // :87

// 4. the two validators
$attestationValidator = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony()); // src/AuthenticatorAttestationResponseValidator.php:34 ; src/CeremonyStep/CeremonyStepManagerFactory.php:144
$assertionValidator   = AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());    // src/AuthenticatorAssertionResponseValidator.php:35 ; src/CeremonyStep/CeremonyStepManagerFactory.php:118
```

**Call `setAllowedOrigins()`.** If you leave it unset, the factory falls back to
`CheckOrigin` (`CeremonyStepManagerFactory.php:126,181`), which is
`@deprecated since 5.2.0 and will be removed in 6.0.0`
(`src/CeremonyStep/CheckOrigin.php:22`). With it set you get `CheckAllowedOrigins`
(`src/CeremonyStep/CheckAllowedOrigins.php:23`), which matches
`scheme://host[:port]` exactly against `clientDataJSON.origin`. Default ports are
stripped during normalisation (`:188-201`), and a host-only entry such as
`'auth.example'` is normalised to `https://auth.example` (`:58-61`).
Subdomains are **rejected** unless you pass `setAllowedOrigins([...], true)`
(`:76`, enforced at `:114-119`).

`setSecuredRelyingPartyId(array)` (`:68`) is the "this RP id may use plain HTTP"
escape hatch used for local development — it is also deprecated at `:65`, and
`CheckAllowedOrigins` only consults it on the no-allowed-origins fallback path
(`:128`), so it is useless once `setAllowedOrigins()` is set. For a local
`http://` origin, put the full origin string in `setAllowedOrigins()` instead.

---

## 1. Building creation options (registration ceremony)

Class: `Webauthn\PublicKeyCredentialCreationOptions`, **final**, extends
`Webauthn\PublicKeyCredentialOptions` — `src/PublicKeyCredentialCreationOptions.php:12`.

Static factory, identical in shape to the constructor
(`src/PublicKeyCredentialCreationOptions.php:100-112`; constructor at `:57-69`):

```php
public static function create(
    PublicKeyCredentialRpEntity $rp,
    PublicKeyCredentialUserEntity $user,
    string $challenge,                                    // RAW BINARY
    array $pubKeyCredParams = [],                         // PublicKeyCredentialParameters[]
    null|AuthenticatorSelectionCriteria $authenticatorSelection = null,
    null|string $attestation = null,
    array $excludeCredentials = [],                       // PublicKeyCredentialDescriptor[]
    null|int $timeout = null,                             // milliseconds, positive-int
    null|AuthenticationExtensions $extensions = null,
    array $hints = [],
    null|string $mediation = null,
): self
```

Where each thing the brief asks about is set:

| Thing | Where | Source |
| --- | --- | --- |
| RP id / RP name | `PublicKeyCredentialRpEntity::create(string $name = '', ?string $id = null, ?string $icon = null)` | `src/PublicKeyCredentialRpEntity.php:23` |
| user entity | `PublicKeyCredentialUserEntity::create(string $name, string $id, string $displayName, ?string $icon = null)` | `src/PublicKeyCredentialUserEntity.php:26` |
| challenge | 3rd positional arg, raw binary | `src/PublicKeyCredentialCreationOptions.php:60`, stored by parent at `src/PublicKeyCredentialOptions.php:33` |
| `residentKey` | 3rd arg of `AuthenticatorSelectionCriteria::create()` | `src/AuthenticatorSelectionCriteria.php:82-86` |
| `userVerification` | 2nd arg of `AuthenticatorSelectionCriteria::create()` | `src/AuthenticatorSelectionCriteria.php:84` |
| `attestation: none` | 6th arg of `PublicKeyCredentialCreationOptions::create()` | `src/PublicKeyCredentialCreationOptions.php:106` |

### Gotcha: `rp.name` is deprecated as of 5.3.0 — pass `''`

`PublicKeyCredentialRpEntity::$name` carries
`@deprecated since 5.3.0 and will be removed in 6.0.0`
(`src/PublicKeyCredentialRpEntity.php:10`), and the parent constructor calls
`trigger_deprecation()` if you pass a non-empty name
(`src/PublicKeyCredentialEntity.php:23-29`). Pass `''` and let the normalizer
default `rp.name` to the RP id — it does exactly that at
`src/Denormalizer/PublicKeyCredentialRpEntityDenormalizer.php:38`
(`'name' => $name === '' ? $object->id : $name`).

`PublicKeyCredentialUserEntity` is **not** affected: it passes `''` up to the
parent and then assigns `$this->name` directly
(`src/PublicKeyCredentialUserEntity.php:20-23`), so a user name is fine.

### Constants you should use rather than string literals

```php
AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED    // 'required'      src/AuthenticatorSelectionCriteria.php:38
AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED   // 'preferred'     :40
AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED // 'preferred'  :26
AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED // 'required'    :24
AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM    // 'platform'      :14
PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE // 'none'    src/PublicKeyCredentialCreationOptions.php:16
PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY           // 'public-key'     src/PublicKeyCredentialDescriptor.php:9
```

All three enumerated arguments are validated in the constructor and throw on a
bad value: attestation at `src/PublicKeyCredentialCreationOptions.php:80-83`
(`InvalidDataException`), resident key / user verification / attachment at
`src/AuthenticatorSelectionCriteria.php:65-73` (`InvalidArgumentException`).

Note that `residentKey` **defaults to `null`** ("no preference",
`src/AuthenticatorSelectionCriteria.php:63`), not to `required`. For passkeys you
must pass `required` explicitly. Doing so also sets the legacy
`requireResidentKey = true` for you (`:75-79`).

### Worked example (verified output)

```php
$options = PublicKeyCredentialCreationOptions::create(
    PublicKeyCredentialRpEntity::create('', 'example.test'),          // name MUST be ''
    PublicKeyCredentialUserEntity::create('alice', $userHandleRaw, 'Alice'),
    random_bytes(32),                                                 // raw challenge
    [
        PublicKeyCredentialParameters::createPk(-7),    // ES256  src/PublicKeyCredentialParameters.php:20
        PublicKeyCredentialParameters::createPk(-257),  // RS256
    ],
    AuthenticatorSelectionCriteria::create(
        null,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
    ),
    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    [],            // excludeCredentials: descriptors of the user's existing passkeys
    60000,
);
echo $serializer->serialize($options, 'json');
```

produces (real output, challenge/user id will differ):

```json
{"challenge":"kAF36BY6TBurwXeIcUi39qwaPl2dukTBv8n5SdNEGhc","timeout":60000,
 "rp":{"id":"example.test","name":"example.test"},
 "user":{"id":"5uDs54ED67b3MbMeIj_ppA","name":"alice","displayName":"Alice"},
 "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
 "authenticatorSelection":{"requireResidentKey":true,"authenticatorAttachment":null,
   "userVerification":"preferred","residentKey":"required"},
 "attestation":"none","excludeCredentials":[]}
```

**Only `-7` (ES256) and `-257` (RS256) are verifiable out of the box.** The
default algorithm manager is `Manager::create()->add(ES256::create(), RS256::create())`
(`src/CeremonyStep/CeremonyStepManagerFactory.php:52`). Advertising an algorithm
you cannot verify produces a registration that fails validation, so keep
`pubKeyCredParams` to those two unless you also call `setAlgorithmManager()` (`:93`).

`excludeCredentials` takes
`PublicKeyCredentialDescriptor::create(string $type, string $id, array $transports = [])`
(`src/PublicKeyCredentialDescriptor.php:51`) with a **raw binary** `$id`. A stored
`CredentialRecord` will build one for you:
`CredentialRecord::getPublicKeyCredentialDescriptor()` (`src/CredentialRecord.php:75`).

`$mediation` is a **server-side** flag, not sent to the browser, and it pairs with
`CeremonyStepManagerFactory::conditionalCreateCeremony()` (`:158`) for the
conditional-create / auto-register flow. Leave it `null` for a normal ceremony —
the docblock explaining this is at `src/PublicKeyCredentialCreationOptions.php:38-48`.
Note the options normalizer does not emit `mediation` at all
(`src/Denormalizer/PublicKeyCredentialOptionsDenormalizer.php:186-203`), so if you
ever use it, it will **not** survive a serialize/deserialize round trip through
the session.

---

## 2. Building request options (login ceremony)

Class: `Webauthn\PublicKeyCredentialRequestOptions`, **final** —
`src/PublicKeyCredentialRequestOptions.php:12`.

```php
public static function create(
    string $challenge,                     // RAW BINARY
    null|string $rpId = null,
    array $allowCredentials = [],          // PublicKeyCredentialDescriptor[]
    null|string $userVerification = null,
    null|int $timeout = null,              // milliseconds
    null|array|AuthenticationExtensions $extensions = null,
    array $hints = [],
): self
```
`src/PublicKeyCredentialRequestOptions.php:61-69`; constructor `:34-42`.

User-verification constants live on this class too — note they are a **different
set** from `AuthenticatorSelectionCriteria`'s, because `null` is legal here:
`USER_VERIFICATION_REQUIREMENT_REQUIRED` / `_PREFERRED` / `_DISCOURAGED` at
`src/PublicKeyCredentialRequestOptions.php:16-20`, validated at `:43-46`.

For a **discoverable-credential (usernameless) login, leave `allowCredentials`
empty**. `CheckAllowedCredentialList` returns immediately when the list is empty
(`src/CeremonyStep/CheckAllowedCredentialList.php:37-39`); when it is non-empty
it requires the asserted credential id to be in the list, or throws
`AuthenticatorResponseVerificationException` (`:41-46`).

Verified output for `PublicKeyCredentialRequestOptions::create(random_bytes(32), 'example.test', [], 'preferred', 60000)`:

```json
{"challenge":"B1mI-Gc2-0uQ-NSIqZwN1Me3IyPyA_l7YcJbe6Na9Es","timeout":60000,
 "rpId":"example.test","allowCredentials":[],"userVerification":"preferred"}
```

---

## 3. Validating an attestation (registration) response

### Step A — turn the browser JSON into objects

```php
use Webauthn\PublicKeyCredential;
use Webauthn\AuthenticatorAttestationResponse;

$credential = $serializer->deserialize($rawJsonFromBrowser, PublicKeyCredential::class, 'json');
$response   = $credential->response;                       // src/PublicKeyCredential.php:15
$response instanceof AuthenticatorAttestationResponse || throw new RuntimeException('not a registration response');
```

`PublicKeyCredential` is `{type, rawId, response}` (`src/PublicKeyCredential.php:12-18`,
`rawId`/`type` inherited from `src/Credential.php:12-15`). The denormalizer picks
attestation vs assertion by looking for `attestationObject` vs `signature` in
`response` (`src/Denormalizer/AuthenticatorResponseDenormalizer.php:26-30`).

> **Gotcha, `src/Denormalizer/PublicKeyCredentialDenormalizer.php:27-29`:** if the
> incoming JSON has no top-level `id` key, `denormalize()` returns the raw
> **array** instead of a `PublicKeyCredential` object — no exception. Browser
> `credential.toJSON()` always includes `id`, but a hand-rolled client payload
> may not. Assert `$credential instanceof PublicKeyCredential` before using it.
> The same method also `hash_equals()`-checks `id` against `rawId` (`:30-32`) and
> throws `InvalidDataException` on mismatch.

### Step B — check it

```php
public function check(
    AuthenticatorAttestationResponse $authenticatorAttestationResponse,
    PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
    string $host,
): CredentialRecord
```
`src/AuthenticatorAttestationResponseValidator.php:52-56`.

- `$publicKeyCredentialCreationOptions` is the **same options object you issued**,
  recovered from the session — that is how the challenge is checked. Round-trip it
  through `$serializer->serialize(...)` / `deserialize(..., PublicKeyCredentialCreationOptions::class, 'json')`;
  verified to preserve the raw challenge and the raw user id exactly.
- `$host` is the request host (e.g. `$_SERVER['HTTP_HOST']`). Once
  `setAllowedOrigins()` is configured, `$host` is only a fallback used on the
  no-allowed-origins path (`src/CeremonyStep/CheckAllowedOrigins.php:125`), but it
  is still a required argument.
- On failure it **throws** (usually `Webauthn\Exception\AuthenticatorResponseVerificationException`,
  re-thrown at `src/AuthenticatorAttestationResponseValidator.php:131`). There is
  no boolean return — wrap in `try`/`catch`.

### Step C — what comes back: `Webauthn\CredentialRecord`

Constructor / factory — `src/CredentialRecord.php:22-36` and `:43-57`:

```php
public function __construct(
    public string $publicKeyCredentialId,   // RAW BINARY credential id
    public string $type,                    // 'public-key'
    public array $transports,               // string[] e.g. ['internal','hybrid']
    public string $attestationType,         // 'none' for our policy
    public TrustPath $trustPath,            // EmptyTrustPath for 'none'
    public Uuid $aaguid,                    // Symfony\Component\Uid\Uuid
    public string $credentialPublicKey,     // RAW BINARY, CBOR-encoded COSE key
    public string $userHandle,              // RAW BINARY
    public int $counter,                    // sign count
    public ?array $otherUI = null,
    public ?bool $backupEligible = null,
    public ?bool $backupStatus = null,
    public ?bool $uvInitialized = null,
) {}
```

**What the brief asked for, exactly:**

| Field | Read from | Source |
| --- | --- | --- |
| credential id | `$record->publicKeyCredentialId` | populated at `src/AuthenticatorAttestationResponseValidator.php:172,180` from `AttestedCredentialData::$credentialId` (`src/AttestedCredentialData.php:16`) |
| public key | `$record->credentialPublicKey` | `:173,189`, from `AttestedCredentialData::$credentialPublicKey` (`src/AttestedCredentialData.php:17`) |
| sign count | `$record->counter` | set twice: `:192` at construction and again at `:81` from `attestationObject->authData->signCount` (`src/AuthenticatorData.php:36`) |
| transports | `$record->transports` | `:178`, taken from `AuthenticatorAttestationResponse::$transports` (`src/AuthenticatorAttestationResponse.php:20`) |

Also populated by `check()` before it returns, and worth persisting if the schema
has room: `$record->backupEligible` (`:82`), `$record->backupStatus` (`:83`),
`$record->uvInitialized` (`:84`), `$record->aaguid`, `$record->attestationType`.

**`transports` is frequently `[]`.** It comes straight from the browser's
`getTransports()`, which not every authenticator populates. Treat an empty array
as "unknown", not as an error.

---

## 4. Validating an assertion (login) response

```php
public function check(
    CredentialRecord $credentialRecord,
    AuthenticatorAssertionResponse $authenticatorAssertionResponse,
    PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
    string $host,
    ?string $userHandle,
): CredentialRecord
```
`src/AuthenticatorAssertionResponseValidator.php:43-49`.

**The stored credential is supplied as argument 1, as a rehydrated
`CredentialRecord`.** There is no repository interface to implement in this
version — you look the credential up yourself (by `rawId` from the response) and
hand the object in.

Two ways to rehydrate it, in preference order for this library:

1. **Store the whole record as JSON** and let the serializer do it:
   ```php
   $json   = $serializer->serialize($record, 'json');                          // on registration
   $record = $serializer->deserialize($json, CredentialRecord::class, 'json'); // on login
   ```
   `src/Denormalizer/CredentialRecordDenormalizer.php:81` (normalize) and `:33`
   (denormalize). Verified to round-trip credential id, public key and transports
   byte-for-byte. This is the only route that does not require you to reconstruct
   `TrustPath` and `Uuid` by hand.
2. **Rebuild from individual columns** with `CredentialRecord::create(...)`.
   For an attestation-`none` passkey the two awkward arguments are:
   `Webauthn\TrustPath\EmptyTrustPath::create()` (`src/TrustPath/EmptyTrustPath.php:9`)
   and `Symfony\Component\Uid\Uuid::fromString($aaguidString)`. A zero AAGUID is
   `'00000000-0000-0000-0000-000000000000'`. `attestationType` is
   `AttestationStatement::TYPE_NONE` = `'none'` (`src/AttestationStatement/AttestationStatement.php:14`).

   Whichever you choose, be consistent: option 2 is fine for the fixed passkey
   columns Task 1 created, and it keeps the DB readable, but it silently drops
   `backupEligible` / `backupStatus` / `uvInitialized` unless you add columns.

**`$userHandle` (argument 5) semantics** — `src/CeremonyStep/CheckUserHandle.php:36-50`:

- Pass the **raw binary** user handle when the user was already identified before
  the ceremony (e.g. a username-first login). The stored record's handle must
  `hash_equals()` it, and if the authenticator also returned one, that must match too.
- Pass `null` for a discoverable-credential login. Then the response **must**
  carry a non-empty `userHandle` and it must match the stored record's, otherwise
  `Webauthn\Exception\InvalidUserHandleException` is thrown.

### `check()` MUTATES the record — you must persist it

On success it writes back onto the object you passed in, before returning it
(`src/AuthenticatorAssertionResponseValidator.php:80-85`):

```php
$credentialRecord->counter        = $authenticatorAssertionResponse->authenticatorData->signCount;
$credentialRecord->backupEligible = ...->isBackupEligible();
$credentialRecord->backupStatus   = ...->isBackedUp();
if ($credentialRecord->uvInitialized === false) { $credentialRecord->uvInitialized = ...->isUserVerified(); }
```

The returned object is the same instance. **Save `$record->counter` back to the
database after every successful login**, or the replay check below is inert.

### Sign-count / replay check — and why a `signCount` of 0 is fine

`CheckCounter` (`src/CeremonyStep/CheckCounter.php:16`) does this
(`:38-44`):

```php
$storedCounter = $credentialRecord->counter;
$responseCounter = $authData->signCount;
if ($responseCounter !== 0 || $storedCounter !== 0) {
    $this->counterChecker->check($credentialRecord, $responseCounter);
}
$credentialRecord->counter = $responseCounter;
```

The default checker is `Counter\ThrowExceptionIfInvalid`
(`src/Counter/ThrowExceptionIfInvalid.php:15`, wired at
`src/CeremonyStep/CeremonyStepManagerFactory.php:51`); it requires
`$currentCounter > $credentialRecord->counter` (`:39`) and throws
`Webauthn\Exception\CounterException` otherwise.

So: **many passkeys always report `signCount = 0`, and that is handled** — with a
stored counter of `0` and a response counter of `0` the guard at `:41` is false
and the checker is skipped entirely. The strict comparison only applies once a
credential has ever reported a non-zero count, which is exactly the desired
behaviour. Do not "fix" this by relaxing the checker. If you do need a different
policy, implement `Counter\CounterChecker`
(`src/Counter/CounterChecker.php:11`: `check(CredentialRecord $credentialRecord, int $currentCounter): void`)
and pass it to `CeremonyStepManagerFactory::setCounterChecker()` (`:59`).

---

## 5. Raw binary vs already-encoded — the part that will bite

**Rule: every PHP-side value in this library is RAW BINARY. Base64url exists only
at the JSON boundary, and the serializer does that conversion for you.**

Since our schema stores base64url TEXT, that means: **encode on the way into the
database, decode on the way out**, and never hand a base64 string to a library
constructor.

### Raw binary (`string` of bytes) in PHP

| Value | Source |
| --- | --- |
| `PublicKeyCredentialOptions::$challenge` | `src/PublicKeyCredentialOptions.php:33` |
| `PublicKeyCredentialUserEntity::$id` (user handle) — **max 64 bytes**, throws `InvalidDataException` above that | `src/PublicKeyCredentialUserEntity.php:12,21` |
| `PublicKeyCredentialDescriptor::$id` | `src/PublicKeyCredentialDescriptor.php:43` |
| `PublicKeyCredential::$rawId` | `src/Credential.php:14`, decoded at `src/Denormalizer/PublicKeyCredentialDenormalizer.php:31` |
| `CredentialRecord::$publicKeyCredentialId`, `$credentialPublicKey`, `$userHandle` | `src/CredentialRecord.php:23,29,30`; decoded at `src/Denormalizer/CredentialRecordDenormalizer.php:36-40` |
| `AuthenticatorAssertionResponse::$signature`, `$userHandle` | `src/AuthenticatorAssertionResponse.php:17,18`; decoded at `src/Denormalizer/AuthenticatorAssertionResponseDenormalizer.php:28-34` |
| `AuthenticatorData::$authData`, `$rpIdHash`, `$flags` | `src/AuthenticatorData.php:33-35` |
| `AttestationObject::$rawAttestationObject` | `src/AttestationStatement/AttestationObject.php:15` |
| `CollectedClientData::$challenge` (decoded for you) and `$rawData` | `src/CollectedClientData.php:51,36` |

`$credentialPublicKey` is a **CBOR-encoded COSE key**, not PEM and not DER. Store
the bytes; do not try to parse or re-encode them.

### Already-encoded (base64url, unpadded) — only inside JSON

Produced by `Base64UrlSafe::encodeUnpadded()` at exactly these points:

| JSON field | Source |
| --- | --- |
| `challenge` (both options types) | `src/Denormalizer/PublicKeyCredentialOptionsDenormalizer.php:176` |
| `user.id` | `src/Denormalizer/PublicKeyCredentialUserEntityDenormalizer.php:58` |
| `allowCredentials[].id`, `excludeCredentials[].id` | `src/Denormalizer/PublicKeyCredentialDescriptorNormalizer.php:27` |
| `publicKeyCredentialId`, `credentialPublicKey`, `userHandle` of a serialized `CredentialRecord` | `src/Denormalizer/CredentialRecordDenormalizer.php:85,91,92` |

### Not binary at all

`transports` (`string[]`), `counter` (`int`), `timeout` (`int`, milliseconds),
`type` / `attestationType` / `userVerification` / `residentKey` / `attestation`
(plain strings), `aaguid` (a `Symfony\Component\Uid\Uuid` object in PHP,
serialised as the dashed string `00000000-0000-0000-0000-000000000000`).

### Decoding tolerance

Inbound decoding is deliberately lenient: `Webauthn\Util\Base64::decode()`
(`src/Util/Base64.php:13-25`) tries URL-safe base64 first, then standard base64,
and throws `InvalidDataException` only if both fail. So the library accepts either
alphabet from a client. It always **emits** unpadded base64url. Our own
persistence should emit base64url too so the two never diverge — use
`ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded()` /
`::decodeNoPadding()` (the `paragonie/constant_time_encoding` package is a
transitive dependency, so it is already installed).

A few call sites use the **strict** `Base64UrlSafe::decodeNoPadding()` rather than
the tolerant helper — notably `clientDataJSON` and the options `challenge`
(`src/Denormalizer/AuthenticatorAttestationResponseDenormalizer.php:27`,
`src/Denormalizer/PublicKeyCredentialOptionsDenormalizer.php:40`). Padded base64
in those fields will throw.

---

## 6. Does it need a PSR-3 logger, a PSR-20 clock, or a serializer?

Short answers, because this matters for a library with no DI container:

**PSR-3 logger — NO, not required.** Both validators default to
`Psr\Log\NullLogger` in their constructors
(`src/AuthenticatorAttestationResponseValidator.php:31`,
`src/AuthenticatorAssertionResponseValidator.php:32`). `psr/log` is a hard
dependency of the package so `NullLogger` is always present; you never have to
supply one. If you want logs, `setLogger(LoggerInterface $logger): void` exists on
both (`:39` and `:145` respectively).

**PSR-14 event dispatcher — NO.** Same pattern: both default to
`Webauthn\Event\NullEventDispatcher` (`:30` / `:31`), a concrete no-op class that
**ships with this library** (`src/Event/NullEventDispatcher.php`).
`setEventDispatcher()` at `:44` / `:150` if you ever want them.

**PSR-20 clock — NO, not on our path.** A clock is referenced in exactly two
places, both optional and both defaulting themselves:
`AttestationStatement\TPMAttestationStatementSupport::__construct(null|ClockInterface $clock = null)`
(`src/AttestationStatement/TPMAttestationStatementSupport.php:51`, defaults to
`new Symfony\Component\Clock\NativeClock()` at `:53`) and
`MetadataService\CertificateChain\PhpCertificateChainValidator`
(`src/MetadataService/CertificateChain/PhpCertificateChainValidator.php:42,45`,
same default). We register neither TPM attestation nor a certificate-chain
validator, so no clock is ever constructed. **If a future task does need one, the
concrete class to pass is `Symfony\Component\Clock\NativeClock`** from
`symfony/clock`, which is already a hard dependency.

**Serializer — YES, this one is genuinely required, and you must build it.**
There is no default. Construct it with the concrete factory that ships with the
library:

```php
$serializer = (new Webauthn\Denormalizer\WebauthnSerializerFactory(
    Webauthn\AttestationStatement\AttestationStatementSupportManager::create()
))->create();   // returns Symfony\Component\Serializer\SerializerInterface
```

`src/Denormalizer/WebauthnSerializerFactory.php:29` (constructor takes the
attestation support manager), `:34` (`create(): SerializerInterface`). It wires 27
denormalizers plus a `JsonEncoder` at `:46-81`. It checks that
`symfony/serializer`, `symfony/property-info` and
`phpdocumentor/reflection-docblock` are present and throws a plain
`RuntimeException` naming the missing package if not (`:36-44`) — all three are
hard dependencies of `web-auth/webauthn-lib`, so this only fires if someone prunes
the tree.

**Build it once and reuse it.** It is stateless with respect to a ceremony;
constructing it per request means re-instantiating 27 normalizers and a
reflection-based property extractor.

**Practical summary: the only collaborator you must create is the serializer.
Everything else has a concrete no-op or sane default that ships in the box, so a
two-class library with no container is a perfectly comfortable fit.**

---

## 7. Deprecations to stay clear of in new code

- `Webauthn\PublicKeyCredentialSource` is `@deprecated since 5.3, use CredentialRecord instead. Will be removed in 6.0.`
  (`src/PublicKeyCredentialSource.php:10`). It is now just an empty subclass of
  `CredentialRecord`. Passing one to `check()` triggers a deprecation
  (`src/AuthenticatorAssertionResponseValidator.php:50-57`). **Use `CredentialRecord` everywhere.**
- `CheckOrigin` — deprecated, see §0; call `setAllowedOrigins()`.
- `CeremonyStepManagerFactory::setSecuredRelyingPartyId()` — deprecated at
  `src/CeremonyStep/CeremonyStepManagerFactory.php:65`.
- `PublicKeyCredentialRpEntity::$name` and `PublicKeyCredentialEntity::$icon` —
  deprecated, see §1.
- `PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_CABLE` — deprecated in
  favour of `..._BLE` (`src/PublicKeyCredentialDescriptor.php:18`). Note the
  library does **not** validate transports against its own list, so whatever the
  browser sends is stored as-is.

---

## Verified end to end

Executed on 2026-09-14 against this exact vendor tree, on `php:8.4-cli`
(PHP 8.4.24), throwaway script, not committed. It exercised: building and
JSON-serialising both options types; deserialising both back and confirming the
raw challenge, `rp.id` and raw user id survive; `CredentialRecord` JSON
round-trip with byte-identical credential id, public key and transports; and
constructing both validators from `CeremonyStepManagerFactory` with no logger,
clock, dispatcher or container. All assertions printed `YES`; the script ended
`SMOKE OK`.

**Not verified, and honestly flagged:** `check()` on either validator was not
run against a real authenticator response, because that needs a real or virtual
authenticator. The `check()` signatures, the mutation behaviour and the field
locations above are read directly from the source cited, but the ceremonies
themselves are first exercised by the tasks that implement them.
