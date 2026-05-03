# Output schema

secretgenerator emits a stable, versioned JSON document on stdout when invoked
with `--json`. The same structure (with the password redacted to a SHA-256
fingerprint) is appended to `--audit-log` files.

The canonical machine-readable schema is published at
[`schemas/output-v1.json`](../schemas/output-v1.json) (JSON Schema 2020-12).
This document is the human-readable companion.

## Stability promise

| Change kind                                  | Allowed within v1?                |
| -------------------------------------------- | --------------------------------- |
| Add a new optional property                  | Yes                               |
| Add a new value to an `enum`                 | Yes                               |
| Rename or remove an existing property        | No — requires schema-version bump |
| Change a property's type or required-ness    | No — requires schema-version bump |
| Reinterpret an existing property's semantics | No — requires schema-version bump |

Consumers that want strict pinning can pass `--require-schema-version=1`,
which makes secretgenerator exit with code 2 if it ever emits a different
schema version.

## Fields

### Required (always present)

| Field            | Type    | Description                                                                                                                                                      |
| ---------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version` | integer | Currently `1`. Const-pinned; bumps require a major version.                                                                                                      |
| `length`         | integer | Length of the credential. For `passphrase`, this is the word count.                                                                                              |
| `charset_id`     | string  | Identifier of the source charset or wordlist. Versioned (`alphanum-v1`, `eff-large-v1`, etc.). When `--exclude` was applied, the suffix `+excluded` is appended. |
| `charset_size`   | integer | Cardinality of the (possibly-excluded) charset.                                                                                                                  |
| `entropy_bits`   | number  | Shannon entropy in bits, computed as `length * log2(charset_size)`.                                                                                              |
| `algorithm`      | string  | Identifier for the generation algorithm (e.g. `crypto/rand+rejection-sampling`, `diceware/eff-large-v1`).                                                        |
| `subcommand`     | enum    | One of: `password`, `passphrase`, `secret`, `api-key`, `pin`, `entropy`.                                                                                         |
| `version`        | string  | Build identity: semantic version (e.g. `v2.0.0`). `dev` for unstamped local builds.                                                                              |
| `commit`         | string  | Build identity: git commit SHA. `none` for unstamped builds.                                                                                                     |
| `build_date`     | string  | Build identity: ISO-8601 UTC timestamp from CI.                                                                                                                  |
| `request_id`     | string  | RFC 4122 version-4 UUID. Allows correlation across stdout and audit log.                                                                                         |
| `timestamp_utc`  | string  | RFC 3339 UTC timestamp of generation, nanosecond precision.                                                                                                      |

### Optional (omitted when zero/empty)

| Field                  | Type    | Description                                                                                                                                 |
| ---------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `password`             | string  | The generated credential. Always present in `--json` output for generation subcommands; omitted for `entropy` (which consumes a password).  |
| `excluded_count`       | integer | Number of distinct runes the caller passed to `--exclude`.                                                                                  |
| `excluded_sha256`      | string  | Hex-encoded SHA-256 of the `--exclude` argument. Lets audit logs correlate exclusion sets without echoing them.                             |
| `required_classes`     | string  | Comma-separated list of character classes the output is guaranteed to contain (or, for `entropy`, observed in the input).                   |
| `warnings`             | array   | Strings describing non-fatal advisories (e.g. when `--allow-weak` bypassed the floor or when a compatibility flag was used).                |
| `crack_time_estimates` | array   | Opt-in (set with `--show-crack-time`). Time-to-break estimates under named attacker profiles.                                               |
| `error`                | object  | Present only on the failure path. Carries a stable `code` (e.g. `E_ENTROPY_TOO_LOW`), an English `message`, and an optional curated `hint`. |

### Audit log additions

The redacted log entry includes one extra field beyond the stdout output:

| Field             | Type   | Description                                      |
| ----------------- | ------ | ------------------------------------------------ |
| `password_sha256` | string | Hex-encoded SHA-256 of the generated credential. |

And omits:

| Field      | Reason                                                                     |
| ---------- | -------------------------------------------------------------------------- |
| `password` | Plaintext is never written to the log. Use `password_sha256` to correlate. |

## crack_time_estimates

When `--show-crack-time` is set, the output includes time-to-break projections
under five named attacker profiles. Each estimate has the shape:

```json
{
  "profile_id": "bcrypt-cost12-v1",
  "description": "Offline attack against bcrypt cost=12 on a single RTX 4090 (Specops 2024, ~50k guesses/sec)",
  "seconds": 3.13e26,
  "human_readable": "7.2e+08 times the age of the universe"
}
```

Profile IDs are versioned (`-v1`); changing the underlying guess rate
requires bumping the suffix. The five profiles span 13 orders of magnitude:

| Profile ID                | Guesses/sec | Real-world analog                 |
| ------------------------- | ----------- | --------------------------------- |
| `online-throttled-v1`     | 100         | Login API with rate limiting      |
| `slow-kdf-v1`             | 1,000       | Argon2id at OWASP 2024 settings   |
| `bcrypt-cost12-v1`        | 50,000      | Single RTX 4090, bcrypt cost-12   |
| `fast-hash-single-gpu-v1` | 1e11        | Single RTX 4090, unsalted SHA-256 |
| `nation-state-v1`         | 1e15        | 10,000 RTX 4090s, fast hash       |

These are estimates. Real-world cracking depends on the specific KDF, the
size of the search space the attacker actually explores (dictionaries vs.
brute force), and hardware availability.

## error (failure path)

When `--json` is set and the requested generation cannot be produced, the
CLI writes a schema-v1 envelope with a populated `error` object to stdout
and exits with the matching integer code. Stderr is silent in JSON mode so
agents see exactly one machine-readable artifact.

Codes are stable strings; agents should branch on these rather than parse
the message or rely on integer exit codes:

| code                 | exit | meaning                                                                                          |
| -------------------- | ---: | ------------------------------------------------------------------------------------------------ |
| `E_INVALID_ARGS`     |    2 | Unknown flag, unknown charset, schema-version mismatch, audit-log write failure, malformed stdin |
| `E_ENTROPY_TOO_LOW`  |    3 | Computed entropy is below `--min-entropy-bits` and `--allow-weak` was not set                    |
| `E_RNG_FAILURE`      |    4 | OS entropy source returned an error mid-generation                                               |
| `E_CHARSET_EMPTY`    |    5 | `--exclude` reduced the charset below the minimum 2 runes                                        |
| `E_CLASS_IMPOSSIBLE` |    6 | `--require-classes` cannot be satisfied (charset lacks the class, or length < class count)       |

Each code has a curated one-line `hint` documenting the typical fix.
Hints are advisory and may be empty for codes added in future versions.

```json
{
  "schema_version": 1,
  "subcommand": "password",
  "version": "v2.0.0",
  "commit": "abc1234",
  "build_date": "2026-05-02T22:00:00Z",
  "request_id": "8a7f...-...-...",
  "timestamp_utc": "2026-05-02T22:01:33Z",
  "error": {
    "code": "E_ENTROPY_TOO_LOW",
    "message": "policy: entropy below floor: 23.82 bits < floor 80.00",
    "hint": "increase --length, choose a richer --charset, or pass --allow-weak (records a warning)"
  }
}
```

## Example

```sh
$ secretgenerator --json -n 24 --show-crack-time
```

```json
{
  "schema_version": 1,
  "password": "VoJgEDVnCoTVMx8cLnMwmHnz",
  "length": 24,
  "charset_id": "alphanum-v1",
  "charset_size": 62,
  "entropy_bits": 142.90071144928498,
  "algorithm": "crypto/rand+rejection-sampling",
  "subcommand": "password",
  "version": "v2.0.0",
  "commit": "1b43032",
  "build_date": "2026-04-29T22:00:00Z",
  "request_id": "f4c54f9c-0f57-4d58-83be-7937cbe077f7",
  "timestamp_utc": "2026-04-29T22:35:11.077695Z",
  "crack_time_estimates": [
    { "profile_id": "online-throttled-v1", "human_readable": "1.2e+23 times the age of the universe", "seconds": 1e+39, "description": "..." },
    ...
  ]
}
```
