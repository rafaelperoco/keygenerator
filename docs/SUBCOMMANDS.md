# Subcommand reference

secretgenerator exposes six subcommands. Each has its own flag set and entropy
floor; all share the same output schema and audit-log format.

| Subcommand   | Default            | Floor (bits) | Recommended use                            |
| ------------ | ------------------ | ------------ | ------------------------------------------ |
| `password`   | 20 char alphanum   | 80           | Generic password from a printable charset  |
| `passphrase` | 8 EFF words        | 80           | Memorable secrets, master passwords        |
| `secret`     | 32 bytes base64url | 128          | Machine-to-machine credentials, API tokens |
| `api-key`    | sk\_<32 base62>    | 128          | SaaS-style API keys (Stripe, GitHub, etc.) |
| `pin`        | 6 digits           | 0 (gated)    | Numeric PINs for rate-limited verifiers    |
| `entropy`    | n/a                | n/a          | Estimate the entropy of an existing secret |

## Common flags

All generation subcommands share these flags via `addCommonFlags`:

| Flag                           | Purpose                                                                                            |
| ------------------------------ | -------------------------------------------------------------------------------------------------- |
| `--json`                       | Emit a structured schema-v1 JSON record on stdout.                                                 |
| `--audit-log <path>`           | Append a redacted JSONL audit record to `<path>` (mode 0600).                                      |
| `--stdin-params`               | Read flags as a JSON object from stdin instead of argv. Avoids leaking sensitive flags to `ps(1)`. |
| `--require-schema-version <n>` | Fail with exit code 2 unless the binary's output schema matches `<n>`.                             |
| `--show-crack-time`            | Include `crack_time_estimates` in the JSON output and a human-readable summary in plain mode.      |
| `--help-json`                  | Emit a machine-readable JSON description of the command and its flags, then exit. Persistent on the root, available on every subcommand. Output mirrors the OpenAPI parameter shape so agents already familiar with OpenAPI can introspect without learning a new schema. |

## Exit codes

| Code | Meaning                                                                                                                |
| ---- | ---------------------------------------------------------------------------------------------------------------------- |
| 0    | Success                                                                                                                |
| 2    | Invalid arguments, unknown charset, schema-version mismatch, audit-log write failure                                   |
| 3    | Computed entropy is below the floor and `--allow-weak` was not set                                                     |
| 4    | RNG / entropy-source failure                                                                                           |
| 5    | `--exclude` left the charset with fewer than 2 runes                                                                   |
| 6    | Required classes cannot be satisfied (charset lacks a class, or length is shorter than the number of distinct classes) |

## password

```
secretgenerator password [flags]
secretgenerator [flags]    # bare invocation is shorthand for `password`
```

Generates a random password from a named charset.

| Flag                 | Default       | Notes                                                                                                                                             |
| -------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-n, --length`       | 20            | Length of the password in characters.                                                                                                             |
| `-c, --charset`      | `alphanum-v1` | One of the named charsets (see `secretgenerator -h` for the full list).                                                                              |
| `-e, --exclude`      | (none)        | Runes to remove from the charset _before_ generation. v1 had a bug where exclusion happened post-generation, shrinking the output; v2 fixes this. |
| `--require-classes`  | (none)        | Comma-separated `lower,upper,digit,symbol`. Generation uses rejection sampling until all required classes are present.                            |
| `--min-entropy-bits` | 80            | Floor the computed entropy must clear. Set to 0 to disable.                                                                                       |
| `--allow-weak`       | false         | Bypass the floor with a warning emitted to `warnings`.                                                                                            |

### Examples

```sh
# Default 20-char alphanumeric.
secretgenerator

# 32 chars with all four classes guaranteed, machine-readable.
secretgenerator --json -n 32 -c alphanum-symbols-v1 \
  --require-classes lower,upper,digit,symbol

# 16 chars excluding visually confusable characters.
secretgenerator -n 16 -e '0Ol1iI'

# Read flags from stdin, audit to a file.
echo '{"length":40,"charset_id":"alphanum-v1"}' | \
  secretgenerator --stdin-params --json --audit-log /var/log/keygen.jsonl
```

## passphrase

```
secretgenerator passphrase [flags]
```

Generates a diceware passphrase from the EFF Large Wordlist (7776 words,
~12.92 bits/word).

| Flag                 | Default | Notes                                                                                                                                                                 |
| -------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-w, --words`        | 8       | 6=EFF minimum (~78 bits), 8=secure-through-2050 (~103 bits), 10=wallet-grade (~129 bits).                                                                             |
| `--separator`        | `-`     | Joins consecutive words. Hyphen is shell/URL/env-file safe. Empty separator is rejected.                                                                              |
| `--capitalize`       | false   | Compatibility flag for sites that mandate uppercase. **Emits a warning**: predictable Title-Case is in every Hashcat ruleset and adds ~0 bits against real attackers. |
| `--digit-suffix`     | false   | Compatibility flag for sites that mandate a digit. **Emits a warning**: appended digits are the #1 attacked transformation.                                           |
| `--min-entropy-bits` | 80      |                                                                                                                                                                       |
| `--allow-weak`       | false   |                                                                                                                                                                       |

### Examples

```sh
# Default 8 words.
secretgenerator passphrase

# Wallet-grade 10 words.
secretgenerator passphrase -w 10 --json --show-crack-time

# Compatibility for a legacy site requiring upper + digit.
secretgenerator passphrase --capitalize --digit-suffix
```

## secret

```
secretgenerator secret [flags]
```

Generates raw random bytes encoded as a printable string. **Recommended for
machine-to-machine use** when there is no human memorization burden.

| Flag                 | Default     | Notes                                                                             |
| -------------------- | ----------- | --------------------------------------------------------------------------------- |
| `-b, --bytes`        | 32          | Number of random bytes (32 → 256 bits of entropy).                                |
| `-E, --encoding`     | `base64url` | One of: `base64url`, `base64`, `base32`, `hex`. base64url is URL/header/env-safe. |
| `--prefix`           | (none)      | Static prefix prepended to the encoded body. Does not contribute to entropy.      |
| `--min-entropy-bits` | 128         | Default 128 follows the NIST SP 800-131A 2030 target.                             |
| `--allow-weak`       | false       |                                                                                   |

### Examples

```sh
# Default 32 bytes → 43 char base64url.
secretgenerator secret

# 64-byte (512-bit) hex secret with a Stripe-style prefix.
secretgenerator secret -b 64 -E hex --prefix "sk_live_"

# JSON for piping to a secret manager.
secretgenerator secret --json | jq -r .password | aws secretsmanager put-secret-value ...
```

## api-key

```
secretgenerator api-key [flags]
```

Generates a token in the `<prefix><separator><base62-body>` form used by
Stripe (`sk_live_…`), GitHub (`ghp_…`), Slack (`xoxb-…`), Anthropic
(`sk-ant-…`), and most modern SaaS APIs.

| Flag                 | Default | Notes                                                     |
| -------------------- | ------- | --------------------------------------------------------- |
| `--prefix`           | `sk`    | Static identifier. Whitespace is rejected.                |
| `--separator`        | `_`     | Between prefix and body.                                  |
| `-n, --length`       | 32      | Length of the base62 body in characters (32 → ~190 bits). |
| `--min-entropy-bits` | 128     |                                                           |
| `--allow-weak`       | false   |                                                           |

### Examples

```sh
secretgenerator api-key                                     # sk_<32 base62>
secretgenerator api-key --prefix ghp                        # ghp_<32 base62>
secretgenerator api-key --prefix sk-ant --separator '-' -n 40
```

## pin

```
secretgenerator pin --acknowledge-low-entropy [flags]
```

Generates a numeric PIN of `--digits` length, rejecting candidates that
match known weak patterns: all-same-digit, strict ascending/descending
sequences, short repetitions, the top-20 DataGenetics 2012 most-common
PINs, and calendar years.

PINs are intrinsically low-entropy (a 6-digit PIN is ~19.9 bits). The
`--acknowledge-low-entropy` flag is **required** to even emit one — this is
deliberate friction. PINs are appropriate only when the verifying system
enforces strict rate limits (banks, hardware tokens). They should never be
used as standalone authenticators.

| Flag                        | Default | Notes                                                |
| --------------------------- | ------- | ---------------------------------------------------- |
| `-n, --digits`              | 6       | Must be ≥ 4.                                         |
| `--acknowledge-low-entropy` | false   | **Required.** No default-on.                         |
| `--allow-weak-pattern`      | false   | Permit PINs matching weak patterns. NOT RECOMMENDED. |

### Example

```sh
secretgenerator pin --acknowledge-low-entropy --digits 6 --json
```

## entropy

```
secretgenerator entropy [password] [flags]
secretgenerator entropy < password.txt
```

Estimates the entropy of an _existing_ password. Output is the Shannon
entropy in bits, assuming each character was drawn uniformly from the
observed character classes — an upper bound. Real entropy is lower if the
password follows a memorable pattern.

Read the password from one of:

- The first positional argument (visible in `ps(1)` — not recommended).
- Stdin (preferred): `secretgenerator entropy < password.txt`.
- `--stdin-params`: `echo '{"password":"..."}' | secretgenerator entropy --stdin-params --json`.

In plain mode, the password is never echoed; only the entropy in bits is
printed. In `--json` mode, the password field is omitted from the schema.

| Flag                       | Default | Notes                            |
| -------------------------- | ------- | -------------------------------- |
| `--json`                   | false   |                                  |
| `--stdin-params`           | false   |                                  |
| `--require-schema-version` | 0       |                                  |
| `--show-crack-time`        | false   | Include time-to-break estimates. |

### Example

```sh
$ echo -n 'correcthorsebatterystaple' | secretgenerator entropy
117.51 bits

$ secretgenerator entropy 'Tr0ub4dor&3' --show-crack-time
72.10 bits
entropy: 72.10 bits
time to crack (average case):
  online-throttled-v1            8.4e+09 millennia
  ...
```
