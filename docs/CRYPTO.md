# Cryptographic basis of secretgenerator

This document explains the cryptographic primitives secretgenerator depends on,
the entropy guarantees it inherits from each operating system, and the
compliance mapping for downstream auditors.

## Entropy source

All randomness comes from Go's `crypto/rand.Reader`. This is a thin wrapper
around the operating system's CSPRNG; **secretgenerator never implements its
own entropy source**.

| OS                                  | Backend                                                  | Notes                                                                                                                            |
| ----------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Linux ≥ 3.17                        | `getrandom(2)` syscall                                   | Blocks until kernel pool is initialized at boot. Compliant with [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final). |
| Linux < 3.17                        | `/dev/urandom`                                           | Same kernel pool, but Go falls back to direct device access.                                                                     |
| macOS, iOS                          | `arc4random_buf`                                         | ChaCha20-based CSPRNG, reseeded automatically.                                                                                   |
| FreeBSD, OpenBSD, NetBSD, Dragonfly | `arc4random_buf`                                         | Same primitive as macOS.                                                                                                         |
| Windows                             | `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` | NIST SP 800-90A DRBG validated under FIPS 140.                                                                                   |
| Solaris, Illumos                    | `getrandom(2)`                                           | Equivalent to Linux.                                                                                                             |
| Plan 9                              | `/dev/random`                                            | Best-effort.                                                                                                                     |

If you are auditing a deployment target, verify the underlying OS provides
real entropy. Embedded targets, virtualization with bad host configuration,
and freshly-booted systems can all starve the entropy pool. secretgenerator
will faithfully reflect whatever bytes the OS provides — including bad ones.

## Uniform sampling

`crypto/rand.Int(reader, max)` returns a uniformly distributed integer in
`[0, max)`. The implementation uses rejection sampling internally to
eliminate modulo bias, so the resulting distribution is exactly uniform
regardless of the relationship between `max` and the underlying byte
boundaries.

The `internal/generator` package uses `rand.Int` for every character pick.
The chi-squared test in `internal/generator/stats_test.go` (1M samples per
charset) verifies uniformity at p > 0.001 across all 10 named charsets.

## Class-requirement enforcement

When `--require-classes` is set, generation uses **rejection sampling at the
candidate level**: a full candidate is generated, classes are checked, and
the entire candidate is discarded if any required class is absent. This
preserves uniformity within the accepted-candidate space, at the cost of
slightly more entropy reads. The retry cap is 100; for any realistic
combination of `length` and required classes (e.g. 12 chars from 93-rune
alphanum-symbols-v1 requiring all 4 classes), the per-attempt acceptance
probability is ~0.84, so 100 retries gives a vanishingly small chance of
spurious failure.

## Audit-log fingerprints

When `--audit-log` is set, the log file gets:

- The SHA-256 hex digest of the generated credential (so the credential
  can be correlated to a specific log entry without ever storing plaintext).
- The SHA-256 hex digest of the `--exclude` argument (same purpose, allows
  audit comparison without echoing the excluded set).
- All other generation parameters (length, charset_id, entropy_bits, etc.).
- A version-4 UUID `request_id` shared with the stdout JSON output for
  cross-referencing.

The log file is opened with `O_APPEND|O_CREATE|O_WRONLY` and mode `0600`.
Existing content is never truncated.

## Memory hygiene

After generating a `[]byte` payload (e.g. raw bytes for `secret`),
secretgenerator zeroizes the slice before returning. **This is best-effort.**
Go's runtime is free to copy values during execution (escape analysis,
stack-to-heap promotion, garbage collection); we cannot reach those copies.

Callers with hard memory-residency requirements (e.g. wallet seed
generation) should run secretgenerator in a memory-restricted environment
(separate process, swap disabled, page-locked memory) and pipe the output
directly into the consumer. The CLI's `--stdin-params` flag exists
specifically to avoid leaking arguments through `/proc/<pid>/cmdline`.

## UUIDs

`request_id` values are RFC 4122 version-4 UUIDs constructed in
`internal/audit/uuid.go`:

1. Read 16 bytes from `crypto/rand`.
2. Set bits 6 and 7 of byte 6 to encode version = 4.
3. Set bits 6 and 7 of byte 8 to encode RFC 4122 variant.
4. Format as canonical 8-4-4-4-12 hex.

Errors from the entropy source abort UUID generation (and the surrounding
operation); we never return a partially-random UUID.

## Compliance mapping

| Subcommand                    | Default entropy | NIST SP 800-63B-4 alignment                                | NIST SP 800-131A alignment     | OWASP ASVS V2.1                            |
| ----------------------------- | --------------- | ---------------------------------------------------------- | ------------------------------ | ------------------------------------------ |
| `password` (20 char alphanum) | 119 bits        | Exceeds 15-char single-factor minimum                      | Exceeds 112-bit floor          | V2.1.1, V2.1.7                             |
| `passphrase` (8 EFF words)    | 103 bits        | Exceeds memorized-secret recommendations                   | Exceeds 112-bit floor [margin] | V2.1.1                                     |
| `secret` (32 bytes)           | 256 bits        | Exceeds all secret-class guidance                          | Exceeds 2030 128-bit target    | V2.7 (machine-readable secrets)            |
| `api-key` (32 base62)         | 190 bits        | Exceeds all guidance                                       | Exceeds 2030 128-bit target    | V2.7, V13.4                                |
| `pin` (6 digits)              | 19.9 bits       | **Below all floors**; safe only with rate-limited verifier | Below 112-bit floor            | Requires V11.1 (rate limiting) on verifier |
| `entropy`                     | n/a             | Reports observed entropy of input                          | n/a                            | n/a                                        |

The `pin` row is intentional: PINs are never appropriate as standalone
authenticators. secretgenerator requires `--acknowledge-low-entropy` to even
emit one, and the JSON output carries a warning. The compliance value of
this subcommand is that it generates _uniform_ PINs, rejecting weak
patterns (top-20 DataGenetics 2012 list, sequences, repetitions, calendar
years), unlike user-chosen PINs which are heavily biased toward `0000`,
`1234`, and birth years.

## What secretgenerator does not provide

- **Key derivation.** Use Argon2id, scrypt, or PBKDF2-HMAC-SHA-256 (in that
  preference order) for password verification. secretgenerator generates raw
  credentials; deriving keys for actual cryptographic operations is the
  consumer's responsibility.
- **Constant-time comparison.** Use `crypto/subtle.ConstantTimeCompare` to
  validate user-supplied credentials against a stored hash.
- **Encryption.** Use `crypto/aes` with `crypto/cipher.NewGCM` for symmetric
  encryption; `crypto/ed25519` for asymmetric signing; `crypto/ecdh` for
  key exchange. secretgenerator's outputs are suitable as inputs to those
  primitives but are not themselves encrypted.

## References

- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) — Memorized Secret Verifiers (finalized 2025)
- [NIST SP 800-131A Rev. 3](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd) — Cryptographic Strength Transitions (2024 draft, 128-bit by 2030)
- [NIST SP 800-90A](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final) — Recommendation for Random Number Generation Using Deterministic Random Bit Generators
- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final) — Recommendation for the Entropy Sources Used for Random Bit Generation
- [OWASP ASVS V2](https://owasp.org/www-project-application-security-verification-standard/) — Authentication
- [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122) — UUID
- [EFF Large Wordlist](https://www.eff.org/dice) — 7776 words for passphrases (CC-BY-3.0)
