# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Structured error output in `--json` mode. When generation fails, the CLI
  emits a schema-v1 envelope with a populated `error` object containing a
  stable `code` (`E_INVALID_ARGS`, `E_ENTROPY_TOO_LOW`, `E_RNG_FAILURE`,
  `E_CHARSET_EMPTY`, `E_CLASS_IMPOSSIBLE`), an English `message`, and an
  optional curated `hint` with one-line remediation. Stderr stays silent
  in JSON mode so agents see exactly one machine-readable artifact.
  Plain mode (without `--json`) keeps the legacy stderr+exit-code
  behavior unchanged.
- `error` field added to `schemas/output-v1.json` (additive, non-breaking).
- `audit.NewError` and the `Error` struct in `internal/audit` for
  programmatic construction.
- E2E coverage for every error path under `--json`.

## [2.0.0] — 2026-04-29

This is a complete rewrite of secretgenerator into an auditable standard for
random credential generation by AI agents and automated systems. **Not
backwards compatible with v1.**

### Added

- Six subcommands: `password`, `passphrase`, `secret`, `api-key`, `pin`, `entropy`.
  See [docs/SUBCOMMANDS.md](docs/SUBCOMMANDS.md).
- Stable schema-v1 JSON output contract with `--json`. See [docs/SCHEMA.md](docs/SCHEMA.md)
  and [schemas/output-v1.json](schemas/output-v1.json).
- Per-subcommand entropy floors aligned with NIST SP 800-63B-4 and NIST SP
  800-131A Rev. 3:
  - `password`: 80 bits
  - `passphrase`: 80 bits
  - `secret`: 128 bits (NIST 2030 target)
  - `api-key`: 128 bits
  - `pin`: 0 bits (gated behind explicit `--acknowledge-low-entropy`)
- `--require-classes lower,upper,digit,symbol` for guaranteed character class
  composition via rejection sampling.
- `--allow-weak` to bypass entropy floors with an audit-recorded warning.
- `--audit-log <path>` for redacted JSONL logging (mode 0600). Plaintext
  passwords are never written; SHA-256 fingerprints are recorded for
  correlation.
- `--stdin-params` to read flags as JSON from stdin (avoids leaking sensitive
  flags through `ps(1)`).
- `--require-schema-version <n>` to pin the output schema version.
- `--show-crack-time` to include time-to-break estimates under named attacker
  profiles in the JSON output.
- 10 versioned charsets: `lower-v1`, `upper-v1`, `digit-v1`, `symbol-v1`,
  `alpha-v1`, `alphanum-v1`, `alphanum-symbols-v1`, `numeric-v1`, `hex-v1`,
  `base62-v1`. Charset IDs are part of the audit contract.
- `--exclude` now applied **before** generation, so the requested length is
  always honored. (v1 had a bug where exclusion happened post-generation.)
- Embedded EFF Large Wordlist (7776 words, CC-BY-3.0) for `passphrase`,
  with SHA-256 verification at process start.
- DataGenetics 2012 weak-PIN blocklist (top 20) + structural rejection rules
  (sequences, repetitions, calendar years) for `pin`.
- Public Go API at `pkg/keygen` with stability promise.
- Distroless multi-arch container image at `ghcr.io/rafaelperoco/secretgenerator`.
- SLSA Level 3 build provenance.
- Cosign keyless signatures (Sigstore/Fulcio) on all release artifacts.
- CycloneDX/SPDX SBOMs with each release archive.
- Trivy CVE scanning gates in the release pipeline; daily filesystem scans
  upload to the GitHub Security tab.
- Comprehensive test suite:
  - Unit tests at ≥90% aggregate coverage.
  - Chi-squared uniformity tests at N=1M samples per charset (build tag `stats`).
  - Fuzz tests on `--exclude` and `IsWeakPIN` (3M-11M execs in 10s each, no failures).
  - E2E tests against the compiled binary covering all exit codes.
- Documentation: `SECURITY.md`, `docs/CRYPTO.md`, `docs/SCHEMA.md`,
  `docs/SUBCOMMANDS.md`, `docs/AUDIT.md`, `CONTRIBUTING.md`.

### Fixed

- v1 bug where `--exclude` shrank the output length (filter applied
  post-generation): a request for 20 chars excluding all lowercase produced
  fewer than 20 chars. Now exclusion modifies the charset before generation
  and the requested length is exact.
- v1 silent RNG-failure degradation (errors caused `continue`, producing
  shorter passwords). Now any entropy-source failure aborts with exit code 4
  and a descriptive error.

### Removed

- v1 flags `--letters` (`-l`) and `--special` (`-s`). Replaced by `--charset`
  (`-c`) with named, versioned identifiers.
- v1 binary name `pwdgen`. The binary is `secretgenerator`.

### Changed

- Module path: `module main` → `github.com/rafaelperoco/secretgenerator`.
- Minimum Go version: 1.23.
- Build flags: `-trimpath -buildvcs=true` for reproducible builds.

### Migration from v1

| v1                     | v2                                                        |
| ---------------------- | --------------------------------------------------------- |
| `pwdgen`               | `secretgenerator`                                            |
| `pwdgen -l -n 20`      | `secretgenerator -c alphanum-v1 -n 20`                       |
| `pwdgen -s -n 20`      | `secretgenerator -c alphanum-symbols-v1 -n 20`               |
| `pwdgen -e 0Ol1 -n 20` | `secretgenerator -e 0Ol1 -n 20` (now produces exactly 20)    |
| (no equivalent)        | `secretgenerator passphrase` (8-word EFF, ~103 bits)         |
| (no equivalent)        | `secretgenerator secret` (32 bytes base64url, machine-grade) |

The v1.x branch is end of life. No further releases.

## [1.0.0] — 2024-XX-XX

Original implementation. End of life with the v2.0.0 release. Use v2.x.
