# secretgenerator

Auditable random credential generator for AI agents and machine-readable
pipelines. Replaces ad-hoc password generation with a verifiable contract
backed by the OS CSPRNG.

[![release](https://img.shields.io/github/v/release/rafaelperoco/secretgenerator?sort=semver)](https://github.com/rafaelperoco/secretgenerator/releases)
[![ci](https://github.com/rafaelperoco/secretgenerator/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaelperoco/secretgenerator/actions/workflows/ci.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![cosign](https://img.shields.io/badge/signed-cosign%20keyless-blueviolet)](https://docs.sigstore.dev/cosign/overview/)
[![npm cli](https://img.shields.io/npm/v/@secretgenerator/cli?label=%40secretgenerator%2Fcli)](https://www.npmjs.com/package/@secretgenerator/cli)
[![npm mcp](https://img.shields.io/npm/v/@secretgenerator/mcp?label=%40secretgenerator%2Fmcp)](https://www.npmjs.com/package/@secretgenerator/mcp)

## TL;DR

```sh
# zero-install (no clone, no compile)
npx -y @secretgenerator/cli password --json --show-crack-time

# permanent install
brew install rafaelperoco/tap/secretgenerator

# Model Context Protocol server (Claude / Cursor / Cline)
npx -y @secretgenerator/mcp
```

Output is stable JSON (schema v1):

```json
{
  "schema_version": 1,
  "password": "VoJgEDVnCoTVMx8cLnMwmHnz",
  "entropy_bits": 142.9,
  "charset_id": "alphanum-v1",
  "algorithm": "crypto/rand+rejection-sampling",
  "subcommand": "password",
  "version": "2.0.0",
  "request_id": "f4c54f9c-0f57-4d58-83be-7937cbe077f7",
  "timestamp_utc": "2026-04-29T22:35:11.077695Z",
  "crack_time_estimates": [
    {
      "profile_id": "nation-state-v1",
      "human_readable": "1.2e+10 times the age of the universe"
    }
  ]
}
```

Pin the schema with `--require-schema-version=1`.

> **Why not let an LLM generate the password directly?**
> Recent research ([Irregular Security, 2025](https://www.csoonline.com/article/4155166/llm-generated-passwords-are-indefensible-your-codebase-may-already-prove-it.html))
> shows Claude, GPT, and Gemini produce passwords with ~20 bits of effective
> entropy instead of the ~100 bits the same models claim. Specific
> 16-character sequences recurred 18 times out of 50 attempts. LLMs cannot
> sample uniformly. secretgenerator is the correct primitive: an LLM tool-calls
> it instead of inventing the credential itself.

## Subcommands

| Subcommand   | Use case                                                                                |
| ------------ | --------------------------------------------------------------------------------------- |
| `password`   | Random password from a named charset (default 20 chars, ~119 bits).                     |
| `passphrase` | Diceware passphrase from the EFF Large Wordlist (default 8 words, ~103 bits).           |
| `secret`     | Raw bytes from the OS CSPRNG, encoded as URL-safe base64 (default 32 bytes / 256 bits). |
| `api-key`    | Token in `prefix_random` form (Stripe-style).                                           |
| `pin`        | Numeric PIN with weak-PIN blocklist enforced.                                           |
| `entropy`    | Estimate the entropy and crack time of an existing password.                            |

```sh
secretgenerator password --json --show-crack-time
secretgenerator passphrase --words 10 --separator -
secretgenerator secret --bytes 32
secretgenerator api-key --prefix sk_live --length 40
secretgenerator pin --digits 6 --acknowledge-low-entropy
echo -n 'Tr0ub4dor&3' | secretgenerator entropy --show-crack-time
```

Full flag reference: [docs/SUBCOMMANDS.md](docs/SUBCOMMANDS.md).

## Install

| Method                 | Command                                                                           |
| ---------------------- | --------------------------------------------------------------------------------- |
| **npm (zero-install)** | `npx -y @secretgenerator/cli`                                                     |
| **Homebrew**           | `brew install rafaelperoco/tap/secretgenerator`                                   |
| **MCP server**         | `npx -y @secretgenerator/mcp`                                                     |
| **Container**          | `docker run --rm ghcr.io/rafaelperoco/secretgenerator:v2.0.0`                     |
| **Go install**         | `go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@v2.0.0`   |
| **GitHub Actions**     | `uses: rafaelperoco/secretgenerator/.github/actions/setup-secretgenerator@v2.0.0` |
| **Python (PyPI)**      | `pip install secretgenerator-py` (CLI binary installed separately)                |
| **Rust (crates.io)**   | `cargo add secretgenerator` (CLI binary installed separately)                     |
| **Verified manual**    | See [verified install](#verified-install) below.                                  |

### Verified install

Every release is signed end-to-end. Verify before extracting:

```sh
# 1. Download the artifacts.
curl -LO https://github.com/rafaelperoco/secretgenerator/releases/download/v2.0.0/secretgenerator_2.0.0_linux_amd64.tar.gz
curl -LO https://github.com/rafaelperoco/secretgenerator/releases/download/v2.0.0/checksums.txt
curl -LO https://github.com/rafaelperoco/secretgenerator/releases/download/v2.0.0/checksums.txt.sig
curl -LO https://github.com/rafaelperoco/secretgenerator/releases/download/v2.0.0/checksums.txt.pem

# 2. Verify the cosign signature (Sigstore/Fulcio + GitHub OIDC).
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "https://github.com/rafaelperoco/secretgenerator/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

# 3. Verify the binary checksum.
sha256sum -c checksums.txt --ignore-missing

# 4. Extract and install.
tar -xzf secretgenerator_2.0.0_linux_amd64.tar.gz
sudo mv secretgenerator /usr/local/bin/
```

The container image is also signed:

```sh
cosign verify ghcr.io/rafaelperoco/secretgenerator:v2.0.0 \
  --certificate-identity-regexp "https://github.com/rafaelperoco/secretgenerator/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Full procedure including SLSA provenance verification: [docs/AUDIT.md](docs/AUDIT.md).

## Features

- **Stable JSON contract** (schema v1) with `--json`. Versioned, schema-pinnable, JSON-Schema-validated.
- **Hard entropy floors** aligned with NIST SP 800-63B-4 and NIST SP 800-131A Rev. 3.
- **Class-requirement guarantees** via rejection sampling.
- **Auditable provenance**: SLSA Level 3, cosign keyless signatures, CycloneDX SBOMs.
- **Audit log** with SHA-256 password fingerprints (never plaintext).
- **Time-to-break estimates** under five named attacker profiles.

## Go library

```go
import "github.com/rafaelperoco/secretgenerator/pkg/secretgen"

res, err := secretgen.Password(secretgen.PasswordOptions{
    Length:          24,
    CharsetID:       "alphanum-symbols-v1",
    RequiredClasses: "lower,upper,digit,symbol",
})
if err != nil { /* errors.Is(err, secretgen.ErrBelowEntropyFloor) etc. */ }

fmt.Println(res.Password, "entropy:", res.EntropyBits)

for _, e := range secretgen.EstimateCrackTime(res.EntropyBits) {
    fmt.Println(e.ProfileID, e.HumanReadable)
}
```

API stability is documented in `pkg/secretgen/doc.go`.

## Examples in 6 languages

Ready-to-run snippets for Python, Node.js, Ruby, Rust, Bash, and Go live
under [`examples/`](examples/README.md). All of them produce the same
schema-v1 output and pin `--require-schema-version=1`.

## Documentation

- [docs/SUBCOMMANDS.md](docs/SUBCOMMANDS.md) — Every flag of every subcommand.
- [docs/SCHEMA.md](docs/SCHEMA.md) — Output schema reference.
- [docs/CRYPTO.md](docs/CRYPTO.md) — Entropy source per OS, NIST/OWASP mapping.
- [docs/AUDIT.md](docs/AUDIT.md) — End-to-end release verification.
- [SECURITY.md](SECURITY.md) — Threat model, vulnerability reporting.
- [CHANGELOG.md](CHANGELOG.md) — Release history.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup, required CI gates.

## License

MIT. The embedded EFF Large Wordlist is CC-BY-3.0; see
`internal/words/eff_large_wordlist.txt` and the EFF announcement at
https://www.eff.org/dice.

## Author

Rafael Peroco
