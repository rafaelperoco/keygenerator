# keygenerator

Auditable random credential generator for AI agents and machine-readable
pipelines. Replaces ad-hoc password generation with a verifiable contract
backed by the OS CSPRNG.

> **Why not let an LLM generate the password directly?**
> Recent research ([Irregular Security, 2025](https://www.csoonline.com/article/4155166/llm-generated-passwords-are-indefensible-your-codebase-may-already-prove-it.html))
> shows Claude, GPT, and Gemini produce passwords with ~20 bits of effective
> entropy instead of the ~100 bits the same models claim. Specific
> 16-character sequences recurred 18 times out of 50 attempts. LLMs cannot
> sample uniformly. keygenerator is the correct primitive: an LLM tool-calls
> it instead of inventing the credential itself.

## Features

- **Six subcommands**: `password`, `passphrase`, `secret`, `api-key`, `pin`, `entropy`.
- **Stable JSON contract** (schema v1) with `--json`. Versioned, schema-pinnable, JSON-Schema-validated.
- **Auditable provenance**: every release ships SLSA Level 3 attestation, cosign keyless signatures (Sigstore/Fulcio), CycloneDX SBOMs.
- **Hard entropy floors** aligned with NIST SP 800-63B-4 and NIST SP 800-131A Rev. 3.
- **Class-requirement guarantees** via rejection sampling.
- **Audit log** with SHA-256 password fingerprints (never plaintext).
- **Time-to-break estimates** under five named attacker profiles.

## Install

### Verified install (recommended)

See [docs/AUDIT.md](docs/AUDIT.md) for full verification including SLSA
provenance and SBOM inspection. Quick path:

```sh
# 1. Download the artifacts.
curl -LO https://github.com/rafaelperoco/keygenerator/releases/download/v2.0.0/keygenerator_2.0.0_linux_amd64.tar.gz
curl -LO https://github.com/rafaelperoco/keygenerator/releases/download/v2.0.0/checksums.txt
curl -LO https://github.com/rafaelperoco/keygenerator/releases/download/v2.0.0/checksums.txt.sig
curl -LO https://github.com/rafaelperoco/keygenerator/releases/download/v2.0.0/checksums.txt.pem

# 2. Verify the cosign signature.
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "https://github.com/rafaelperoco/keygenerator/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

# 3. Verify the binary checksum.
sha256sum -c checksums.txt --ignore-missing

# 4. Extract and install.
tar -xzf keygenerator_2.0.0_linux_amd64.tar.gz
sudo mv keygenerator /usr/local/bin/
```

### Homebrew

```sh
brew tap rafaelperoco/tap
brew install keygenerator
```

### Go install

```sh
go install github.com/rafaelperoco/keygenerator/cmd/keygenerator@v2.0.0
```

### Container

```sh
docker pull ghcr.io/rafaelperoco/keygenerator:v2.0.0
docker run --rm ghcr.io/rafaelperoco/keygenerator:v2.0.0 --json
```

The container is signed; verify with:

```sh
cosign verify ghcr.io/rafaelperoco/keygenerator:v2.0.0 \
  --certificate-identity-regexp "https://github.com/rafaelperoco/keygenerator/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Usage

```sh
# Default: 20-char alphanumeric password, ~119 bits.
keygenerator

# Machine-readable JSON with crack-time estimates.
keygenerator --json --show-crack-time

# Strong API token, Stripe-style.
keygenerator api-key --prefix sk_live --length 40

# Diceware passphrase, 8 words (~103 bits, secure through 2050).
keygenerator passphrase

# 32-byte machine-to-machine secret (256 bits, base64url).
keygenerator secret

# Estimate the strength of an existing password.
echo -n 'Tr0ub4dor&3' | keygenerator entropy --show-crack-time
```

See [docs/SUBCOMMANDS.md](docs/SUBCOMMANDS.md) for every flag of every
subcommand.

## Output schema

```sh
keygenerator --json --show-crack-time -n 24
```

```json
{
  "schema_version": 1,
  "password": "VoJgEDVnCoTVMx8cLnMwmHnz",
  "length": 24,
  "charset_id": "alphanum-v1",
  "charset_size": 62,
  "entropy_bits": 142.9,
  "algorithm": "crypto/rand+rejection-sampling",
  "subcommand": "password",
  "version": "v2.0.0",
  "commit": "1b43032",
  "build_date": "2026-04-29T22:00:00Z",
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

The full schema is published as [schemas/output-v1.json](schemas/output-v1.json)
(JSON Schema 2020-12). Pin the version with `--require-schema-version=1`.

## Go library

```go
import "github.com/rafaelperoco/keygenerator/pkg/keygen"

res, err := keygen.Password(keygen.PasswordOptions{
    Length:          24,
    CharsetID:       "alphanum-symbols-v1",
    RequiredClasses: "lower,upper,digit,symbol",
})
if err != nil { /* errors.Is(err, keygen.ErrBelowEntropyFloor) etc. */ }

fmt.Println(res.Password, "entropy:", res.EntropyBits)

// Time-to-break estimates.
for _, e := range keygen.EstimateCrackTime(res.EntropyBits) {
    fmt.Println(e.ProfileID, e.HumanReadable)
}
```

API stability is documented in `pkg/keygen/doc.go`.

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
