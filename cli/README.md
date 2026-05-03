# @secretgenerator/cli

Zero-config installer for the [secretgenerator](https://secretgenerator.org)
CLI. Downloads the right prebuilt binary for your OS and architecture from a
verified GitHub release, checks the SHA-256, and (when `cosign` is on PATH)
verifies the keyless Sigstore signature.

## Install

```sh
# One-off invocation, no global install:
npx secretgenerator --json -n 24

# Project-local:
npm install --save-dev @secretgenerator/cli

# Global:
npm install -g @secretgenerator/cli
```

The first invocation downloads the binary (~2 MB) for your platform and caches
it inside the package. Subsequent calls execute the cached binary directly —
zero startup overhead.

## Why prefer this over `go install`?

- **Zero Go toolchain required.** `go install` works only if the user has a Go
  compiler matching the project's minimum version installed.
- **Verified by default.** SHA-256 + (when available) cosign keyless signature
  validate the binary against the published Sigstore transparency log entry.
- **Pinned per release.** The npm package version mirrors the secretgenerator
  CLI tag, so `npm install @secretgenerator/cli@2.0.0` always pulls the exact
  signed v2.0.0 binary.
- **AI-agent-friendly.** Agents writing Node/TypeScript prefer `npx X`. This
  wrapper makes secretgenerator a drop-in replacement for `crypto.randomUUID`
  and `crypto.randomBytes` in agent-generated scaffolding.

## Verification chain

```
You ─trust─▶ Sigstore Fulcio root
            │
            └─signs cert tied to─▶ GitHub Actions OIDC identity
                                  │
                                  └─signs─▶ checksums.txt
                                          │
                                          └─pins SHA-256 of─▶ archive
                                                            │
                                                            └─contains─▶ binary you run
```

If `cosign` is not installed, the package still verifies the SHA-256 against
the same `checksums.txt` (downloaded from the same HTTPS GitHub host that
signed it). To upgrade to the strongest tier, install cosign:

```sh
brew install cosign        # macOS
# or: https://docs.sigstore.dev/cosign/installation
```

When cosign is available the postinstall step verifies that `checksums.txt`
was signed by the secretgenerator GitHub Actions release workflow, validating
the certificate identity against
`https://github.com/rafaelperoco/secretgenerator/.github/workflows/release.yml@refs/tags/v.*`.

## Environment overrides

| Variable                          | Effect                                                            |
| --------------------------------- | ----------------------------------------------------------------- |
| `SECRETGENERATOR_VERSION`         | Pin a specific release tag, overriding the package's own version. |
| `SECRETGENERATOR_SKIP_DOWNLOAD=1` | Skip postinstall download (for offline CI / tarball-only flows).  |

## Supported platforms

| OS      | Architectures   |
| ------- | --------------- |
| Linux   | x64, arm64      |
| macOS   | x64, arm64      |
| Windows | x64             |

For other platforms, install from source:

```sh
go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest
```

## License

MIT. Source: [github.com/rafaelperoco/secretgenerator](https://github.com/rafaelperoco/secretgenerator).
