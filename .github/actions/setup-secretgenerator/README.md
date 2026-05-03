# setup-secretgenerator

GitHub Action that installs the auditable
[`secretgenerator`](https://github.com/rafaelperoco/secretgenerator) CLI on
the runner, verifies its cosign keyless signature and SHA-256 checksum,
and exposes it on `PATH`.

Works on `ubuntu-*`, `macos-*`, and `windows-*` runners (amd64 and
arm64). Internally a composite action — no Node.js, no Docker, just
`curl`, `cosign`, and `tar`/`unzip`.

## Usage

```yaml
- uses: rafaelperoco/secretgenerator/.github/actions/setup-secretgenerator@v2.0.0
  with:
    version: v2.0.0 # or "latest" (default)

- run: secretgenerator password --json --require-schema-version=1
```

Pin the action by tag (`@v2.0.0`) or, for stricter supply-chain hygiene,
by commit SHA.

## Inputs

| Name            | Default  | Description                                                                                             |
| --------------- | -------- | ------------------------------------------------------------------------------------------------------- |
| `version`       | `latest` | Release tag to install (`v2.0.0`, `latest`). `latest` skips prereleases.                                |
| `verify-cosign` | `"true"` | When `"true"`, verifies the cosign keyless signature on `checksums.txt`. Installs `cosign` when absent. |

## Outputs

| Name      | Description                               |
| --------- | ----------------------------------------- |
| `version` | The resolved release tag (e.g. `v2.0.0`). |
| `bin`     | Absolute path to the installed binary.    |

## What it verifies

1. Cosign keyless signature on `checksums.txt` (Sigstore / Fulcio +
   GitHub OIDC). The certificate identity must be issued from
   `https://github.com/rafaelperoco/secretgenerator/.github/workflows/release.yml`
   and the OIDC issuer must be GitHub Actions.
2. SHA-256 of the platform archive matches the entry in `checksums.txt`.
3. A live smoke test: a 16-character password is generated and the
   schema-v1 envelope is parsed.

If any step fails the job fails — there is no soft mode.
