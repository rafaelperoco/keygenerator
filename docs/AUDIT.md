# Auditing keygenerator releases

This document describes how to verify, end-to-end, that a `keygenerator` binary
you have downloaded was built from the source in this repository, by GitHub
Actions, with no tampering in transit.

The verification chain is:

```
You ─trust─▶ Sigstore Fulcio (root CA)
            │
            └─signs cert tied to─▶ GitHub Actions OIDC identity
                                  │
                                  └─signs─▶ checksums.txt
                                          │
                                          └─pins SHA-256 of─▶ keygenerator binary
```

You do **not** need to trust this README, the project maintainer, or any web
host. You only need to trust:

1. The Sigstore project's root keys (distributed with `cosign`).
2. GitHub Actions' OIDC token issuer (a known, audited service).
3. That the GitHub repository at `github.com/rafaelperoco/keygenerator` is the
   one you intend to install from.

Everything else is verifiable cryptographically.

## Tools you need

```sh
# Sigstore signature verification
brew install cosign        # macOS
# or: https://docs.sigstore.dev/cosign/installation

# SLSA provenance verification
go install github.com/slsa-framework/slsa-verifier/v2/cmd/slsa-verifier@latest

# SBOM inspection (optional but recommended)
brew install syft
```

## Verifying a release

### 1. Download the artifacts

From the [release page](https://github.com/rafaelperoco/keygenerator/releases),
download:

- `keygenerator_<version>_<os>_<arch>.tar.gz` — the binary archive
- `checksums.txt` — SHA-256 hashes of every release artifact
- `checksums.txt.sig` — cosign signature over `checksums.txt`
- `checksums.txt.pem` — cosign certificate (Fulcio-issued)
- `multiple.intoto.jsonl` — SLSA Level 3 provenance attestation
- `keygenerator_<version>_<os>_<arch>.tar.gz.sbom.json` — CycloneDX SBOM

### 2. Verify the cosign signature on `checksums.txt`

This step proves: "the GitHub Actions workflow at
`github.com/rafaelperoco/keygenerator` produced this `checksums.txt`."

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "https://github.com/rafaelperoco/keygenerator/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

Expected output: `Verified OK`.

### 3. Verify the binary checksum

This step proves: "the binary I have matches what the workflow signed."

```sh
sha256sum -c checksums.txt --ignore-missing
```

Expected output: `keygenerator_<version>_<os>_<arch>.tar.gz: OK`.

### 4. Verify SLSA Level 3 provenance

This step proves: "the binary was built from the source at the commit shown,
in a hardened CI environment, by a non-falsifiable workflow."

```sh
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/rafaelperoco/keygenerator \
  --source-tag v<version> \
  keygenerator_<version>_<os>_<arch>.tar.gz
```

Expected output: `Verified signature against tlog entry ...` and
`PASSED: SLSA verification passed`.

### 5. Verify the binary's self-reported identity matches

After extracting the archive, the binary itself reports its build identity in
every JSON output. Check that it matches the release tag:

```sh
./keygenerator --json | jq '{version, commit, build_date}'
```

The `version` should match the release tag, and `commit` should match the git
SHA shown on the [release page](https://github.com/rafaelperoco/keygenerator/releases).

### 6. (Optional) Inspect the SBOM

The SBOM lists every dependency that went into the build:

```sh
syft scan keygenerator_<version>_<os>_<arch>.tar.gz.sbom.json
```

You can also scan for known vulnerabilities. The release pipeline already
runs Trivy as a gate before publishing, but a fresh scan from your machine
catches CVEs disclosed after the release was cut:

```sh
trivy sbom keygenerator_<version>_<os>_<arch>.tar.gz.sbom.json
# Alternative tool with same SBOM input
grype sbom:keygenerator_<version>_<os>_<arch>.tar.gz.sbom.json
```

The project's own daily Trivy scan results are visible in the GitHub
Security tab at
https://github.com/rafaelperoco/keygenerator/security/code-scanning

## Verifying a container image

```sh
cosign verify ghcr.io/rafaelperoco/keygenerator:v<version> \
  --certificate-identity-regexp "https://github.com/rafaelperoco/keygenerator/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## What this does NOT prove

- That the source code at the verified commit is **correct**. Read the source.
- That `crypto/rand` on your OS is producing real entropy. That depends on
  your kernel and hardware; see [docs/CRYPTO.md](CRYPTO.md).
- That the verifier system (Sigstore Rekor, Fulcio) has not been compromised.
  These are well-audited services, but you may want to pin transparency-log
  entries with `--rekor-url` and `--certificate-chain` for extreme threat
  models.

## Reporting verification failures

If any step above fails, **do not run the binary**. Open a security advisory
at https://github.com/rafaelperoco/keygenerator/security/advisories/new with
the artifact filenames, the exact command you ran, and the failure output.
