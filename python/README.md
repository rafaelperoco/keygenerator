# secretgenerator (Python)

[![pypi](https://img.shields.io/pypi/v/secretgenerator)](https://pypi.org/project/secretgenerator/)
[![python](https://img.shields.io/pypi/pyversions/secretgenerator)](https://pypi.org/project/secretgenerator/)

Auditable random credential generator for AI agents and machine-readable
pipelines. This Python package wraps the
[`secretgenerator`](https://github.com/rafaelperoco/secretgenerator) CLI
and exposes its stable schema-v1 JSON output as Python dicts.

## Install

The Python package and the CLI binary install separately:

```sh
pip install secretgenerator
```

Then install the CLI once with whichever method fits your environment:

```sh
npm install -g @secretgenerator/cli
# or
brew install rafaelperoco/tap/secretgenerator
# or
go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest
```

## Quick start

```python
import secretgenerator as sg

pw = sg.password(length=24, charset="alphanum-symbols-v1",
                 require_classes="lower,upper,digit,symbol")
print(pw["password"], "—", pw["entropy_bits"], "bits")

phrase = sg.passphrase(words=8, separator="-")
print(phrase["password"])

token = sg.api_key(length=40, prefix="sk_live")
print(token["password"])

bits = sg.entropy("Tr0ub4dor&3")["entropy_bits"]
print(f"that pasword has {bits:.1f} bits")
```

Every function returns a parsed schema-v1 dict with the same shape as
the CLI's `--json` output (see
[`schemas/output-v1.json`](https://github.com/rafaelperoco/secretgenerator/blob/main/schemas/output-v1.json)).

## Error handling

```python
try:
    sg.password(length=4)  # below the 80-bit floor
except sg.SecretgeneratorError as e:
    if e.code == "E_ENTROPY_TOO_LOW":
        # Stable code; safe to branch on.
        ...
```

The `code` attribute exposes a stable identifier from the CLI's error
envelope (`E_ENTROPY_TOO_LOW`, `E_CHARSET_EMPTY`, `E_CLASS_IMPOSSIBLE`,
`E_INVALID_ARGS`, `E_RNG_FAILURE`).

## Why a wrapper instead of a pure-Python implementation?

Cryptographic primitives belong in audited binaries with reproducible
builds and SLSA provenance, not duplicated across language wrappers.
The CLI is signed end-to-end with cosign keyless (Sigstore/Fulcio +
GitHub OIDC) and ships SLSA Level 3 attestation. This wrapper is a
thin transport — it parses JSON.
