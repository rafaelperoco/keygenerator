# secretgenerator

[![crates.io](https://img.shields.io/crates/v/secretgenerator)](https://crates.io/crates/secretgenerator)
[![docs.rs](https://docs.rs/secretgenerator/badge.svg)](https://docs.rs/secretgenerator)

Rust bindings for the auditable
[`secretgenerator`](https://github.com/rafaelperoco/secretgenerator) CLI.
This crate is a thin transport layer: each function shells out to the
binary, parses the schema-v1 JSON envelope, and returns a typed
`Output`. Cryptographic primitives stay in the audited binary with
SLSA Level 3 provenance and cosign keyless signatures; this crate just
parses JSON.

## Install

The crate and the binary install separately:

```sh
cargo add secretgenerator
```

Then install the CLI once with whichever method fits your environment:

```sh
brew install rafaelperoco/tap/secretgenerator
# or
npm install -g @secretgenerator/cli
# or
go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest
```

## Quick start

```rust
use secretgenerator::{password, PasswordOptions};

let out = password(
    PasswordOptions::default()
        .length(24)
        .charset("alphanum-symbols-v1")
        .require_classes("lower,upper,digit,symbol"),
)?;
println!("{} ({:.1} bits)", out.password, out.entropy_bits);
# Ok::<_, secretgenerator::Error>(())
```

Run the full example with `cargo run --example quickstart`.

## Error handling

```rust
use secretgenerator::{password, PasswordOptions, Error};

match password(PasswordOptions::default().length(4)) {
    Err(e) if e.cli_code() == Some("E_ENTROPY_TOO_LOW") => {
        // Stable code; safe to branch on.
    }
    other => { /* ... */ let _ = other; }
}
```

The CLI's stable error codes are `E_ENTROPY_TOO_LOW`,
`E_CHARSET_EMPTY`, `E_CLASS_IMPOSSIBLE`, `E_INVALID_ARGS`, and
`E_RNG_FAILURE`.

## Why not pure Rust?

Cryptographic primitives belong in audited binaries with reproducible
builds and SLSA provenance, not duplicated across language wrappers.
Verify any release end-to-end with the procedure in
[docs/AUDIT.md](https://github.com/rafaelperoco/secretgenerator/blob/main/docs/AUDIT.md).
