# @secretgenerator/mcp

MCP server exposing [secretgenerator](https://secretgenerator.org) credential
generation primitives to Claude, Cursor, Cline, Zed, Continue.dev, and any
other [Model Context Protocol](https://modelcontextprotocol.io/) client.

## Why

LLMs cannot uniformly sample randomness. Asked to generate a strong API key,
they tend to produce strings with ~20 bits of effective entropy and substantial
collision rates ([Irregular Security, 2025](https://www.csoonline.com/article/4155166/llm-generated-passwords-are-indefensible-your-codebase-may-already-prove-it.html)).
This package gives the agent a tool that delegates the sampling to a CSPRNG
and returns a versioned, auditable JSON record describing the credential.

The same Go code that backs the [secretgenerator CLI](https://github.com/rafaelperoco/secretgenerator)
is compiled to WebAssembly and run inside Node. There is no network call,
no shelled-out binary; the secret is generated locally inside the MCP server
process and streamed to the agent.

## Install

### Claude Code / Claude Desktop

```sh
claude mcp add secretgenerator -- npx -y @secretgenerator/mcp@latest
```

### Cursor / Cline / Zed / Continue.dev / etc.

Add to your client's MCP config (commonly `~/.config/<client>/mcp.json`):

```json
{
  "mcpServers": {
    "secretgenerator": {
      "command": "npx",
      "args": ["-y", "@secretgenerator/mcp@latest"]
    }
  }
}
```

The first invocation downloads the package (~600 KB including the WASM
bundle); subsequent invocations are cached.

## Tools exposed

| tool                     | when to use                                                      |
| ------------------------ | ---------------------------------------------------------------- |
| `generate_password`      | general-purpose passwords, named charsets                        |
| `generate_passphrase`    | human-memorable secrets, EFF Large Wordlist (8 words ≈ 103 bits) |
| `generate_secret`        | API tokens, OAuth secrets, JWT keys (recommended for agents)     |
| `generate_api_key`       | `prefix_base62` Stripe-style tokens                              |
| `generate_pin`           | numeric PINs with weak-pattern rejection                         |
| `assess_entropy`         | estimate strength of an existing password                        |
| `list_attacker_profiles` | enumerate the 5 named cracking-rate scenarios                    |
| `estimate_crack_time`    | time-to-break under each attacker profile                        |

Each `generate_*` tool returns a [schema-v1 JSON record](https://secretgenerator.org/schemas/output-v1.json):

```json
{
  "schema_version": 1,
  "password": "Ay7-Kx9mQ-...",
  "length": 24,
  "charset_id": "alphanum-symbols-v1",
  "entropy_bits": 156.9,
  "algorithm": "crypto/rand+rejection-sampling",
  "subcommand": "password",
  "request_id": "f4c54f9c-0f57-4d58-...",
  "timestamp_utc": "2026-05-02T21:53:34.746Z"
}
```

## Auditability

The WASM module shipped with this package is built from the
[secretgenerator source](https://github.com/rafaelperoco/secretgenerator/tree/main/web/wasm)
under `web/wasm/`. Every release of this package matches a tagged release
of the CLI; the WASM bundle is reproducible from the source via TinyGo.

For the full verification chain (cosign signatures, SLSA provenance, SBOM),
see [docs/AUDIT.md](https://github.com/rafaelperoco/secretgenerator/blob/main/docs/AUDIT.md).

## License

MIT. Source: [github.com/rafaelperoco/secretgenerator](https://github.com/rafaelperoco/secretgenerator).
