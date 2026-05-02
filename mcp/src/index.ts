#!/usr/bin/env node
// secretgenerator MCP server. Exposes the same generation primitives as
// the secretgenerator CLI (and as the secretgenerator.org web generator)
// via the Model Context Protocol so any MCP-aware client (Claude Desktop,
// Claude Code, Cursor, Cline, Zed, Continue.dev, ...) can call them.
//
// Why this matters: LLMs cannot uniformly sample randomness. When asked to
// "generate an API key", they tend to produce strings with ~20 bits of
// effective entropy and substantial collision rates (Irregular Security,
// 2025). Exposing this tool via MCP means the agent can delegate the
// sampling to a CSPRNG-backed primitive and audit the result via a
// versioned JSON schema.
//
// Install:
//   claude mcp add secretgenerator -- npx -y @secretgenerator/mcp@latest
//
// All generation is local. No network calls. The Go code that backs the
// CLI is compiled to WASM and run in a Node sandbox.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { loadBindings, unwrap, type Result } from "./wasm.js";

const server = new Server(
  {
    name: "secretgenerator",
    version: "2.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ─── Tool catalog ──────────────────────────────────────────────────────────
//
// Tool names use snake_case (MCP convention). Descriptions intentionally
// long: agents read these to decide when to use a tool, so being explicit
// about *when* to pick each subcommand prevents the model from picking
// `generate_password` when `generate_secret` is the right call for an API
// token, or vice versa.

const TOOLS = [
  {
    name: "generate_password",
    description:
      "Generate a high-entropy random password from a named character set. " +
      "Use this for general-purpose passwords (user accounts, encrypted vaults, " +
      "manual logins). For machine-to-machine tokens prefer `generate_secret`. " +
      "For human-memorable secrets prefer `generate_passphrase`. " +
      "Default: 20 characters from `alphanum-v1` (~119 bits of entropy). " +
      "Returns a schema-v1 JSON record describing the credential and its provenance.",
    inputSchema: {
      type: "object",
      properties: {
        length: {
          type: "integer",
          minimum: 1,
          description: "Length of the password in characters. Default 20.",
        },
        charsetId: {
          type: "string",
          description:
            "Named, versioned character set. Common choices: `alphanum-v1` (a-z A-Z 0-9), " +
            "`alphanum-symbols-v1` (adds !@#$...), `lower-v1`, `upper-v1`, " +
            "`digit-v1`, `hex-v1`, `base62-v1`, `numeric-v1`. Default `alphanum-v1`.",
        },
        exclude: {
          type: "string",
          description:
            "Characters to remove from the charset BEFORE generation. The output " +
            "length is still honored; the charset just shrinks. Useful for excluding " +
            "look-alikes like `0Ol1iI` when humans will type the password.",
        },
        requiredClasses: {
          type: "string",
          description:
            "Comma-separated classes the output is guaranteed to contain. " +
            "Valid values: `lower`, `upper`, `digit`, `symbol`. " +
            "Example: `lower,upper,digit,symbol`. Generation uses rejection sampling " +
            "until all required classes are present.",
        },
        minEntropyBits: {
          type: "number",
          description:
            "Minimum acceptable Shannon entropy in bits. Default 80. Set to 0 to disable. " +
            "If the requested length × log2(charset size) is below this floor and " +
            "`allowWeak` is false, the call fails with a clear error.",
        },
        allowWeak: {
          type: "boolean",
          description:
            "If true, permit generation below the entropy floor. The result will " +
            "include a `warnings` array documenting that the floor was bypassed. " +
            "Default false.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "generate_passphrase",
    description:
      "Generate a diceware-style passphrase using the EFF Large Wordlist (7776 words, " +
      "~12.92 bits per word). Use this for human-memorable secrets like master " +
      "passwords, encryption recovery phrases, or anything a human will type. " +
      "Default: 8 words (~103 bits) joined by hyphens — Reinhold's `secure-through-2050` " +
      "threshold. Returns a schema-v1 JSON record.",
    inputSchema: {
      type: "object",
      properties: {
        words: {
          type: "integer",
          minimum: 1,
          description:
            "Number of words. 6 = EFF minimum (~78 bits). 8 = secure-through-2050 (~103 bits). " +
            "10 = wallet-grade (~129 bits). Default 8.",
        },
        separator: {
          type: "string",
          description:
            "String joining consecutive words. Default `-`. Hyphen is shell/URL/env-file safe. " +
            "Empty string is rejected (would let adjacent words fuse and lose entropy).",
        },
        capitalize: {
          type: "boolean",
          description:
            "Compatibility flag for sites mandating uppercase. Capitalizes the first letter " +
            "of each word. The result includes a warning that this adds ~0 bits against real " +
            "attackers (Title-Case is in every Hashcat ruleset). Prefer adding a word instead. " +
            "Default false.",
        },
        digitSuffix: {
          type: "boolean",
          description:
            "Compatibility flag for sites mandating a digit. Appends a single random digit " +
            "(adds log2(10) ≈ 3.32 bits). The result includes a warning. " +
            "Default false.",
        },
        minEntropyBits: {
          type: "number",
          description: "Default 80. See `generate_password`.",
        },
        allowWeak: {
          type: "boolean",
          description: "See `generate_password`. Default false.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "generate_secret",
    description:
      "Generate a high-entropy machine-readable secret from raw CSPRNG bytes. " +
      "**Recommended for API tokens, OAuth client secrets, JWT signing keys, and any " +
      "machine-to-machine credential** — humans never see this string, so we don't waste " +
      "entropy on memorable charsets. Default: 32 bytes (256 bits) encoded as URL-safe " +
      "base64 without padding (43 characters). Returns a schema-v1 JSON record.",
    inputSchema: {
      type: "object",
      properties: {
        bytes: {
          type: "integer",
          minimum: 1,
          description:
            "Number of random bytes (8 bits each). 16 = 128 bits, 32 = 256 bits, " +
            "64 = 512 bits. Default 32.",
        },
        encoding: {
          type: "string",
          enum: ["base64url", "base64", "base32", "hex"],
          description:
            "Output encoding. `base64url` is URL/header/env-file safe (default). " +
            "`base64` includes / and + (safe in JSON, not URLs). `base32` is shorter " +
            "alphabet for case-insensitive systems. `hex` for systems that need only " +
            "ASCII letters and digits.",
        },
        prefix: {
          type: "string",
          description:
            "Static prefix prepended to the encoded body. Does not contribute to entropy. " +
            "Useful for namespacing (e.g. `sk_live_`, `prod_`).",
        },
        minEntropyBits: {
          type: "number",
          description:
            "Default 128 — the NIST SP 800-131A 2030 target for symmetric-key strength. " +
            "Set to 0 to disable.",
        },
        allowWeak: {
          type: "boolean",
          description: "See `generate_password`. Default false.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "generate_api_key",
    description:
      "Generate a token in the `<prefix><separator><base62>` form used by Stripe " +
      "(`sk_live_...`), GitHub (`ghp_...`), Slack (`xoxb-...`), Anthropic (`sk-ant-...`), " +
      "and most modern SaaS APIs. Default: `sk_<32 base62 chars>` (~190 bits). " +
      "The base62 body is drawn uniformly from a CSPRNG; the prefix is a static identifier " +
      "and contributes zero entropy. Returns a schema-v1 JSON record.",
    inputSchema: {
      type: "object",
      properties: {
        prefix: {
          type: "string",
          description:
            "Static identifier (e.g. `sk`, `ghp`, `xoxb`, `sk-ant`). Whitespace is rejected.",
        },
        separator: {
          type: "string",
          description: "Between prefix and body. Default `_`.",
        },
        length: {
          type: "integer",
          minimum: 1,
          description: "Length of the base62 body in characters. Default 32 (~190 bits).",
        },
        minEntropyBits: {
          type: "number",
          description: "Default 128. See `generate_secret`.",
        },
        allowWeak: {
          type: "boolean",
          description: "See `generate_password`. Default false.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "generate_pin",
    description:
      "Generate a numeric PIN with weak-pattern rejection. PINs are intrinsically low " +
      "entropy (a 6-digit PIN is ~19.9 bits) and **safe only when the verifier enforces " +
      "rate limiting** (banking apps, hardware tokens). Never use a PIN as a standalone " +
      "authenticator. The tool requires `acknowledgeLowEntropy: true` to even generate one. " +
      "Rejects all-same-digit, strict ascending/descending sequences, short repetitions, " +
      "the top-20 DataGenetics 2012 most-common PINs, and calendar-year patterns.",
    inputSchema: {
      type: "object",
      properties: {
        digits: {
          type: "integer",
          minimum: 4,
          description: "Number of digits. Must be >= 4. Default 6.",
        },
        acknowledgeLowEntropy: {
          type: "boolean",
          description:
            "**Required.** The caller must explicitly acknowledge that PINs are " +
            "low-entropy and only safe with verifier-side rate limiting.",
        },
        allowWeakPattern: {
          type: "boolean",
          description:
            "If true, permit PINs matching weak patterns (NOT RECOMMENDED). Default false.",
        },
      },
      required: ["acknowledgeLowEntropy"],
      additionalProperties: false,
    },
  },
  {
    name: "assess_entropy",
    description:
      "Estimate the entropy of an EXISTING password. Returns the Shannon entropy in bits " +
      "assuming each character was drawn uniformly from the observed character classes — " +
      "an UPPER BOUND. Real entropy is lower if the password follows a memorable pattern " +
      "(dictionary word, year, name). Use this when validating user-supplied passwords " +
      "or auditing legacy credentials. Output never echoes the password in plaintext, only " +
      "its length, observed classes, and computed entropy.",
    inputSchema: {
      type: "object",
      properties: {
        password: {
          type: "string",
          description: "The password to assess. Not echoed in the response.",
        },
      },
      required: ["password"],
      additionalProperties: false,
    },
  },
  {
    name: "list_attacker_profiles",
    description:
      "Return the named attacker profiles used to estimate time-to-break for a given " +
      "entropy. Profiles span 13 orders of magnitude: `online-throttled-v1` " +
      "(rate-limited login API, ~100 g/s), `slow-kdf-v1` (Argon2id at OWASP defaults, " +
      "~1k g/s), `bcrypt-cost12-v1` (single RTX 4090, ~50k g/s), `fast-hash-single-gpu-v1` " +
      "(~1e11 g/s), `nation-state-v1` (10k GPUs against fast hash, ~1e15 g/s). " +
      "Profile IDs are versioned; updating a rate is a breaking change.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "estimate_crack_time",
    description:
      "Compute time-to-break estimates for a given entropy in bits across all attacker " +
      "profiles. Returns an array of {profile_id, description, seconds, human_readable}. " +
      "Use after `generate_*` or `assess_entropy` to surface a human-readable strength " +
      "summary like '7.2e+08 times the age of the universe'.",
    inputSchema: {
      type: "object",
      properties: {
        entropyBits: {
          type: "number",
          minimum: 0,
          description: "The credential's entropy in bits.",
        },
      },
      required: ["entropyBits"],
      additionalProperties: false,
    },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const sgen = await loadBindings();
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;

  const handlers: Record<string, () => unknown> = {
    generate_password: () => unwrap<Result>(sgen.password(args)),
    generate_passphrase: () => unwrap<Result>(sgen.passphrase(args)),
    generate_secret: () => unwrap<Result>(sgen.secret(args)),
    generate_api_key: () => unwrap<Result>(sgen.apiKey(args)),
    generate_pin: () => unwrap<Result>(sgen.pin(args)),
    assess_entropy: () => unwrap<Result>(sgen.entropy(args)),
    list_attacker_profiles: () => sgen.attackerProfiles(),
    estimate_crack_time: () => sgen.crackTimes(Number(args.entropyBits)),
  };

  const handler = handlers[req.params.name];
  if (!handler) {
    throw new Error(`unknown tool: ${req.params.name}`);
  }

  try {
    const result = handler();
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({ error: msg }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);

// Keep the process alive; the SDK manages the stdio loop.
