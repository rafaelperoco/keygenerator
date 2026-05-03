// Catalog of per-subcommand pages. Each entry drives one route under
// /<slug>/ and feeds the SEO metadata, intro copy, and snippet block.
// Keep this file the single source of truth — index.astro and the
// per-page layouts both read from here.

export type SubcommandSlug =
  | "password"
  | "passphrase"
  | "secret"
  | "api-key"
  | "pin";

export type SnippetExample = {
  language: string;
  filename: string;
  code: string;
};

export type SubcommandPage = {
  slug: SubcommandSlug;
  /** Subcommand id passed to the WASM Generator (matches CLI argv). */
  generatorId: SubcommandSlug;
  title: string;
  metaDescription: string;
  h1: string;
  intro: string;
  defaults: { name: string; value: string }[];
  cliExamples: { label: string; cmd: string }[];
  snippets: SnippetExample[];
  faq: { q: string; a: string }[];
};

const SCHEMA_PIN = "--require-schema-version=1";

const PYTHON_SNIPPET = (subcommand: SubcommandSlug, args: string) => `import secretgenerator_py as sg

result = sg.${subcommand.replace("-", "_")}(${args})
print(result["password"], "—", result["entropy_bits"], "bits")`;

const NODE_SNIPPET = (subcommand: SubcommandSlug, args: string[]) => `import { execFileSync } from "node:child_process";

const json = execFileSync("secretgenerator", [
  "${subcommand}", "--json", "${SCHEMA_PIN}",
  ${args.map((a) => JSON.stringify(a)).join(", ")}
], { encoding: "utf8" });
const out = JSON.parse(json);
console.log(out.password, "—", out.entropy_bits, "bits");`;

const RUST_SNIPPET = (
  subcommand: string,
  builder: string,
) => `use secretgenerator::{${subcommand}, ${capitalize(subcommand)}Options};

let r = ${subcommand}(${builder})?;
println!("{} ({:.1} bits)", r.password, r.entropy_bits);
# Ok::<_, secretgenerator::Error>(())`;

function capitalize(s: string): string {
  // password -> Password, api_key -> ApiKey
  return s
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("");
}

const GO_SNIPPET = (call: string) => `package main

import (
\t"fmt"
\t"github.com/rafaelperoco/secretgenerator/pkg/secretgen"
)

func main() {
\tres, err := ${call}
\tif err != nil { panic(err) }
\tfmt.Printf("%s (%.1f bits)\\n", res.Password, res.EntropyBits)
}`;

export const SUBCOMMANDS: SubcommandPage[] = [
  {
    slug: "password",
    generatorId: "password",
    title: "Random password generator (auditable, NIST-aligned) — secretgenerator",
    metaDescription:
      "Cryptographically secure password generator backed by the OS CSPRNG. Schema-v1 JSON output, NIST 800-63B-4 entropy floors, class guarantees, SLSA L3.",
    h1: "Auditable random password generator",
    intro:
      "Uses the OS CSPRNG with rejection sampling, no modulo bias. Default 20 characters at ~119 bits — well above the NIST SP 800-63B-4 floor. Class requirements (lower, upper, digit, symbol) are guaranteed, not nudged.",
    defaults: [
      { name: "length", value: "20" },
      { name: "charset", value: "alphanum-v1" },
      { name: "min entropy", value: "80 bits (NIST floor)" },
      { name: "algorithm", value: "crypto/rand + rejection sampling" },
    ],
    cliExamples: [
      {
        label: "Default 20-char alphanumeric",
        cmd: "secretgenerator password --json --show-crack-time",
      },
      {
        label: "24-char with all classes guaranteed",
        cmd: "secretgenerator password --length 24 --charset alphanum-symbols-v1 --require-classes lower,upper,digit,symbol --json",
      },
      {
        label: "Pin schema for safe parsing",
        cmd: `secretgenerator password ${SCHEMA_PIN} --json`,
      },
    ],
    snippets: [
      {
        language: "Python",
        filename: "generate_password.py",
        code: PYTHON_SNIPPET(
          "password",
          'length=24, charset="alphanum-symbols-v1", require_classes="lower,upper,digit,symbol"',
        ),
      },
      {
        language: "Node.js",
        filename: "generate-password.mjs",
        code: NODE_SNIPPET("password", [
          "--length",
          "24",
          "--charset",
          "alphanum-symbols-v1",
          "--require-classes",
          "lower,upper,digit,symbol",
        ]),
      },
      {
        language: "Rust",
        filename: "main.rs",
        code: RUST_SNIPPET(
          "password",
          'PasswordOptions::default().length(24).charset("alphanum-symbols-v1").require_classes("lower,upper,digit,symbol")',
        ),
      },
      {
        language: "Go",
        filename: "main.go",
        code: GO_SNIPPET(
          'secretgen.Password(secretgen.PasswordOptions{\n\t\tLength: 24,\n\t\tCharsetID: "alphanum-symbols-v1",\n\t\tRequiredClasses: "lower,upper,digit,symbol",\n\t})',
        ),
      },
    ],
    faq: [
      {
        q: "Is this safer than letting Claude or ChatGPT generate the password?",
        a: "Yes. Recent studies show LLMs produce passwords with ~20 bits of effective entropy regardless of what they claim — they cannot uniformly sample. secretgenerator delegates to the OS CSPRNG so every output is uniform across the chosen charset.",
      },
      {
        q: "Why does the JSON output omit the password by default in some commands?",
        a: "It does not for password — the password field is part of schema v1. The entropy subcommand omits it because the caller already has the candidate. See docs/SCHEMA.md.",
      },
      {
        q: "Can I disable the entropy floor?",
        a: "Pass --allow-weak. The output will carry a warning entry that propagates to the audit log so the deviation is recorded.",
      },
    ],
  },
  {
    slug: "passphrase",
    generatorId: "passphrase",
    title: "Diceware passphrase generator (EFF Large Wordlist) — secretgenerator",
    metaDescription:
      "Generate auditable diceware passphrases from the EFF Large Wordlist. SHA-256 verified at startup. Schema-v1 JSON output, ~103 bits at 8 words.",
    h1: "Diceware passphrase generator",
    intro:
      "Words sampled uniformly from the EFF Large Wordlist (7,776 entries, ~12.92 bits per word) with the wordlist hash verified at process start. Eight words gives ~103 bits — strong against everything short of a nation-state, memorable enough for humans.",
    defaults: [
      { name: "words", value: "8" },
      { name: "separator", value: "-" },
      { name: "wordlist", value: "EFF Large (7,776 words)" },
      { name: "min entropy", value: "80 bits (Reinhold/EFF floor)" },
    ],
    cliExamples: [
      {
        label: "Default 8-word, dash-separated",
        cmd: "secretgenerator passphrase --json --show-crack-time",
      },
      {
        label: "10 words, space separator",
        cmd: 'secretgenerator passphrase --words 10 --separator " " --json',
      },
      {
        label: "Compatibility flags for legacy verifiers",
        cmd: "secretgenerator passphrase --capitalize --digit-suffix --json",
      },
    ],
    snippets: [
      {
        language: "Python",
        filename: "generate_passphrase.py",
        code: PYTHON_SNIPPET("passphrase", 'words=10, separator="-"'),
      },
      {
        language: "Node.js",
        filename: "generate-passphrase.mjs",
        code: NODE_SNIPPET("passphrase", ["--words", "10", "--separator", "-"]),
      },
      {
        language: "Rust",
        filename: "main.rs",
        code: RUST_SNIPPET(
          "passphrase",
          'PassphraseOptions::default().words(10).separator("-")',
        ),
      },
    ],
    faq: [
      {
        q: "Why diceware instead of just a long random password?",
        a: "Memorability without sacrificing entropy. Six diceware words (~77.5 bits) is roughly equivalent in strength to a 13-character random alphanumeric, but a human can actually retain it.",
      },
      {
        q: "How is the wordlist's integrity verified?",
        a: "The binary embeds the EFF Large Wordlist with a SHA-256 hash that is verified at process start. If the embedded copy ever drifts from the published EFF list, generation refuses to start.",
      },
    ],
  },
  {
    slug: "secret",
    generatorId: "secret",
    title:
      "CSPRNG secret generator (base64url, 256-bit) — secretgenerator",
    metaDescription:
      "Generate raw CSPRNG bytes encoded as URL-safe base64. Designed for machine-to-machine API tokens, JWT secrets, encryption keys. Schema-v1, SLSA L3.",
    h1: "Machine-to-machine secret generator",
    intro:
      "Raw bytes from the OS CSPRNG, encoded as URL-safe base64 without padding. Default 32 bytes (256 bits) — the right shape for JWT signing keys, opaque API tokens, session IDs, and seed material. No charset to argue about, just bytes.",
    defaults: [
      { name: "bytes", value: "32 (256 bits)" },
      { name: "encoding", value: "URL-safe base64, no padding" },
      { name: "min entropy", value: "128 bits (NIST 800-131A target)" },
      { name: "algorithm", value: "crypto/rand + base64url" },
    ],
    cliExamples: [
      {
        label: "Default 32 bytes",
        cmd: "secretgenerator secret --json",
      },
      {
        label: "Prefixed for environment variables",
        cmd: 'secretgenerator secret --prefix "JWT_" --json',
      },
      {
        label: "64 bytes for HMAC-SHA-512 keys",
        cmd: "secretgenerator secret --bytes 64 --json",
      },
    ],
    snippets: [
      {
        language: "Python",
        filename: "generate_secret.py",
        code: PYTHON_SNIPPET("secret", "bytes_=32"),
      },
      {
        language: "Node.js",
        filename: "generate-secret.mjs",
        code: NODE_SNIPPET("secret", ["--bytes", "32"]),
      },
      {
        language: "Rust",
        filename: "main.rs",
        code: RUST_SNIPPET("secret", "SecretOptions::default().bytes(32)"),
      },
    ],
    faq: [
      {
        q: "Why base64url and not hex?",
        a: "Same entropy in fewer characters (43 vs 64 for 32 bytes), URL-safe, and matches the encoding used by JWT, OAuth, and most modern APIs. If you need hex, pipe through xxd or shasum.",
      },
      {
        q: "Is 32 bytes enough?",
        a: "Yes for almost everything. NIST SP 800-131A targets 128 bits of strength; 32 bytes (256 bits) gives a 2× safety margin. Use 64 bytes for HMAC-SHA-512 keys where the hash output size dictates the recommended key length.",
      },
    ],
  },
  {
    slug: "api-key",
    generatorId: "api-key",
    title: "API key generator (Stripe-style prefix_random) — secretgenerator",
    metaDescription:
      "Generate Stripe-style API keys with a configurable prefix and base62 secret body. Schema-v1 JSON, audit log, NIST-aligned entropy.",
    h1: "Stripe-style API key generator",
    intro:
      "Tokens in the prefix_random shape that Stripe popularized: a static identifier ('sk_live', 'ghp', 'xoxb') makes leaked tokens trivially classifiable in repo scans, plus a base62 random body sized for ≥128 bits. Default 32 characters of base62 = ~190 bits.",
    defaults: [
      { name: "prefix", value: "sk" },
      { name: "separator", value: "_" },
      { name: "body length", value: "32 chars (~190 bits)" },
      { name: "min entropy", value: "128 bits" },
    ],
    cliExamples: [
      {
        label: "Default sk_*",
        cmd: "secretgenerator api-key --json",
      },
      {
        label: "Stripe live secret key",
        cmd: 'secretgenerator api-key --prefix "sk_live" --length 40 --json',
      },
      {
        label: "GitHub-style PAT",
        cmd: 'secretgenerator api-key --prefix "ghp" --separator "_" --length 36 --json',
      },
    ],
    snippets: [
      {
        language: "Python",
        filename: "generate_api_key.py",
        code: PYTHON_SNIPPET("api-key", 'prefix="sk_live", length=40'),
      },
      {
        language: "Node.js",
        filename: "generate-api-key.mjs",
        code: NODE_SNIPPET("api-key", [
          "--prefix",
          "sk_live",
          "--length",
          "40",
        ]),
      },
      {
        language: "Rust",
        filename: "main.rs",
        code: RUST_SNIPPET(
          "api_key",
          'ApiKeyOptions::default().prefix("sk_live").length(40)',
        ),
      },
    ],
    faq: [
      {
        q: "Why does the prefix matter for security?",
        a: "GitHub's secret scanning, Trufflehog, gitleaks, and similar tools recognize known prefixes. A leaked token with a recognizable prefix gets revoked within minutes by upstream platforms; an opaque random string can sit in a public repo for months.",
      },
      {
        q: "Should the prefix be counted toward entropy?",
        a: "No. The prefix is a public identifier; only the base62 body contributes entropy. Set --length to size the secret body alone.",
      },
    ],
  },
  {
    slug: "pin",
    generatorId: "pin",
    title: "Numeric PIN generator with weak-pattern blocklist — secretgenerator",
    metaDescription:
      "Cryptographically secure numeric PIN generator that rejects all-same-digit, sequences, top-20 weak PINs, and calendar years. Audit log, schema-v1.",
    h1: "Auditable numeric PIN generator",
    intro:
      "PINs are intrinsically low-entropy (a 4-digit PIN carries only ~13 bits) so the subcommand requires --acknowledge-low-entropy. Output is rejected when it matches all-same-digit, strict sequences, the DataGenetics-2012 top-20 most-common PINs, calendar years, or short repetitions. Use only with rate-limited verifiers.",
    defaults: [
      { name: "digits", value: "6 (~19.9 bits)" },
      { name: "blocklist", value: "Top-20 + sequences + years" },
      { name: "acknowledgement", value: "Required" },
    ],
    cliExamples: [
      {
        label: "Default 6 digits",
        cmd: "secretgenerator pin --acknowledge-low-entropy --json",
      },
      {
        label: "8 digits with crack time",
        cmd: "secretgenerator pin --digits 8 --acknowledge-low-entropy --show-crack-time --json",
      },
      {
        label: "Disable blocklist (NOT RECOMMENDED)",
        cmd: "secretgenerator pin --acknowledge-low-entropy --allow-weak-pattern --json",
      },
    ],
    snippets: [
      {
        language: "Python",
        filename: "generate_pin.py",
        code: PYTHON_SNIPPET("pin", "digits=6"),
      },
      {
        language: "Node.js",
        filename: "generate-pin.mjs",
        code: NODE_SNIPPET("pin", [
          "--digits",
          "6",
          "--acknowledge-low-entropy",
        ]),
      },
      {
        language: "Rust",
        filename: "main.rs",
        code: RUST_SNIPPET("pin", "PinOptions::default().digits(6)"),
      },
    ],
    faq: [
      {
        q: "Why require --acknowledge-low-entropy?",
        a: "Forcing the caller to spell it out makes accidental misuse loud. PINs belong on rate-limited verifiers (banking apps, hardware tokens) — never as primary authenticators.",
      },
      {
        q: "What's in the weak-pattern blocklist?",
        a: "All-same-digit (1111), strict sequences (1234, 9876), short repetitions (1212, 123123), the DataGenetics 2012 top-20 most-common PINs, and four-digit calendar years from 1900–2099.",
      },
    ],
  },
];

export function findSubcommand(slug: string): SubcommandPage | undefined {
  return SUBCOMMANDS.find((s) => s.slug === slug);
}
