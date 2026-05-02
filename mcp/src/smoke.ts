// Smoke test: load the WASM, generate one credential of each kind, print to
// stdout. Used by CI to verify the package bundle is functional without
// pulling in the full MCP transport. Run with: `npm run smoke`.

import { loadBindings, unwrap, type Result } from "./wasm.js";

async function main() {
  const sgen = await loadBindings();
  console.log(`secretgen ${sgen.version} schema_version=${sgen.schemaVersion}`);

  const checks: Array<[string, () => unknown]> = [
    ["password", () => unwrap<Result>(sgen.password({}))],
    ["passphrase", () => unwrap<Result>(sgen.passphrase({}))],
    ["secret", () => unwrap<Result>(sgen.secret({}))],
    [
      "api-key",
      () => unwrap<Result>(sgen.apiKey({ prefix: "sk", separator: "_", length: 32 })),
    ],
    [
      "pin",
      () =>
        unwrap<Result>(sgen.pin({ digits: 6, acknowledgeLowEntropy: true })),
    ],
    [
      "entropy",
      () => unwrap<Result>(sgen.entropy({ password: "Tr0ub4dor&3" })),
    ],
  ];

  for (const [name, fn] of checks) {
    try {
      const r = fn() as Result;
      const preview = r.password
        ? r.password.length > 24
          ? r.password.slice(0, 12) + "…" + r.password.slice(-8)
          : r.password
        : "(no plaintext)";
      console.log(`  ${name.padEnd(11)} ${preview.padEnd(24)} ${r.entropy_bits.toFixed(1)} bits`);
    } catch (err) {
      console.error(`  ${name} FAILED: ${err instanceof Error ? err.message : err}`);
      process.exitCode = 1;
    }
  }

  const cracks = sgen.crackTimes(128);
  console.log(`crackTimes(128) → ${cracks.length} profiles`);
  process.exit(process.exitCode ?? 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
