// Generate an auditable password from Node.js by shelling out to
// secretgenerator. The CLI prints a stable JSON envelope (schema v1).
//
// This snippet pins the schema version so any future incompatible
// change fails loudly instead of silently changing field shapes.
//
// Install once:
//   npm install -g @secretgenerator/cli
//   # or: brew install rafaelperoco/tap/secretgenerator

import { execFileSync } from "node:child_process";

function generatePassword({ length = 24 } = {}) {
  const out = execFileSync(
    "secretgenerator",
    [
      "password",
      "--json",
      "--require-schema-version=1",
      "--show-crack-time",
      "--length",
      String(length),
      "--charset",
      "alphanum-symbols-v1",
    ],
    { encoding: "utf8" },
  );
  return JSON.parse(out);
}

const result = generatePassword({ length: 24 });
console.log(`password: ${result.password}`);
console.log(`entropy:  ${result.entropy_bits.toFixed(1)} bits`);
const ns = result.crack_time_estimates.find(
  (e) => e.profile_id === "nation-state-v1",
);
console.log(`crack:    ${ns.human_readable} (nation-state)`);
