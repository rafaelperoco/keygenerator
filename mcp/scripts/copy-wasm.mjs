#!/usr/bin/env node
// Build the secretgenerator WASM module and copy it into mcp/wasm/. The web
// site already does this via web/scripts; the MCP package has its own copy
// so npm consumers don't need to install Astro or TinyGo when they `npm
// install @secretgenerator/mcp`.

import { execSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mcpRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(mcpRoot, "..");
const wasmDir = path.join(mcpRoot, "wasm");

mkdirSync(wasmDir, { recursive: true });

const tinygoRoot = (() => {
  try {
    return execSync("tinygo env TINYGOROOT", { encoding: "utf8" }).trim();
  } catch {
    console.error("[copy-wasm] tinygo not available on PATH; skipping WASM build.");
    console.error("[copy-wasm] On a CI runner, ensure TinyGo is installed before npm install.");
    process.exit(0);
  }
})();

const wasmOut = path.join(wasmDir, "keygen.wasm");
const execJsOut = path.join(wasmDir, "wasm_exec.js");

console.log(`[copy-wasm] building keygen.wasm via tinygo (TINYGOROOT=${tinygoRoot})`);
const r = spawnSync(
  "tinygo",
  ["build", "-o", wasmOut, "-target", "wasm", "-no-debug", "./web/wasm"],
  { cwd: repoRoot, stdio: "inherit" }
);
if (r.status !== 0) {
  console.error("[copy-wasm] tinygo build failed");
  process.exit(1);
}

const tinygoExecJs = path.join(tinygoRoot, "targets", "wasm_exec.js");
if (!existsSync(tinygoExecJs)) {
  console.error(`[copy-wasm] could not find wasm_exec.js at ${tinygoExecJs}`);
  process.exit(1);
}
copyFileSync(tinygoExecJs, execJsOut);

console.log(`[copy-wasm] wrote ${wasmOut} and ${execJsOut}`);
