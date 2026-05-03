#!/usr/bin/env node
// `npx secretgenerator <args>` entry point.
//
// On first run after install, the binary lives at <packageRoot>/bin/.
// This wrapper simply execs it with the user's argv. We pass the user's
// stdio through unchanged so JSON pipelines, audit logs, and TTY-aware
// behavior all work transparently.
//
// If the postinstall step did not run (some npm install configurations,
// CI containers without network), we fall back to invoking install on
// demand the first time the binary is missing. This makes the package
// resilient to npm's `--ignore-scripts`.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { detectAsset, UnsupportedPlatformError } from "./platform.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const binDir = path.join(packageRoot, "bin");

main().catch((err) => {
  console.error(`secretgenerator: ${err.message}`);
  process.exit(1);
});

async function main() {
  let asset;
  try {
    asset = detectAsset();
  } catch (err) {
    if (err instanceof UnsupportedPlatformError) {
      console.error(err.message);
      process.exit(2);
    }
    throw err;
  }

  const binary = path.join(binDir, asset.binary);
  if (!existsSync(binary)) {
    // Lazy install: --ignore-scripts users only pay the cost on first run.
    console.error(
      "[secretgenerator] binary not found; running install (this happens once per machine)"
    );
    const installScript = path.join(__dirname, "install.js");
    await runChild(process.execPath, [installScript], "inherit");
    if (!existsSync(binary)) {
      throw new Error(
        `binary still missing at ${binary} after install; check earlier output for the reason`
      );
    }
  }

  const status = await runChild(binary, process.argv.slice(2), "inherit");
  process.exit(status);
}

function runChild(cmd: string, args: string[], stdio: "inherit"): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio,
      // Forward signals so Ctrl-C in npx propagates to the child.
      windowsHide: true,
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) {
        // Re-raise the signal to the parent so shell-level exit code
        // semantics (130 for SIGINT, etc.) are preserved.
        process.kill(process.pid, signal);
      }
      resolve(code ?? 0);
    });
  });
}
