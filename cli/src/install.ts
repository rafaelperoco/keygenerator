#!/usr/bin/env node
// postinstall hook: download the secretgenerator binary for the current
// platform, verify its integrity, extract it next to dist/run.js so the
// `bin` entry can exec it directly.
//
// Download steps (each fails fast with a clear message):
//   1. Determine the right release version (env override or package.json).
//   2. Compute archive name + URL.
//   3. Fetch the archive, checksums.txt, checksums.txt.sig, checksums.txt.pem.
//   4. Verify the archive's SHA-256 against checksums.txt.
//   5. (Optional) Verify cosign keyless signature on checksums.txt.
//   6. Extract the binary, drop it at <packageRoot>/bin/<binary>.
//   7. Save a marker file at <packageRoot>/bin/.installed so run.js can
//      detect a successful install on subsequent invocations.

import {
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createReadStream } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { ReadableStream } from "node:stream/web";
import { detectAsset, UnsupportedPlatformError } from "./platform.js";
import {
  cosignAvailable,
  verifyChecksum,
  verifyCosign,
  IntegrityError,
} from "./verify.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// dist/install.js is in `cli/dist/`, packageRoot is `cli/`.
const packageRoot = path.resolve(__dirname, "..");
const binDir = path.join(packageRoot, "bin");
const installedMarker = path.join(binDir, ".installed");

const REPO = "rafaelperoco/secretgenerator";

main().catch((err) => {
  // Do not exit 1 — that would block `npm install` for legitimate users
  // (CI environments without network, npm install in tarball-only mode,
  // etc.). Print a clear error so the user can retry on first run.
  console.error(`[secretgenerator] install failed: ${err.message}`);
  console.error(
    `[secretgenerator] you can retry by running \`npx secretgenerator --version\`, ` +
      `or install manually from ${`https://github.com/${REPO}/releases/latest`}.`
  );
  process.exit(0);
});

async function main() {
  if (process.env.SECRETGENERATOR_SKIP_DOWNLOAD === "1") {
    console.log("[secretgenerator] SECRETGENERATOR_SKIP_DOWNLOAD=1; skipping postinstall");
    return;
  }

  let asset;
  try {
    asset = detectAsset();
  } catch (err) {
    if (err instanceof UnsupportedPlatformError) {
      console.warn(`[secretgenerator] ${err.message}`);
      return;
    }
    throw err;
  }

  const version = readVersion();
  const archiveName = `secretgenerator_${stripV(version)}_${asset.suffix}`;
  const baseUrl = `https://github.com/${REPO}/releases/download/${version}`;
  const archiveUrl = `${baseUrl}/${archiveName}`;
  const checksumsUrl = `${baseUrl}/checksums.txt`;
  const sigUrl = `${baseUrl}/checksums.txt.sig`;
  const pemUrl = `${baseUrl}/checksums.txt.pem`;

  console.log(`[secretgenerator] downloading ${archiveName}`);
  const work = mkdtempSync(path.join(tmpdir(), "secretgen-install-"));

  try {
    const archivePath = path.join(work, archiveName);
    const checksumsPath = path.join(work, "checksums.txt");
    const sigPath = path.join(work, "checksums.txt.sig");
    const pemPath = path.join(work, "checksums.txt.pem");

    await Promise.all([
      download(archiveUrl, archivePath),
      download(checksumsUrl, checksumsPath),
      download(sigUrl, sigPath, { allowMissing: true }),
      download(pemUrl, pemPath, { allowMissing: true }),
    ]);

    const checksumsText = readFileSync(checksumsPath, "utf8");
    verifyChecksum(archivePath, archiveName, checksumsText);
    console.log(`[secretgenerator] SHA-256 verified for ${archiveName}`);

    if (existsSync(sigPath) && existsSync(pemPath) && cosignAvailable()) {
      if (verifyCosign(checksumsPath, pemPath, sigPath)) {
        console.log("[secretgenerator] cosign keyless signature verified (Sigstore/Fulcio)");
      }
    } else if (!cosignAvailable()) {
      console.log(
        "[secretgenerator] cosign not on PATH; skipped Sigstore signature check (SHA-256 still verified)"
      );
    }

    mkdirSync(binDir, { recursive: true });
    extract(archivePath, binDir, asset.format);
    const binPath = path.join(binDir, asset.binary);
    if (!existsSync(binPath)) {
      throw new IntegrityError(
        `archive ${archiveName} did not contain ${asset.binary} after extraction`
      );
    }

    if (process.platform !== "win32") {
      // Mark executable.
      const fs = await import("node:fs");
      fs.chmodSync(binPath, 0o755);
    }

    writeFileSync(
      installedMarker,
      JSON.stringify({ version, asset: asset.suffix, installedAt: new Date().toISOString() })
    );
    console.log(`[secretgenerator] installed ${binPath} (release ${version})`);
  } finally {
    try {
      rmSync(work, { recursive: true, force: true });
    } catch {
      // tempdir cleanup is best-effort
    }
  }
}

function readVersion(): string {
  // Allow override (used by smoke tests pinning a specific tag).
  if (process.env.SECRETGENERATOR_VERSION) {
    return process.env.SECRETGENERATOR_VERSION;
  }
  const pkg = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")) as {
    version: string;
  };
  return `v${pkg.version}`;
}

function stripV(v: string): string {
  return v.startsWith("v") ? v.slice(1) : v;
}

async function download(
  url: string,
  out: string,
  opts: { allowMissing?: boolean } = {}
): Promise<void> {
  const res = await fetch(url, { redirect: "follow" });
  if (res.status === 404 && opts.allowMissing) {
    return;
  }
  if (!res.ok || !res.body) {
    throw new Error(`download ${url} -> HTTP ${res.status}`);
  }
  const nodeStream = Readable.fromWeb(res.body as unknown as ReadableStream<Uint8Array>);
  await pipeline(nodeStream, createWriteStream(out));
}

function extract(archive: string, dest: string, format: "tar.gz" | "zip") {
  if (format === "tar.gz") {
    const r = spawnSync("tar", ["-xzf", archive, "-C", dest], {
      stdio: "inherit",
    });
    if (r.status !== 0) throw new Error(`tar exit ${r.status}`);
    return;
  }
  // zip — use Node's built-in zlib + a small inflate; the simplest cross-
  // platform approach on Windows is `tar -xf` which Windows 10+ ships
  // with. Fall back to PowerShell Expand-Archive if tar is missing.
  const r = spawnSync("tar", ["-xf", archive, "-C", dest], {
    stdio: "inherit",
  });
  if (r.status !== 0) {
    const ps = spawnSync(
      "powershell",
      ["-Command", `Expand-Archive -Path '${archive}' -DestinationPath '${dest}' -Force`],
      { stdio: "inherit" }
    );
    if (ps.status !== 0) {
      throw new Error("zip extraction failed: tar and Expand-Archive both errored");
    }
  }
}

// Reading the archive is delegated to `tar` / `Expand-Archive`; the
// pipeline-and-stream imports above are kept because download() uses them.
void createReadStream;
