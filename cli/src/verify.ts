// Verification helpers used during postinstall. Two layers:
//
// 1. SHA-256 against the `checksums.txt` published by goreleaser. This
//    is the minimum integrity check; it ensures the archive matches what
//    the GitHub release advertised.
//
// 2. Cosign keyless signature on `checksums.txt.sig` / `checksums.txt.pem`,
//    when the `cosign` binary is on PATH. This is the strongest tier:
//    proves the checksums file was produced by the
//    secretgenerator GitHub Actions workflow (Sigstore Fulcio + GitHub
//    OIDC). When cosign is not present we still trust the SHA-256 because
//    the file came from the same HTTPS GitHub host that signed it; the
//    cosign step is a defense-in-depth, not the primary chain.
//
// We deliberately do NOT bundle a cosign binary in the npm package; we
// fall through gracefully so machines without cosign still get the
// installer to work.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

export class IntegrityError extends Error {}

/** Returns lowercase-hex SHA-256 of a file. */
export function sha256OfFile(p: string): string {
  const h = createHash("sha256");
  h.update(readFileSync(p));
  return h.digest("hex");
}

/** Parses the goreleaser-style checksums.txt:
 *
 *   abc...123  secretgenerator_v2.0.0_linux_amd64.tar.gz
 *
 * Returns a map from filename to lowercase-hex SHA-256. Lines that do not
 * match the shape are silently skipped (the file may contain blank lines
 * or future headers).
 */
export function parseChecksums(text: string): Map<string, string> {
  const m = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+?)\s*$/i);
    if (match) {
      m.set(match[2], match[1].toLowerCase());
    }
  }
  return m;
}

/** Throws IntegrityError when the SHA-256 of `archivePath` does not
 *  match the entry for `archiveName` in `checksums.txt`. */
export function verifyChecksum(
  archivePath: string,
  archiveName: string,
  checksumsText: string
): string {
  const map = parseChecksums(checksumsText);
  const expected = map.get(archiveName);
  if (!expected) {
    throw new IntegrityError(
      `checksums.txt has no entry for ${archiveName}. ` +
        "Was the release truncated, or is this an unexpected version tag?"
    );
  }
  const got = sha256OfFile(archivePath);
  if (got !== expected) {
    throw new IntegrityError(
      `SHA-256 mismatch for ${archiveName}: got ${got}, want ${expected}. ` +
        "The archive was modified in transit. Aborting installation."
    );
  }
  return expected;
}

/** Returns true when `cosign` is on PATH. Used to gate the keyless
 *  signature verification step (best-effort, optional). */
export function cosignAvailable(): boolean {
  const r = spawnSync("cosign", ["version"], { stdio: "ignore" });
  return r.status === 0;
}

/** Verifies cosign keyless signature on checksums.txt. The certificate
 *  identity is constrained to the secretgenerator release workflow; only
 *  files signed by that identity pass. Returns true on success, false
 *  (with a console.warn) on any failure — failure is non-fatal because
 *  the SHA-256 chain already authenticated the archive. */
export function verifyCosign(
  checksumsPath: string,
  certPath: string,
  sigPath: string
): boolean {
  const args = [
    "verify-blob",
    "--certificate",
    certPath,
    "--signature",
    sigPath,
    "--certificate-identity-regexp",
    "https://github.com/rafaelperoco/secretgenerator/.github/workflows/release.yml@refs/tags/v.*",
    "--certificate-oidc-issuer",
    "https://token.actions.githubusercontent.com",
    checksumsPath,
  ];
  const r = spawnSync("cosign", args, { encoding: "utf8" });
  if (r.status !== 0) {
    console.warn(
      `[secretgenerator] cosign verification failed (non-fatal): ${(r.stderr || "").trim()}`
    );
    return false;
  }
  return true;
}
