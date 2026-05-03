// Maps Node's process.platform / process.arch to the asset filenames
// goreleaser produces for secretgenerator releases. The mapping must match
// .goreleaser.yaml's archive name template:
//   {{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}.{tar.gz|zip}

import os from "node:os";

export type Asset = {
  /** Release archive name without the leading project_version_ prefix. */
  suffix: string;
  /** "tar.gz" or "zip" — determines extraction strategy. */
  format: "tar.gz" | "zip";
  /** Binary name inside the archive (no extension on POSIX, .exe on Windows). */
  binary: string;
};

export class UnsupportedPlatformError extends Error {
  constructor(platform: string, arch: string) {
    super(
      `secretgenerator: no prebuilt release for ${platform}/${arch}. ` +
        "Supported: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64. " +
        "If your platform is unsupported, install from source via " +
        "`go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest`."
    );
  }
}

export function detectAsset(): Asset {
  const platform = process.platform;
  const arch = process.arch;
  switch (`${platform}/${arch}`) {
    case "linux/x64":
      return { suffix: "linux_amd64.tar.gz", format: "tar.gz", binary: "secretgenerator" };
    case "linux/arm64":
      return { suffix: "linux_arm64.tar.gz", format: "tar.gz", binary: "secretgenerator" };
    case "darwin/x64":
      return { suffix: "darwin_amd64.tar.gz", format: "tar.gz", binary: "secretgenerator" };
    case "darwin/arm64":
      return { suffix: "darwin_arm64.tar.gz", format: "tar.gz", binary: "secretgenerator" };
    case "win32/x64":
      return { suffix: "windows_amd64.zip", format: "zip", binary: "secretgenerator.exe" };
    default:
      throw new UnsupportedPlatformError(platform, arch);
  }
}

/** Where the downloaded binary is cached on disk. Honors NPM-style local
 * install layouts (the npm package's own dir) since postinstall runs there. */
export function cacheDir(packageRoot: string): string {
  return packageRoot;
}

export function homedirSafe(): string {
  try {
    return os.homedir();
  } catch {
    return "/tmp";
  }
}
