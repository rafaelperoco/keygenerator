// Node-side loader for keygen.wasm. Mirrors web/src/lib/wasm.ts but reads
// the binary from disk and uses globalThis instead of window.
//
// TinyGo emits a wasm_exec.js shim that, when evaluated, attaches a `Go`
// constructor to the host global. We evaluate it in a fresh module scope
// using the vm module so we don't pollute the user's globalThis.

import { readFileSync } from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// dist/ sits at mcp/dist/, wasm/ sits at mcp/wasm/.
const wasmDir = path.resolve(__dirname, "..", "wasm");

export type CrackTimeEstimate = {
  profile_id: string;
  description: string;
  seconds: number;
  human_readable: string;
};

export type Result = {
  schema_version: number;
  password?: string;
  length: number;
  charset_id: string;
  charset_size: number;
  entropy_bits: number;
  excluded_count?: number;
  excluded_sha256?: string;
  required_classes?: string;
  algorithm: string;
  subcommand: string;
  version: string;
  commit: string;
  build_date: string;
  request_id: string;
  timestamp_utc: string;
  warnings?: string[];
  crack_time_estimates?: CrackTimeEstimate[];
};

type ResultOrError = Result | { error: string };

export type AttackerProfile = {
  id: string;
  description: string;
  guesses_per_second: number;
};

export type GoBindings = {
  password: (opts: Record<string, unknown>) => ResultOrError;
  secret: (opts: Record<string, unknown>) => ResultOrError;
  passphrase: (opts: Record<string, unknown>) => ResultOrError;
  apiKey: (opts: Record<string, unknown>) => ResultOrError;
  pin: (opts: Record<string, unknown>) => ResultOrError;
  entropy: (opts: Record<string, unknown>) => ResultOrError;
  charsets: () => string[];
  attackerProfiles: () => AttackerProfile[];
  crackTimes: (bits: number) => CrackTimeEstimate[];
  schemaVersion: number;
  version: string;
};

let bindings: GoBindings | null = null;
let initPromise: Promise<GoBindings> | null = null;

/**
 * Load and instantiate the WASM module. Idempotent: subsequent calls
 * return the cached bindings without re-instantiating.
 */
export function loadBindings(): Promise<GoBindings> {
  if (bindings) return Promise.resolve(bindings);
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const execJs = readFileSync(path.join(wasmDir, "wasm_exec.js"), "utf8");

    // wasm_exec.js relies on a few globals that exist in browsers and in
    // recent Node versions but it expects to install Go on the host
    // global. We evaluate it in a sandboxed VM context with our own
    // global and pull `Go` back out.
    type GoCtor = new () => {
      run: (instance: WebAssembly.Instance) => Promise<void>;
      importObject: WebAssembly.Imports;
    };
    type SandboxGlobal = {
      Go?: GoCtor;
      globalThis: Record<string, unknown>;
      [k: string]: unknown;
    };

    const sandbox: SandboxGlobal = {
      // Bridge whatever wasm_exec.js needs from the real globalThis without
      // letting it overwrite ours.
      Go: undefined,
      globalThis: undefined as unknown as Record<string, unknown>,
      console,
      crypto: globalThis.crypto,
      performance: globalThis.performance,
      TextEncoder: globalThis.TextEncoder,
      TextDecoder: globalThis.TextDecoder,
      fetch: globalThis.fetch,
      Date,
      Math,
      Promise,
      // Some shims look for `window`; alias to the sandbox itself.
      window: undefined as unknown as Record<string, unknown>,
    };
    sandbox.globalThis = sandbox as unknown as Record<string, unknown>;
    sandbox.window = sandbox as unknown as Record<string, unknown>;

    vm.createContext(sandbox);
    vm.runInContext(execJs, sandbox, { filename: "wasm_exec.js" });

    if (!sandbox.Go) {
      throw new Error("wasm_exec.js loaded but Go constructor not exposed");
    }

    const go = new sandbox.Go();

    // Compile and instantiate the WASM module.
    const wasmBytes = readFileSync(path.join(wasmDir, "keygen.wasm"));
    const mod = await WebAssembly.instantiate(wasmBytes, go.importObject);

    // TinyGo's main blocks forever to keep the syscall/js callback table
    // alive — do not await. The bindings we want are attached to the
    // sandbox's `secretgen` global synchronously by the time main() runs
    // its first lines.
    void go.run(mod.instance);

    // Yield once so main() registers the bindings before we read them.
    await new Promise((r) => setImmediate(r));

    const sgen = (sandbox as Record<string, unknown>).secretgen as
      | GoBindings
      | undefined;
    if (!sgen) {
      throw new Error("WASM ran but did not expose `secretgen` bindings");
    }
    bindings = sgen;
    return bindings;
  })();

  return initPromise;
}

/** Throw on the {error: ...} shape; return Result on success. */
export function unwrap<T>(r: T | { error: string }): T {
  if (typeof r === "object" && r !== null && "error" in r) {
    throw new Error((r as { error: string }).error);
  }
  return r as T;
}
