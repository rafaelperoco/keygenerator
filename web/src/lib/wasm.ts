// Loads the TinyGo-built secretgenerator WASM module and exposes a typed
// surface for React components. The WASM module attaches a `secretgen`
// global; this module wraps it in a Promise-based API.

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

export type PasswordOptions = {
  length?: number;
  charsetId?: string;
  exclude?: string;
  requiredClasses?: string;
  minEntropyBits?: number;
  allowWeak?: boolean;
};

export type SecretOptions = {
  bytes?: number;
  encoding?: string;
  prefix?: string;
  minEntropyBits?: number;
  allowWeak?: boolean;
};

export type PassphraseOptions = {
  words?: number;
  separator?: string;
  capitalize?: boolean;
  digitSuffix?: boolean;
  minEntropyBits?: number;
  allowWeak?: boolean;
};

export type APIKeyOptions = {
  prefix?: string;
  separator?: string;
  length?: number;
  minEntropyBits?: number;
  allowWeak?: boolean;
};

export type PINOptions = {
  digits?: number;
  acknowledgeLowEntropy?: boolean;
  allowWeakPattern?: boolean;
};

export type EntropyOptions = {
  password: string;
};

export type AttackerProfile = {
  id: string;
  description: string;
  guesses_per_second: number;
};

type GoBindings = {
  password: (opts: PasswordOptions) => ResultOrError;
  secret: (opts: SecretOptions) => ResultOrError;
  passphrase: (opts: PassphraseOptions) => ResultOrError;
  apiKey: (opts: APIKeyOptions) => ResultOrError;
  pin: (opts: PINOptions) => ResultOrError;
  entropy: (opts: EntropyOptions) => ResultOrError;
  charsets: () => string[];
  attackerProfiles: () => AttackerProfile[];
  crackTimes: (bits: number) => CrackTimeEstimate[];
  schemaVersion: number;
  version: string;
};

declare global {
  interface Window {
    secretgen?: GoBindings;
    Go?: new () => {
      run: (instance: WebAssembly.Instance) => Promise<void>;
      importObject: WebAssembly.Imports;
    };
  }
}

let loadPromise: Promise<GoBindings> | null = null;

/**
 * Loads keygen.wasm (idempotent). The first call fetches and instantiates;
 * subsequent calls return the cached bindings.
 */
export function loadWasm(basePath = "/"): Promise<GoBindings> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("loadWasm: not in a browser environment"));
  }
  if (loadPromise) return loadPromise;

  loadPromise = (async () => {
    // Inject wasm_exec.js if not already loaded.
    if (!window.Go) {
      await new Promise<void>((resolve, reject) => {
        const s = document.createElement("script");
        s.src = `${basePath.replace(/\/$/, "")}/wasm_exec.js`;
        s.onload = () => resolve();
        s.onerror = () => reject(new Error("failed to load wasm_exec.js"));
        document.head.appendChild(s);
      });
    }
    if (!window.Go) {
      throw new Error("wasm_exec.js loaded but window.Go undefined");
    }

    const go = new window.Go();
    const wasmUrl = `${basePath.replace(/\/$/, "")}/keygen.wasm`;
    const result = await WebAssembly.instantiateStreaming(
      fetch(wasmUrl),
      go.importObject
    );

    // Don't await go.run — TinyGo's main blocks forever to keep callbacks alive.
    void go.run(result.instance);

    // Wait one microtask for the module's main() to set up window.secretgen.
    await new Promise((r) => setTimeout(r, 0));

    if (!window.secretgen) {
      throw new Error("WASM loaded but window.secretgen not set");
    }
    return window.secretgen;
  })();

  return loadPromise;
}

/** Throws on the {error: "..."} shape; returns Result on success. */
export function unwrap(r: ResultOrError): Result {
  if ("error" in r) throw new Error(r.error);
  return r;
}
