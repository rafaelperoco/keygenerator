import { useEffect, useRef, useState } from "react";
import {
  loadWasm,
  unwrap,
  type AttackerProfile,
  type CrackTimeEstimate,
  type Result,
} from "../lib/wasm";

type Subcommand = "password" | "passphrase" | "secret" | "api-key" | "pin";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; result: Result; cracks: CrackTimeEstimate[] };

const DEFAULTS: Record<Subcommand, () => Promise<Result>> = {
  password: async () => {
    const m = await loadWasm();
    return unwrap(
      m.password({
        length: 24,
        charsetId: "alphanum-symbols-v1",
        requiredClasses: "lower,upper,digit,symbol",
        minEntropyBits: -1,
      })
    );
  },
  passphrase: async () => {
    const m = await loadWasm();
    return unwrap(m.passphrase({ words: 8, separator: "-" }));
  },
  secret: async () => {
    const m = await loadWasm();
    return unwrap(m.secret({ bytes: 32, encoding: "base64url" }));
  },
  "api-key": async () => {
    const m = await loadWasm();
    return unwrap(
      m.apiKey({ prefix: "sk", separator: "_", length: 32 })
    );
  },
  pin: async () => {
    const m = await loadWasm();
    return unwrap(m.pin({ digits: 6, acknowledgeLowEntropy: true }));
  },
};

const SUBCOMMAND_LABEL: Record<Subcommand, string> = {
  password: "password",
  passphrase: "passphrase",
  secret: "secret",
  "api-key": "api-key",
  pin: "pin",
};

const SUBCOMMAND_HINT: Record<Subcommand, string> = {
  password: "20+ chars, all classes, ~140 bits — generic high-entropy password",
  passphrase: "8 EFF words, ~103 bits — Reinhold's secure-through-2050 line",
  secret: "32 bytes, 256 bits, base64url — recommended for AI agents and APIs",
  "api-key": "sk_<32 base62>, ~190 bits — Stripe-style format",
  pin: "6 digits, ~20 bits — PINs are intrinsically weak; safe only with rate-limited verifiers",
};

export default function Generator() {
  const [active, setActive] = useState<Subcommand>("password");
  const [state, setState] = useState<State>({ kind: "loading" });
  const [copied, setCopied] = useState<"password" | "json" | null>(null);
  const [profiles, setProfiles] = useState<AttackerProfile[]>([]);
  const liveRegion = useRef<HTMLDivElement>(null);

  // Generate on mount and whenever the active subcommand changes.
  useEffect(() => {
    let cancelled = false;
    setState({ kind: "loading" });
    (async () => {
      try {
        const m = await loadWasm();
        if (!cancelled && profiles.length === 0) {
          setProfiles(m.attackerProfiles());
        }
        const result = await DEFAULTS[active]();
        if (cancelled) return;
        const cracks = m.crackTimes(result.entropy_bits);
        setState({ kind: "ready", result, cracks });
      } catch (err) {
        if (!cancelled) {
          setState({
            kind: "error",
            message: err instanceof Error ? err.message : String(err),
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [active]);

  // Reset copied indicator after 2s.
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(null), 1800);
    return () => clearTimeout(t);
  }, [copied]);

  async function regenerate() {
    setState({ kind: "loading" });
    try {
      const m = await loadWasm();
      const result = await DEFAULTS[active]();
      const cracks = m.crackTimes(result.entropy_bits);
      setState({ kind: "ready", result, cracks });
      if (liveRegion.current) {
        liveRegion.current.textContent = "regenerated";
      }
    } catch (err) {
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function copyPassword() {
    if (state.kind !== "ready" || !state.result.password) return;
    await navigator.clipboard.writeText(state.result.password);
    setCopied("password");
  }

  async function copyJSON() {
    if (state.kind !== "ready") return;
    await navigator.clipboard.writeText(JSON.stringify(state.result, null, 2));
    setCopied("json");
  }

  return (
    <div className="grid gap-4">
      {/* Tabs */}
      <div role="tablist" aria-label="Generator type" className="flex flex-wrap gap-1 text-sm">
        {(Object.keys(SUBCOMMAND_LABEL) as Subcommand[]).map((key) => (
          <button
            key={key}
            role="tab"
            aria-selected={active === key}
            onClick={() => setActive(key)}
            className={
              "px-3 py-1.5 rounded-md font-mono text-xs transition " +
              (active === key
                ? "bg-[var(--color-fg)] text-[var(--color-bg)]"
                : "border border-[var(--color-line)] text-[var(--color-mute)] hover:text-[var(--color-fg)] hover:border-[var(--color-fg)]/40")
            }
          >
            {SUBCOMMAND_LABEL[key]}
          </button>
        ))}
      </div>

      <p className="text-xs text-[var(--color-mute)]">{SUBCOMMAND_HINT[active]}</p>

      {/* Output */}
      <div className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] p-4 sm:p-5 min-w-0">
        {state.kind === "loading" && (
          <div className="font-mono text-sm text-[var(--color-mute)] flex items-center gap-3">
            <span className="inline-block h-2 w-2 rounded-full bg-[var(--color-accent)] animate-pulse" />
            generating in your browser…
          </div>
        )}
        {state.kind === "error" && (
          <div className="font-mono text-sm text-[var(--color-bad)]">
            error: {state.message}
          </div>
        )}
        {state.kind === "ready" && (
          <div className="grid gap-4">
            <div className="grid gap-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[10px] uppercase tracking-wider text-[var(--color-mute)] font-mono shrink-0">
                  output
                </span>
                <div className="flex items-center gap-3 sm:gap-2 shrink-0">
                  <button
                    onClick={regenerate}
                    className="text-xs sm:text-[11px] font-mono text-[var(--color-mute)] hover:text-[var(--color-fg)] active:text-[var(--color-fg)] transition py-1"
                    aria-label="regenerate using browser CSPRNG"
                    title="generate again (uses your browser CSPRNG)"
                  >
                    <span className="sm:hidden">↻</span>
                    <span className="hidden sm:inline">↻ regenerate</span>
                  </button>
                  <button
                    onClick={copyPassword}
                    className="text-xs sm:text-[11px] font-mono text-[var(--color-mute)] hover:text-[var(--color-fg)] active:text-[var(--color-fg)] transition py-1"
                    aria-label="copy generated credential"
                  >
                    {copied === "password" ? "✓ copied" : "copy"}
                  </button>
                </div>
              </div>
              <div className="font-mono text-sm sm:text-base md:text-lg break-all leading-relaxed text-[var(--color-fg)] select-all">
                {state.result.password}
              </div>
            </div>

            {/* On mobile: 2 stats per row, charset + schema collapse into a
                single line each below. On md+, all four side-by-side. */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 border-t border-[var(--color-line)] text-xs font-mono">
              <Stat
                label="entropy"
                value={
                  <>
                    <b>{state.result.entropy_bits.toFixed(1)}</b>{" "}
                    <span className="text-[var(--color-mute)]">bits</span>
                  </>
                }
              />
              <Stat
                label="length"
                value={
                  <>
                    {state.result.length}
                    <span className="text-[var(--color-mute)]">
                      {state.result.subcommand === "passphrase" ? " words" : " chars"}
                    </span>
                  </>
                }
              />
              <div className="col-span-2 md:col-span-1">
                <Stat
                  label="charset"
                  value={<span className="break-all">{state.result.charset_id}</span>}
                />
              </div>
              <div className="col-span-2 md:col-span-1">
                <Stat
                  label="schema"
                  value={
                    <>
                      v{state.result.schema_version}
                      <span className="text-[var(--color-mute)] block md:inline md:before:content-['_·_'] break-all">
                        {state.result.algorithm}
                      </span>
                    </>
                  }
                />
              </div>
            </div>

            <EntropyBar bits={state.result.entropy_bits} />

            {state.result.warnings && state.result.warnings.length > 0 && (
              <div className="border-t border-[var(--color-line)] pt-3 grid gap-1">
                {state.result.warnings.map((w, i) => (
                  <p key={i} className="text-xs text-[var(--color-warn)] font-mono">
                    ⚠ {w}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Threat models — list on mobile, table on >=sm */}
      {state.kind === "ready" && state.cracks.length > 0 && (
        <details className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] min-w-0">
          <summary className="cursor-pointer px-4 sm:px-5 py-3 text-xs font-mono uppercase tracking-wider text-[var(--color-mute)] hover:text-[var(--color-fg)]">
            time to break (5 attacker profiles)
          </summary>
          <div className="px-4 sm:px-5 pb-5">
            {/* Mobile: stacked rows */}
            <div className="grid gap-3 sm:hidden">
              {state.cracks.map((c) => {
                const profile = profiles.find((p) => p.id === c.profile_id);
                return (
                  <div key={c.profile_id} className="border-t border-[var(--color-line)] pt-3 text-xs font-mono">
                    <div className="text-[var(--color-fg)] break-all">{c.profile_id}</div>
                    {profile && (
                      <div className="text-[10px] text-[var(--color-mute)] mt-0.5">
                        {profile.description}
                      </div>
                    )}
                    <div className="mt-2 flex items-center justify-between gap-3">
                      <span className="text-[var(--color-mute)] text-[11px] shrink-0">
                        {profile ? formatRate(profile.guesses_per_second) : "—"}
                      </span>
                      <span className="text-[var(--color-fg)] text-right break-words">
                        {c.human_readable}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
            {/* Desktop: table */}
            <table className="hidden sm:table w-full text-xs font-mono">
              <thead>
                <tr className="text-[var(--color-mute)] text-left">
                  <th className="py-2 font-normal">model</th>
                  <th className="py-2 font-normal">guesses/sec</th>
                  <th className="py-2 font-normal">expected time</th>
                </tr>
              </thead>
              <tbody>
                {state.cracks.map((c) => {
                  const profile = profiles.find((p) => p.id === c.profile_id);
                  return (
                    <tr key={c.profile_id} className="border-t border-[var(--color-line)]">
                      <td className="py-2 pr-4 align-top">
                        <div className="text-[var(--color-fg)]">{c.profile_id}</div>
                        {profile && (
                          <div className="text-[10px] text-[var(--color-mute)] mt-0.5 max-w-md whitespace-normal">
                            {profile.description}
                          </div>
                        )}
                      </td>
                      <td className="py-2 pr-4 align-top text-[var(--color-mute)]">
                        {profile ? formatRate(profile.guesses_per_second) : "—"}
                      </td>
                      <td className="py-2 align-top text-[var(--color-fg)]">
                        {c.human_readable}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {/* JSON */}
      {state.kind === "ready" && (
        <details className="rounded-lg border border-[var(--color-line)] bg-[var(--color-panel)] min-w-0">
          <summary className="cursor-pointer px-4 sm:px-5 py-3 text-xs font-mono uppercase tracking-wider text-[var(--color-mute)] hover:text-[var(--color-fg)]">
            response.json — schema v{state.result.schema_version}
          </summary>
          <div className="px-4 sm:px-5 pb-5">
            <div className="flex justify-end mb-2">
              <button
                onClick={copyJSON}
                className="text-[11px] font-mono text-[var(--color-mute)] hover:text-[var(--color-fg)] transition"
              >
                {copied === "json" ? "✓ copied" : "copy json"}
              </button>
            </div>
            <pre className="text-[10px] sm:text-[11px] font-mono leading-relaxed whitespace-pre-wrap break-all sm:break-normal sm:whitespace-pre sm:overflow-x-auto max-w-full">
{JSON.stringify(state.result, null, 2)}
            </pre>
          </div>
        </details>
      )}

      <p className="text-xs text-[var(--color-mute)]">
        generation runs entirely in your browser via WebAssembly compiled from
        the same Go code that backs the CLI. nothing is sent to any server.
        the WASM bundle is published with the rest of the site under{" "}
        <a
          className="underline decoration-[var(--color-line)] hover:decoration-[var(--color-fg)]"
          href="https://github.com/rafaelperoco/secretgenerator"
          target="_blank"
          rel="noopener"
        >
          rafaelperoco/secretgenerator
        </a>
        .
      </p>

      <div ref={liveRegion} className="sr-only" aria-live="polite" />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-mute)] mb-1">
        {label}
      </div>
      <div>{value}</div>
    </div>
  );
}

function EntropyBar({ bits }: { bits: number }) {
  const max = 256;
  const pct = Math.min(100, (bits / max) * 100);
  // Reference thresholds (NIST/Reinhold-aligned). Each one is "lit" when
  // bits >= threshold. Only render visual ticks above sm; mobile shows
  // a single bar plus a textual band classifier so the layout stays calm.
  const thresholds = [
    { at: 80, lbl: "min" },
    { at: 128, lbl: "strong" },
    { at: 192, lbl: "agent" },
    { at: 256, lbl: "max" },
  ];
  const band =
    bits >= 192
      ? "agent-grade"
      : bits >= 128
      ? "strong"
      : bits >= 80
      ? "minimum acceptable"
      : "weak";
  return (
    <div className="pt-3 border-t border-[var(--color-line)] min-w-0">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] uppercase tracking-wider text-[var(--color-mute)] font-mono">
          entropy band
        </span>
        <span className="text-[10px] font-mono text-[var(--color-fg)]">{band}</span>
      </div>
      <div className="relative h-1.5 bg-[var(--color-line)] rounded-full sm:mb-7">
        <div
          className="absolute inset-y-0 left-0 bg-[var(--color-accent)] rounded-full transition-all"
          style={{ width: pct + "%" }}
        />
        {/* Tick marks only on sm+ to avoid mobile congestion. */}
        <div className="hidden sm:block">
          {thresholds.map((t) => (
            <span
              key={t.at}
              className={
                "absolute -top-1 flex flex-col items-center font-mono text-[9px] " +
                (bits >= t.at ? "text-[var(--color-fg)]" : "text-[var(--color-mute)]")
              }
              style={{
                left: (t.at / max) * 100 + "%",
                transform: t.at === max ? "translateX(-100%)" : "translateX(-50%)",
              }}
            >
              <span className="block h-3.5 w-px bg-current opacity-60" />
              <span className="mt-1 whitespace-nowrap">
                <span className="opacity-70">{t.at}</span>{" "}
                <span className="opacity-50">{t.lbl}</span>
              </span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function formatRate(g: number): string {
  if (g >= 1e15) return (g / 1e15).toFixed(0) + "Pg/s";
  if (g >= 1e12) return (g / 1e12).toFixed(0) + "Tg/s";
  if (g >= 1e9) return (g / 1e9).toFixed(0) + "Gg/s";
  if (g >= 1e6) return (g / 1e6).toFixed(0) + "Mg/s";
  if (g >= 1e3) return (g / 1e3).toFixed(0) + "kg/s";
  return g.toFixed(0) + " g/s";
}
