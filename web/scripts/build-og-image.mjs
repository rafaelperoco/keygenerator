#!/usr/bin/env node
// Generates web/public/og-image.png — the 1200×630 social-preview card
// referenced from <meta property="og:image"> and <meta name="twitter:image">.
//
// Composition mirrors the site: dark background, IBM Plex Sans wordmark,
// JetBrains Mono sample JSON, accent stripe. Rendered with Satori (HTML/JSX
// to SVG) then rasterized via @resvg/resvg-js. Reproducible at build time.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import https from "node:https";
import satori from "satori";
import { Resvg } from "@resvg/resvg-js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, "..");
const publicDir = path.join(webRoot, "public");
const cacheDir = path.join(webRoot, "node_modules", ".cache", "og-fonts");
mkdirSync(cacheDir, { recursive: true });

const FONTS = [
  {
    name: "IBM Plex Sans",
    weight: 600,
    file: "ibm-plex-sans-600.ttf",
    url: "https://cdn.jsdelivr.net/fontsource/fonts/ibm-plex-sans@latest/latin-600-normal.ttf",
  },
  {
    name: "IBM Plex Sans",
    weight: 400,
    file: "ibm-plex-sans-400.ttf",
    url: "https://cdn.jsdelivr.net/fontsource/fonts/ibm-plex-sans@latest/latin-400-normal.ttf",
  },
  {
    name: "JetBrains Mono",
    weight: 500,
    file: "jetbrains-mono-500.ttf",
    url: "https://cdn.jsdelivr.net/fontsource/fonts/jetbrains-mono@latest/latin-500-normal.ttf",
  },
];

await main();

async function main() {
  const fonts = await Promise.all(FONTS.map(loadFont));
  const svg = await satori(card(), { width: 1200, height: 630, fonts });
  const png = new Resvg(svg, { fitTo: { mode: "width", value: 1200 } })
    .render()
    .asPng();
  writeFileSync(path.join(publicDir, "og-image.png"), png);
  console.log(`[build-og-image] wrote og-image.png (${png.length} bytes)`);
}

async function loadFont({ name, weight, file, url }) {
  const cached = path.join(cacheDir, file);
  let data;
  try {
    data = readFileSync(cached);
  } catch {
    data = await download(url);
    writeFileSync(cached, data);
  }
  return { name, weight, data, style: "normal" };
}

function download(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve(download(res.headers.location));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`download ${url} -> ${res.statusCode}`));
        return;
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
  });
}

// ─── Card composition ──────────────────────────────────────────────────────
//
// Satori accepts a JSX-ish object tree. Layout: full-bleed dark background,
// accent stripe at the top, wordmark + version on the left, JSON sample
// floating on the right with a faint border. Tagline below the wordmark.
function card() {
  const bg = "#0d0e10";
  const fg = "#e6e7e9";
  const mute = "#8a8d92";
  const accent = "#7dd3fc";
  const line = "#1f2125";
  const panel = "#131418";

  const sample = [
    "{",
    '  "schema_version": 1,',
    '  "password": "WH\\\\3x<>E0A#T\'xiC",',
    '  "length": 16,',
    '  "entropy_bits": 104.62,',
    '  "algorithm": "crypto/rand",',
    '  "subcommand": "password"',
    "}",
  ].join("\n");

  return {
    type: "div",
    props: {
      style: {
        width: "1200px",
        height: "630px",
        background: bg,
        color: fg,
        display: "flex",
        flexDirection: "column",
        fontFamily: "IBM Plex Sans",
        position: "relative",
      },
      children: [
        // accent stripe
        {
          type: "div",
          props: {
            style: {
              width: "100%",
              height: "4px",
              background: accent,
              display: "flex",
            },
          },
        },
        // body
        {
          type: "div",
          props: {
            style: {
              flex: "1 1 0",
              display: "flex",
              flexDirection: "row",
              padding: "70px 72px",
              gap: "60px",
              alignItems: "stretch",
              justifyContent: "space-between",
            },
            children: [
              // left column: wordmark + tagline
              {
                type: "div",
                props: {
                  style: {
                    display: "flex",
                    flexDirection: "column",
                    flex: "1 1 0",
                    justifyContent: "space-between",
                  },
                  children: [
                    {
                      type: "div",
                      props: {
                        style: { display: "flex", flexDirection: "column", gap: "20px" },
                        children: [
                          {
                            type: "div",
                            props: {
                              style: {
                                display: "flex",
                                alignItems: "center",
                                gap: "16px",
                              },
                              children: [
                                {
                                  type: "div",
                                  props: {
                                    style: {
                                      width: "30px",
                                      height: "30px",
                                      border: `2px solid ${fg}`,
                                      borderRadius: "4px",
                                      display: "flex",
                                      alignItems: "center",
                                      justifyContent: "center",
                                    },
                                    children: {
                                      type: "div",
                                      props: {
                                        style: {
                                          width: "16px",
                                          height: "16px",
                                          background: fg,
                                        },
                                      },
                                    },
                                  },
                                },
                                {
                                  type: "div",
                                  props: {
                                    style: {
                                      fontSize: "44px",
                                      fontWeight: 600,
                                      letterSpacing: "-1px",
                                      display: "flex",
                                    },
                                    children: "secretgenerator",
                                  },
                                },
                              ],
                            },
                          },
                          {
                            type: "div",
                            props: {
                              style: {
                                fontSize: "12px",
                                color: accent,
                                fontFamily: "JetBrains Mono",
                                textTransform: "uppercase",
                                letterSpacing: "2px",
                                display: "flex",
                              },
                              children: "random credential generation · auditable",
                            },
                          },
                          {
                            type: "div",
                            props: {
                              style: {
                                fontSize: "54px",
                                fontWeight: 600,
                                lineHeight: 1.05,
                                letterSpacing: "-1.5px",
                                marginTop: "12px",
                                display: "flex",
                                flexWrap: "wrap",
                              },
                              children:
                                "A verifiable standard for credentials generated by AI agents.",
                            },
                          },
                        ],
                      },
                    },
                    {
                      type: "div",
                      props: {
                        style: {
                          display: "flex",
                          gap: "16px",
                          fontSize: "16px",
                          color: mute,
                          fontFamily: "JetBrains Mono",
                          alignItems: "center",
                        },
                        children: [
                          {
                            type: "div",
                            props: {
                              style: { display: "flex" },
                              children: "secretgenerator.org",
                            },
                          },
                          {
                            type: "div",
                            props: {
                              style: {
                                width: "4px",
                                height: "4px",
                                background: mute,
                                borderRadius: "999px",
                              },
                            },
                          },
                          {
                            type: "div",
                            props: {
                              style: { display: "flex" },
                              children: "schema v1 · SLSA L3 · cosign",
                            },
                          },
                        ],
                      },
                    },
                  ],
                },
              },
              // right column: JSON sample card
              {
                type: "div",
                props: {
                  style: {
                    width: "440px",
                    border: `1px solid ${line}`,
                    background: panel,
                    borderRadius: "12px",
                    padding: "28px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "16px",
                  },
                  children: [
                    {
                      type: "div",
                      props: {
                        style: {
                          fontSize: "11px",
                          color: mute,
                          fontFamily: "JetBrains Mono",
                          textTransform: "uppercase",
                          letterSpacing: "2px",
                          display: "flex",
                        },
                        children: "response.json · schema v1",
                      },
                    },
                    {
                      type: "div",
                      props: {
                        style: {
                          fontFamily: "JetBrains Mono",
                          fontSize: "16px",
                          lineHeight: 1.55,
                          color: fg,
                          whiteSpace: "pre",
                          display: "flex",
                          flexDirection: "column",
                        },
                        children: sample.split("\n").map((line, i) => ({
                          type: "div",
                          key: i,
                          props: { style: { display: "flex" }, children: line },
                        })),
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
      ],
    },
  };
}
