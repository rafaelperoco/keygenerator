#!/usr/bin/env node
// Generates web/public/releases.xml — an RSS 2.0 feed of GitHub releases
// for rafaelperoco/secretgenerator. Subscribers (RSS readers, Datadog
// release-tracking integrations, security teams watching for CVE
// disclosures) get updates without polling the GitHub UI.
//
// We hit the GitHub REST API anonymously: 60 requests/hour/IP without
// auth, plenty for a once-per-deploy build. If we ever exceed that,
// bump GITHUB_TOKEN into the env and the existing fetch call picks it
// up automatically through the Authorization header check below.

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webRoot = path.resolve(__dirname, "..");
const publicDir = path.join(webRoot, "public");

const REPO = "rafaelperoco/secretgenerator";
const SITE = "https://secretgenerator.org";
const FEED_URL = `${SITE}/releases.xml`;
const TITLE = "secretgenerator releases";
const DESCRIPTION =
  "Release announcements for the auditable random credential generator. Each item links to the signed GitHub release and its release notes.";

main().catch((err) => {
  console.error("[build-releases-rss] failed:", err.message);
  // Soft-fail: an empty feed is better than blocking deploy on a
  // GitHub API hiccup.
  writeFileSync(path.join(publicDir, "releases.xml"), emptyFeed());
  console.error("[build-releases-rss] wrote empty placeholder feed");
});

async function main() {
  const releases = await fetchReleases();
  const xml = buildFeed(releases);
  writeFileSync(path.join(publicDir, "releases.xml"), xml);
  console.log(`[build-releases-rss] wrote releases.xml (${releases.length} releases)`);
}

async function fetchReleases() {
  const url = `https://api.github.com/repos/${REPO}/releases?per_page=50`;
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "secretgenerator-rss-builder",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
  }
  const all = await res.json();
  // Skip drafts. Pre-releases are kept (they are still real, signed
  // builds) but flagged in the title.
  return all.filter((r) => !r.draft);
}

function buildFeed(releases) {
  const now = new Date().toUTCString();
  const items = releases.map(itemXml).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>${escape(TITLE)}</title>
    <link>${SITE}/</link>
    <atom:link href="${FEED_URL}" rel="self" type="application/rss+xml" />
    <description>${escape(DESCRIPTION)}</description>
    <language>en-us</language>
    <lastBuildDate>${now}</lastBuildDate>
    <generator>secretgenerator/web/scripts/build-releases-rss.mjs</generator>
${items}
  </channel>
</rss>
`;
}

function itemXml(r) {
  const tag = r.tag_name;
  const titlePrefix = r.prerelease ? "[pre-release] " : "";
  const title = `${titlePrefix}${tag}${r.name && r.name !== tag ? ` — ${r.name}` : ""}`;
  const pub = new Date(r.published_at || r.created_at).toUTCString();
  const url = r.html_url;
  // The GitHub release body is markdown. Wrap the whole thing in CDATA
  // and let the reader render it as plain text — turning it into HTML
  // here would mean pulling in a markdown renderer for one feature.
  const body = r.body || "";
  return `    <item>
      <title>${escape(title)}</title>
      <link>${url}</link>
      <guid isPermaLink="true">${url}</guid>
      <pubDate>${pub}</pubDate>
      <dc:creator>${escape(r.author?.login || "rafaelperoco")}</dc:creator>
      <description><![CDATA[${body}]]></description>
    </item>`;
}

function escape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function emptyFeed() {
  const now = new Date().toUTCString();
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escape(TITLE)}</title>
    <link>${SITE}/</link>
    <atom:link href="${FEED_URL}" rel="self" type="application/rss+xml" />
    <description>${escape(DESCRIPTION)}</description>
    <language>en-us</language>
    <lastBuildDate>${now}</lastBuildDate>
  </channel>
</rss>
`;
}
