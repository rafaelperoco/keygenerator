// @ts-check
import { defineConfig } from "astro/config";

import tailwindcss from "@tailwindcss/vite";
import react from "@astrojs/react";
import sitemap from "@astrojs/sitemap";

// https://astro.build/config
export default defineConfig({
  site: "https://secretgenerator.org",

  // GitHub Pages serves from the root when a custom domain is set;
  // no `base` is needed.
  output: "static",

  vite: {
    plugins: [tailwindcss()],
  },

  integrations: [
    react(),
    sitemap({
      // Per-subcommand pages and the homepage are the public surface.
      // /llms.txt, /llms-full.txt, /robots.txt, /og-image.png are
      // served as static files and intentionally excluded.
      filter: (page) => {
        const u = new URL(page);
        return (
          u.pathname === "/" ||
          /^\/(password|passphrase|secret|api-key|pin)\/$/.test(u.pathname)
        );
      },
      serialize(item) {
        const u = new URL(item.url);
        if (u.pathname === "/") {
          item.priority = 1.0;
          item.changefreq = "weekly";
        } else {
          item.priority = 0.8;
          item.changefreq = "weekly";
        }
        return item;
      },
    }),
  ],
});
