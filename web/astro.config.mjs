// @ts-check
import { defineConfig } from "astro/config";

import tailwindcss from "@tailwindcss/vite";
import react from "@astrojs/react";

// https://astro.build/config
export default defineConfig({
  site: "https://secretgenerator.org",

  // GitHub Pages serves from the root when a custom domain is set;
  // no `base` is needed.
  output: "static",

  vite: {
    plugins: [tailwindcss()],
  },

  integrations: [react()],
});