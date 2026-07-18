// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  site: 'https://faegit.github.io',
  base: '/faevault-site',
  output: 'static',
  trailingSlash: 'always',
});
