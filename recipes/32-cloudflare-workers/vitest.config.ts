import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { include: ["test/**/*.test.ts"], exclude: ["test/e2e/**"] },
  // Mirrors the wrangler alias: keep the Node-only transport out of workerd.
  resolve: { alias: { '@dnsid-ai/transport': new URL('./src/shims/transport.ts', import.meta.url).pathname } },
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.ingress.jsonc' },
  })],
});
