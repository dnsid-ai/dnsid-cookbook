import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { include: ['test/live/**/*.test.ts'] },
  resolve: { alias: { '@dnsid-ai/transport': new URL('./src/shims/transport.ts', import.meta.url).pathname } },
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.ingress.jsonc' },
    miniflare: { bindings: {
      DNSID_LOG_POLICY_URL: process.env.DNSID_LOG_POLICY_URL ?? '',
      DNSID_CHECKPOINT_URL: process.env.DNSID_CHECKPOINT_URL ?? '',
      DNSID_CHECKPOINT_KEY: process.env.DNSID_CHECKPOINT_KEY ?? '',
    } },
  })],
});
