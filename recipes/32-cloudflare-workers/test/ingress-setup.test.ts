import { expect, it, vi } from 'vitest';
import type { IngressEnv } from '../src/ingress.ts';

const mocks = vi.hoisted(() => ({ registry: vi.fn(async () => ({})) }));
vi.mock('@dnsid-ai/log-c2sp-tlog', () => ({
  createC2spTlogVerificationRegistry: mocks.registry,
  createFetchBackedC2spResourceFetcher: vi.fn(),
  requiredC2spResourceFetchGuarantees: vi.fn(),
}));
vi.mock('@dnsid-ai/sdk', async importOriginal => ({
  ...await importOriginal<typeof import('@dnsid-ai/sdk')>(),
  createIdentityVerifier: vi.fn(() => ({ verifyDomain: vi.fn() })),
}));

it('shares setup and rebuilds only when verifier settings change', async () => {
  const { default: ingress } = await import('../src/ingress.ts');
  const env = {
    ORIGIN_URL: 'https://origin.example',
    ORIGIN_SECRET: 'test-secret',
    DNSID_LOG_POLICY_URL: 'https://log.example/policy',
  } as IngressEnv;
  const call = () => ingress.fetch(new Request('https://ingress.example/test'), env);

  await Promise.all([call(), call()]);
  expect(mocks.registry).toHaveBeenCalledTimes(1);

  env.ORIGIN_SECRET = 'updated-secret';
  env.ORIGIN_URL = 'https://other.example';
  await call();
  expect(mocks.registry).toHaveBeenCalledTimes(1);

  env.DNSID_DOH_URL = 'https://dns.example/query';
  await call();
  expect(mocks.registry).toHaveBeenCalledTimes(2);

  env.DNSID_LOG_POLICY_URL = 'https://other-log.example/policy';
  await call();
  expect(mocks.registry).toHaveBeenCalledTimes(3);
});

it('rejects invalid environment settings before initialization, including with a warm cache', async () => {
  const { default: ingress } = await import('../src/ingress.ts');
  const valid = {
    ORIGIN_URL: 'https://origin.example',
    ORIGIN_SECRET: 'test-secret',
    DNSID_LOG_POLICY_URL: 'https://log.example/policy',
  } as IngressEnv;
  await ingress.fetch(new Request('https://ingress.example/test'), valid);
  const setups = mocks.registry.mock.calls.length;

  for (const [field, value] of [
    ['ORIGIN_URL', 'http://origin.example'],
    ['ORIGIN_URL', 'not-a-url'],
    ['DNSID_LOG_POLICY_URL', 'http://log.example/policy'],
    ['DNSID_DOH_URL', 'ftp://dns.example'],
    ['DNSID_DOH_URL', ''],
    ['ORIGIN_SECRET', ''],
  ]) {
    await expect(ingress.fetch(new Request('https://ingress.example/test'), {
      ...valid, [field]: value,
    })).rejects.toThrow(`Invalid ingress configuration: ${field}`);
  }
  expect(mocks.registry).toHaveBeenCalledTimes(setups);
});
