import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { DNSSECState } from '@dnsid-ai/protocol';
import { dohResolver } from '../../src/shared/dns.ts';
import { workersFetchJson } from '../../src/shared/fetch-json.ts';

const settings = env as unknown as Record<string, string>;

function setting(name: string): string {
  const value = settings[name];
  if (!value) {
    throw new Error(`Set ${name} before running optional live checks`);
  }
  return value;
}

// Live network checks: they validate behavior inside workerd, not fixtures.
describe('live services', () => {
  it('DoH reports DNSSEC VALID for a signed zone', async () => {
    const [records, state] = await dohResolver().fetchTXT('_dmarc.cloudflare.com');
    expect(state).toBe(DNSSECState.VALID);
    expect(records[0]!.strings.join('')).toMatch(/^v=DMARC1/);
  });

  it('DoH reports FAILED for a bogus zone', async () => {
    const [, state] = await dohResolver().fetchTXT('dnssec-failed.org');
    expect(state).toBe(DNSSECState.FAILED);
  });

  it('fetchJson enforces host pinning and returns bounded JSON', async () => {
    const fetchJson = workersFetchJson();
    const { data, tlsCert } = await fetchJson('https://registry.npmjs.org/@dnsid-ai%2fsdk/latest', { allowedHost: 'registry.npmjs.org' });
    expect(data).toHaveProperty('version');
    expect(tlsCert.notAfter.getTime()).toBeGreaterThan(Date.now());
    await expect(fetchJson('https://registry.npmjs.org/', { allowedHost: 'other.example' })).rejects.toThrow(/not permitted/);
  });

  it('C2SP log verification registry loads under nodejs_compat', async () => {
    const { createC2spTlogVerificationRegistry, createFetchBackedC2spResourceFetcher, requiredC2spResourceFetchGuarantees } = await import('@dnsid-ai/log-c2sp-tlog');
    const registry = await createC2spTlogVerificationRegistry({
      policyUrl: setting('DNSID_LOG_POLICY_URL'),
      checkpointMaxAge: 86_400_000,
      resourceFetcher: createFetchBackedC2spResourceFetcher(fetch, requiredC2spResourceFetchGuarantees()),
    });
    expect(registry).toBeTruthy();
  });

  it('verifies a real C2SP checkpoint signature with node:crypto Ed25519', async () => {
    const { parseCheckpoint, parseSignedNoteVerifierKey, verifyCheckpointSignature, leafHash } = await import('@dnsid-ai/log-c2sp-tlog');
    const checkpoint = parseCheckpoint(await (await fetch(setting('DNSID_CHECKPOINT_URL'))).text());
    const key = parseSignedNoteVerifierKey(setting('DNSID_CHECKPOINT_KEY'));
    expect(verifyCheckpointSignature(checkpoint, key)).toBe(true);
    expect(leafHash(new Uint8Array([1])).length).toBe(32);
  });
});
