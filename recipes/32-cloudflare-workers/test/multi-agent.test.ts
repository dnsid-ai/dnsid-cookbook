import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { HttpSignaturesProfile } from '@dnsid-ai/http-signatures';
import { hashToken } from './signing-fixture.ts';
import egress, { type EgressEnv } from '../src/egress.ts';
import { fixtureIdentity, fixtureVerifier, type Fixture } from './fixture.ts';

let first: Fixture;
let second: Fixture;

async function configuration(agents: Record<string, Fixture>): Promise<EgressEnv> {
  const registry: Record<string, { privateJwk: string; tokenHashes: string[] }> = {};
  for (const [id, fixture] of Object.entries(agents)) {
    const digest = await hashToken(`${id}-token`);
    registry[fixture.domain] = { privateJwk: fixture.privateJwk, tokenHashes: [digest] };
  }

  return { DNSID_AGENTS: JSON.stringify(registry) };
}

function request(agent: string) {
  return new Request('https://egress.example/resource', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${agent}-token`,
      'DNSid-Destination': 'https://service.example',
      // Caller-controlled identity claims must not select a signing key.
      'DNSid-Agent': 'other.example',
    },
    body: `body for ${agent}`,
  });
}

function verifyForwarded(...identities: Fixture[]) {
  const { verifier } = fixtureVerifier(...identities);
  const profile = new HttpSignaturesProfile({ domain: 'verifier.example', identityResolver: verifier });
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const outbound = input as Request;
    const identity = await profile.verifySignedHttpRequest(outbound);
    expect(outbound.headers.has('authorization')).toBe(false);
    return Response.json({ domain: identity.domain, body: await outbound.text() });
  });
}

beforeAll(async () => {
  first = await fixtureIdentity('first.example');
  second = await fixtureIdentity('second.example', 'other.example');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('multi-agent egress entrypoint', () => {
  it('keeps identities and keys isolated across concurrent cold and warm requests', async () => {
    verifyForwarded(first, second);
    const env = await configuration({ first, second });

    for (let batch = 0; batch < 2; batch++) {
      await Promise.all(Array.from({ length: 20 }, async (_, index) => {
        const agent = index % 2 === 0 ? 'first' : 'second';
        const response = await egress.fetch(request(agent), env);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({
          domain: agent === 'first' ? first.domain : second.domain,
          body: `body for ${agent}`,
        });
      }));
    }
  });

  it('rejects unknown tokens and tokens for removed agents without forwarding', async () => {
    const outbound = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('must not forward'));
    const env = await configuration({ first });
    expect((await egress.fetch(request('unknown'), env)).status).toBe(401);

    env.DNSID_AGENTS = '{}';
    const response = await egress.fetch(request('first'), env);
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'unauthenticated' });
    expect(outbound).not.toHaveBeenCalled();
  });

  it('supports overlapping tokens and revokes a removed token after a config change', async () => {
    verifyForwarded(first);
    const env = await configuration({ first });
    const other = JSON.parse((await configuration({ replacement: first })).DNSID_AGENTS);
    const registry = JSON.parse(env.DNSID_AGENTS);
    registry[first.domain].tokenHashes.push(other[first.domain].tokenHashes[0]);
    env.DNSID_AGENTS = JSON.stringify(registry);

    expect((await egress.fetch(request('first'), env)).status).toBe(200);
    expect((await egress.fetch(request('replacement'), env)).status).toBe(200);

    registry[first.domain].tokenHashes.shift();
    env.DNSID_AGENTS = JSON.stringify(registry);
    expect((await egress.fetch(request('first'), env)).status).toBe(401);
    expect((await egress.fetch(request('replacement'), env)).status).toBe(200);
  });

  it('rejects a token shared by two agents and malformed token hashes', async () => {
    const outbound = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('must not forward'));
    const env = await configuration({ first, second });
    const registry = JSON.parse(env.DNSID_AGENTS);
    registry[second.domain].tokenHashes = registry[first.domain].tokenHashes;
    env.DNSID_AGENTS = JSON.stringify(registry);
    await expect(egress.fetch(request('first'), env)).rejects.toThrow('cannot belong to multiple agents');

    registry[second.domain].tokenHashes = ['invalid-hash'];
    env.DNSID_AGENTS = JSON.stringify(registry);
    await expect(egress.fetch(request('first'), env)).rejects.toThrow('SHA-256 tokenHashes array');
    expect(outbound).not.toHaveBeenCalled();
  });

  it('rebuilds the cached signer when the configured key changes', async () => {
    const oldFetch = verifyForwarded(first);
    const original = await configuration({ first });
    expect((await egress.fetch(request('first'), original)).status).toBe(200);
    oldFetch.mockRestore();

    const rotated = await fixtureIdentity(first.domain);
    verifyForwarded(rotated);
    const updated = await configuration({ first: rotated });
    expect((await egress.fetch(request('first'), updated)).status).toBe(200);
  });

  it('recovers after invalid key configuration without exposing key contents', async () => {
    const env = await configuration({ first });
    const invalid = JSON.stringify({ [first.domain]: { privateJwk: 'sensitive-invalid-value', tokenHashes: [] } });
    await expect(egress.fetch(request('first'), { ...env, DNSID_AGENTS: invalid }))
      .rejects.toThrow('DNSID_AGENTS contains an invalid signing key');

    verifyForwarded(first);
    expect((await egress.fetch(request('first'), env)).status).toBe(200);
  });
});
