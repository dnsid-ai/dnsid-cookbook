import { parseSignatureInput } from '@dnsid-ai/http-signatures';
import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { createIngressHandler, type IngressEnv } from '../src/ingress.ts';
import { createTestEgress } from './signing-fixture.ts';
import { fixtureIdentity, fixtureVerifier, type Fixture } from './fixture.ts';

const BANK = 'https://bank.example';
const ingressEnv = { ORIGIN_URL: 'https://bank-origin.internal', ORIGIN_SECRET: 'origin-secret', DNSID_LOG_POLICY_URL: '', NONCES: (env as unknown as IngressEnv).NONCES };

let enrolled: Fixture, stranger: Fixture;
let originSeen: Request[];
let ingress: (r: Request) => Promise<Response>;
let egressFor: (f: Fixture) => Promise<(r: Request) => Promise<Response>>;

beforeAll(async () => {
  enrolled = await fixtureIdentity('enrolled.example');
  stranger = await fixtureIdentity('stranger.example', 'other.example');
  const { verifier } = fixtureVerifier(enrolled, stranger);
  originSeen = [];
  const origin = async (r: Request) => {
    originSeen.push(r);
    return Response.json({ agent: r.headers.get('DNSid-Agent'), body: r.body ? await r.text() : null });
  };
  const handle = createIngressHandler(verifier, origin as typeof fetch);
  // The egress Worker's outbound fetch reaches the bank's ingress Worker.
  ingress = r => handle(r, ingressEnv);
  egressFor = identity => createTestEgress(identity, ingress);
});

const viaEgress = (path: string, init: RequestInit = {}, token = 'agent-token', destination = BANK) =>
  new Request(`https://egress.example${path}`, {
    ...init, headers: { authorization: `Bearer ${token}`, 'DNSid-Destination': destination, ...init.headers },
  });

describe('request forwarding', () => {
  it('forwards arbitrary paths, methods, queries, and signed bodies for backend policy', async () => {
    const res = await (await egressFor(enrolled))(viaEgress('/transfers?mode=test', { method: 'POST', body: '{"amount":1}' }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ agent: enrolled.domain, body: '{"amount":1}' });
    const seen = originSeen.at(-1)!;
    expect(seen.url).toBe('https://bank-origin.internal/transfers?mode=test');
    expect(seen.method).toBe('POST');
    expect(seen.headers.get('DNSid-Origin-Auth')).toBe('origin-secret');
    expect(seen.headers.has('authorization')).toBe(false);
  });

  it('forwards any verified agent with its accountable entity', async () => {
    const res = await (await egressFor(stranger))(viaEgress('/accounts/1/balance'));
    expect(res.status).toBe(200);
    expect(originSeen.at(-1)!.headers.get('DNSid-Agent')).toBe(stranger.domain);
    expect(originSeen.at(-1)!.headers.get('DNSid-Accountable-Entity')).toBe('other.example');
  });


});

describe('egress signing headers', () => {
  it('replaces caller signatures and digest with a fresh verifiable signature', async () => {
    const body = 'fresh request body';
    const staleDigest = 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:';
    const egress = await createTestEgress(enrolled, async request => {
      const signatures = parseSignatureInput(request.headers.get('Signature-Input')!);
      expect(signatures.size).toBe(1);
      expect(signatures.has('caller')).toBe(false);
      expect(request.headers.get('Signature')).not.toContain('caller=');
      expect(request.headers.get('Content-Digest')).toBeTruthy();
      expect(request.headers.get('Content-Digest')).not.toBe(staleDigest);
      return ingress(request);
    });

    const response = await egress(viaEgress('/resource', {
      method: 'POST',
      body,
      headers: {
        Signature: 'caller=:AQID:',
        'Signature-Input': 'caller=("@method");created=1;keyid="caller"',
        'Content-Digest': staleDigest,
      },
    }));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ agent: enrolled.domain, body });
  });
});

describe('egress destinations', () => {
  it('signs and forwards to a destination without an allowlist', async () => {
    let forwarded: Request | undefined;
    const egress = await createTestEgress(enrolled, async request => {
      forwarded = request;
      return new Response('destination response');
    });
    const response = await egress(viaEgress('/resource?limit=1', {}, 'agent-token', 'https://another.example'));
    expect(await response.text()).toBe('destination response');
    expect(forwarded!.url).toBe('https://another.example/resource?limit=1');
    expect(forwarded!.headers.has('Signature')).toBe(true);
    expect(forwarded!.headers.has('authorization')).toBe(false);
  });

  it.each(['http://service.example', 'data:x', 'file:///tmp/example', 'ftp://service.example'])(
    'rejects non-HTTPS destination %s without forwarding', async destination => {
      let forwarded = false;
      const egress = await createTestEgress(enrolled, async () => {
        forwarded = true;
        return new Response();
      });

      const response = await egress(viaEgress('/resource', {}, 'agent-token', destination));
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: 'destination_required',
        message: 'DNSid-Destination must be an absolute HTTPS URL',
      });
      expect(forwarded).toBe(false);
    },
  );

  it('rejects missing and malformed destinations', async () => {
    const egress = await egressFor(enrolled);
    const missing = viaEgress('/accounts/1/balance');
    missing.headers.delete('DNSid-Destination');
    expect((await egress(missing)).status).toBe(400);
    expect((await egress(viaEgress('/accounts/1/balance', {}, 'agent-token', 'not a URL'))).status).toBe(400);
  });
});

describe('ingress hardening', () => {
  async function captureSigned(path: string, init: RequestInit = {}) {
    let captured!: Request;
    const egress = await createTestEgress(enrolled, async request => {
      captured = request;
      return new Response();
    });
    await egress(viaEgress(path, init));
    return captured;
  }

  it('overwrites caller-supplied identity and origin-auth headers', async () => {
    const signed = await captureSigned('/accounts/1/balance');
    const headers = new Headers(signed.headers);
    headers.set('DNSid-Agent', 'forged.example');
    headers.set('DNSid-Accountable-Entity', 'forged-entity.example');
    headers.set('DNSid-Origin-Auth', 'forged-secret');
    headers.set('DNSid-Custom', 'untrusted');
    const response = await ingress(new Request(signed, { headers }));
    expect(response.status).toBe(200);
    const seen = originSeen.at(-1)!;
    expect(seen.headers.get('DNSid-Agent')).toBe(enrolled.domain);
    expect(seen.headers.get('DNSid-Accountable-Entity')).toBe('customer.example');
    expect(seen.headers.get('DNSid-Origin-Auth')).toBe(ingressEnv.ORIGIN_SECRET);
    expect(seen.headers.has('DNSid-Custom')).toBe(false);
  });

  it('rejects unsigned requests', async () => {
    expect((await ingress(new Request(`${BANK}/accounts/1/balance`))).status).toBe(401);
  });

  it('rejects a replayed signature', async () => {
    const signed = await captureSigned('/accounts/1/balance');
    expect((await ingress(signed.clone())).status).toBe(200);
    const replay = await ingress(signed.clone());
    expect(replay.status).toBe(401);
    expect((await replay.json() as { error: string }).error).toBe('replay');
  });

  it('rejects a tampered body', async () => {
    const signed = await captureSigned('/support', { method: 'POST', body: 'original' });
    const tampered = new Request(signed, { body: 'tampered' });
    const res = await ingress(tampered);
    expect(res.status).toBe(401);
  });

  it('rejects a second signature (replay-ambiguity guard)', async () => {
    const signed = await captureSigned('/accounts/1/balance');
    const headers = new Headers(signed.headers);
    headers.set('Signature-Input', `${headers.get('Signature-Input')}, sig2=("@method");created=1;keyid="x#y";nonce="n"`);
    headers.set('Signature', `${headers.get('Signature')}, sig2=:AAAA:`);
    expect((await ingress(new Request(signed, { headers }))).status).toBe(401);
  });

  it('verifies 25 concurrent cold requests', async () => {
    const { verifier, stats } = fixtureVerifier(enrolled);
    const handle = createIngressHandler(verifier, (async () => new Response('ok')) as typeof fetch);
    const requests = await Promise.all(Array.from({ length: 25 }, () => captureSigned('/accounts/1/balance')));
    const results = await Promise.all(requests.map(r => handle(r, ingressEnv)));
    expect(results.map(r => r.status)).toEqual(Array(25).fill(200));
    expect(stats.dnsLookups).toBeLessThan(25); // in-flight verifications are shared, not repeated
  });
});
