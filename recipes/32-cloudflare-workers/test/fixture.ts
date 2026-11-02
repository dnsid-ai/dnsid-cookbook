import {
  createIdentityVerifier, DNSID_DRAFT01_VERSION, DNSSECState, DnsIdTxtRecord, LogRegistry, toBase64Url,
  type DnsIdJWK, type JsonFetcher, type LoggedStateEvidence, type LogReader,
} from '@dnsid-ai/sdk';

/** A self-contained published DNSid identity: TXT record, JWKS, status and log, all stubbed. */
export async function fixtureIdentity(domain: string, entity = 'customer.example') {
  const op = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey('jwk', op.privateKey) as JsonWebKey;
  const kid = 'op-1';
  const operationalKey = { kty: 'OKP', crv: 'Ed25519', x: privateJwk.x!, kid, alg: 'EdDSA', use: 'sig' } as DnsIdJWK;

  const ek = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
  const ekJwk = await crypto.subtle.exportKey('jwk', ek.publicKey) as JsonWebKey;
  const entityKey = { kty: 'EC', crv: 'P-256', x: ekJwk.x!, y: ekJwk.y!, kid: 'entity-1', alg: 'ES256', use: 'sig' } as DnsIdJWK;

  const record = new DnsIdTxtRecord();
  record.v = DNSID_DRAFT01_VERSION;
  record.gi = entity;
  record.ek = `https://${entity}/entity-jwks.json`;
  record.ku = `https://${domain}/.well-known/jwks.json`;
  record.lr = 'microledger:ref';
  record.su = `https://${domain}/status`;
  record.agentFQDN = domain;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, ek.privateKey, new TextEncoder().encode(record.canonical()));
  record.sg = toBase64Url(new Uint8Array(sig));

  return {
    domain,
    privateJwk: JSON.stringify({ ...privateJwk, kid }),
    txt: record.serialize(),
    jwks: { [record.ku]: { keys: [operationalKey] }, [record.ek]: { keys: [entityKey] } } as Record<string, unknown>,
    statusUrl: record.su,
  };
}

export type Fixture = Awaited<ReturnType<typeof fixtureIdentity>>;

/** A verifier whose DNS, HTTPS and log access are served from fixtures. Counts DNS lookups. */
export function fixtureVerifier(...identities: Fixture[]) {
  const stats = { dnsLookups: 0 };
  const byName = new Map(identities.map(i => [`_dnsid.${i.domain}`, i]));
  const fetchJson: JsonFetcher = async url => {
    const tlsCert = { notAfter: new Date(Date.now() + 3600_000), san: [new URL(url).hostname] };
    for (const i of identities) {
      if (url === i.statusUrl) return { data: { state: 'ACTIVE', lastTransitionAt: new Date().toISOString() }, tlsCert };
      if (url in i.jwks) return { data: i.jwks[url], tlsCert };
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const evidence = (lr: string): LoggedStateEvidence => ({
    logReference: lr, loggedState: 'ACTIVE', historyStart: `${lr}@0`, historyEnd: `${lr}@0`,
    completeThrough: '1', completenessMode: 'test', checkpoint: new Uint8Array(), freshnessTime: new Date(),
  });
  const logReader: LogReader = {
    canonical: async () => new Uint8Array(),
    keyTimestamp: async () => new Date(),
    verifyBilateralBinding: async () => ({ initialOperationalThumbprint: 'i', initialEntityThumbprint: 'e', timestamp: new Date() }),
    verifyOperationalContinuity: async () => {},
    verifyNonRevocation: async () => evidence('microledger:ref'),
    readEvent: async () => { throw new Error('not implemented'); },
    rebuildHistory: async () => [],
  };
  const logRegistry = new LogRegistry();
  logRegistry.register('microledger', () => logReader);
  const verifier = createIdentityVerifier({}, {
    fetchJson,
    logRegistry,
    dnsResolver: {
      fetchTXT: async name => {
        stats.dnsLookups++;
        await scheduler.wait(5); // real I/O, so concurrent requests overlap
        const i = byName.get(name);
        return [i ? [{ strings: [i.txt], ttl: 300 }] : [], DNSSECState.UNSIGNED];
      },
    },
  });
  return { verifier, stats };
}
