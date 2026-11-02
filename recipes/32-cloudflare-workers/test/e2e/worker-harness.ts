import { readFileSync } from 'node:fs';
import { Resolver } from 'node:dns/promises';
import { createHash } from 'node:crypto';
import { convertV4MiniflareOptions, Miniflare } from 'miniflare';
import { Agent, fetch as undiciFetch } from 'undici';
import { startTestOrigin } from './origin.ts';

export const ENROLLED = 'enrolled.test';
export const STRANGER = 'stranger.test';
export const REVOKED = 'revoked.test';
const INGRESS = 'https://ingress.test';
const DOH = 'https://doh.local.invalid/dns-query';
const TOKENS = {
  'egress-enrolled': 'enrolled-token',
  'egress-stranger': 'stranger-token',
  'egress-revoked': 'revoked-token',
};

export async function createWorkerHarness(local: { state: string; dnsPort: number; proxyPort: number; logPolicyUrl: string }) {
  const STATE = local.state;
  const origin = await startTestOrigin('origin-secret');
  const dns = new Resolver();
  dns.setServers([`127.0.0.1:${local.dnsPort}`]);
  const localTls = new Agent({
    connect: {
      ca: readFileSync(`${STATE}/certs/root-ca.pem`),
      lookup: (_host, _opts, cb) => cb(null, [{ address: '127.0.0.1', family: 4 }]),
    },
  });

  let mf: Miniflare;
  let lastSignedRequest: Request | undefined;
  const originSeen: { agent: string | null; entity: string | null; auth: string | null }[] = [];

  /** Everything the Workers fetch goes through here. Unknown hosts are refused (no internet needed). */
  async function outbound(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (process.env.E2E_TRACE) console.log(`      → ${request.method} ${url.href.slice(0, 110)}`);
    if (url.href.startsWith(DOH)) return dohJson(url.searchParams.get('name')!);
    if (url.origin === INGRESS) {
      lastSignedRequest = request.clone();
      return (await mf.getWorker('ingress')).fetch(request as never) as unknown as Response;
    }
    if (url.hostname === 'test-origin.internal') {
      originSeen.push({ agent: request.headers.get('dnsid-agent'), entity: request.headers.get('dnsid-accountable-entity'), auth: request.headers.get('dnsid-origin-auth') });
      const originUrl = new URL(url.pathname + url.search, origin.url);
      const response = await undiciFetch(originUrl, {
        method: request.method,
        headers: Object.fromEntries(request.headers),
        body: request.body ? new Uint8Array(await request.arrayBuffer()) : undefined,
        redirect: 'manual',
      });
      return new Response(await response.arrayBuffer(), {
        status: response.status,
        headers: response.headers as never,
      });
    }
    if (url.hostname.endsWith('.test')) {
      url.port = String(local.proxyPort);
      const res = await undiciFetch(url, { method: request.method, headers: request.headers as never, redirect: 'manual', dispatcher: localTls });
      return new Response(await res.arrayBuffer(), { status: res.status, headers: res.headers as never });
    }
    return new Response(`blocked outbound ${url.host}`, { status: 502 });
  }

  async function dohJson(name: string): Promise<Response> {
    try {
      const txt = await dns.resolveTxt(name.replace(/\.$/, ''));
      const quote = (s: string) => `"${s.replace(/[\\"]/g, c => `\\${c}`)}"`;
      return Response.json({ Status: 0, AD: false, Answer: txt.map(strings => ({ name, type: 16, TTL: 60, data: strings.map(quote).join(' ') })) });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOTFOUND' || (e as NodeJS.ErrnoException).code === 'ENODATA') return Response.json({ Status: 3, AD: false });
      throw e;
    }
  }

  const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
  const privateJwk = (fqdn: string) => readFileSync(`${STATE}/agents/${fqdn}/private.jwk`, 'utf8');
  const common = { modules: true, compatibilityDate: '2026-10-01', compatibilityFlags: ['nodejs_compat'], outboundService: outbound };
  const agentDomains = {
    'egress-enrolled': ENROLLED,
    'egress-stranger': STRANGER,
    'egress-revoked': REVOKED,
  };
  const egressWorker = {
    ...common, name: 'egress', scriptPath: '.out/egress/egress.js',
    bindings: {
      DNSID_AGENTS: JSON.stringify(Object.fromEntries((Object.keys(agentDomains) as Array<keyof typeof agentDomains>).map(id => {
        const domain = agentDomains[id];
        return [domain, { privateJwk: privateJwk(domain), tokenHashes: [sha256(TOKENS[id])] }];
      }))),
    },
  };

  mf = new Miniflare(convertV4MiniflareOptions({
    workers: [
      {
        ...common, name: 'ingress', scriptPath: '.out/ingress/ingress.js',
        durableObjects: { NONCES: { className: 'NonceStore', useSQLite: true } },
        bindings: {
          DNSID_LOG_POLICY_URL: local.logPolicyUrl,
          DNSID_DOH_URL: DOH,
          ORIGIN_SECRET: 'origin-secret',
          ORIGIN_URL: 'https://test-origin.internal',
        },
      },
      egressWorker,
    ],
  }));

  const viaEgress = async (worker: keyof typeof TOKENS, path: string, init: RequestInit = {}) =>
    (await mf.getWorker('egress')).fetch(`https://egress.test${path}`, {
      ...init, headers: { authorization: `Bearer ${TOKENS[worker]}`, 'DNSid-Destination': INGRESS, ...(init.headers as object) },
    } as never) as unknown as Response;

  try {
    await mf.ready;
  } catch (error) {
    await mf.dispose();
    await localTls.close();
    await origin.close();
    throw error;
  }

  return {
    viaEgress,
    originSeen,
    originUrl: origin.url,
    async unsigned() {
      return mf.dispatchFetch(`${INGRESS}/echo`) as unknown as Response;
    },
    async replayLastRequest() {
      if (!lastSignedRequest) {
        throw new Error('No signed request to replay');
      }
      return (await mf.getWorker('ingress')).fetch(lastSignedRequest.clone() as never) as unknown as Response;
    },
    async close() {
      try {
        await mf.dispose();
      } finally {
        try {
          await localTls.close();
        } finally {
          await origin.close();
        }
      }
    },
  };
}
