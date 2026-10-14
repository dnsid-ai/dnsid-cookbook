/**
 * publicdata.test: a public data service that answers only DNSid-signed
 * requests. Every request, GET included, must carry an RFC 9421 signature
 * tagged `publicdata-v1` from an agent whose identity verifies and is ACTIVE
 * right now. Each request is logged with the agent that sent it, the
 * accountable entity behind it, and its live status.
 *
 *   npm run publicdata
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { appendFile, mkdir } from 'node:fs/promises';
import { DnsIdTxtRecord, VerificationError, type VerifiedDomain } from '@dnsid-ai/sdk';
import { createDnsidFetch, createDnsResolverFromServer } from '@dnsid-ai/transport';
import { HttpSignaturesProfile } from '@dnsid-ai/http-signatures';
import { createVerifier } from '@dnsid-ai/agent-sdk-plugin/verify';
import { byIso3, countries, SOURCE } from './dataset.ts';
import { ensureAgent, issueAgent, registrationStatus } from '../dnsid-local.ts';

export const SIGNATURE_TAG = 'publicdata-v1';
const DOMAIN = 'publicdata.test';
// The firewall lets DNSid Local's proxy reach only host ports 3101-3104.
const PORT = Number(process.env.PUBLICDATA_PORT ?? 3103);
// Pinned public origin: the proxy terminates TLS, so the request arrives as
// http on localhost, but the signature covers https://publicdata.test.
const PUBLIC_ORIGIN = `https://${DOMAIN}`;
const MAX_BODY = 64 * 1024;
const MAX_AGE_S = 300;
const LOG_FILE = 'logs/publicdata.jsonl';
// Optional allowlist of accountable entities (gi), comma-separated. Unset
// means any ACTIVE DNSid agent may read this public data.
const TRUSTED = process.env.PUBLICDATA_TRUSTED_ENTITIES?.split(',').filter(Boolean);

class Refused extends Error {}

// Replay guard: verification checks freshness, not reuse.
const seen = new Map<string, number>();
function rejectReplay(signatureInput: string) {
  const now = Date.now();
  for (const [k, until] of seen) if (until < now) seen.delete(k);
  const keyid = /keyid="([^"]+)"/.exec(signatureInput)?.[1];
  const nonce = /nonce="([^"]+)"/.exec(signatureInput)?.[1];
  if (!keyid || !nonce) throw new Refused('signature has no keyid or nonce');
  const key = `${keyid} ${nonce}`;
  if (seen.has(key)) throw new Refused('replayed signature');
  seen.set(key, now + (MAX_AGE_S + 5) * 1000);
}

/** The signer the request claims to be, before verification. Only for logging refusals. */
function claimedSigner(headers: Headers): string | undefined {
  return /keyid="([^"#]+)/.exec(headers.get('signature-input') ?? '')?.[1];
}

/**
 * For the log only, never for a decision: the accountable entity (gi) the
 * claimed signer's record names, and the state its status endpoint serves.
 * A revoked agent's key set is gone (HTTP 410), so verification stops before
 * it reaches status; this lookup says why. Nothing here is verified.
 */
async function describeClaimed(domain: string) {
  try {
    const [records] = await createDnsResolverFromServer(process.env.DNSID_DNS_SERVER!).fetchTXT(`_dnsid.${domain}`);
    const record = DnsIdTxtRecord.parse(records[0].strings.join(''));
    const fetchStatus = createDnsidFetch({
      dnsServer: process.env.DNSID_DNS_SERVER,
      caBundlePath: process.env.DNSID_CA_BUNDLE,
      privateAddressHosts: ['.test'],
    });
    const status = await (await fetchStatus(record.su)).json();
    return { claimed_accountable: record.gi, claimed_state: status.state ?? null };
  } catch {
    return { claimed_accountable: null, claimed_state: null };
  }
}

async function toRequest(req: IncomingMessage): Promise<Request> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Refused('body too large');
    chunks.push(chunk);
  }
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers.set(name, value);
  }
  const body = chunks.length ? Buffer.concat(chunks) : undefined;
  return new Request(new URL(req.url ?? '/', PUBLIC_ORIGIN), { method: req.method, headers, body });
}

function route(url: URL): { status: number; body: unknown } {
  if (url.pathname === '/v1/countries') return { status: 200, body: { source: SOURCE, countries } };
  const match = /^\/v1\/health-spending\/([A-Za-z]{3})$/.exec(url.pathname);
  if (match) {
    const row = byIso3.get(match[1].toUpperCase());
    return row
      ? { status: 200, body: { source: SOURCE, ...row } }
      : { status: 404, body: { error: 'unknown country', see: '/v1/countries' } };
  }
  return {
    status: 404,
    body: { error: 'not found', endpoints: ['/v1/countries', '/v1/health-spending/{ISO3}'] },
  };
}

async function log(entry: Record<string, unknown>) {
  const line = JSON.stringify({ time: new Date().toISOString(), ...entry });
  console.log(line);
  await appendFile(LOG_FILE, line + '\n');
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  const path = req.url ?? '/';
  let request: Request | undefined;
  try {
    request = await toRequest(req);
    const sender: VerifiedDomain = await profile.verifySignedHttpRequest(request, {
      requiredTag: SIGNATURE_TAG,
    });
    rejectReplay(request.headers.get('signature-input') ?? '');
    const accountable = sender.record.governanceId();
    if (TRUSTED && !TRUSTED.includes(accountable)) {
      throw new Refused(`accountable entity ${accountable} is not on the allowlist`);
    }

    const { status, body } = route(new URL(request.url));
    await log({
      decision: 'served',
      method: req.method,
      path,
      agent: sender.domain,
      accountable,
      state: sender.registryStatus.state,
      http: status,
    });
    res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  } catch (error) {
    if (!(error instanceof VerificationError || error instanceof Refused)) throw error;
    const claimed = request ? claimedSigner(request.headers) : undefined;
    await log({
      decision: 'refused',
      method: req.method,
      path,
      claimed_agent: claimed ?? null,
      ...(claimed ? await describeClaimed(claimed) : {}),
      reason: error instanceof VerificationError ? error.code : 'Refused',
      detail: error.message,
      http: 401,
    });
    // Generic body for the caller; the reason stays in the server log.
    res.writeHead(401, { 'content-type': 'text/plain' }).end('unauthorized: DNSid verification failed\n');
  }
}

// Bring publicdata.test online so that researchers' verify hooks accept it.
const env = await ensureAgent(DOMAIN, `http://localhost:${PORT}`);
if ((await registrationStatus(DOMAIN, env)) !== 'READY') await issueAgent(DOMAIN, env);
Object.assign(process.env, env);

const profile = new HttpSignaturesProfile({
  domain: DOMAIN,
  identityResolver: await createVerifier(),
});

await mkdir('logs', { recursive: true });
// Listen on all interfaces: DNSid Local's proxy runs in Docker and reaches
// this port through host.docker.internal, not loopback.
createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error('internal error:', error);
    if (!res.headersSent) res.writeHead(500).end();
  });
}).listen(PORT, () => {
  console.error(`${DOMAIN} listening on :${PORT}, requiring tag ${SIGNATURE_TAG}`);
});
