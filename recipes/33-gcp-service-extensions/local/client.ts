// LOCAL MODE ONLY. Sends requests through the local edges (local/stack.ts) and prints what came back, one JSON object
// per line; local/recipe.ts judges them. It signs as the DNSid Local agent it runs as:
//
//   dnsid local agent ensure --state <state> --upstream <url> <fqdn> -- node local/client.ts <run directory> <case>…
//
// The CLI sets DNSID_DOMAIN and DNSID_CONFIG_DIR for the agent; the key is found the way the SDK's own environment
// constructor finds it (`private.jwk` or `private.pem` in DNSID_CONFIG_DIR, or else in its `<fqdn>` subdirectory) and
// read with the SDK's LocalKeyProvider. It is never printed, copied or written. Signing is the SDK's RFC 9421 profile
// (scripts/live/signer.ts), and requests go over TLS pinned to the edge's own certificate (scripts/live/http.ts).
//
// Cases: `unsigned` (needs no identity), `signed-get`, `signed-head`, `tampered` (signed for one query, sent with
// another), `forged-headers` (signed, with caller-supplied x-dnsid-* identity headers) and `untrusted-governance`
// (signed, through the edge whose verifier doesn't trust DNSid Local's governance).

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

import { fingerprintOf } from '../scripts/lib/pinned-tls.ts';
import { authorityOf, h1, type Exchange, type Target } from '../scripts/live/http.ts';
import { createSigner, type Signer } from '../scripts/live/signer.ts';
import { READY_FILE, type Ready } from './stack.ts';

export const CASES = ['unsigned', 'signed-get', 'signed-head', 'tampered', 'forged-headers', 'untrusted-governance'] as const;
export type CaseName = (typeof CASES)[number];

export const FORGED_IDENTITY = 'forged-identity.test';

export interface Observation {
  readonly case: CaseName;
  /** The identity that signed, or null for `unsigned`. */
  readonly domain: string | null;
  readonly edge: 'trusted' | 'untrusted';
  readonly status: number | null;
  readonly cacheControl: string | null;
  readonly body: string;
  readonly error: string | null;
}

export class ClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClientError';
  }
}

/** Where the SDK's environment constructor looks for an identity's key: the directory itself, or its `<fqdn>` child. */
export function keyDirectory(configDir: string, domain: string): string {
  if (existsSync(join(configDir, 'private.jwk')) || existsSync(join(configDir, 'private.pem'))) return configDir;
  return join(configDir, domain);
}

export function normalizedDomain(value: string | undefined): string {
  const domain = value?.trim().toLowerCase().replace(/\.$/, '');
  if (domain === undefined || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+test$/.test(domain)) {
    throw new ClientError('DNSID_DOMAIN is not a DNSid Local (.test) identity: run under `dnsid local agent ensure`');
  }
  return domain;
}

export async function loadAgentSigner(env: Readonly<Record<string, string | undefined>>): Promise<Signer> {
  const domain = normalizedDomain(env['DNSID_DOMAIN']);
  const configDir = env['DNSID_CONFIG_DIR']?.trim();
  if (configDir === undefined || configDir === '') throw new ClientError('DNSID_CONFIG_DIR is not set: run under `dnsid local agent ensure`');
  let keyProvider;
  try {
    keyProvider = await LocalKeyProvider.fromDirectory(keyDirectory(configDir, domain));
  } catch {
    throw new ClientError(`the agent's private key could not be read from its DNSid Local directory`);
  }
  return createSigner(domain, keyProvider);
}

export function readReady(runDir: string): Ready {
  let ready: Ready;
  try {
    ready = JSON.parse(readFileSync(join(runDir, READY_FILE), 'utf8')) as Ready;
  } catch {
    throw new ClientError('the local stack is not running (no ready.json): run `make run` first');
  }
  return ready;
}

function targetOf(ready: Ready, edge: 'trusted' | 'untrusted'): Target {
  const { port, certificatePem } = ready.edges[edge];
  return { host: ready.host, port, pin: { certificatePem, fingerprint256: fingerprintOf(certificatePem) } };
}

/** One case: the request it sends and the edge it goes to. */
export async function runCase(name: CaseName, ready: Ready, signer: Signer | undefined): Promise<Observation> {
  const edge = name === 'untrusted-governance' ? 'untrusted' : 'trusted';
  const target = targetOf(ready, edge);
  const base = `https://${authorityOf(target)}`;
  const method = name === 'signed-head' ? 'HEAD' : 'GET';
  let path = '/accounts';
  let headers: [string, string][] = [];
  if (name !== 'unsigned') {
    if (signer === undefined) throw new ClientError(`case ${name} needs an identity: run under \`dnsid local agent ensure\``);
    if (name === 'tampered') {
      headers = await signer.sign(method, `${base}/accounts?view=summary`);
      path = '/accounts?view=everything';
    } else {
      headers = await signer.sign(method, `${base}${path}`);
    }
    if (name === 'forged-headers') {
      headers.push(['x-dnsid-verified-domain', FORGED_IDENTITY], ['x-dnsid-governance-id', FORGED_IDENTITY]);
    }
  }
  const exchange: Exchange = await h1(target, { method, path, headers, timeoutMs: 15_000 });
  return {
    case: name,
    domain: signer?.domain ?? null,
    edge,
    status: exchange.status ?? null,
    cacheControl: exchange.headers['cache-control'] ?? null,
    body: exchange.body.slice(0, 4096),
    error: exchange.error ?? null,
  };
}

async function main(): Promise<void> {
  const [runDir, ...names] = process.argv.slice(2);
  try {
    if (runDir === undefined || names.length === 0) throw new ClientError(`usage: node local/client.ts <run directory> <${CASES.join('|')}>…`);
    const unknown = names.find((name) => !(CASES as readonly string[]).includes(name));
    if (unknown !== undefined) throw new ClientError('unknown case');
    const ready = readReady(runDir);
    const signer = names.every((name) => name === 'unsigned') ? undefined : await loadAgentSigner(process.env);
    for (const name of names as CaseName[]) process.stdout.write(`${JSON.stringify(await runCase(name, ready, signer))}\n`);
  } catch (error) {
    process.stderr.write(`client: ${error instanceof ClientError ? error.message : 'failed'}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.main) await main();
