// Demo Bank: the protected, read-only sample API behind the verifier. `node server.ts` serves it on 0.0.0.0 at Cloud
// Run's `PORT` (8080 when unset). Importing this module starts nothing; only running it as the entry point does.
//
// Two routes, `/accounts` (the caller's accounts) and `/accounts/<id>` (one of them), GET and HEAD only, with synthetic
// data: no real person, account number or identifier. It answers only a request carrying exactly one well-formed
// `x-dnsid-verified-domain` and `x-dnsid-governance-id`, the identity context the verifier sets on a request it lets
// through. What a verified agent may read is Demo Bank's own decision (accountsFor): each verified domain maps to its own
// synthetic accounts, and an account outside that mapping is refused, whichever governance vouched for the caller.
//
// The identity headers count only with the verifier's attestation of them: exactly one `x-dnsid-attestation`, an
// HMAC-SHA256 under the deployment's own key (`DNSID_ATTESTATION_KEY`, which Terraform generates for each deployment and
// gives to the verifier and Demo Bank alone) over the two values and the time, at most ATTESTATION_MAX_AGE_S old
// (src/attestation.ts makes it). Their presence alone authenticates nothing: Google's load balancer has been seen to
// forward requests without evaluating the authorization policy for some minutes after the policy was created, and a
// caller's forged headers would then arrive unremoved. What else keeps direct callers out is the deployment (restricted
// ingress, the default URL disabled, and the authorization policy covering every forwarding rule), which the live tests
// check. See README.md.
//
// Every request gets one structured log record with bounded fields: a locally generated id, the method (when it is one
// this service knows), the route, the status and outcome, and, for an accepted request, the two identity values. Never
// raw headers, signatures, authorization values, the attestation or its key, the path or query string, or exception text.

import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

export const DEFAULT_PORT = 8080;
export const LISTEN_HOST = '0.0.0.0';
export const ACCOUNTS_PATH = '/accounts';
export const VERIFIED_DOMAIN_HEADER = 'x-dnsid-verified-domain';
export const GOVERNANCE_ID_HEADER = 'x-dnsid-governance-id';
export const ATTESTATION_HEADER = 'x-dnsid-attestation';
export const ATTESTATION_KEY_SETTING = 'DNSID_ATTESTATION_KEY';
/** The oldest attestation accepted, and how far ahead of this service's clock one may be (seconds). */
export const ATTESTATION_MAX_AGE_S = 30;
export const ATTESTATION_MAX_FUTURE_S = 5;
/** How long a stop waits for requests in flight before closing every connection. */
export const SHUTDOWN_GRACE_MS = 3_000;

export const BANK = Object.freeze({ bank: 'Demo Bank', synthetic: true });

export interface Account {
  readonly id: string;
  readonly type: 'checking' | 'savings';
  readonly currency: 'USD';
  readonly balance: string;
}

/**
 * Demo Bank's account policy, the application's authorization: the synthetic accounts a verified domain may read. Each
 * domain maps to its own two accounts, derived from the domain name alone, so nothing has to be configured for a new
 * agent and no two agents share an account. A trusted DNSid identity says who the agent is and who is accountable for
 * it; this mapping, not the edge, decides what it may read. Nothing here is, or is derived from, a real account.
 */
export function accountsFor(verifiedDomain: string): readonly Account[] {
  const h = createHash('sha256').update(`demo-bank synthetic accounts\n${verifiedDomain}`).digest('hex');
  const balance = (hex: string) => (Number.parseInt(hex, 16) % 2_000_000 / 100).toFixed(2);
  return Object.freeze([
    Object.freeze({ id: `demo-checking-${h.slice(0, 10)}`, type: 'checking' as const, currency: 'USD' as const, balance: balance(h.slice(20, 28)) }),
    Object.freeze({ id: `demo-savings-${h.slice(10, 20)}`, type: 'savings' as const, currency: 'USD' as const, balance: balance(h.slice(28, 36)) }),
  ]);
}

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
// The same domain-name shape the verifier accepts for a governance ID: at most 253 characters, at least two labels, and
// a final label that isn't all digits.
const DOMAIN = new RegExp(`^(?=.{1,253}$)(?:${LABEL}\\.)+(?=[a-z0-9-]*[a-z])${LABEL}$`);

export type OriginOutcome =
  | 'served'
  | 'identity_missing'
  | 'identity_malformed'
  | 'attestation_missing'
  | 'attestation_invalid'
  | 'attestation_stale'
  | 'account_not_permitted'
  | 'method_not_allowed'
  | 'not_found';

export interface OriginRecord {
  readonly severity: 'INFO';
  readonly event: 'origin_request';
  readonly id: string;
  /** GET or HEAD as received; any other method is recorded as `other`, never echoed. */
  readonly method: 'GET' | 'HEAD' | 'other';
  readonly route: 'accounts' | 'account' | 'other';
  readonly status: number;
  readonly outcome: OriginOutcome;
  readonly verifiedDomain?: string;
  readonly governanceId?: string;
}

export type OriginLogSink = (record: OriginRecord) => void;

export const stdoutOriginLog: OriginLogSink = (record) => void process.stdout.write(`${JSON.stringify(record)}\n`);

type Identity = { verifiedDomain: string; governanceId: string };

/**
 * The identity context: each header exactly once, nonempty, a domain name of at most 253 characters. Counted on the raw
 * header list, since Node joins repeated headers into one value.
 */
export function identityContext(rawHeaders: readonly string[]): Identity | 'identity_missing' | 'identity_malformed' {
  // Matched by name, never by indexing an object with a header name: `constructor` or `__proto__` would find inherited
  // properties.
  const domain: string[] = [];
  const governance: string[] = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = (rawHeaders[i] as string).toLowerCase();
    if (name === VERIFIED_DOMAIN_HEADER) domain.push(rawHeaders[i + 1] as string);
    else if (name === GOVERNANCE_ID_HEADER) governance.push(rawHeaders[i + 1] as string);
  }
  if (domain.length === 0 || governance.length === 0) return 'identity_missing';
  if (domain.length !== 1 || governance.length !== 1) return 'identity_malformed';
  const [verifiedDomain, governanceId] = [domain[0] as string, governance[0] as string];
  if (!DOMAIN.test(verifiedDomain) || !DOMAIN.test(governanceId)) return 'identity_malformed';
  return { verifiedDomain, governanceId };
}

/** The key's form, as the verifier reads it (src/attestation.ts): 32 to 256 base64url characters, whose bytes are the key. */
const KEY_FORM = /^[A-Za-z0-9_-]{32,256}$/;

/** The attestation key from its setting. Throws a StartupError that never repeats the value unless well formed. */
export function attestationKeyFromSetting(value: string | undefined): Buffer {
  if (value === undefined || !KEY_FORM.test(value)) throw new StartupError(`${ATTESTATION_KEY_SETTING} must be set to 32 to 256 characters from A-Z, a-z, 0-9, "-" and "_"`);
  return Buffer.from(value, 'ascii');
}

const ATTESTATION_FORM = /^v1\.([0-9]{1,12})\.([A-Za-z0-9_-]{43})$/;

/**
 * Whether the verifier attested this identity: exactly one `x-dnsid-attestation`, of the form v1.<seconds>.<MAC>, whose
 * MAC is HMAC-SHA256(key, "dnsid-attestation v1\n<seconds>\n<domain>\n<governance>") (compared in constant time), made
 * at most ATTESTATION_MAX_AGE_S before `nowMs` and at most ATTESTATION_MAX_FUTURE_S after it.
 */
export function checkAttestation(
  rawHeaders: readonly string[],
  identity: Identity,
  key: Uint8Array,
  nowMs: number,
): 'attested' | 'attestation_missing' | 'attestation_invalid' | 'attestation_stale' {
  const values: string[] = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if ((rawHeaders[i] as string).toLowerCase() === ATTESTATION_HEADER) values.push(rawHeaders[i + 1] as string);
  }
  if (values.length === 0) return 'attestation_missing';
  if (values.length !== 1) return 'attestation_invalid';
  const form = ATTESTATION_FORM.exec(values[0] as string);
  if (form === null) return 'attestation_invalid';
  const seconds = Number(form[1]);
  const expected = createHmac('sha256', key)
    .update(`dnsid-attestation v1\n${seconds}\n${identity.verifiedDomain}\n${identity.governanceId}`, 'utf8')
    .digest();
  const given = Buffer.from(form[2] as string, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return 'attestation_invalid';
  // Checked after the MAC, so a forged value is always `attestation_invalid`, whatever time it claims.
  const age = Math.floor(nowMs / 1000) - seconds;
  if (age > ATTESTATION_MAX_AGE_S || age < -ATTESTATION_MAX_FUTURE_S) return 'attestation_stale';
  return 'attested';
}

const ERRORS: Record<Exclude<OriginOutcome, 'served'>, { status: number; body: string }> = {
  identity_missing: { status: 403, body: '{"error":"identity_context_required"}' },
  identity_malformed: { status: 403, body: '{"error":"identity_context_invalid"}' },
  attestation_missing: { status: 403, body: '{"error":"identity_attestation_required"}' },
  attestation_invalid: { status: 403, body: '{"error":"identity_attestation_invalid"}' },
  attestation_stale: { status: 403, body: '{"error":"identity_attestation_stale"}' },
  account_not_permitted: { status: 403, body: '{"error":"account_not_permitted"}' },
  method_not_allowed: { status: 405, body: '{"error":"method_not_allowed"}' },
  not_found: { status: 404, body: '{"error":"not_found"}' },
};

function pathOf(url: string | undefined): string {
  const raw = url ?? '';
  const query = raw.indexOf('?');
  return query === -1 ? raw : raw.slice(0, query);
}

function send(request: IncomingMessage, response: ServerResponse, status: number, body: string, extra: Record<string, string> = {}): void {
  const bytes = Buffer.from(body, 'utf8');
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(bytes.length),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extra,
  });
  // HEAD: the same status and headers as GET, and no body.
  response.end(request.method === 'HEAD' ? undefined : bytes);
}

/** `/accounts/<id>`: one path segment of lower-case letters, digits and hyphens. */
const ACCOUNT_PATH = new RegExp(`^${ACCOUNTS_PATH}/([a-z0-9-]{1,64})$`);

/**
 * The request handler: route, then method, then identity context, then the verifier's attestation of it (under
 * `attestationKey`, at `now()`), then Demo Bank's account policy.
 */
export function handler(
  log: OriginLogSink,
  attestationKey: Uint8Array,
  now: () => number = Date.now,
): (request: IncomingMessage, response: ServerResponse) => void {
  if (!(attestationKey instanceof Uint8Array) || attestationKey.length < 32) throw new StartupError('an attestation key of at least 32 bytes is required');
  const key = Buffer.from(attestationKey);
  return (request, response) => {
    const id = randomUUID();
    const method = request.method === 'GET' || request.method === 'HEAD' ? request.method : 'other';
    const path = pathOf(request.url);
    const wanted = ACCOUNT_PATH.exec(path)?.[1];
    const route = path === ACCOUNTS_PATH ? 'accounts' : wanted !== undefined ? 'account' : 'other';
    const record = (status: number, outcome: OriginOutcome, identity?: Identity) =>
      log(Object.freeze({ severity: 'INFO', event: 'origin_request', id, method, route, status, outcome, ...identity }));
    const refuse = (outcome: Exclude<OriginOutcome, 'served'>, extra?: Record<string, string>, identity?: Identity) => {
      const { status, body } = ERRORS[outcome];
      send(request, response, status, body, extra);
      record(status, outcome, identity);
    };
    if (route === 'other') return refuse('not_found');
    if (method === 'other') return refuse('method_not_allowed', { allow: 'GET, HEAD' });
    const identity = identityContext(request.rawHeaders);
    if (typeof identity === 'string') return refuse(identity);
    // An unattested identity is not recorded as the caller's: it is only what the request claimed.
    const attested = checkAttestation(request.rawHeaders, identity, key, now());
    if (attested !== 'attested') return refuse(attested);
    const permitted = accountsFor(identity.verifiedDomain);
    if (route === 'accounts') {
      send(request, response, 200, JSON.stringify({ ...BANK, accounts: permitted, caller: identity }));
      return record(200, 'served', identity);
    }
    // Another agent's account, or none at all: the same refusal, so it says nothing about which accounts exist.
    const account = permitted.find((a) => a.id === wanted);
    if (account === undefined) return refuse('account_not_permitted', undefined, identity);
    send(request, response, 200, JSON.stringify({ ...BANK, account, caller: identity }));
    record(200, 'served', identity);
  };
}

export class StartupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StartupError';
  }
}

/** Cloud Run's `PORT`: absent means 8080; anything but a whole number from 1 to 65535 is refused, never echoed. */
export function portFromSetting(value: string | undefined): number {
  if (value === undefined) return DEFAULT_PORT;
  if (!/^[0-9]{1,5}$/.test(value)) throw new StartupError('PORT is not a port number');
  const port = Number(value);
  if (port < 1 || port > 65_535) throw new StartupError('PORT is not a port number');
  return port;
}

export interface Origin {
  readonly server: Server;
  readonly port: number;
  /** Stops accepting, lets requests in flight finish for up to the grace period, then closes every connection. */
  stop(): Promise<void>;
}

export interface OriginOptions {
  /** The deployment's attestation key (DNSID_ATTESTATION_KEY), shared with the verifier. Required. */
  readonly attestationKey: Uint8Array;
  readonly log?: OriginLogSink;
  readonly shutdownGraceMs?: number;
  /** The clock attestations are judged by; Date.now by default. */
  readonly now?: () => number;
}

/** Builds the server and listens. Rejects with a StartupError whose message names only the port or the missing key. */
export async function listen(host: string, port: number, options: OriginOptions): Promise<Origin> {
  const server = createServer({ requestTimeout: 10_000, headersTimeout: 5_000 }, handler(options.log ?? stdoutOriginLog, options.attestationKey, options.now));
  server.keepAliveTimeout = 5_000;
  await new Promise<void>((resolve, reject) => {
    const failed = () => reject(new StartupError(`could not listen on port ${port}`));
    server.once('error', failed);
    server.listen(port, host, () => {
      server.off('error', failed);
      resolve();
    });
  });
  const grace = options.shutdownGraceMs ?? SHUTDOWN_GRACE_MS;
  let stopping: Promise<void> | undefined;
  return {
    server,
    port: (server.address() as { port: number }).port,
    stop() {
      stopping ??= new Promise<void>((resolve) => {
        const timer = setTimeout(() => server.closeAllConnections(), grace);
        timer.unref();
        server.close(() => {
          clearTimeout(timer);
          resolve();
        });
        server.closeIdleConnections();
      });
      return stopping;
    },
  };
}

function line(record: Record<string, unknown>): string {
  return `${JSON.stringify(record)}\n`;
}

async function main(): Promise<void> {
  let origin: Origin;
  try {
    origin = await listen(LISTEN_HOST, portFromSetting(process.env['PORT']), { attestationKey: attestationKeyFromSetting(process.env[ATTESTATION_KEY_SETTING]) });
  } catch (error) {
    const reason = error instanceof StartupError ? error.message : 'startup failed';
    process.stderr.write(line({ severity: 'ERROR', event: 'origin_startup_failed', reason }));
    process.exitCode = 1;
    return;
  }
  process.stdout.write(line({ severity: 'INFO', event: 'origin_listening', port: origin.port }));
  const stop = () => {
    process.off('SIGTERM', stop);
    process.off('SIGINT', stop);
    void origin.stop().then(() => process.stdout.write(line({ severity: 'INFO', event: 'origin_stopped' })));
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (import.meta.main) await main();
