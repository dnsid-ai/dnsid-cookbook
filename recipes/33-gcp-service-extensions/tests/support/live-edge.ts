// TEST ONLY: a FIXTURE EDGE for the live tests' own tests. It is NOT Google's load balancer and proves nothing about
// what Google does; it lets scripts/live/ run every case against something that behaves the way the plan says the
// deployment should, and against deliberately broken variants, so each case is seen to pass and to fail.
//
// An HTTPS listener on 127.0.0.1 (HTTP/1.1 and HTTP/2, a certificate for 127.0.0.1 made in memory) in front of the real
// verifier gRPC service (offline test identities on a test C2SP log) and the real Demo Bank, joined by the test
// forwarding harness: a path with a `..` segment is redirected; every other request's header fields go to the verifier,
// with the end of stream set when the request carries no content (HTTP/2: the headers frame ended the stream; HTTP/1.1:
// no Content-Length above 0 and no Transfer-Encoding); a denial is answered as is; a continuation is forwarded to Demo
// Bank with its header mutation applied. "Down" answers every request with a 500, as the load balancer does when the
// callout can't answer.

import { randomBytes } from 'node:crypto';
import { createSecureServer, type Http2ServerRequest, type Http2ServerResponse } from 'node:http2';
import type { AddressInfo } from 'node:net';
import type { TestContext } from 'node:test';

import { listen, type OriginRecord } from '../../origin/server.ts';
import { createVerificationRuntime, governancePolicy } from '../../src/identity.ts';
import { createCalloutService, type TerminalRecord } from '../../src/service.ts';
import { forwardThroughVerifier } from './forwarding-harness.ts';
import { byteClient, type ByteClient } from './grpc-client.ts';
import { fixtureBackend, type FixtureLog, type FixtureNetwork } from './identity-fixture.ts';
import { selfSignedCertificate } from './local-https.ts';
import type { Field } from './signing.ts';

/** Ways the fixture edge can be broken, each something a live case must catch. */
export type Fault =
  | 'none'
  | 'forward-everything' // no verification at all: every request reaches Demo Bank
  | 'keep-forged-headers' // the continuation's mutation isn't applied: forged x-dnsid-* headers reach Demo Bank
  | 'forward-dotdot' // a `..` path is normalized and forwarded instead of redirected
  | 'html-denials' // denials come back as an HTML 403 (not the verifier's own)
  | 'cache' // the last 200 is served again to any GET of the same path
  | 'eos-always' // the end of stream is always set, so content goes unnoticed
  | 'decode-for-origin-only'; // the verifier checks the path as sent, Demo Bank gets it with unreserved escapes decoded

export interface FixtureEdge {
  readonly port: number;
  readonly certificate: string;
  readonly originRecords: (OriginRecord & { at: string })[];
  readonly verifierRecords: (TerminalRecord & { at: string })[];
  fault: Fault;
  /** The verifier can't answer: every request gets the load balancer's 500. */
  down: boolean;
  /** Which governance list the verifier is running with. */
  governance: 'trusted' | 'untrusted';
  /**
   * As Google's front end did on the live deployment of 2026-11-14: a request carrying content gets the load balancer's own
   * 400 (HTML) before the verifier is asked. Off by default, so the verifier's own body checks are exercised.
   */
  refusesContent: boolean;
  /** Percent-encoded unreserved characters in the path are decoded before the verifier and Demo Bank see it (RFC 3986). */
  decodesUnreserved: boolean;
  /** Demo Bank's own port: its run.app URL, opened, reaches it directly (no verifier). */
  readonly originPort: number;
  /** Demo Bank's run.app URL is open to every caller (the forged-identity case's change). */
  originExposed: boolean;
  readonly requests: { method: string; path: string; protocol: string }[];
  /** A new revision of the trusted verifier, as a Cloud Run update makes: a fresh instance, nothing cached. */
  newRevision(): Promise<void>;
}

export async function fixtureEdge(
  t: TestContext,
  options: { network: FixtureNetwork; log: FixtureLog; trusted: readonly string[]; untrusted: string },
): Promise<FixtureEdge> {
  const certificate = selfSignedCertificate('127.0.0.1');
  const originRecords: (OriginRecord & { at: string })[] = [];
  const verifierRecords: (TerminalRecord & { at: string })[] = [];
  // The fixture deployment's attestation key, shared by its verifiers and Demo Bank, as Terraform's is.
  const attestationKey = randomBytes(32);
  const origin = await listen('127.0.0.1', 0, { attestationKey, log: (record) => void originRecords.push({ ...record, at: new Date().toISOString() }), shutdownGraceMs: 200 });
  const verifier = async (governance: readonly string[]) => {
    const runtime = createVerificationRuntime({
      governance: governancePolicy(governance.map((governanceId) => ({ governanceId }))),
      backend: fixtureBackend(options.network, options.log),
    });
    const service = createCalloutService({ runtime, attestationKey, log: (record) => void verifierRecords.push({ ...record, at: new Date().toISOString() }), shutdownGraceMs: 200 });
    const port = await service.listen('127.0.0.1', 0);
    return { service, client: byteClient(port) };
  };
  let trusted = await verifier(options.trusted);
  const retired: Awaited<ReturnType<typeof verifier>>[] = [];
  const untrusted = await verifier([options.untrusted]);
  const cache = new Map<string, { status: number; headers: Record<string, string>; body: string }>();

  const edge: FixtureEdge = {
    port: 0,
    certificate: certificate.cert,
    originRecords,
    verifierRecords,
    fault: 'none',
    down: false,
    governance: 'trusted',
    refusesContent: false,
    decodesUnreserved: false,
    originPort: origin.port,
    originExposed: false,
    requests: [],
    async newRevision() {
      retired.push(trusted);
      trusted = await verifier(options.trusted);
    },
  };

  const handle = async (req: Http2ServerRequest, res: Http2ServerResponse) => {
    const protocol = req.httpVersion === '2.0' ? 'h2' : 'http/1.1';
    const path = req.url;
    edge.requests.push({ method: req.method, path, protocol });
    const body: Buffer[] = [];
    for await (const chunk of req) body.push(chunk as Buffer);
    const send = (status: number, headers: Record<string, string>, text: string) => {
      res.writeHead(status, headers);
      if (req.method === 'HEAD') res.end();
      else res.end(text);
    };
    if (edge.down) return send(500, { 'content-type': 'text/html' }, '<html><body>Internal Server Error</body></html>');
    if (path.split('?')[0]?.split('/').includes('..') && edge.fault !== 'forward-dotdot') {
      return send(301, { location: new URL(path, 'https://127.0.0.1').pathname }, '');
    }
    const length = req.headers['content-length'];
    const hasContent =
      protocol === 'h2' ? !(req.stream as unknown as { endAfterHeaders: boolean }).endAfterHeaders : (length !== undefined && length !== '0') || req.headers['transfer-encoding'] !== undefined;
    if (edge.refusesContent && hasContent) return send(400, { 'content-type': 'text/html; charset=UTF-8' }, '<html><title>Error 400 (Bad Request)</title></html>');
    const dotdot = edge.fault === 'forward-dotdot' ? new URL(path, 'https://127.0.0.1').pathname : path;
    const decoded = decodeUnreserved(dotdot);
    const forwardedPath = edge.decodesUnreserved ? decoded : dotdot;
    if (edge.fault === 'cache' && req.method === 'GET' && cache.has(forwardedPath)) {
      const hit = cache.get(forwardedPath) as { status: number; headers: Record<string, string>; body: string };
      return send(hit.status, { ...hit.headers, age: '1' }, hit.body);
    }
    const authority = protocol === 'h2' ? String(req.headers[':authority'] ?? '') : String(req.headers['host'] ?? '');
    const fields: Field[] = [
      [':method', req.method],
      [':authority', authority],
      [':path', forwardedPath],
      [':scheme', 'https'],
    ];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = (req.rawHeaders[i] as string).toLowerCase();
      if (name.startsWith(':') || name === 'host') continue;
      fields.push([name, req.rawHeaders[i + 1] as string]);
    }
    const eos = edge.fault === 'eos-always' || !hasContent;
    let result;
    if (edge.fault === 'forward-everything') {
      result = await forwardViaOrigin(origin.port, fields);
    } else {
      const client: ByteClient = edge.governance === 'trusted' ? trusted.client : untrusted.client;
      result = await forwardThroughVerifier(client, origin.port, fields, eos);
      if (edge.fault === 'decode-for-origin-only' && result.kind === 'forwarded') {
        // The same verified headers, to the same Demo Bank, with a path the verifier didn't check.
        const verified = result.sent.filter(([name]) => name !== 'host').map(([n, v]) => [n, v.toString('latin1')] as Field);
        result = await forwardViaOrigin(origin.port, [[':method', req.method], [':authority', authority], [':path', decoded], ...verified]);
      }
      if (edge.fault === 'keep-forged-headers' && result.kind === 'forwarded') {
        // Send the caller's own x-dnsid-* headers to Demo Bank on top of the verifier's.
        const forged = fields.filter(([name]) => name.startsWith('x-dnsid-'));
        result = await forwardViaOrigin(origin.port, [...fields.filter(([name]) => !name.startsWith('x-dnsid-')), ...forged, ...result.sent.filter(([name]) => name.startsWith('x-dnsid-')).map(([n, v]) => [n, v.toString('latin1')] as Field)]);
      }
    }
    if (result.kind === 'denied') {
      if (edge.fault === 'html-denials') return send(403, { 'content-type': 'text/html' }, '<html>Forbidden</html>');
      return send(result.status, { 'cache-control': 'no-store' }, result.reason);
    }
    if (result.kind === 'refused') return send(500, { 'content-type': 'text/html' }, '<html>refused</html>');
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(result.headers)) {
      if (value !== undefined && !['connection', 'keep-alive', 'transfer-encoding', 'date'].includes(name)) headers[name] = Array.isArray(value) ? value.join(', ') : String(value);
    }
    if (result.status === 200) cache.set(forwardedPath, { status: result.status, headers, body: result.body });
    return send(result.status, headers, result.body);
  };

  const server = createSecureServer({ key: certificate.key, cert: certificate.cert, allowHTTP1: true }, (req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  (edge as { port: number }).port = (server.address() as AddressInfo).port;
  t.after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      // HTTP/2 sessions and HTTP/1.1 sockets left open by clients are closed with the server.
      setTimeout(resolve, 500).unref();
    });
    for (const v of [...retired, trusted, untrusted]) v.client.close();
    for (const v of [...retired, trusted, untrusted]) await v.service.shutdown();
    await origin.stop();
  });
  return edge;
}

/** Straight to Demo Bank, no verifier: the `forward-everything` fault, and the forged-header fault's second leg. */
async function forwardViaOrigin(originPort: number, fields: Field[]) {
  const { request } = await import('node:http');
  const value = (name: string) => String(fields.find(([key]) => key === name)?.[1] ?? '');
  const headers = [['host', value(':authority')], ...fields.filter(([name]) => !name.startsWith(':')).map(([n, v]) => [n, String(v)])].flat();
  return new Promise<{ kind: 'forwarded'; sent: [string, Buffer][]; status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: originPort, method: value(':method'), path: value(':path'), agent: false, headers: headers as unknown as Record<string, string> }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => (body += chunk));
      res.on('end', () => resolve({ kind: 'forwarded', sent: [], status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

const UNRESERVED_ESCAPE = /%(4[1-9A-F]|5[0-9A]|6[1-9A-F]|7[0-9A]|3[0-9]|2D|2E|5F|7E)/gi;

/** The path (not the query) with each percent-encoded unreserved character (RFC 3986, section 2.3) decoded. */
function decodeUnreserved(path: string): string {
  const query = path.indexOf('?');
  const [p, q] = query === -1 ? [path, ''] : [path.slice(0, query), path.slice(query)];
  return p.replace(UNRESERVED_ESCAPE, (_, hex: string) => String.fromCharCode(parseInt(hex, 16))) + q;
}
