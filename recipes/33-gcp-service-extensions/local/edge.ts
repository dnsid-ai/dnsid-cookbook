// LOCAL MODE ONLY. The local edge: a LOCAL FORWARDING HARNESS standing where Google's Application Load Balancer stands
// in the deployment. It is NOT Google's load balancer, NOT Envoy and NOT Service Extensions, and running it proves
// nothing about what any of them does. It joins the real verifier and the real Demo Bank the way the plan says the load
// balancer joins them, so the local mode exercises everything this repository's code decides:
//
//   - HTTPS on 127.0.0.1 (HTTP/1.1 and HTTP/2), with a certificate made in memory for 127.0.0.1 (its private key is
//     never written anywhere; the certificate is, so clients can pin it);
//   - a path with a `..` segment is redirected, never forwarded;
//   - every other request's header fields go to the verifier as one ext_proc request-headers message, with the end of
//     stream set when the request carries no content (HTTP/2: the headers frame ended the stream; HTTP/1.1: no
//     Content-Length above 0 and no Transfer-Encoding), over a real gRPC connection, with a 3,000 ms deadline;
//   - a denial is answered with the verifier's own 403; a continuation is forwarded to Demo Bank with its header
//     mutation applied (removals, then sets: tests/support/response-wire.ts's model of Envoy's order);
//   - no answer from the verifier, a non-OK status or anything but one response is a 500, as the load balancer's
//     `fail_open = false`.
//
// What it cannot establish, and the live validation checks instead: how Google's load balancer rewrites or normalizes
// the request (authority, path, query, header case, duplicates), whether it sets the end of stream as assumed, its
// redirect of `..` paths, its timeout and error pages, the authorization policy's coverage of forwarding rules, Cloud
// Run ingress, and every timing.

import { createSecureServer, type Http2SecureServer, type Http2ServerRequest, type Http2ServerResponse } from 'node:http2';
import type { AddressInfo } from 'node:net';

import { selfSignedCertificate } from '../tests/support/local-https.ts';
import { forwardThroughVerifier } from '../tests/support/forwarding-harness.ts';
import { byteClient, type ByteClient } from '../tests/support/grpc-client.ts';
import type { Field } from '../tests/support/signing.ts';

/** The load balancer's callout timeout in the deployment (infra/service). */
export const EDGE_CALLOUT_TIMEOUT_MS = 3_000;

export interface EdgeRecord {
  readonly event: 'edge_request';
  readonly edge: string;
  readonly method: string;
  readonly protocol: 'h2' | 'http/1.1';
  /** What the edge did: redirected (`..`), denied (the verifier's 403), forwarded to Demo Bank, or failed (500). */
  readonly outcome: 'redirected' | 'denied' | 'forwarded' | 'failed';
  readonly status: number;
}

export interface LocalEdge {
  readonly name: string;
  readonly port: number;
  /** The edge's certificate, PEM: the only thing a client should trust for it. */
  readonly certificatePem: string;
  stop(): Promise<void>;
}

export interface EdgeOptions {
  readonly name: string;
  readonly verifierPort: number;
  readonly originPort: number;
  readonly host?: string;
  readonly port?: number;
  readonly log?: (record: EdgeRecord) => void;
}

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'date', 'proxy-connection', 'upgrade']);

export async function startLocalEdge(options: EdgeOptions): Promise<LocalEdge> {
  const host = options.host ?? '127.0.0.1';
  const certificate = selfSignedCertificate(host);
  const client: ByteClient = byteClient(options.verifierPort);
  const log = options.log ?? (() => {});

  const handle = async (req: Http2ServerRequest, res: Http2ServerResponse) => {
    const protocol = req.httpVersion === '2.0' ? 'h2' : 'http/1.1';
    const send = (outcome: EdgeRecord['outcome'], status: number, headers: Record<string, string>, text: string) => {
      log({ event: 'edge_request', edge: options.name, method: req.method, protocol, outcome, status });
      res.writeHead(status, headers);
      if (req.method === 'HEAD') res.end();
      else res.end(text);
    };
    // Content is read and discarded: the verifier sees headers only, as an authorization extension does.
    for await (const _chunk of req);
    const path = req.url;
    if (path.split('?')[0]?.split('/').includes('..')) {
      return send('redirected', 301, { location: new URL(path, `https://${host}`).pathname }, '');
    }
    const authority = protocol === 'h2' ? String(req.headers[':authority'] ?? '') : String(req.headers['host'] ?? '');
    const fields: Field[] = [
      [':method', req.method],
      [':authority', authority],
      [':path', path],
      [':scheme', 'https'],
    ];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = (req.rawHeaders[i] as string).toLowerCase();
      if (name.startsWith(':') || name === 'host') continue;
      fields.push([name, req.rawHeaders[i + 1] as string]);
    }
    const length = req.headers['content-length'];
    const eos =
      protocol === 'h2'
        ? (req.stream as unknown as { endAfterHeaders: boolean }).endAfterHeaders
        : (length === undefined || length === '0') && req.headers['transfer-encoding'] === undefined;
    const result = await forwardThroughVerifier(client, options.originPort, fields, eos, EDGE_CALLOUT_TIMEOUT_MS);
    if (result.kind === 'denied') return send('denied', result.status, { 'cache-control': 'no-store' }, result.reason);
    if (result.kind === 'refused') return send('failed', 500, { 'content-type': 'text/plain' }, 'edge: the verifier did not answer');
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(result.headers)) {
      if (value !== undefined && !HOP_BY_HOP.has(name)) headers[name] = Array.isArray(value) ? value.join(', ') : String(value);
    }
    return send('forwarded', result.status, headers, result.body);
  };

  const server: Http2SecureServer = createSecureServer({ key: certificate.key, cert: certificate.cert, allowHTTP1: true }, (req, res) => {
    handle(req, res).catch(() => {
      log({ event: 'edge_request', edge: options.name, method: req.method, protocol: req.httpVersion === '2.0' ? 'h2' : 'http/1.1', outcome: 'failed', status: 500 });
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('edge: the verifier or Demo Bank could not be reached');
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(options.port ?? 0, host, () => {
        server.off('error', reject);
        resolve();
      });
    });
  } catch (error) {
    client.close();
    throw error;
  }
  const sessions = new Set<{ destroy(): void }>();
  server.on('session', (session) => {
    sessions.add(session);
    session.on('close', () => sessions.delete(session));
  });
  const sockets = new Set<{ destroy(): void }>();
  server.on('secureConnection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return {
    name: options.name,
    port: (server.address() as AddressInfo).port,
    certificatePem: certificate.cert,
    async stop() {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        for (const session of sessions) session.destroy();
        for (const socket of sockets) socket.destroy();
      });
      client.close();
    },
  };
}
