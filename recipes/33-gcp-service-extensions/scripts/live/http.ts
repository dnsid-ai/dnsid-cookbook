// The live tests' HTTP clients. Requests to the deployment's endpoint go over TLS pinned to its certificate
// (scripts/lib/pinned-tls.ts), as HTTP/1.1 or HTTP/2 chosen by ALPN, with the header list sent exactly as given (repeats
// stay repeats, names keep their case on HTTP/1.1) and the path sent as given (no normalization). Requests to other
// routes (run.app URLs, plain HTTP) use the system's ordinary trust. Every request has a timeout; a failure to connect
// or answer is returned as an outcome, never thrown.

import { connect as h2connect, constants as h2c, type ClientHttp2Session, type IncomingHttpHeaders as H2Headers } from 'node:http2';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import type { TLSSocket } from 'node:tls';

import { pinnedConnectionOptions, type PinnedTls } from '../lib/pinned-tls.ts';

export const MAX_BODY_BYTES = 65_536;

export interface Target {
  /** The endpoint's host: its IP address. */
  readonly host: string;
  readonly port: number;
  readonly pin: PinnedTls;
}

export interface Exchange {
  readonly status?: number;
  /** Response headers, lowercased names, values joined with ", " when repeated. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** The negotiated protocol: http/1.1 or h2. */
  readonly protocol?: string;
  /** Set when there was no HTTP response: a connection, TLS or timeout failure. */
  readonly error?: string;
  readonly ms: number;
}

export interface RequestSpec {
  readonly method: string;
  readonly path: string;
  /** Sent in this order, as given; `host` is added first unless present. */
  readonly headers?: readonly (readonly [string, string])[];
  readonly body?: Buffer;
  /** HTTP/1.1 only: send the body with Transfer-Encoding: chunked (no Content-Length). */
  readonly chunked?: boolean;
  readonly timeoutMs?: number;
}

function flatten(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || name.startsWith(':')) continue;
    out[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return out;
}

/** The authority a client sends, as the signed URL has it: the host, with the port only when it isn't 443. */
export function authorityOf(target: Target): string {
  return target.port === 443 ? target.host : `${target.host}:${target.port}`;
}

function errorText(error: unknown): string {
  const e = error as NodeJS.ErrnoException;
  return `${e.code ?? e.name ?? 'Error'}: ${String(e.message ?? '').slice(0, 160)}`;
}

/** HTTP/1.1 over pinned TLS (ALPN http/1.1). */
export function h1(target: Target, spec: RequestSpec): Promise<Exchange> {
  const started = performance.now();
  const headers = [...(spec.headers ?? [])];
  if (!headers.some(([name]) => name.toLowerCase() === 'host')) headers.unshift(['Host', authorityOf(target)]);
  if (spec.body !== undefined && spec.chunked) headers.push(['Transfer-Encoding', 'chunked']);
  else if (spec.body !== undefined && !headers.some(([name]) => name.toLowerCase() === 'content-length')) {
    headers.push(['Content-Length', String(spec.body.length)]);
  }
  return new Promise((resolve) => {
    let done = false;
    const finish = (exchange: Omit<Exchange, 'ms'>) => {
      if (done) return;
      done = true;
      resolve({ ...exchange, ms: Math.round(performance.now() - started) });
    };
    const options: RequestOptions & { ALPNProtocols: string[] } = {
      ...(pinnedConnectionOptions(target.host, target.pin) as RequestOptions),
      port: target.port,
      method: spec.method,
      path: spec.path,
      // A flat [name, value, …] list: sent in this order, repeats and letter case kept, and no Host added by Node.
      headers: headers.flat() as unknown as Record<string, string>,
      agent: false,
      ALPNProtocols: ['http/1.1'],
      timeout: spec.timeoutMs ?? 15_000,
    };
    const req = httpsRequest(
      options,
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          if (size < MAX_BODY_BYTES) chunks.push(chunk.subarray(0, MAX_BODY_BYTES - size));
          size += chunk.length;
        });
        res.on('end', () =>
          finish({
            status: res.statusCode ?? 0,
            headers: flatten(res.headers),
            body: Buffer.concat(chunks).toString('utf8'),
            protocol: (res.socket as TLSSocket | null)?.alpnProtocol || 'http/1.1',
          }),
        );
        res.on('error', (error) => finish({ headers: {}, body: '', error: errorText(error) }));
      },
    );
    req.on('timeout', () => {
      req.destroy();
      finish({ headers: {}, body: '', error: 'timeout' });
    });
    req.on('error', (error) => finish({ headers: {}, body: '', error: errorText(error) }));
    if (spec.body !== undefined) req.write(spec.body);
    req.end();
  });
}

/**
 * HTTP/2 over pinned TLS (ALPN h2). With a body, the headers frame does not end the stream and no length header is
 * added: the content follows in DATA frames, which is what makes an HTTP/2 GET carry content without a length header.
 */
export function h2(target: Target, spec: RequestSpec): Promise<Exchange> {
  const started = performance.now();
  return new Promise((resolve) => {
    let done = false;
    let session: ClientHttp2Session | undefined;
    const finish = (exchange: Omit<Exchange, 'ms'>) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      session?.close();
      session?.destroy();
      resolve({ ...exchange, ms: Math.round(performance.now() - started) });
    };
    const timer = setTimeout(() => finish({ headers: {}, body: '', error: 'timeout' }), spec.timeoutMs ?? 15_000);
    try {
      session = h2connect(`https://${target.host}:${target.port}`, {
        ...pinnedConnectionOptions(target.host, target.pin),
        ALPNProtocols: ['h2'],
      });
    } catch (error) {
      finish({ headers: {}, body: '', error: errorText(error) });
      return;
    }
    session.on('error', (error) => finish({ headers: {}, body: '', error: errorText(error) }));
    const requestHeaders: Record<string, string | string[]> = {
      [h2c.HTTP2_HEADER_METHOD]: spec.method,
      [h2c.HTTP2_HEADER_PATH]: spec.path,
      [h2c.HTTP2_HEADER_SCHEME]: 'https',
      [h2c.HTTP2_HEADER_AUTHORITY]: authorityOf(target),
    };
    for (const [name, value] of spec.headers ?? []) {
      const key = name.toLowerCase();
      const existing = requestHeaders[key];
      requestHeaders[key] = existing === undefined ? value : [...(Array.isArray(existing) ? existing : [existing]), value];
    }
    const stream = session.request(requestHeaders, { endStream: spec.body === undefined });
    let status: number | undefined;
    let headers: Record<string, string> = {};
    const chunks: Buffer[] = [];
    let size = 0;
    stream.on('response', (h: H2Headers) => {
      status = Number(h[h2c.HTTP2_HEADER_STATUS]);
      headers = flatten(h as Record<string, string | string[] | undefined>);
    });
    stream.on('data', (chunk: Buffer) => {
      if (size < MAX_BODY_BYTES) chunks.push(chunk.subarray(0, MAX_BODY_BYTES - size));
      size += chunk.length;
    });
    stream.on('end', () =>
      finish(
        status === undefined
          ? { headers: {}, body: '', error: 'the stream ended without a response' }
          : { status, headers, body: Buffer.concat(chunks).toString('utf8'), protocol: session?.alpnProtocol ?? 'h2' },
      ),
    );
    stream.on('error', (error) => finish(status === undefined ? { headers: {}, body: '', error: errorText(error) } : { status, headers, body: Buffer.concat(chunks).toString('utf8'), protocol: 'h2' }));
    if (spec.body !== undefined) stream.end(spec.body);
  });
}

/** A request to a URL that isn't the pinned endpoint (run.app, plain HTTP), with the system's ordinary trust. */
export function plain(url: string, spec: Omit<RequestSpec, 'path'>): Promise<Exchange> {
  const started = performance.now();
  const parsed = new URL(url);
  const send = parsed.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve) => {
    let done = false;
    const finish = (exchange: Omit<Exchange, 'ms'>) => {
      if (done) return;
      done = true;
      resolve({ ...exchange, ms: Math.round(performance.now() - started) });
    };
    const req = send(
      {
        host: parsed.hostname,
        port: parsed.port === '' ? undefined : Number(parsed.port),
        method: spec.method,
        path: `${parsed.pathname}${parsed.search}`,
        headers: Object.fromEntries(spec.headers ?? []),
        agent: false,
        timeout: spec.timeoutMs ?? 15_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          if (size < MAX_BODY_BYTES) chunks.push(chunk.subarray(0, MAX_BODY_BYTES - size));
          size += chunk.length;
        });
        res.on('end', () => finish({ status: res.statusCode ?? 0, headers: flatten(res.headers), body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', (error) => finish({ headers: {}, body: '', error: errorText(error) }));
      },
    );
    req.on('timeout', () => {
      req.destroy();
      finish({ headers: {}, body: '', error: 'timeout' });
    });
    req.on('error', (error) => finish({ headers: {}, body: '', error: errorText(error) }));
    req.end();
  });
}

/**
 * Opens a gRPC call to `path` on `url` the way a gRPC client does (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md):
 * an HTTP/2 POST with `content-type: application/grpc` and `te: trailers`, carrying one empty length-prefixed message,
 * then the end of the stream. https URLs use the system's ordinary trust; an http URL is HTTP/2 without TLS (prior
 * knowledge), as a local verifier listens. The answer's trailers (grpc-status, grpc-message) are merged into its headers,
 * so a gRPC server that answered at all can be told from one that didn't.
 */
export function grpcCall(url: string, path: string, timeoutMs = 15_000): Promise<Exchange> {
  const started = performance.now();
  return new Promise((resolve) => {
    let done = false;
    let session: ClientHttp2Session | undefined;
    const finish = (exchange: Omit<Exchange, 'ms'>) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      session?.close();
      session?.destroy();
      resolve({ ...exchange, ms: Math.round(performance.now() - started) });
    };
    const timer = setTimeout(() => finish({ headers: {}, body: '', error: 'timeout' }), timeoutMs);
    const parsed = new URL(url);
    try {
      session = h2connect(parsed.origin);
    } catch (error) {
      finish({ headers: {}, body: '', error: errorText(error) });
      return;
    }
    session.on('error', (error) => finish({ headers: {}, body: '', error: errorText(error) }));
    const stream = session.request({
      [h2c.HTTP2_HEADER_METHOD]: 'POST',
      [h2c.HTTP2_HEADER_PATH]: path,
      [h2c.HTTP2_HEADER_SCHEME]: parsed.protocol === 'https:' ? 'https' : 'http',
      [h2c.HTTP2_HEADER_AUTHORITY]: parsed.host,
      'content-type': 'application/grpc',
      te: 'trailers',
    });
    let status: number | undefined;
    let headers: Record<string, string> = {};
    const chunks: Buffer[] = [];
    let size = 0;
    stream.on('response', (h: H2Headers) => {
      status = Number(h[h2c.HTTP2_HEADER_STATUS]);
      headers = flatten(h as Record<string, string | string[] | undefined>);
    });
    stream.on('trailers', (h: H2Headers) => {
      headers = { ...headers, ...flatten(h as Record<string, string | string[] | undefined>) };
    });
    stream.on('data', (chunk: Buffer) => {
      if (size < MAX_BODY_BYTES) chunks.push(chunk.subarray(0, MAX_BODY_BYTES - size));
      size += chunk.length;
    });
    const settle = () =>
      finish(
        status === undefined
          ? { headers: {}, body: '', error: 'the stream ended without a response' }
          : { status, headers, body: Buffer.concat(chunks).toString('latin1'), protocol: 'h2' },
      );
    stream.on('end', settle);
    stream.on('close', settle);
    stream.on('error', (error) => (status === undefined ? finish({ headers: {}, body: '', error: errorText(error) }) : settle()));
    // One message: not compressed, length 0.
    stream.end(Buffer.from([0, 0, 0, 0, 0]));
  });
}
