// TEST ONLY. Local clients for the callout's gRPC service: a grpc-js client that sends and receives raw message bytes on
// `ExternalProcessor/Process` (so a test can send malformed protobuf and read the exact response bytes), and a bare
// node:http2 client for gRPC framing that grpc-js clients never produce. Both talk to a real listener on loopback.

import { connect, constants as h2 } from 'node:http2';

import { Client, credentials, Metadata, status, type ClientDuplexStream, type StatusObject } from '@grpc/grpc-js';

import { PROCESS_METHOD } from '../../src/ext-proc.ts';

export const PROCESS_PATH = PROCESS_METHOD.path;

const bytesOut = (value: Buffer) => value;
const bytesIn = (value: Buffer) => Buffer.from(value);

export interface RawStream {
  readonly call: ClientDuplexStream<Buffer, Buffer>;
  /** Every response message received, in order, as bytes. */
  readonly responses: Buffer[];
  /** The stream's final status (OK or not); never rejects. */
  readonly status: Promise<StatusObject>;
  /** When the first response arrived, on the monotonic clock. */
  firstResponseAt: number | undefined;
  write(bytes: Uint8Array): void;
  end(): void;
  cancel(): void;
}

export interface ByteClient {
  open(options?: { deadlineMs?: number }): RawStream;
  close(): void;
}

/** A grpc-js client on `host:port` (loopback unless given) that sends and receives `Process` messages as bytes. */
export function byteClient(port: number, options: Record<string, number> = {}, host = '127.0.0.1'): ByteClient {
  const client = new Client(`${host}:${port}`, credentials.createInsecure(), options);
  return {
    open(openOptions = {}) {
      const callOptions = openOptions.deadlineMs === undefined ? {} : { deadline: Date.now() + openOptions.deadlineMs };
      const call = client.makeBidiStreamRequest(PROCESS_PATH, bytesOut, bytesIn, new Metadata(), callOptions);
      const responses: Buffer[] = [];
      const stream: RawStream = {
        call,
        responses,
        firstResponseAt: undefined,
        status: new Promise((resolve) => {
          call.on('status', resolve);
        }),
        write: (bytes) => void call.write(Buffer.from(bytes)),
        end: () => void call.end(),
        cancel: () => call.cancel(),
      };
      call.on('data', (message: Buffer) => {
        stream.firstResponseAt ??= performance.now();
        responses.push(message);
      });
      // A non-OK status is also emitted as an error; the status promise is what tests read.
      call.on('error', () => {});
      return stream;
    },
    close: () => client.close(),
  };
}

/** Sends one message, keeping the send side open, and waits for the stream's status. */
export async function exchange(client: ByteClient, bytes: Uint8Array, options: { halfClose?: boolean; deadlineMs?: number } = {}) {
  const stream = client.open(options.deadlineMs === undefined ? {} : { deadlineMs: options.deadlineMs });
  stream.write(bytes);
  if (options.halfClose === true) stream.end();
  const final = await stream.status;
  return { stream, status: final };
}

/** One gRPC length-prefixed message: compressed flag, 4-byte big-endian length, then the bytes. */
export function grpcFrame(bytes: Uint8Array, options: { compressed?: boolean; declaredLength?: number } = {}): Buffer {
  const prefix = Buffer.alloc(5);
  prefix.writeUInt8(options.compressed === true ? 1 : 0, 0);
  prefix.writeUInt32BE(options.declaredLength ?? bytes.length, 1);
  return Buffer.concat([prefix, Buffer.from(bytes)]);
}

export interface RawHttp2Result {
  readonly headers: Record<string, unknown>;
  readonly trailers: Record<string, unknown>;
  readonly data: Buffer;
  /** grpc-status, from the trailers (or from the headers of a trailers-only response). */
  readonly grpcStatus: number | undefined;
}

/** A bare HTTP/2 POST to the Process path: whatever bytes the test gives, then end of stream. */
export function rawHttp2Call(
  port: number,
  body: Buffer,
  options: { destroyAfterMs?: number; headers?: Record<string, string> } = {},
): Promise<RawHttp2Result | 'destroyed'> {
  return new Promise((resolve, reject) => {
    const session = connect(`http://127.0.0.1:${port}`);
    session.on('error', () => {});
    const request = session.request({
      [h2.HTTP2_HEADER_METHOD]: 'POST',
      [h2.HTTP2_HEADER_PATH]: PROCESS_PATH,
      [h2.HTTP2_HEADER_CONTENT_TYPE]: 'application/grpc',
      te: 'trailers',
      ...options.headers,
    });
    let headers: Record<string, unknown> = {};
    let trailers: Record<string, unknown> = {};
    const chunks: Buffer[] = [];
    request.on('response', (h) => (headers = { ...h }));
    request.on('trailers', (t) => (trailers = { ...t }));
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('error', () => {});
    request.on('close', () => {
      session.close();
      if (options.destroyAfterMs !== undefined) return;
      const raw = trailers['grpc-status'] ?? headers['grpc-status'];
      resolve({ headers, trailers, data: Buffer.concat(chunks), grpcStatus: raw === undefined ? undefined : Number(raw) });
    });
    if (options.destroyAfterMs === undefined) {
      request.end(body);
    } else {
      request.write(body);
      setTimeout(() => {
        session.destroy();
        resolve('destroyed');
      }, options.destroyAfterMs);
    }
    session.on('close', () => reject(new Error('session closed early')));
  });
}

/** The gRPC messages in a response body: [compressed flag, bytes][]. */
export function grpcMessages(data: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let at = 0;
  while (at + 5 <= data.length) {
    const length = data.readUInt32BE(at + 1);
    out.push(data.subarray(at + 5, at + 5 + length));
    at += 5 + length;
  }
  return out;
}

export { status };

export interface BlockedHttp2Call {
  /** Response DATA bytes received on the blocked stream (none, while the window stays closed). */
  readonly data: Buffer[];
  readonly headers: Record<string, unknown>[];
  readonly trailers: Record<string, unknown>[];
  /** The blocked stream's RST_STREAM code once it closed (0: closed normally), or undefined while open. */
  rstCode: number | undefined;
  /** Opens the connection's flow-control windows, so anything still queued for it can be sent. */
  openWindow(): void;
  /** A second, ordinary call on the same connection (after `openWindow`): the whole body, then end of stream. */
  callAgain(body: Buffer): Promise<RawHttp2Result>;
  close(): void;
}

/**
 * A bare HTTP/2 connection whose client advertises a zero flow-control window, so the server can send headers and
 * trailers but no DATA: a response message stays queued at the server until `openWindow`. One call on the Process
 * path, with the request message sent and the send side left open (no deadline, no cancellation).
 */
export function blockedHttp2Call(port: number, body: Buffer): BlockedHttp2Call {
  const session = connect(`http://127.0.0.1:${port}`, { settings: { initialWindowSize: 0 } });
  session.on('error', () => {});
  const headers = () => ({
    [h2.HTTP2_HEADER_METHOD]: 'POST',
    [h2.HTTP2_HEADER_PATH]: PROCESS_PATH,
    [h2.HTTP2_HEADER_CONTENT_TYPE]: 'application/grpc',
    te: 'trailers',
  });
  const request = session.request(headers());
  const call: BlockedHttp2Call = {
    data: [],
    headers: [],
    trailers: [],
    rstCode: undefined,
    openWindow: () => {
      session.settings({ initialWindowSize: 65_535 });
      session.setLocalWindowSize(1 << 20);
    },
    callAgain: (again) =>
      new Promise((resolve) => {
        const next = session.request(headers());
        let h: Record<string, unknown> = {};
        let t: Record<string, unknown> = {};
        const chunks: Buffer[] = [];
        next.on('response', (x) => (h = { ...x }));
        next.on('trailers', (x) => (t = { ...x }));
        next.on('data', (chunk: Buffer) => chunks.push(chunk));
        next.on('error', () => {});
        next.on('close', () => {
          const raw = t['grpc-status'] ?? h['grpc-status'];
          resolve({ headers: h, trailers: t, data: Buffer.concat(chunks), grpcStatus: raw === undefined ? undefined : Number(raw) });
        });
        next.end(again);
      }),
    close: () => session.destroy(),
  };
  request.on('response', (x) => call.headers.push({ ...x }));
  request.on('data', (chunk: Buffer) => call.data.push(chunk));
  request.on('trailers', (x) => call.trailers.push({ ...x }));
  request.on('error', () => {});
  request.on('close', () => (call.rstCode = request.rstCode));
  request.write(body);
  return call;
}
