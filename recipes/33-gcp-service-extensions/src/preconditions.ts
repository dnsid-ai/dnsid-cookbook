// Request preconditions for the authorization callout: the first check the verifier makes, before any signature work.
//
// The load balancer sends the request's headers as an Envoy ext_proc `ProcessingRequest` whose `request_headers` is an
// `HttpHeaders` message:
// https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto#service-ext-proc-v3-httpheaders
// The shapes below follow that proto's field names as decoded with `keepCase` (`end_of_stream`, `raw_value`).
//
// Passing these preconditions means only that the request is eligible for verification. It says nothing about who sent
// it, whether it is authorized, or whether it may be forwarded.

export interface HeaderValue {
  key?: unknown;
  value?: unknown;
  raw_value?: unknown;
}

export interface HttpHeadersMessage {
  headers?: { headers?: unknown } | null;
  end_of_stream?: unknown;
}

export interface ProcessingRequestMessage {
  request_headers?: HttpHeadersMessage | null;
}

export type DenyReason =
  | 'malformed_headers_message'
  | 'method_missing'
  | 'method_ambiguous'
  | 'method_not_allowed'
  | 'body_not_ruled_out'
  | 'body_indicated';

export interface PreconditionDenial {
  readonly outcome: 'deny';
  readonly status: 403;
  readonly reason: DenyReason;
}

/** A header as received: the name as sent and the value's exact bytes, in the order received. */
export interface ReceivedHeader {
  readonly name: string;
  readonly value: Uint8Array;
}

export interface EligibleForVerification {
  readonly outcome: 'eligible_for_verification';
  readonly method: 'GET' | 'HEAD';
  readonly headers: readonly ReceivedHeader[];
}

export type PreconditionResult = EligibleForVerification | PreconditionDenial;

const utf8 = new TextEncoder();
// `ignoreBOM: true` keeps a leading byte-order mark in the decoded text; by default the decoder drops it silently, and
// a malformed `\uFEFFGET` would read as `GET`.
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const ALLOWED_METHODS: readonly (readonly ['GET' | 'HEAD', Uint8Array])[] = [
  ['GET', utf8.encode('GET')],
  ['HEAD', utf8.encode('HEAD')],
];
const ZERO = utf8.encode('0');

function deny(reason: DenyReason): PreconditionDenial {
  return { outcome: 'deny', status: 403, reason };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// A header's value travels in `raw_value` (bytes) or `value` (string). When both are set they must agree; otherwise
// the header is ambiguous and the message is refused rather than guessing which one Envoy meant.
function headerBytes(entry: Record<string, unknown>): Uint8Array | undefined {
  const raw = entry['raw_value'];
  const text = entry['value'];
  const hasRaw = raw instanceof Uint8Array && raw.length > 0;
  const hasText = typeof text === 'string' && text.length > 0;
  if (raw !== undefined && raw !== null && !(raw instanceof Uint8Array)) return undefined;
  if (text !== undefined && text !== null && typeof text !== 'string') return undefined;
  if (hasRaw && hasText) {
    const fromText = utf8.encode(text);
    if (!sameBytes(fromText, raw)) return undefined;
  }
  if (hasRaw) return Uint8Array.from(raw);
  if (hasText) return utf8.encode(text);
  return new Uint8Array(0);
}

function readHeaders(message: HttpHeadersMessage): ReceivedHeader[] | undefined {
  const map = message.headers;
  if (!isObject(map)) return undefined;
  const list = map['headers'];
  if (!Array.isArray(list)) return undefined;
  const received: ReceivedHeader[] = [];
  for (const entry of list) {
    if (!isObject(entry)) return undefined;
    const name = entry['key'];
    if (typeof name !== 'string' || name.length === 0) return undefined;
    const value = headerBytes(entry);
    if (value === undefined) return undefined;
    received.push({ name, value });
  }
  return received;
}

function valuesOf(headers: readonly ReceivedHeader[], name: string): Uint8Array[] {
  return headers.filter((header) => header.name.toLowerCase() === name).map((header) => header.value);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function decode(bytes: Uint8Array): string | undefined {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return undefined;
  }
}

/**
 * Checks the method and that the request can't carry a body. Only an exact `GET` or `HEAD` whose headers message has
 * `end_of_stream` set to the boolean `true` is eligible; length headers never stand in for that indication.
 */
export function checkRequestPreconditions(request: ProcessingRequestMessage | null | undefined): PreconditionResult {
  if (!isObject(request)) return deny('malformed_headers_message');
  const message = request.request_headers;
  if (!isObject(message)) return deny('malformed_headers_message');
  const headers = readHeaders(message);
  if (headers === undefined) return deny('malformed_headers_message');

  const methods = valuesOf(headers, ':method');
  if (methods.length === 0) return deny('method_missing');
  if (methods.length > 1) return deny('method_ambiguous');
  const methodBytes = methods[0] as Uint8Array;
  const text = decode(methodBytes);
  if (text === undefined || text.length === 0) return deny('method_missing');
  // The method is matched on its exact bytes, never on decoded or normalized text.
  const method = ALLOWED_METHODS.find(([, bytes]) => sameBytes(methodBytes, bytes))?.[0];
  if (method === undefined) return deny('method_not_allowed');

  // HTTP/2 can send content with neither Content-Length nor Transfer-Encoding, so only the stream's end, as Envoy
  // reports it, rules a body out. Anything but the boolean true is refused.
  if (message.end_of_stream !== true) return deny('body_not_ruled_out');

  // The stream has ended, so a header announcing content contradicts it; refuse rather than pick one.
  if (valuesOf(headers, 'transfer-encoding').length > 0) return deny('body_indicated');
  for (const length of valuesOf(headers, 'content-length')) {
    if (!sameBytes(length, ZERO)) return deny('body_indicated');
  }

  return { outcome: 'eligible_for_verification', method, headers };
}
