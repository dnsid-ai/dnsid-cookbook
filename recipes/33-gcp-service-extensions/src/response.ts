// The callout's answer to the load balancer: one ext_proc `ProcessingResponse` per request's headers, serialized with
// the `PROCESS_METHOD` response serializer that `@grpc/proto-loader` builds from the vendored Envoy schema.
// Schema: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto
//
// - A request whose whole verification passed (`verification_passed`, after the lifecycle stage) continues:
//   `request_headers.response` with status CONTINUE and a `header_mutation` that removes every received `x-dnsid-*`
//   header by its concrete name, then sets exactly `x-dnsid-verified-domain` and `x-dnsid-governance-id` from the
//   verified identity and, when the service has an attestation key (the deployed verifier always has: src/main.ts),
//   `x-dnsid-attestation`, the verifier's HMAC over those two values and the time (src/attestation.ts). Nothing else
//   about the request changes.
// - Everything else is an `immediate_response`: HTTP 403, `Cache-Control: no-store` and a short fixed reason code as the
//   body. Anything this module doesn't recognize as one of those two is a fixed `internal_error` denial; nothing but
//   a verified request ever continues.
//
// How the load balancer applies the mutation (Envoy v1.40.2, source/extensions/filters/http/ext_proc/mutation_utils.cc,
// `applyHeaderMutations`): every `remove_headers` name first, lowercased, removing all of that header's values; then
// each `set_headers` entry, which replaces any existing values (`setCopy`) because ext_proc reads `append` as false by
// default. `append_action` is set to OVERWRITE_IF_EXISTS_OR_ADD, which states the same thing in the schema. So each of
// the two headers ends with exactly one value, the verifier's. That Google's load balancer forwards it this way is
// not shown by these tests.

import { ATTESTATION_HEADER, attest } from './attestation.ts';
import { PROCESS_METHOD } from './ext-proc.ts';
import type { DecodeRejectionReason } from './ext-proc.ts';
import type { IdentityDenyReason } from './identity.ts';
import type { LifecycleDenyReason } from './lifecycle.ts';
import type { DenyReason, ReceivedHeader } from './preconditions.ts';
import type { SignatureDenyReason } from './signature.ts';

export const IDENTITY_HEADER_PREFIX = 'x-dnsid-';
export const VERIFIED_DOMAIN_HEADER = 'x-dnsid-verified-domain';
export const GOVERNANCE_ID_HEADER = 'x-dnsid-governance-id';
/** More distinct received `x-dnsid-*` names than this is denied, well under Envoy's default 100-header mutation limit. */
export const MAX_REMOVED_HEADERS = 64;
/** The largest serialized response sent; Google closes the callout stream on one over 128 kB. */
export const MAX_RESPONSE_BYTES = 16_384;
/** The longest verified domain or governance ID set as a header value (a DNS name is at most 253 characters). */
const MAX_IDENTITY_VALUE_BYTES = 253;

export type ResponseDenyReason =
  | 'internal_error' // an outcome this module doesn't recognize, or an unexpected failure
  | 'identity_headers_excessive' // more than MAX_REMOVED_HEADERS distinct x-dnsid-* names to remove
  | 'identity_header_invalid' // an x-dnsid-* name that can't be named in remove_headers
  | 'response_too_large' // the serialized response would exceed MAX_RESPONSE_BYTES
  | 'unexpected_message'; // the gRPC service received another message on the stream before it answered the first

export type ResponseReason =
  | DecodeRejectionReason
  | DenyReason
  | SignatureDenyReason
  | IdentityDenyReason
  | LifecycleDenyReason
  | ResponseDenyReason;

// Every reason code a denial may carry. Typed as a complete record, so a reason added to a stage and not here fails the
// type check. A reason not in it is never written to a response.
const REASONS: Readonly<Record<ResponseReason, true>> = Object.freeze({
  empty_message: true,
  malformed_message: true,
  conflicting_fields: true,
  unsupported_message_type: true,
  invalid_utf8_string: true,
  malformed_headers_message: true,
  method_missing: true,
  method_ambiguous: true,
  method_not_allowed: true,
  body_not_ruled_out: true,
  body_indicated: true,
  header_not_representable: true,
  authority_missing: true,
  authority_ambiguous: true,
  path_missing: true,
  path_ambiguous: true,
  target_not_representable: true,
  signature_missing: true,
  signature_ambiguous: true,
  signature_malformed: true,
  signature_label_mismatch: true,
  signature_coverage_insufficient: true,
  signature_keyid_missing: true,
  signature_created_missing: true,
  signature_expired: true,
  signature_created_in_future: true,
  signature_lifetime_invalid: true,
  signer_lookup_failed: true,
  signature_key_unknown: true,
  signature_invalid: true,
  verification_cancelled: true,
  verification_budget_exhausted: true,
  identity_not_found: true,
  identity_invalid: true,
  identity_inactive: true,
  identity_unavailable: true,
  governance_not_trusted: true,
  lifecycle_unavailable: true,
  lifecycle_not_established: true,
  lifecycle_evidence_invalid: true,
  lifecycle_evidence_stale: true,
  identity_evidence_expired: true,
  internal_error: true,
  identity_headers_excessive: true,
  identity_header_invalid: true,
  response_too_large: true,
  unexpected_message: true,
});

export const RESPONSE_REASONS: readonly ResponseReason[] = Object.freeze(Object.keys(REASONS) as ResponseReason[]);

function isReason(value: unknown): value is ResponseReason {
  return typeof value === 'string' && Object.hasOwn(REASONS, value);
}

/**
 * What a continuation's terminal log record may say about the request it lets through: the verified domain and
 * governance ID (the same values the response sets as headers) and the lifecycle evidence's age at the decision. Taken
 * from the verification result, never from the request's headers.
 */
export interface VerifiedSummary {
  readonly domain: string;
  readonly governanceId: string;
  readonly evidenceAgeMs: number;
  /** How the log evidence's completeness was established: `trusted-index` (a signed stream bundle) or `full-scan`. */
  readonly completenessMode: string;
  /** Where the identity material came from: `hit`, `miss`, `partial` or `off` (src/identity.ts, MaterialCacheUse). */
  readonly materialCache: string;
}

/** The serialized response and what it decided. `response` is a fresh copy; the caller may keep or change it. */
export type CalloutResponse =
  | { readonly decision: 'continue'; readonly response: Buffer; readonly verified: VerifiedSummary }
  | { readonly decision: 'deny'; readonly reason: ResponseReason; readonly response: Buffer };

/** The caller's request: its own cancellation signal and original deadline (`performance.now()` clock). */
export interface ResponseContext {
  readonly signal: AbortSignal;
  readonly deadline: number;
  /** The deployment's attestation key: when present, a continuation also sets `x-dnsid-attestation`. */
  readonly attestationKey?: Uint8Array;
}

/** Test hook. Not part of any response. */
export interface ResponseObserver {
  /** A continuation has been built, validated and serialized; the final cancellation and deadline checks come next. */
  continuationSerialized?(): void;
}

// ---------- building and checking the messages ----------

const utf8 = new TextEncoder();
const OVERWRITE = 'OVERWRITE_IF_EXISTS_OR_ADD';
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
const NO_STORE = Object.freeze(['cache-control', 'no-store'] as const);

class InvalidResponse extends Error {}
class ResponseTooLarge extends Error {}

function fail(): never {
  throw new InvalidResponse('invalid response shape');
}

/** ASCII-only lowercasing, as Envoy's `LowerCaseString` does; other characters are left as they are. */
function asciiLower(name: string): string {
  return name.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

function visibleAscii(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte >= 0x21 && byte <= 0x7e);
}

function setHeader(name: string, value: Uint8Array) {
  return { header: { key: name, raw_value: Buffer.from(value) }, append_action: OVERWRITE };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function keys(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) fail();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) fail();
  return value;
}

function checkSetHeaders(list: unknown, expected: readonly (readonly [string, Uint8Array | undefined])[]): void {
  if (!Array.isArray(list) || list.length !== expected.length) fail();
  list.forEach((entry, i) => {
    const option = keys(entry, ['header', 'append_action']);
    if (option['append_action'] !== OVERWRITE) fail();
    const header = keys(option['header'], ['key', 'raw_value']);
    const [name, value] = expected[i] as readonly [string, Uint8Array | undefined];
    const raw = header['raw_value'];
    if (header['key'] !== name || !(raw instanceof Uint8Array) || raw.length === 0 || !visibleAscii(raw)) fail();
    if (value !== undefined && !Buffer.from(raw).equals(value)) fail();
  });
}

/**
 * Checks a continuation message before it is serialized: exactly the fields this module sets, nothing else. The
 * serializer drops unknown fields and unknown enum names silently and encodes two response branches if given them, so
 * a mistake here would otherwise become an empty or ambiguous message rather than an error.
 */
function checkContinuation(
  message: unknown,
  removals: readonly string[],
  domain: Uint8Array,
  governance: Uint8Array,
  attestation: Uint8Array | undefined,
): void {
  const top = keys(message, ['request_headers']);
  const headersResponse = keys(top['request_headers'], ['response']);
  const common = keys(headersResponse['response'], ['status', 'header_mutation']);
  if (common['status'] !== 'CONTINUE') fail();
  const mutation = keys(common['header_mutation'], ['set_headers', 'remove_headers']);
  checkSetHeaders(mutation['set_headers'], [
    [VERIFIED_DOMAIN_HEADER, domain],
    [GOVERNANCE_ID_HEADER, governance],
    ...(attestation === undefined ? [] : [[ATTESTATION_HEADER, attestation] as const]),
  ]);
  const remove = mutation['remove_headers'];
  if (!Array.isArray(remove) || remove.length !== removals.length || remove.length > MAX_REMOVED_HEADERS) fail();
  if (new Set(remove).size !== remove.length) fail();
  remove.forEach((name, i) => {
    if (name !== removals[i] || typeof name !== 'string' || !name.startsWith(IDENTITY_HEADER_PREFIX) || !TOKEN.test(name)) fail();
  });
}

function checkDenial(message: unknown, reason: ResponseReason): void {
  const top = keys(message, ['immediate_response']);
  const immediate = keys(top['immediate_response'], ['status', 'headers', 'body']);
  const status = keys(immediate['status'], ['code']);
  if (status['code'] !== 'Forbidden') fail();
  const headers = keys(immediate['headers'], ['set_headers']);
  checkSetHeaders(headers['set_headers'], [[NO_STORE[0], utf8.encode(NO_STORE[1])]]);
  const body = immediate['body'];
  if (!(body instanceof Uint8Array) || !Buffer.from(body).equals(Buffer.from(reason, 'ascii'))) fail();
}

// A decoded or built message in a comparable form: bytes as hex, object keys sorted, empty repeated fields (which the
// deserializer reports as empty arrays) left out, and the deserializer's virtual oneof name dropped.
function canonical(value: unknown): unknown {
  if (value instanceof Uint8Array) return `bytes:${Buffer.from(value).toString('hex')}`;
  if (Array.isArray(value)) return value.map(canonical);
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const field = value[key];
      if (key === 'response' && typeof field === 'string') continue;
      if (Array.isArray(field) && field.length === 0) continue;
      out[key] = canonical(field);
    }
    return out;
  }
  return value;
}

/**
 * Serializes with the service's own serializer, then reads the bytes back with its deserializer and requires the
 * same message, in the expected branch, and within the size bound. Throws InvalidResponse otherwise.
 */
function serialize(message: Record<string, unknown>, branch: 'request_headers' | 'immediate_response'): Buffer {
  const bytes = PROCESS_METHOD.responseSerialize(message);
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_RESPONSE_BYTES) {
    throw new ResponseTooLarge();
  }
  const decoded = PROCESS_METHOD.responseDeserialize(bytes) as Record<string, unknown>;
  if (decoded['response'] !== branch) fail();
  if (JSON.stringify(canonical(decoded)) !== JSON.stringify(canonical(message))) fail();
  return bytes;
}

// ---------- denials ----------

function buildDenial(reason: ResponseReason): Buffer {
  const message = {
    immediate_response: {
      status: { code: 'Forbidden' },
      headers: { set_headers: [setHeader(NO_STORE[0], utf8.encode(NO_STORE[1]))] },
      body: Buffer.from(reason, 'ascii'),
    },
  };
  checkDenial(message, reason);
  return serialize(message, 'immediate_response');
}

// Every denial is built, checked and serialized once, when the module loads, so answering with one can't fail.
const DENIALS: ReadonlyMap<ResponseReason, Buffer> = new Map(RESPONSE_REASONS.map((reason) => [reason, buildDenial(reason)]));

/** The serialized 403 for `reason`; any value that isn't a known reason code gets the `internal_error` denial. */
export function denialResponse(reason: unknown): CalloutResponse {
  const known: ResponseReason = isReason(reason) ? reason : 'internal_error';
  return { decision: 'deny', reason: known, response: Buffer.from(DENIALS.get(known) as Buffer) };
}

// ---------- the verified continuation ----------

/** The verified identity summary, read field by field; undefined unless every field is a usable header value. */
function verifiedValues(
  outcome: Record<string, unknown>,
): { domain: Uint8Array; governance: Uint8Array; summary: VerifiedSummary } | undefined {
  const identity = outcome['identity'];
  const lifecycle = outcome['lifecycle'];
  if (!isRecord(identity) || !isRecord(lifecycle) || lifecycle['loggedState'] !== 'ACTIVE') return undefined;
  const domain = identity['domain'];
  const governance = identity['governanceId'];
  const evidenceAgeMs = lifecycle['evidenceAgeMs'];
  const completenessMode = lifecycle['completenessMode'];
  const materialCache = identity['materialCache'];
  if (typeof domain !== 'string' || typeof governance !== 'string') return undefined;
  if (typeof evidenceAgeMs !== 'number' || !Number.isFinite(evidenceAgeMs)) return undefined;
  // Bounded, known values only: they reach the log as they are.
  if (typeof completenessMode !== 'string' || !/^[a-z][a-z-]{0,31}$/.test(completenessMode)) return undefined;
  if (materialCache !== 'hit' && materialCache !== 'miss' && materialCache !== 'partial' && materialCache !== 'off') return undefined;
  const values = { domain: utf8.encode(domain), governance: utf8.encode(governance) };
  for (const value of [values.domain, values.governance]) {
    if (value.length === 0 || value.length > MAX_IDENTITY_VALUE_BYTES || !visibleAscii(value)) return undefined;
  }
  return { ...values, summary: Object.freeze({ domain, governanceId: governance, evidenceAgeMs, completenessMode, materialCache }) };
}

/**
 * The concrete, lowercased, distinct names of every received header that starts with `x-dnsid-` in any letter case,
 * in the order first received. `remove_headers` names headers exactly; it has no prefix or wildcard form.
 */
function identityHeaderNames(received: readonly ReceivedHeader[]): string[] | ResponseDenyReason {
  const names: string[] = [];
  for (const header of received) {
    const name = asciiLower(header.name);
    if (!name.startsWith(IDENTITY_HEADER_PREFIX)) continue;
    // Envoy refuses a remove_headers name that isn't a valid header name, so such a header couldn't be removed.
    if (!TOKEN.test(name)) return 'identity_header_invalid';
    if (!names.includes(name)) names.push(name);
    if (names.length > MAX_REMOVED_HEADERS) return 'identity_headers_excessive';
  }
  return names;
}

function continuation(
  outcome: Record<string, unknown>,
  received: readonly ReceivedHeader[],
  context: ResponseContext,
  observer: ResponseObserver | undefined,
): CalloutResponse {
  const values = verifiedValues(outcome);
  if (values === undefined) return denialResponse('internal_error');
  const removals = identityHeaderNames(received);
  if (typeof removals === 'string') return denialResponse(removals);
  const key = context.attestationKey;
  if (key !== undefined && (!(key instanceof Uint8Array) || key.length === 0)) return denialResponse('internal_error');
  const attestation = key === undefined ? undefined : utf8.encode(attest(key, values.summary.domain, values.summary.governanceId));
  const set = [setHeader(VERIFIED_DOMAIN_HEADER, values.domain), setHeader(GOVERNANCE_ID_HEADER, values.governance)];
  if (attestation !== undefined) set.push(setHeader(ATTESTATION_HEADER, attestation));
  const message = {
    request_headers: {
      response: {
        status: 'CONTINUE',
        header_mutation: {
          // Applied in this order by the load balancer: removals, then sets. Every received x-dnsid-* name is removed,
          // the ones set below included, so a caller's value never survives whatever order a proxy used.
          set_headers: set,
          remove_headers: removals,
        },
      },
    },
  };
  checkContinuation(message, removals, values.domain, values.governance, attestation);
  let bytes: Buffer;
  try {
    bytes = serialize(message, 'request_headers');
  } catch (error) {
    if (error instanceof ResponseTooLarge) return denialResponse('response_too_large');
    throw error;
  }
  observer?.continuationSerialized?.();
  // Checked last, after the response has been built and serialized, with nothing after: a request cancelled or out of
  // its original budget by now is denied as such, never continued.
  if (!(context.signal instanceof AbortSignal) || context.signal.aborted) return denialResponse('verification_cancelled');
  if (!(performance.now() < context.deadline)) return denialResponse('verification_budget_exhausted');
  return { decision: 'continue', response: bytes, verified: values.summary };
}

/**
 * The response for one request's outcome. Only `verification_passed` (the whole verification, lifecycle included)
 * continues, with mutations planned from `received`, the headers exactly as received. A denial or decoding rejection
 * becomes its own 403; any other value, or a failure while building the response, is the `internal_error` 403.
 * Synchronous: nothing is awaited between the final checks and the return. Neither argument is changed.
 */
export function respond(
  outcome: unknown,
  received: readonly ReceivedHeader[],
  context: ResponseContext,
  observer?: ResponseObserver,
): CalloutResponse {
  try {
    if (!isRecord(outcome)) return denialResponse('internal_error');
    const kind = outcome['outcome'];
    if (kind === 'verification_passed') return continuation(outcome, received, context, observer);
    if (kind === 'deny' || kind === 'reject') return denialResponse(outcome['reason']);
    return denialResponse('internal_error');
  } catch {
    return denialResponse('internal_error');
  }
}
