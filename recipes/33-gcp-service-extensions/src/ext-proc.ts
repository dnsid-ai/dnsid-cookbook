// Decoding of the ext_proc messages the load balancer sends the authorization callout, up to the request preconditions.
//
// The schema is Envoy's own, vendored byte for byte under `proto/` from pinned upstream commits (see
// `proto/PROVENANCE.md`); nothing here restates it. Requests are decoded with the deserializer that
// `@grpc/proto-loader` builds for `envoy.service.ext_proc.v3.ExternalProcessor/Process`, the one the gRPC service will
// use, after a wire-level check against the same schema.
//
// Passing these checks means only that a request is eligible for verification. Nothing here verifies a signature,
// answers the load balancer, or forwards anything.

import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import protoLoader from '@grpc/proto-loader';
import protobuf from 'protobufjs';

import { checkRequestPreconditions, type PreconditionResult, type ProcessingRequestMessage } from './preconditions.ts';

/** The vendored schema, found from this file's location so the caller's working directory doesn't matter. */
export const PROTO_DIR = fileURLToPath(new URL('../proto/', import.meta.url));
const SERVICE_PROTO = 'envoy/service/ext_proc/v3/external_processor.proto';
const SERVICE = 'envoy.service.ext_proc.v3.ExternalProcessor';
const REQUEST_TYPE = 'envoy.service.ext_proc.v3.ProcessingRequest';

/**
 * How decoded messages are converted to plain objects. `bytes` is deliberately not set: that is the only setting that
 * leaves `bytes` fields as the decoded `Buffer` (`String` gives base64 text, `Array` gives numbers).
 */
export const LOADER_OPTIONS = Object.freeze({
  keepCase: true, // the proto's own snake_case names: `end_of_stream`, `raw_value`
  longs: String,
  enums: String,
  defaults: false, // an absent field stays absent; a default never stands in for it
  arrays: true, // a repeated field the sender left empty is an empty array
  objects: false,
  oneofs: true, // names the `request` member that is set
  includeDirs: [PROTO_DIR],
});

const packageDefinition = protoLoader.loadSync(SERVICE_PROTO, { ...LOADER_OPTIONS, includeDirs: [...LOADER_OPTIONS.includeDirs] });
const service = packageDefinition[SERVICE] as protoLoader.ServiceDefinition | undefined;
const processMethod = service?.['Process'];
if (processMethod === undefined || !processMethod.requestStream || !processMethod.responseStream) {
  throw new Error(`${SERVICE}/Process is missing from ${SERVICE_PROTO}`);
}

// The same files, loaded as protobufjs reflection for the wire-level check. The well-known types under
// google/protobuf/ come from protobufjs' bundled copies, as they do for @grpc/proto-loader.
const reflection = new protobuf.Root();
reflection.resolvePath = (_origin, target) => (target.startsWith('google/protobuf/') ? target : join(PROTO_DIR, target));
reflection.loadSync(SERVICE_PROTO, { keepCase: true });
reflection.resolveAll();
const requestType = reflection.lookupType(REQUEST_TYPE);

const REQUEST_HEADERS = 'request_headers';
const MAX_DEPTH = 32;
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export type DecodeRejectionReason =
  | 'empty_message' // no bytes at all
  | 'malformed_message' // not a ProcessingRequest on the wire: truncated, a bad tag or wire type, too deeply nested
  | 'conflicting_fields' // two members of one oneof, or a non-repeated message field sent twice
  | 'unsupported_message_type' // a ProcessingRequest, but not a request's headers
  | 'invalid_utf8_string'; // a `string` field (a header's `key` or `value`) that isn't valid UTF-8 on the wire

/** A message that never reaches the preconditions. The reason is a fixed code; nothing from the payload is echoed. */
export interface DecodeRejection {
  readonly outcome: 'reject';
  readonly reason: DecodeRejectionReason;
}

export type DecodeResult =
  | { readonly outcome: 'decoded'; readonly message: ProcessingRequestMessage }
  | DecodeRejection;

function reject(reason: DecodeRejectionReason): DecodeRejection {
  return { outcome: 'reject', reason };
}

/** What the service deserializer throws. The message is fixed per reason; nothing from the payload is in it. */
export class DecodeRejectionError extends Error {
  readonly reason: DecodeRejectionReason;
  constructor(reason: DecodeRejectionReason) {
    super(`ext_proc request rejected: ${reason}`);
    this.name = 'DecodeRejectionError';
    this.reason = reason;
  }
}

function expectedWireType(field: protobuf.FieldBase): number | undefined {
  if (field.resolvedType instanceof protobuf.Type) return 2;
  if (field.resolvedType instanceof protobuf.Enum) return 0;
  return (protobuf.types.basic as Record<string, number | undefined>)[field.type];
}

// Checks the encoding against the schema before anything is converted. protobufjs decodes by field number alone: it
// reads a field sent with the wrong wire type as if it were right, keeps every member of a oneof it receives, and
// replaces (rather than merges) a message field sent twice, and it turns invalid UTF-8 in a `string` field into U+FFFD
// without saying so, which would change a header's bytes. Each of those is refused here instead. A header value that
// isn't UTF-8 travels in `raw_value`, which is kept as sent. Map entries (`attributes`, and the maps inside
// `metadata_context`) are embedded messages and are checked the same way, key and value.
function checkWire(type: protobuf.Type, reader: protobuf.Reader, end: number, depth: number): DecodeRejectionReason | undefined {
  if (depth > MAX_DEPTH) return 'malformed_message';
  const seenMessages = new Set<number>();
  const oneofMembers = new Map<string, number>();
  while (reader.pos < end) {
    const tag = reader.uint32();
    const id = tag >>> 3;
    const wireType = tag & 7;
    if (id === 0) return 'malformed_message';
    const field = type.fieldsById[id];
    if (field === undefined) {
      reader.skipType(wireType);
      continue;
    }
    if (field instanceof protobuf.MapField) {
      if (wireType !== 2) return 'malformed_message';
      const entry = checkNested(reader, end, (entryEnd) => checkMapEntry(field, reader, entryEnd, depth + 1));
      if (entry !== undefined) return entry;
      continue;
    }
    const expected = expectedWireType(field);
    const packed = field.repeated && expected !== 2 && wireType === 2;
    if (wireType !== expected && !packed) return 'malformed_message';
    if (field.partOf !== null) {
      const member = oneofMembers.get(field.partOf.name);
      if (member !== undefined && member !== id) return 'conflicting_fields';
      oneofMembers.set(field.partOf.name, id);
    }
    if (field.resolvedType instanceof protobuf.Type && !field.repeated) {
      if (seenMessages.has(id)) return 'conflicting_fields';
      seenMessages.add(id);
    }
    const value = checkValue(field, wireType, reader, end, depth);
    if (value !== undefined) return value;
  }
  return reader.pos === end ? undefined : 'malformed_message';
}

// One map entry: `key = 1` of the map's key type and `value = 2` of its value type, under the same rules as any other
// message. A value message sent twice in one entry is refused, as for any non-repeated message field. Two entries with
// the same key are valid protobuf (the last one wins) and are left to the decoder.
function checkMapEntry(field: protobuf.MapField, reader: protobuf.Reader, end: number, depth: number): DecodeRejectionReason | undefined {
  if (depth > MAX_DEPTH) return 'malformed_message';
  let valueSeen = false;
  while (reader.pos < end) {
    const tag = reader.uint32();
    const id = tag >>> 3;
    const wireType = tag & 7;
    if (id === 0) return 'malformed_message';
    if (id === 1) {
      const keyWireType = (protobuf.types.mapKey as Record<string, number | undefined>)[field.keyType];
      if (wireType !== keyWireType) return 'malformed_message';
      const key = field.keyType === 'string' ? checkString(reader, end) : (reader.skipType(wireType), undefined);
      if (key !== undefined) return key;
      continue;
    }
    if (id === 2) {
      if (wireType !== expectedWireType(field)) return 'malformed_message';
      if (field.resolvedType instanceof protobuf.Type) {
        if (valueSeen) return 'conflicting_fields';
        valueSeen = true;
      }
      const value = checkValue(field, wireType, reader, end, depth);
      if (value !== undefined) return value;
      continue;
    }
    reader.skipType(wireType);
  }
  return reader.pos === end ? undefined : 'malformed_message';
}

// A field's value, its wire type already checked: a message is checked recursively within its length, a string as
// UTF-8, anything else skipped.
function checkValue(field: protobuf.FieldBase, wireType: number, reader: protobuf.Reader, end: number, depth: number): DecodeRejectionReason | undefined {
  const resolved = field.resolvedType;
  if (resolved instanceof protobuf.Type) {
    return checkNested(reader, end, (nestedEnd) => checkWire(resolved, reader, nestedEnd, depth + 1));
  }
  if (field.type === 'string' && wireType === 2) return checkString(reader, end);
  reader.skipType(wireType);
  return undefined;
}

function checkNested(reader: protobuf.Reader, end: number, check: (nestedEnd: number) => DecodeRejectionReason | undefined): DecodeRejectionReason | undefined {
  const length = reader.uint32();
  const nestedEnd = reader.pos + length;
  if (nestedEnd > end) return 'malformed_message';
  const nested = check(nestedEnd);
  if (nested !== undefined) return nested;
  return reader.pos === nestedEnd ? undefined : 'malformed_message';
}

function checkString(reader: protobuf.Reader, end: number): DecodeRejectionReason | undefined {
  const text = reader.bytes();
  if (reader.pos > end) return 'malformed_message';
  try {
    strictUtf8.decode(text);
  } catch {
    return 'invalid_utf8_string';
  }
  return undefined;
}

// proto-loader's own deserializer: decode, then convert. It is never exported; the service gets the guarded one below.
const unguardedDeserialize = processMethod.requestDeserialize;

/**
 * The service-facing deserializer for `ProcessingRequest`: checks the wire encoding against the schema, then decodes
 * and converts with proto-loader's deserializer. Bytes that fail throw a `DecodeRejectionError` with a fixed reason.
 * It checks encoding only; which message types the callout accepts is `decodeProcessingRequest`'s decision.
 */
export function deserializeProcessingRequest(data: Uint8Array): object {
  if (!(data instanceof Uint8Array)) throw new DecodeRejectionError('malformed_message');
  if (data.length === 0) throw new DecodeRejectionError('empty_message');
  const buffer = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  let wire: DecodeRejectionReason | undefined;
  try {
    wire = checkWire(requestType, protobuf.Reader.create(buffer), buffer.length, 0);
  } catch {
    throw new DecodeRejectionError('malformed_message');
  }
  if (wire !== undefined) throw new DecodeRejectionError(wire);
  try {
    return unguardedDeserialize(buffer);
  } catch {
    throw new DecodeRejectionError('malformed_message');
  }
}

/**
 * The gRPC method definition for `ExternalProcessor/Process`, as proto-loader builds it but with
 * `requestDeserialize` replaced by `deserializeProcessingRequest`, so a service registered with it always validates.
 */
export const PROCESS_METHOD: protoLoader.MethodDefinition<object, object> = Object.freeze({
  ...processMethod,
  requestDeserialize: deserializeProcessingRequest,
});

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Decodes one serialized `ProcessingRequest` and accepts it only when it carries a request's headers. Any other
 * message, or bytes that aren't a well-formed one, is a fixed rejection.
 */
export function decodeProcessingRequest(bytes: Uint8Array): DecodeResult {
  let decoded: unknown;
  try {
    decoded = PROCESS_METHOD.requestDeserialize(bytes as Buffer);
  } catch (error) {
    return reject(error instanceof DecodeRejectionError ? error.reason : 'malformed_message');
  }

  if (!isObject(decoded) || decoded['request'] !== REQUEST_HEADERS) return reject('unsupported_message_type');
  const headers = decoded[REQUEST_HEADERS];
  if (!isObject(headers)) return reject('unsupported_message_type');
  return { outcome: 'decoded', message: decoded as ProcessingRequestMessage };
}

/** Decodes a serialized `ProcessingRequest` and applies the request preconditions to the headers it carries. */
export function checkSerializedRequest(bytes: Uint8Array): PreconditionResult | DecodeRejection {
  const decoded = decodeProcessingRequest(bytes);
  if (decoded.outcome === 'reject') return decoded;
  return checkRequestPreconditions(decoded.message);
}
