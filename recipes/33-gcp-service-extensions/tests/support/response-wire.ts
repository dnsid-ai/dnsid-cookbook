// Reading the callout's serialized ProcessingResponse in tests, two ways:
// - with the service's own deserializer (`PROCESS_METHOD.responseDeserialize`, enums as names, bytes as Buffers);
// - independently, with protobufjs reflection over the same vendored schema, enums as numbers, so the HTTP status and
//   the append action are asserted as the numbers on the wire.
// And a local model of how a header mutation is applied, for protocol-semantic tests only.

import assert from 'node:assert/strict';
import { join } from 'node:path';

import protobuf from 'protobufjs';

import { PROCESS_METHOD, PROTO_DIR } from '../../src/ext-proc.ts';

const root = new protobuf.Root();
root.resolvePath = (_origin, target) => (target.startsWith('google/protobuf/') ? target : join(PROTO_DIR, target));
root.loadSync('envoy/service/ext_proc/v3/external_processor.proto', { keepCase: true });
root.resolveAll();
const responseType = root.lookupType('envoy.service.ext_proc.v3.ProcessingResponse');

/** The response as the service's deserializer reads it. */
export function viaService(bytes: Uint8Array): Record<string, any> {
  return PROCESS_METHOD.responseDeserialize(Buffer.from(bytes)) as Record<string, any>;
}

/** The response as plain protobufjs reads it: numeric enums, bytes as Buffers, defaults omitted, oneof named. */
export function viaReflection(bytes: Uint8Array): Record<string, any> {
  return responseType.toObject(responseType.decode(bytes), { enums: Number, longs: String, defaults: false, oneofs: true, arrays: false });
}

export interface WireHeader {
  readonly key: string;
  readonly rawValue: Buffer;
  readonly appendAction: number | undefined;
}

export interface DecodedDenial {
  readonly status: number;
  readonly headers: WireHeader[];
  readonly body: Buffer;
}

export interface DecodedContinuation {
  readonly status: number | undefined;
  readonly setHeaders: WireHeader[];
  readonly removeHeaders: string[];
}

function wireHeaders(list: unknown): WireHeader[] {
  return ((list as any[] | undefined) ?? []).map((option) => {
    assert.deepEqual(Object.keys(option.header).sort(), ['key', 'raw_value'], 'header values travel in raw_value only');
    return { key: option.header.key, rawValue: Buffer.from(option.header.raw_value), appendAction: option.append_action };
  });
}

/** Asserts an immediate_response and nothing else, both decoders agreeing, and returns its parts. */
export function decodeDenial(bytes: Uint8Array): DecodedDenial {
  const service = viaService(bytes);
  assert.equal(service['response'], 'immediate_response');
  assert.deepEqual(Object.keys(service).sort(), ['immediate_response', 'response']);
  const message = viaReflection(bytes);
  assert.equal(message['response'], 'immediate_response');
  assert.deepEqual(Object.keys(message).sort(), ['immediate_response', 'response'], 'no other response field');
  const immediate = message['immediate_response'];
  assert.deepEqual(Object.keys(immediate).sort(), ['body', 'headers', 'status'], 'no grpc_status or details');
  assert.deepEqual(Object.keys(immediate.headers), ['set_headers'], 'no remove_headers');
  assert.equal(service['immediate_response'].status.code, 'Forbidden');
  return { status: immediate.status.code, headers: wireHeaders(immediate.headers.set_headers), body: Buffer.from(immediate.body) };
}

/** Asserts a request_headers continuation and nothing else, both decoders agreeing, and returns its parts. */
export function decodeContinuation(bytes: Uint8Array): DecodedContinuation {
  const service = viaService(bytes);
  assert.equal(service['response'], 'request_headers');
  assert.equal(service['request_headers'].response.status, 'CONTINUE');
  const message = viaReflection(bytes);
  assert.equal(message['response'], 'request_headers');
  assert.deepEqual(Object.keys(message).sort(), ['request_headers', 'response'], 'no metadata or mode override');
  assert.deepEqual(Object.keys(message['request_headers']), ['response']);
  const common = message['request_headers'].response;
  const fields = Object.keys(common).sort();
  // CONTINUE is 0: written explicitly here, so it may be present (as 0) or, from another encoder, absent.
  assert.ok(
    JSON.stringify(fields) === JSON.stringify(['header_mutation', 'status']) || JSON.stringify(fields) === JSON.stringify(['header_mutation']),
    `only status and header_mutation: ${fields.join(',')}`,
  );
  assert.ok(common.status === undefined || common.status === 0);
  const mutation = common.header_mutation;
  return {
    status: common.status,
    setHeaders: wireHeaders(mutation.set_headers),
    removeHeaders: [...((mutation.remove_headers as string[] | undefined) ?? [])],
  };
}

/** HeaderValueOption.HeaderAppendAction.OVERWRITE_IF_EXISTS_OR_ADD in the pinned schema. */
export const OVERWRITE_IF_EXISTS_OR_ADD = 2;
/** type.v3.StatusCode.Forbidden in the pinned schema. */
export const FORBIDDEN = 403;

export type HeaderList = [name: string, value: Buffer][];

/**
 * A LOCAL MODEL, for protocol-semantic tests only: applies a decoded mutation to a header list the way Envoy v1.40.2's
 * ext_proc filter does (source/extensions/filters/http/ext_proc/mutation_utils.cc, `applyHeaderMutations`): each
 * remove_headers name, lowercased, removes every value of that header; then each set_headers entry replaces every
 * value of its (lowercased) header with its raw_value, since ext_proc reads `append` as false when unset. Names are
 * lowercased as Envoy's header map stores them. `order: 'sets-first'` models a hypothetical proxy that applied them the
 * other way round. It proves nothing about what Google's load balancer forwards.
 */
export function applyMutation(headers: HeaderList, mutation: DecodedContinuation, order: 'removals-first' | 'sets-first' = 'removals-first'): HeaderList {
  let out: HeaderList = headers.map(([name, value]) => [name.toLowerCase(), Buffer.from(value)]);
  const removals = () => {
    for (const name of mutation.removeHeaders) out = out.filter(([key]) => key !== name.toLowerCase());
  };
  const sets = () => {
    for (const header of mutation.setHeaders) {
      const name = header.key.toLowerCase();
      const first = out.findIndex(([key]) => key === name);
      const entry: [string, Buffer] = [name, Buffer.from(header.rawValue)];
      if (first === -1) out.push(entry);
      else out = out.flatMap((current, i) => (current[0] !== name ? [current] : i === first ? [entry] : []));
    }
  };
  if (order === 'removals-first') {
    removals();
    sets();
  } else {
    sets();
    removals();
  }
  return out;
}

export function valuesOf(headers: HeaderList, name: string): string[] {
  return headers.filter(([key]) => key === name).map(([, value]) => value.toString('latin1'));
}
