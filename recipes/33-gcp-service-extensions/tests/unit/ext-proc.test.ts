// Local tests of the ext_proc decoding boundary: serialized `ProcessingRequest` bytes in, through the deserializer the
// gRPC service will use, into the request preconditions. They show protobuf compatibility with the pinned Envoy schema
// only; they involve no gRPC transport, say nothing about how Google's load balancer fills these messages, and do no
// DNSid verification.
// Schema: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto
//         https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  checkSerializedRequest,
  decodeProcessingRequest,
  DecodeRejectionError,
  deserializeProcessingRequest,
  LOADER_OPTIONS,
  PROCESS_METHOD,
  PROTO_DIR,
} from '../../src/ext-proc.ts';

// A minimal protobuf wire writer, written from the encoding spec (https://protobuf.dev/programming-guides/encoding/)
// and independent of the library under test. Field numbers, from the pinned .proto files:
//   ProcessingRequest: request_headers = 2, response_headers = 3, request_body = 4, response_body = 5,
//                      request_trailers = 6, response_trailers = 7, observability_mode = 10
//   HttpHeaders: headers = 1, end_of_stream = 3      HeaderMap: headers = 1      HeaderValue: key = 1, value = 2, raw_value = 3
//   ProcessingRequest: metadata_context = 8 (Metadata), attributes = 9 (map<string, Struct>)
//   Metadata: filter_metadata = 1 (map<string, Struct>), typed_filter_metadata = 2 (map<string, Any>)
//   Struct: fields = 1 (map<string, Value>)      ListValue: values = 1      Any: type_url = 1, value = 2
//   Value: null_value = 1, number_value = 2, string_value = 3, bool_value = 4, struct_value = 5, list_value = 6
//   A map entry is a message: key = 1, value = 2.
function varint(n: number): Buffer {
  const out: number[] = [];
  do {
    const low = n & 0x7f;
    n = Math.floor(n / 128);
    out.push(n > 0 ? low | 0x80 : low);
  } while (n > 0);
  return Buffer.from(out);
}
const tag = (field: number, wireType: number) => varint((field << 3) | wireType);
const len = (field: number, ...payload: Buffer[]) => {
  const body = Buffer.concat(payload);
  return Buffer.concat([tag(field, 2), varint(body.length), body]);
};
const bool = (field: number, value: number) => Buffer.concat([tag(field, 0), varint(value)]);
const bytes = (text: string) => Buffer.from(text, 'latin1');

type Entry = { key: string | Buffer; value?: string | Buffer; raw?: string | Buffer };
function headerValue({ key, value, raw }: Entry): Buffer {
  const parts = [len(1, typeof key === 'string' ? Buffer.from(key) : key)];
  if (value !== undefined) parts.push(len(2, typeof value === 'string' ? Buffer.from(value) : value));
  if (raw !== undefined) parts.push(len(3, typeof raw === 'string' ? Buffer.from(raw) : raw));
  return Buffer.concat(parts);
}
const headerMap = (entries: Entry[]) => len(1, ...entries.map((entry) => len(1, headerValue(entry))));
/** HttpHeaders: `eos` undefined omits end_of_stream; a number writes that varint, so 0 is an explicit false. */
const httpHeaders = (entries: Entry[], eos?: number) =>
  Buffer.concat([headerMap(entries), eos === undefined ? Buffer.alloc(0) : bool(3, eos)]);
const requestHeaders = (entries: Entry[], eos?: number) => len(2, httpHeaders(entries, eos));

const BASE: Entry[] = [
  { key: ':authority', raw: 'bank.example' },
  { key: ':path', raw: '/accounts/123?view=summary' },
  { key: ':scheme', raw: 'https' },
  { key: 'signature-input', raw: 'sig1=("@method" "@authority" "@target-uri");created=1762900000;keyid="k1"' },
  { key: 'signature', raw: 'sig1=:AAAA:' },
];
const signed = (method: Entry | null, eos?: number, extra: Entry[] = []) =>
  requestHeaders([...(method === null ? [] : [method]), ...BASE, ...extra], eos);

const entry = (key: Buffer | string, ...value: Buffer[]) => Buffer.concat([len(1, typeof key === 'string' ? Buffer.from(key) : key), ...value]);
const stringValue = (text: string | Buffer) => len(3, typeof text === 'string' ? Buffer.from(text) : text);
/** A Struct with one field, `key`, holding the Value body given. */
const struct = (key: Buffer | string, valueBody: Buffer) => len(1, entry(key, len(2, valueBody)));
/** A Struct `depth` levels deep: each level's field `a` holds the next Struct; the innermost holds a string. */
function nestedStruct(depth: number): Buffer {
  let body = struct('a', stringValue('x'));
  for (let i = 1; i < depth; i++) body = struct('a', len(5, body));
  return body;
}
/** ProcessingRequest.attributes: one map entry, `key` to the Struct body given. */
const attributes = (key: Buffer | string, structBody: Buffer) => len(9, entry(key, len(2, structBody)));
const signedGet = () => signed({ key: ':method', raw: 'GET' }, 1);

const hex = (value: unknown) => Buffer.from(value as Uint8Array).toString('hex');

function assertDenied(result: unknown, reason: string) {
  assert.deepEqual(result, { outcome: 'deny', status: 403, reason });
}
function assertRejected(result: unknown, reason: string) {
  assert.deepEqual(result, { outcome: 'reject', reason });
}
function assertDeserializerRejects(bytesIn: unknown, reason: string, marker?: string) {
  assert.throws(
    () => PROCESS_METHOD.requestDeserialize(bytesIn as Buffer),
    (error: unknown) => {
      assert.ok(error instanceof DecodeRejectionError);
      assert.equal(error.reason, reason);
      assert.equal(error.message, `ext_proc request rejected: ${reason}`);
      if (marker !== undefined) assert.equal(`${error.message} ${String(error.stack)}`.includes(marker), false);
      return true;
    },
  );
  assertRejected(checkSerializedRequest(bytesIn as Uint8Array), reason);
}
function decodedHeaders(result: ReturnType<typeof decodeProcessingRequest>) {
  assert.equal(result.outcome, 'decoded');
  assert.ok(result.outcome === 'decoded');
  return result.message.request_headers as { headers: { headers: Record<string, unknown>[] }; end_of_stream?: unknown };
}

const here = fileURLToPath(new URL('.', import.meta.url));
const FIXTURE = readFileSync(join(here, '../fixtures/ext-proc/request-headers-get.bin'));
const FIXTURE_SHA256 = '8bc5de965dccc5501f758856cc9189321047c75a64855fa01c2905bc181602f0';

describe('ext_proc decoding (local, serialized protobuf)', () => {
  describe('the pinned schema and loader', () => {
    it('vendored schema files match proto/SHA256SUMS', () => {
      const lines = readFileSync(join(PROTO_DIR, 'SHA256SUMS'), 'utf8').trim().split('\n');
      assert.ok(lines.length > 0);
      for (const line of lines) {
        const [sum, path] = line.split(/ {2}/);
        assert.ok(sum && path);
        assert.equal(createHash('sha256').update(readFileSync(join(PROTO_DIR, path))).digest('hex'), sum, path);
      }
    });

    it('uses the bidirectional Process method of the ext_proc service', () => {
      assert.equal(PROCESS_METHOD.path, '/envoy.service.ext_proc.v3.ExternalProcessor/Process');
      assert.equal(PROCESS_METHOD.requestStream, true);
      assert.equal(PROCESS_METHOD.responseStream, true);
    });

    it('has the conversion settings it documents', () => {
      const { includeDirs, ...settings } = LOADER_OPTIONS;
      assert.deepEqual(settings, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: false,
        arrays: true,
        objects: false,
        oneofs: true,
      });
      assert.equal('bytes' in LOADER_OPTIONS, false);
      assert.deepEqual(includeDirs, [PROTO_DIR]);
    });

    it('loads from any working directory', () => {
      const moduleUrl = new URL('../../src/ext-proc.ts', import.meta.url).href;
      const fixture = FIXTURE.toString('hex');
      const script =
        `const m = await import(${JSON.stringify(moduleUrl)});` +
        `const r = m.checkSerializedRequest(Buffer.from(${JSON.stringify(fixture)}, 'hex'));` +
        `console.log(r.outcome, r.method, process.cwd());`;
      const output = execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: tmpdir(), encoding: 'utf8' });
      assert.equal(output.trim(), `eligible_for_verification GET ${tmpdir()}`);
    });
  });

  // The fixture was assembled byte by byte from the wire format, not by this library, and decoded independently with
  // protoc 35.1 against the same schema (tests/fixtures/ext-proc/README.md, request-headers-get.protoc.txt).
  describe('fixed binary fixture', () => {
    it('is the recorded fixture', () => {
      assert.equal(createHash('sha256').update(FIXTURE).digest('hex'), FIXTURE_SHA256);
      assert.equal(FIXTURE.length, 271);
    });

    it('decodes to the fields protoc reports, with snake_case names, raw bytes and header order', () => {
      const result = decodeProcessingRequest(FIXTURE);
      assert.ok(result.outcome === 'decoded');
      assert.deepEqual(Object.keys(result.message).sort(), ['request', 'request_headers']);
      assert.equal((result.message as Record<string, unknown>)['request'], 'request_headers');
      const message = decodedHeaders(result);
      assert.deepEqual(Object.keys(message).sort(), ['end_of_stream', 'headers']);
      assert.equal(message.end_of_stream, true);
      const expected: [string, 'raw_value' | 'value', string][] = [
        [':method', 'raw_value', 'GET'],
        [':authority', 'raw_value', 'bank.example'],
        [':path', 'raw_value', '/accounts/a%2Fb%20c?view=summary&q=%7E'],
        [':scheme', 'value', 'https'],
        ['signature-input', 'raw_value', 'sig1=("@method" "@authority" "@target-uri");created=1762900000;keyid="k1"'],
        ['signature', 'raw_value', 'sig1=:AAEC/w==:'],
        ['x-empty', 'raw_value', ''],
        ['accept', 'value', '*/*'],
      ];
      assert.equal(message.headers.headers.length, expected.length);
      message.headers.headers.forEach((entry, i) => {
        const [key, field, value] = expected[i] as (typeof expected)[number];
        assert.deepEqual(Object.keys(entry).sort(), ['key', field].sort(), key);
        assert.equal(entry['key'], key);
        if (field === 'raw_value') {
          assert.ok(entry['raw_value'] instanceof Uint8Array, key);
          assert.equal(hex(entry['raw_value']), Buffer.from(value).toString('hex'), key);
        } else {
          assert.equal(entry['value'], value, key);
        }
      });
    });

    it('is eligible for verification as GET, with every header in order and its exact bytes', () => {
      const result = checkSerializedRequest(FIXTURE);
      assert.ok(result.outcome === 'eligible_for_verification');
      assert.equal(result.method, 'GET');
      assert.deepEqual(
        result.headers.map((h) => [h.name, Buffer.from(h.value).toString('latin1')]),
        [
          [':method', 'GET'],
          [':authority', 'bank.example'],
          [':path', '/accounts/a%2Fb%20c?view=summary&q=%7E'],
          [':scheme', 'https'],
          ['signature-input', 'sig1=("@method" "@authority" "@target-uri");created=1762900000;keyid="k1"'],
          ['signature', 'sig1=:AAEC/w==:'],
          ['x-empty', ''],
          ['accept', '*/*'],
        ],
      );
    });

    it('is what the wire writer here produces, and what the schema serializer writes back', () => {
      const entries: Entry[] = [
        { key: ':method', raw: 'GET' },
        { key: ':authority', raw: 'bank.example' },
        { key: ':path', raw: '/accounts/a%2Fb%20c?view=summary&q=%7E' },
        { key: ':scheme', value: 'https' },
        { key: 'signature-input', raw: 'sig1=("@method" "@authority" "@target-uri");created=1762900000;keyid="k1"' },
        { key: 'signature', raw: 'sig1=:AAEC/w==:' },
        { key: 'x-empty', raw: '' },
        { key: 'accept', value: '*/*' },
      ];
      assert.equal(requestHeaders(entries, 1).toString('hex'), FIXTURE.toString('hex'));
      // The fixture writes the empty raw_value explicitly (1a 00). protoc's text output leaves it out, as it does any
      // empty proto3 value; protobufjs keeps it present through decode and writes it back.
      const serialized = PROCESS_METHOD.requestSerialize(PROCESS_METHOD.requestDeserialize(FIXTURE));
      assert.equal(Buffer.from(serialized).toString('hex'), FIXTURE.toString('hex'));
    });

    it('is never eligible when truncated at any length', () => {
      for (let n = 1; n < FIXTURE.length; n++) {
        assertRejected(checkSerializedRequest(FIXTURE.subarray(0, n)), 'malformed_message');
      }
    });
  });

  describe('end_of_stream', () => {
    for (const method of ['GET', 'HEAD']) {
      it(`${method} with end_of_stream true is eligible for verification, and nothing more`, () => {
        const result = checkSerializedRequest(signed({ key: ':method', raw: method }, 1));
        assert.ok(result.outcome === 'eligible_for_verification');
        assert.equal(result.method, method);
        assert.deepEqual(Object.keys(result).sort(), ['headers', 'method', 'outcome']);
      });
    }

    for (const method of ['GET', 'HEAD']) {
      it(`${method} with end_of_stream explicitly false on the wire is denied`, () => {
        const bytesIn = signed({ key: ':method', raw: method }, 0);
        assert.equal(decodedHeaders(decodeProcessingRequest(bytesIn)).end_of_stream, false);
        assertDenied(checkSerializedRequest(bytesIn), 'body_not_ruled_out');
      });

      it(`${method} with end_of_stream omitted is denied, and the decoder supplies no default`, () => {
        const bytesIn = signed({ key: ':method', raw: method });
        const message = decodedHeaders(decodeProcessingRequest(bytesIn));
        assert.equal('end_of_stream' in message, false);
        assert.equal(message.end_of_stream, undefined);
        assertDenied(checkSerializedRequest(bytesIn), 'body_not_ruled_out');
      });
    }

    it('reads a bool varint other than 0 or 1 as true, as protobuf defines', () => {
      const bytesIn = signed({ key: ':method', raw: 'GET' }, 2);
      assert.equal(decodedHeaders(decodeProcessingRequest(bytesIn)).end_of_stream, true);
      assert.equal(checkSerializedRequest(bytesIn).outcome, 'eligible_for_verification');
    });

    it('takes the last end_of_stream on the wire, as protobuf defines for scalars', () => {
      const lastFalse = len(2, httpHeaders([{ key: ':method', raw: 'GET' }, ...BASE], 1), bool(3, 0));
      assertDenied(checkSerializedRequest(lastFalse), 'body_not_ruled_out');
    });

    it('a body-indicating Content-Length or Transfer-Encoding is still denied with end_of_stream true', () => {
      assertDenied(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'content-length', raw: '5' }])), 'body_indicated');
      assertDenied(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'transfer-encoding', value: 'chunked' }])), 'body_indicated');
      assert.equal(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'content-length', raw: '0' }])).outcome, 'eligible_for_verification');
    });
  });

  describe('header value representations', () => {
    it('accepts the method as raw_value bytes or as a value string', () => {
      for (const method of [{ key: ':method', raw: 'GET' }, { key: ':method', value: 'GET' }, { key: ':method', value: 'GET', raw: 'GET' }]) {
        assert.equal(checkSerializedRequest(signed(method, 1)).outcome, 'eligible_for_verification');
      }
    });

    it('refuses a header whose value and raw_value disagree', () => {
      assertDenied(checkSerializedRequest(signed({ key: ':method', value: 'GET', raw: 'POST' }, 1)), 'malformed_headers_message');
    });

    it('keeps raw_value as a Buffer of the exact bytes and value as a string', () => {
      const message = decodedHeaders(decodeProcessingRequest(signed({ key: ':method', value: 'GET' }, 1)));
      const [method, authority] = message.headers.headers;
      assert.deepEqual(method, { key: ':method', value: 'GET' });
      assert.ok(Buffer.isBuffer(authority?.['raw_value']));
      assert.equal(hex(authority?.['raw_value']), Buffer.from('bank.example').toString('hex'));
    });

    it('keeps an omitted value as absent, which reads as an empty value', () => {
      const bytesIn = signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'x-none' }, { key: 'x-empty-raw', raw: '' }, { key: 'x-empty-text', value: '' }]);
      const message = decodedHeaders(decodeProcessingRequest(bytesIn));
      assert.deepEqual(message.headers.headers.at(-3), { key: 'x-none' });
      const result = checkSerializedRequest(bytesIn);
      assert.ok(result.outcome === 'eligible_for_verification');
      assert.deepEqual(result.headers.slice(-3).map((h) => [h.name, h.value.length]), [['x-none', 0], ['x-empty-raw', 0], ['x-empty-text', 0]]);
    });

    it('denies a :method with no value', () => {
      assertDenied(checkSerializedRequest(signed({ key: ':method' }, 1)), 'method_missing');
    });

    it('denies a request without :method', () => {
      assertDenied(checkSerializedRequest(signed(null, 1)), 'method_missing');
    });

    it('denies headers messages with omitted or empty header maps', () => {
      assertDenied(checkSerializedRequest(len(2)), 'malformed_headers_message');
      assertDenied(checkSerializedRequest(len(2, bool(3, 1))), 'malformed_headers_message');
      assertDenied(checkSerializedRequest(len(2, len(1), bool(3, 1))), 'method_missing');
    });
  });

  describe('exact bytes', () => {
    it('denies byte-order-mark-prefixed methods in either representation', () => {
      const bom = Buffer.from([0xef, 0xbb, 0xbf]);
      for (const method of ['GET', 'HEAD']) {
        const prefixed = Buffer.concat([bom, Buffer.from(method)]);
        assertDenied(checkSerializedRequest(signed({ key: ':method', raw: prefixed }, 1)), 'method_not_allowed');
        assertDenied(checkSerializedRequest(signed({ key: ':method', value: prefixed }, 1)), 'method_not_allowed');
        const message = decodedHeaders(decodeProcessingRequest(signed({ key: ':method', value: prefixed }, 1)));
        assert.equal(message.headers.headers[0]?.['value'], `\uFEFF${method}`);
      }
    });

    it('denies a byte-order-mark-prefixed Content-Length of 0 in either representation', () => {
      const prefixed = Buffer.from([0xef, 0xbb, 0xbf, 0x30]);
      assertDenied(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'content-length', raw: prefixed }])), 'body_indicated');
      assertDenied(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'content-length', value: prefixed }])), 'body_indicated');
    });

    it('does not normalize method bytes', () => {
      for (const method of ['get', 'GET ', ' GET', 'GET\0', 'GЕT']) {
        assertDenied(checkSerializedRequest(signed({ key: ':method', raw: method }, 1)), 'method_not_allowed');
      }
    });

    it('denies duplicate :method entries, keeping both on decode', () => {
      const bytesIn = requestHeaders([{ key: ':method', raw: 'GET' }, ...BASE, { key: ':method', raw: 'GET' }], 1);
      const message = decodedHeaders(decodeProcessingRequest(bytesIn));
      assert.equal(message.headers.headers.filter((h) => h['key'] === ':method').length, 2);
      assertDenied(checkSerializedRequest(bytesIn), 'method_ambiguous');
      assertDenied(checkSerializedRequest(requestHeaders([{ key: ':method', raw: 'GET' }, { key: ':method', value: 'POST' }, ...BASE], 1)), 'method_ambiguous');
    });

    it('preserves non-UTF-8 signature bytes, escaped path and query bytes, duplicates and order', () => {
      const signature = Buffer.from([0x73, 0x69, 0x67, 0x31, 0x3d, 0x3a, 0xff, 0x00, 0x80, 0x3a]);
      const path = bytes('/a%2Fb/%2e%2E/c%20d?x=%41&x=1&y=%zz&');
      const entries: Entry[] = [
        { key: ':method', raw: 'HEAD' },
        { key: ':path', raw: path },
        { key: 'Signature', raw: signature },
        { key: 'signature', raw: 'second' },
        { key: 'x-bom', raw: Buffer.from([0xef, 0xbb, 0xbf, 0x41]) },
        { key: 'x-replacement', value: '\uFFFD' },
      ];
      const result = checkSerializedRequest(requestHeaders(entries, 1));
      assert.ok(result.outcome === 'eligible_for_verification');
      assert.deepEqual(
        result.headers.map((h) => [h.name, hex(h.value)]),
        [
          [':method', Buffer.from('HEAD').toString('hex')],
          [':path', path.toString('hex')],
          ['Signature', signature.toString('hex')],
          ['signature', Buffer.from('second').toString('hex')],
          ['x-bom', 'efbbbf41'],
          ['x-replacement', 'efbfbd'],
        ],
      );
    });

    it('accepts a Uint8Array view at an offset into a larger buffer', () => {
      const backing = new Uint8Array(FIXTURE.length + 7);
      backing.set(FIXTURE, 3);
      const result = checkSerializedRequest(backing.subarray(3, 3 + FIXTURE.length));
      assert.equal(result.outcome, 'eligible_for_verification');
    });
  });

  // The deserializer a gRPC service registered with PROCESS_METHOD would call, invoked directly.
  describe('the service-facing deserializer', () => {
    it('is the guarded deserializer, and the method definition is frozen', () => {
      assert.equal(PROCESS_METHOD.requestDeserialize, deserializeProcessingRequest);
      assert.ok(Object.isFrozen(PROCESS_METHOD));
      assert.throws(() => {
        (PROCESS_METHOD as { requestDeserialize: unknown }).requestDeserialize = (b: Buffer) => b;
      }, TypeError);
    });

    it('decodes a well-formed request, with snake_case names and raw bytes', () => {
      const decoded = PROCESS_METHOD.requestDeserialize(FIXTURE) as Record<string, unknown>;
      assert.equal(decoded['request'], 'request_headers');
      const message = decoded['request_headers'] as { end_of_stream: boolean; headers: { headers: Record<string, unknown>[] } };
      assert.equal(message.end_of_stream, true);
      assert.ok(Buffer.isBuffer(message.headers.headers[0]?.['raw_value']));
    });

    it('throws a fixed rejection for empty, truncated and malformed bytes', () => {
      assertDeserializerRejects(Buffer.alloc(0), 'empty_message');
      assertDeserializerRejects(FIXTURE.subarray(0, 40), 'malformed_message');
      assertDeserializerRejects(Buffer.from([0x0f]), 'malformed_message');
      assertDeserializerRejects('GET', 'malformed_message');
    });

    it('throws on conflicting fields', () => {
      assertDeserializerRejects(Buffer.concat([signedGet(), len(4, bool(2, 1))]), 'conflicting_fields');
      assertDeserializerRejects(Buffer.concat([signed({ key: ':method', raw: 'POST' }), signedGet()]), 'conflicting_fields');
    });

    it('throws on header key or value strings that are not valid UTF-8, echoing nothing', () => {
      const marker = 'secret-marker-9c1d';
      assertDeserializerRejects(signed({ key: ':method', raw: 'GET' }, 1, [{ key: marker, value: Buffer.from([0xff]) }]), 'invalid_utf8_string', marker);
      assertDeserializerRejects(signed({ key: Buffer.from([0x78, 0xff]), raw: marker }, 1), 'invalid_utf8_string', marker);
    });
  });

  describe('map fields (attributes and metadata_context)', () => {
    it('decodes valid attributes and metadata alongside the request headers', () => {
      const typedAny = Buffer.concat([len(1, Buffer.from('type.googleapis.com/x.Y')), len(2, Buffer.from([0xff, 0x00]))]);
      const bytesIn = Buffer.concat([
        signedGet(),
        attributes('request', struct('path', stringValue('/a%2Fb'))),
        len(8, len(1, entry('envoy.filters.http.x', len(2, struct('flag', bool(4, 1))))), len(2, entry('typed', len(2, typedAny)))),
        attributes('nested', nestedStruct(4)),
      ]);
      const decoded = PROCESS_METHOD.requestDeserialize(bytesIn) as Record<string, any>;
      assert.deepEqual(decoded['attributes']['request'], { fields: { path: { stringValue: '/a%2Fb', kind: 'stringValue' } } });
      assert.equal(decoded['attributes']['nested']['fields']['a']['structValue']['fields']['a']['kind'], 'structValue');
      assert.deepEqual(decoded['metadata_context']['filter_metadata']['envoy.filters.http.x'], { fields: { flag: { boolValue: true, kind: 'boolValue' } } });
      const any = decoded['metadata_context']['typed_filter_metadata']['typed'];
      assert.equal(any['type_url'], 'type.googleapis.com/x.Y');
      assert.equal(hex(any['value']), 'ff00');
      assert.equal(checkSerializedRequest(bytesIn).outcome, 'eligible_for_verification');
    });

    it('accepts an empty Struct value and unknown fields in an entry', () => {
      const bytesIn = Buffer.concat([signedGet(), len(9, entry('k', len(2)), bool(15, 1)), len(9, entry('', len(2)))]);
      const decoded = PROCESS_METHOD.requestDeserialize(bytesIn) as Record<string, any>;
      assert.deepEqual(decoded['attributes'], { k: {}, '': {} });
      assert.equal(checkSerializedRequest(bytesIn).outcome, 'eligible_for_verification');
    });

    // Valid protobuf (the value would be an empty Struct), but the pinned proto-loader/protobufjs conversion throws on
    // it, so it is refused rather than guessed at.
    it('refuses an entry whose message value is omitted', () => {
      assertDeserializerRejects(Buffer.concat([signedGet(), len(9)]), 'malformed_message');
      assertDeserializerRejects(Buffer.concat([signedGet(), len(9, entry('k'))]), 'malformed_message');
    });

    it('keeps the last of two entries with the same key, as protobuf defines', () => {
      const bytesIn = Buffer.concat([signedGet(), attributes('k', struct('v', stringValue('first'))), attributes('k', struct('v', stringValue('last')))]);
      const decoded = PROCESS_METHOD.requestDeserialize(bytesIn) as Record<string, any>;
      assert.equal(decoded['attributes']['k']['fields']['v']['stringValue'], 'last');
    });

    it('throws on map keys that are not valid UTF-8 or not length-delimited', () => {
      assertDeserializerRejects(Buffer.concat([signedGet(), attributes(Buffer.from([0x6b, 0xff]), len(1))]), 'invalid_utf8_string');
      assertDeserializerRejects(Buffer.concat([signedGet(), len(8, len(1, entry(Buffer.from([0xc0, 0x80]), len(2))))]), 'invalid_utf8_string');
      assertDeserializerRejects(Buffer.concat([signedGet(), len(8, len(2, entry(Buffer.from([0xed, 0xa0, 0x80]))))]), 'invalid_utf8_string');
      assertDeserializerRejects(Buffer.concat([signedGet(), attributes('k', struct(Buffer.from([0x76, 0xff]), stringValue('v')))]), 'invalid_utf8_string');
      assertDeserializerRejects(Buffer.concat([signedGet(), len(9, tag(1, 0), varint(5), len(2))]), 'malformed_message');
      // varint 0 in place of a string key, which a decoder could read as the empty key
      assertDeserializerRejects(Buffer.concat([signedGet(), len(9, tag(1, 0), varint(0), len(2))]), 'malformed_message');
    });

    it('throws on map values that are malformed, conflicting or not valid UTF-8', () => {
      const cases: [string, Buffer, string][] = [
        ['a Struct value sent as a varint', len(9, entry('k', tag(2, 0), varint(1))), 'malformed_message'],
        ['a Struct value sent as varint 0, which a decoder could read as an empty Struct', len(9, entry('k', tag(2, 0), varint(0))), 'malformed_message'],
        ['a map entry sent as a varint', Buffer.concat([tag(9, 0), varint(1)]), 'malformed_message'],
        ['an entry running past its map field', Buffer.concat([tag(9, 2), varint(10), len(1, Buffer.from('k'))]), 'malformed_message'],
        ['a value running past its entry', len(9, len(1, Buffer.from('k')), tag(2, 2), varint(9), Buffer.from('ab')), 'malformed_message'],
        ['a Struct value sent twice in one entry', len(9, entry('k', len(2, struct('a', stringValue('x'))), len(2, struct('b', stringValue('y'))))), 'conflicting_fields'],
        ['a string_value that is not UTF-8', attributes('k', struct('v', stringValue(Buffer.from([0xff, 0xfe])))), 'invalid_utf8_string'],
        ['two members of Value.kind', attributes('k', struct('v', Buffer.concat([stringValue('x'), bool(4, 1)]))), 'conflicting_fields'],
        ['a number_value sent as a varint', attributes('k', struct('v', bool(2, 1))), 'malformed_message'],
        ['a list element that is not UTF-8', attributes('k', struct('v', len(6, len(1, stringValue(Buffer.from([0x80])))))), 'invalid_utf8_string'],
        ['a filter_metadata value that is not UTF-8', len(8, len(1, entry('f', len(2, struct('v', stringValue(Buffer.from([0xff]))))))), 'invalid_utf8_string'],
        ['an Any type_url that is not UTF-8', len(8, len(2, entry('t', len(2, len(1, Buffer.from([0xff])))))), 'invalid_utf8_string'],
        ['a stray end-group tag in an entry', len(9, entry('k'), Buffer.from([0x0c])), 'malformed_message'],
      ];
      for (const [name, field, reason] of cases) {
        assert.doesNotThrow(() => assertDeserializerRejects(Buffer.concat([signedGet(), field]), reason), name);
      }
    });

    it('throws on excessive nesting through maps, and accepts nesting within the limit', () => {
      assert.doesNotThrow(() => PROCESS_METHOD.requestDeserialize(Buffer.concat([signedGet(), attributes('k', nestedStruct(10))])));
      assertDeserializerRejects(Buffer.concat([signedGet(), attributes('k', nestedStruct(11))]), 'malformed_message');
      assertDeserializerRejects(Buffer.concat([signedGet(), attributes('k', nestedStruct(200))]), 'malformed_message');
      assertDeserializerRejects(Buffer.concat([signedGet(), len(8, len(1, entry('f', len(2, nestedStruct(200)))))]), 'malformed_message');
    });
  });

  describe('messages that never become eligible', () => {
    it('rejects an empty message', () => {
      assertRejected(checkSerializedRequest(new Uint8Array(0)), 'empty_message');
      assertRejected(checkSerializedRequest(Buffer.alloc(0)), 'empty_message');
    });

    it('rejects input that is not bytes', () => {
      for (const input of [undefined, null, 'GET', [0x12, 0x00], {}]) {
        assertRejected(checkSerializedRequest(input as unknown as Uint8Array), 'malformed_message');
      }
    });

    it('rejects truncated messages', () => {
      const whole = signed({ key: ':method', raw: 'GET' }, 1);
      for (const n of [1, 2, 3, 10, whole.length - 1]) {
        assertRejected(checkSerializedRequest(whole.subarray(0, n)), 'malformed_message');
      }
      // A length that runs past the end of its enclosing message.
      assertRejected(checkSerializedRequest(Buffer.from('1203' + '0a05' + '00', 'hex')), 'malformed_message');
    });

    it('rejects malformed encodings', () => {
      const cases: [string, Buffer][] = [
        ['wire type 7', Buffer.from([0x0f])],
        ['field number 0', Buffer.from([0x02, 0x00])],
        ['overlong varint', Buffer.from('ffffffffffffffffffffff', 'hex')],
        ['request_headers sent as a varint', Buffer.concat([tag(2, 0), varint(1)])],
        ['end_of_stream sent length-delimited', len(2, headerMap([{ key: ':method', raw: 'GET' }]), len(3, Buffer.from([1])))],
        ['a header key sent as a varint', len(2, len(1, len(1, tag(1, 0), varint(7))), bool(3, 1))],
        ['a stray end-group tag', Buffer.from([0x0c])],
      ];
      for (const [name, bytesIn] of cases) {
        const result = checkSerializedRequest(bytesIn);
        assert.equal(result.outcome, 'reject', name);
        assert.ok(result.outcome === 'reject');
        assert.equal(result.reason, 'malformed_message', name);
      }
    });

    it('rejects every ProcessingRequest that is not a request headers message', () => {
      const headersBody = httpHeaders([{ key: ':method', raw: 'GET' }, ...BASE], 1);
      const variants: [string, Buffer][] = [
        ['response_headers', len(3, headersBody)],
        ['request_body', len(4, len(1, Buffer.from('x')), bool(2, 1))],
        ['response_body', len(5)],
        ['request_trailers', len(6, len(1))],
        ['response_trailers', len(7)],
        ['observability_mode only', bool(10, 1)],
        ['an unknown field only', bool(99, 1)],
      ];
      for (const [name, bytesIn] of variants) {
        assertRejected(checkSerializedRequest(bytesIn), 'unsupported_message_type');
        assert.equal(decodeProcessingRequest(bytesIn).outcome, 'reject', name);
      }
    });

    it('rejects conflicting fields rather than picking one', () => {
      const headers = signed({ key: ':method', raw: 'GET' }, 1);
      const cases: [string, Buffer][] = [
        ['request_headers then request_body', Buffer.concat([headers, len(4, bool(2, 1))])],
        ['request_body then request_headers', Buffer.concat([len(4, bool(2, 1)), headers])],
        ['request_headers twice', Buffer.concat([signed({ key: ':method', raw: 'POST' }), headers])],
        ['the header map twice', len(2, headerMap([{ key: ':method', raw: 'POST' }]), headerMap([{ key: ':method', raw: 'GET' }, ...BASE]), bool(3, 1))],
      ];
      for (const [name, bytesIn] of cases) {
        const result = checkSerializedRequest(bytesIn);
        assert.deepEqual(result, { outcome: 'reject', reason: 'conflicting_fields' }, name);
      }
    });

    it('rejects a header key or value string that is not valid UTF-8', () => {
      assertRejected(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: 'x', value: Buffer.from([0xff, 0xc0, 0x41]) }])), 'invalid_utf8_string');
      assertRejected(checkSerializedRequest(signed({ key: ':method', raw: 'GET' }, 1, [{ key: Buffer.from([0x78, 0xff]), raw: 'v' }])), 'invalid_utf8_string');
      assertRejected(checkSerializedRequest(signed({ key: ':method', value: Buffer.from([0x47, 0x45, 0x54, 0xed, 0xa0, 0x80]) }, 1)), 'invalid_utf8_string');
    });

    it('ignores unknown fields, as protobuf defines', () => {
      const withUnknown = len(2, len(1, len(1, headerValue({ key: ':method', raw: 'GET' }), bool(15, 1))), bool(3, 1), bool(15, 1));
      assert.equal(checkSerializedRequest(Buffer.concat([withUnknown, bool(99, 1)])).outcome, 'eligible_for_verification');
    });

    it('gives a fixed rejection that echoes nothing from the payload', () => {
      const marker = 'secret-marker-7f3a';
      const inputs = [
        Buffer.concat([signed({ key: ':method', raw: marker }, 1)]).subarray(0, 30),
        len(3, httpHeaders([{ key: ':method', raw: marker }], 1)),
        signed({ key: marker, value: Buffer.from([0xff]) }, 1),
      ];
      for (const input of inputs) {
        const result = checkSerializedRequest(input);
        assert.equal(result.outcome, 'reject');
        assert.deepEqual(Object.keys(result).sort(), ['outcome', 'reason']);
        assert.equal(JSON.stringify(result).includes(marker), false);
      }
    });
  });
});
