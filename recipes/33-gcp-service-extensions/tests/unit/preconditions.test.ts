// Local message-level tests of the request preconditions. They exercise the verifier's handling of Envoy ext_proc
// `HttpHeaders` messages built here; they are not evidence of how Google's load balancer forwards requests, and they
// involve no DNSid verification.
// Message contract: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/ext_proc/v3/external_processor.proto#service-ext-proc-v3-httpheaders

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { checkRequestPreconditions, type ProcessingRequestMessage } from '../../src/preconditions.ts';

type Header = [name: string, value: string];

const HTTP1_HEADERS: Header[] = [
  [':authority', 'bank.example'],
  [':path', '/accounts/123?view=summary'],
  [':scheme', 'https'],
  ['signature-input', 'sig1=("@method" "@authority" "@target-uri");created=1762900000;keyid="k1"'],
  ['signature', 'sig1=:AAAA:'],
];

function rawHeaders(headers: Header[]) {
  return headers.map(([key, value]) => ({ key, raw_value: Buffer.from(value) }));
}

function request(method: string | null, endOfStream: unknown, extra: Header[] = []): ProcessingRequestMessage {
  const headers: Header[] = [...(method === null ? [] : [[':method', method] as Header]), ...HTTP1_HEADERS, ...extra];
  const message: Record<string, unknown> = { headers: { headers: rawHeaders(headers) } };
  if (endOfStream !== undefined) message['end_of_stream'] = endOfStream;
  return { request_headers: message };
}

function assertDenied(result: ReturnType<typeof checkRequestPreconditions>, reason: string) {
  assert.deepEqual(result, { outcome: 'deny', status: 403, reason });
}

describe('request preconditions (local, message-level)', () => {
  describe('bodyless GET and HEAD with end_of_stream=true', () => {
    for (const method of ['GET', 'HEAD']) {
      it(`${method} is eligible for verification, and nothing more`, () => {
        const result = checkRequestPreconditions(request(method, true));
        assert.equal(result.outcome, 'eligible_for_verification');
        assert.ok(result.outcome === 'eligible_for_verification');
        assert.equal(result.method, method);
        assert.deepEqual(Object.keys(result).sort(), ['headers', 'method', 'outcome']);
      });
    }

    it('keeps every header, in order, with its name and exact bytes', () => {
      const bytes = Buffer.from([0x73, 0x69, 0x67, 0x31, 0x3d, 0x3a, 0xff, 0x00, 0x3a]);
      const input: ProcessingRequestMessage = {
        request_headers: {
          end_of_stream: true,
          headers: {
            headers: [
              { key: ':method', raw_value: Buffer.from('GET') },
              { key: 'Signature', raw_value: bytes },
              { key: 'x-plain', value: 'text value' },
              { key: 'x-empty', raw_value: Buffer.alloc(0) },
            ],
          },
        },
      };
      const result = checkRequestPreconditions(input);
      assert.ok(result.outcome === 'eligible_for_verification');
      assert.deepEqual(
        result.headers.map((h) => [h.name, Buffer.from(h.value).toString('hex')]),
        [
          [':method', Buffer.from('GET').toString('hex')],
          ['Signature', bytes.toString('hex')],
          ['x-plain', Buffer.from('text value').toString('hex')],
          ['x-empty', ''],
        ],
      );
    });

    it('copies header bytes, so later changes to the message cannot alter them', () => {
      const raw = Buffer.from('sig1=:AAAA:');
      const input: ProcessingRequestMessage = {
        request_headers: {
          end_of_stream: true,
          headers: { headers: [{ key: ':method', raw_value: Buffer.from('GET') }, { key: 'signature', raw_value: raw }] },
        },
      };
      const result = checkRequestPreconditions(input);
      raw.fill(0);
      assert.ok(result.outcome === 'eligible_for_verification');
      assert.equal(Buffer.from(result.headers[1]!.value).toString(), 'sig1=:AAAA:');
    });
  });

  describe('end_of_stream false or missing', () => {
    for (const method of ['GET', 'HEAD']) {
      it(`${method} with end_of_stream=false is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, false)), 'body_not_ruled_out');
      });
      it(`${method} with end_of_stream missing is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, undefined)), 'body_not_ruled_out');
      });
    }
  });

  describe('malformed end_of_stream values are not coerced', () => {
    const values: [string, unknown][] = [
      ['the string "true"', 'true'],
      ['the string "1"', '1'],
      ['the number 1', 1],
      ['an object', {}],
      ['an array', [true]],
      ['null', null],
      ['a boxed true', new Boolean(true)],
    ];
    for (const method of ['GET', 'HEAD']) {
      for (const [label, value] of values) {
        it(`${method} with end_of_stream as ${label} is denied`, () => {
          assertDenied(checkRequestPreconditions(request(method, value)), 'body_not_ruled_out');
        });
      }
    }
  });

  describe('HTTP/2-style headers with no length headers', () => {
    for (const method of ['GET', 'HEAD']) {
      it(`${method} without Content-Length or Transfer-Encoding is denied when the stream has not ended`, () => {
        assertDenied(checkRequestPreconditions(request(method, false)), 'body_not_ruled_out');
        assertDenied(checkRequestPreconditions(request(method, undefined)), 'body_not_ruled_out');
      });
    }
  });

  describe('requests carrying a body', () => {
    for (const method of ['GET', 'HEAD']) {
      it(`${method} with Transfer-Encoding: chunked and the stream open is denied`, () => {
        const result = checkRequestPreconditions(request(method, false, [['transfer-encoding', 'chunked']]));
        assertDenied(result, 'body_not_ruled_out');
      });
      it(`${method} with Content-Length: 5 and the stream open is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, false, [['content-length', '5']])), 'body_not_ruled_out');
      });
      it(`${method} whose headers announce content but whose stream has ended is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, true, [['Transfer-Encoding', 'chunked']])), 'body_indicated');
        assertDenied(checkRequestPreconditions(request(method, true, [['content-length', '5']])), 'body_indicated');
        assertDenied(checkRequestPreconditions(request(method, true, [['content-length', 'abc']])), 'body_indicated');
        assertDenied(checkRequestPreconditions(request(method, true, [['content-length', '00']])), 'body_indicated');
        assertDenied(checkRequestPreconditions(request(method, true, [['content-length', ' 0']])), 'body_indicated');
      });
    }
  });

  describe('Content-Length: 0 never overrides the end-of-stream indication', () => {
    for (const method of ['GET', 'HEAD']) {
      it(`${method} with Content-Length: 0 and end_of_stream=false is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, false, [['content-length', '0']])), 'body_not_ruled_out');
      });
      it(`${method} with Content-Length: 0 and end_of_stream missing is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, undefined, [['content-length', '0']])), 'body_not_ruled_out');
      });
      it(`${method} with exactly Content-Length: 0 and end_of_stream=true stays eligible`, () => {
        assert.equal(checkRequestPreconditions(request(method, true, [['content-length', '0']])).outcome, 'eligible_for_verification');
      });
    }
  });

  describe('methods', () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'get', 'Head', ' GET', 'GET ']) {
      it(`${JSON.stringify(method)} is denied`, () => {
        assertDenied(checkRequestPreconditions(request(method, true)), 'method_not_allowed');
      });
    }

    it('a missing :method is denied', () => {
      assertDenied(checkRequestPreconditions(request(null, true)), 'method_missing');
    });

    it('an empty :method is denied', () => {
      assertDenied(checkRequestPreconditions(request('', true)), 'method_missing');
    });

    it('a :method that is not valid UTF-8 is denied', () => {
      const input: ProcessingRequestMessage = {
        request_headers: { end_of_stream: true, headers: { headers: [{ key: ':method', raw_value: Buffer.from([0xff, 0x47]) }] } },
      };
      assertDenied(checkRequestPreconditions(input), 'method_missing');
    });

    it('two :method headers are denied, even when both say GET', () => {
      assertDenied(checkRequestPreconditions(request('GET', true, [[':method', 'GET']])), 'method_ambiguous');
      assertDenied(checkRequestPreconditions(request('GET', true, [[':method', 'POST']])), 'method_ambiguous');
    });

    it('a :method whose value and raw_value disagree is denied', () => {
      const input: ProcessingRequestMessage = {
        request_headers: {
          end_of_stream: true,
          headers: { headers: [{ key: ':method', value: 'GET', raw_value: Buffer.from('POST') }] },
        },
      };
      assertDenied(checkRequestPreconditions(input), 'malformed_headers_message');
    });

    it('a :method whose value and raw_value agree is accepted', () => {
      const input: ProcessingRequestMessage = {
        request_headers: {
          end_of_stream: true,
          headers: { headers: [{ key: ':method', value: 'GET', raw_value: Buffer.from('GET') }] },
        },
      };
      assert.equal(checkRequestPreconditions(input).outcome, 'eligible_for_verification');
    });

    describe('a leading byte-order mark is not stripped', () => {
      const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
      for (const method of ['GET', 'HEAD']) {
        it(`BOM + ${method} in raw_value is denied`, () => {
          const input: ProcessingRequestMessage = {
            request_headers: {
              end_of_stream: true,
              headers: { headers: [{ key: ':method', raw_value: Buffer.concat([BOM, Buffer.from(method)]) }] },
            },
          };
          assertDenied(checkRequestPreconditions(input), 'method_not_allowed');
        });
        it(`BOM + ${method} in value is denied`, () => {
          const input: ProcessingRequestMessage = {
            request_headers: { end_of_stream: true, headers: { headers: [{ key: ':method', value: `\uFEFF${method}` }] } },
          };
          assertDenied(checkRequestPreconditions(input), 'method_not_allowed');
        });
        it(`BOM + ${method} in both value and raw_value is denied`, () => {
          const input: ProcessingRequestMessage = {
            request_headers: {
              end_of_stream: true,
              headers: {
                headers: [{ key: ':method', value: `\uFEFF${method}`, raw_value: Buffer.concat([BOM, Buffer.from(method)]) }],
              },
            },
          };
          assertDenied(checkRequestPreconditions(input), 'method_not_allowed');
        });
        it(`${method} with Content-Length: BOM + 0 and the stream ended is denied`, () => {
          const viaRaw: ProcessingRequestMessage = {
            request_headers: {
              end_of_stream: true,
              headers: {
                headers: [
                  { key: ':method', raw_value: Buffer.from(method) },
                  { key: 'content-length', raw_value: Buffer.concat([BOM, Buffer.from('0')]) },
                ],
              },
            },
          };
          const viaText: ProcessingRequestMessage = {
            request_headers: {
              end_of_stream: true,
              headers: { headers: [{ key: ':method', value: method }, { key: 'content-length', value: '\uFEFF0' }] },
            },
          };
          assertDenied(checkRequestPreconditions(viaRaw), 'body_indicated');
          assertDenied(checkRequestPreconditions(viaText), 'body_indicated');
        });
      }
    });

    it('a method with a trailing NUL or a lookalike character is denied', () => {
      for (const method of ['GET\u0000', 'G\u0415T', 'ＧＥＴ', 'HEAD\u200b']) {
        assertDenied(checkRequestPreconditions(request(method, true)), 'method_not_allowed');
      }
    });

    it('POST, PUT and DELETE are denied whatever the end-of-stream indication', () => {
      for (const method of ['POST', 'PUT', 'DELETE']) {
        for (const eos of [true, false, undefined]) {
          assertDenied(checkRequestPreconditions(request(method, eos)), 'method_not_allowed');
        }
      }
    });
  });

  describe('malformed messages', () => {
    const cases: [string, unknown][] = [
      ['undefined', undefined],
      ['null', null],
      ['a string', 'GET'],
      ['no request_headers', {}],
      ['request_headers null', { request_headers: null }],
      ['no header map', { request_headers: { end_of_stream: true } }],
      ['header list not an array', { request_headers: { end_of_stream: true, headers: { headers: {} } } }],
      ['a header entry that is not an object', { request_headers: { end_of_stream: true, headers: { headers: ['GET'] } } }],
      ['a header with no name', { request_headers: { end_of_stream: true, headers: { headers: [{ raw_value: Buffer.from('GET') }] } } }],
      [
        'a header value of the wrong type',
        { request_headers: { end_of_stream: true, headers: { headers: [{ key: ':method', value: 7 }] } } },
      ],
      [
        'a raw_value of the wrong type',
        { request_headers: { end_of_stream: true, headers: { headers: [{ key: ':method', raw_value: 'GET' }] } } },
      ],
    ];
    for (const [label, input] of cases) {
      it(`${label} is denied`, () => {
        assertDenied(checkRequestPreconditions(input as ProcessingRequestMessage), 'malformed_headers_message');
      });
    }
  });

  it('a denial carries only the status and a reason code', () => {
    const result = checkRequestPreconditions(request('POST', true, [['authorization', 'Bearer secret']]));
    assert.deepEqual(Object.keys(result).sort(), ['outcome', 'reason', 'status']);
    assert.doesNotMatch(JSON.stringify(result), /secret|bank\.example|sig1/);
  });
});
