// The response layer on its own, at the wire: each test serializes with the service's `PROCESS_METHOD.responseSerialize`
// and reads the bytes back with its `responseDeserialize` and, independently, with protobufjs reflection (numeric
// enums). The outcomes here are CONSTRUCTED values in the shapes the stages return, not SDK-verified results; the
// integrated tests (callout.test.ts) run the real pipeline.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { checkAttestation } from '../../origin/server.ts';
import { ATTESTATION_HEADER } from '../../src/attestation.ts';
import { PROCESS_METHOD } from '../../src/ext-proc.ts';
import type { ReceivedHeader } from '../../src/preconditions.ts';
import {
  GOVERNANCE_ID_HEADER,
  MAX_REMOVED_HEADERS,
  MAX_RESPONSE_BYTES,
  RESPONSE_REASONS,
  VERIFIED_DOMAIN_HEADER,
  denialResponse,
  respond,
  type CalloutResponse,
  type ResponseContext,
} from '../../src/response.ts';
import {
  FORBIDDEN,
  OVERWRITE_IF_EXISTS_OR_ADD,
  applyMutation,
  decodeContinuation,
  decodeDenial,
  valuesOf,
  viaService,
  type HeaderList,
} from '../support/response-wire.ts';

const DOMAIN = 'agent-gov-fixture.test';
const GOVERNANCE = 'gov-fixture.test';

function header(name: string, value: string | Uint8Array): ReceivedHeader {
  return { name, value: typeof value === 'string' ? Buffer.from(value, 'latin1') : Uint8Array.from(value) };
}

function received(method = 'GET', extra: [string, string][] = []): ReceivedHeader[] {
  return [
    header(':method', method),
    header(':authority', 'api-example.test'),
    header(':path', '/accounts/123?view=summary'),
    header(':scheme', 'https'),
    header('signature-input', 'sig1=("@method" "@authority" "@target-uri");created=1;keyid="k"'),
    header('signature', 'sig1=:AAAA:'),
    header('accept', 'application/json'),
    ...extra.map(([name, value]) => header(name, value)),
  ];
}

/** A constructed `verification_passed` (not SDK-verified), with internal fields the response must never forward. */
function passed(identity: Partial<Record<'domain' | 'governanceId', unknown>> = {}, lifecycle: Record<string, unknown> = {}) {
  return {
    outcome: 'verification_passed',
    signature: { outcome: 'signature_stage_passed', keyId: 'KEYID-SECRET-MARKER', sdkResult: { secret: 'SDK-OBJECT-MARKER' } },
    identity: { domain: DOMAIN, governanceId: GOVERNANCE, entityKeyThumbprint: 'THUMBPRINT-MARKER', dnssecState: 'UNKNOWN', materialCache: 'miss', ...identity },
    lifecycle: {
      loggedState: 'ACTIVE',
      logReference: 'LOGREF-MARKER',
      historyEnd: 'x@0',
      completeThrough: '1',
      completenessMode: 'full-scan',
      freshnessTime: '2026-01-01T00:00:00.000Z',
      evidenceAgeMs: 1,
      ...lifecycle,
    },
  };
}

function live(budgetMs = 5000): ResponseContext {
  return { signal: new AbortController().signal, deadline: performance.now() + budgetMs };
}

function asList(headers: readonly ReceivedHeader[]): HeaderList {
  return headers.map(({ name, value }) => [name, Buffer.from(value)]);
}

function assertDeny(result: CalloutResponse, reason: string): void {
  assert.equal(result.decision, 'deny', `expected a denial (${reason})`);
  assert.equal(result.decision === 'deny' && result.reason, reason);
  const denial = decodeDenial(result.response);
  assert.equal(denial.status, FORBIDDEN);
  assert.equal(denial.body.toString('latin1'), reason);
}

function assertContinue(result: CalloutResponse) {
  assert.equal(result.decision, 'continue', JSON.stringify(result.decision === 'deny' ? result.reason : ''));
  return decodeContinuation(result.response);
}

const SENSITIVE = ['MARKER', 'Error', 'stack', 'https://', 'sig1', 'AAAA', 'checkpoint', 'api-example.test', 'accounts'];

function assertNoLeak(bytes: Uint8Array): void {
  const text = Buffer.from(bytes).toString('latin1');
  for (const marker of SENSITIVE) assert.equal(text.includes(marker), false, `"${marker}" in the response`);
}

describe('response: denials on the wire', () => {
  test('every reason code is an immediate 403 with exactly Cache-Control: no-store (raw_value) and the code as the body', () => {
    // 46 from the stages and the response layer, plus the gRPC service's unexpected_message.
    assert.equal(RESPONSE_REASONS.length, 47);
    for (const reason of RESPONSE_REASONS) {
      const result = denialResponse(reason);
      assertDeny(result, reason);
      const denial = decodeDenial(result.response);
      assert.equal(denial.headers.length, 1);
      assert.equal(denial.headers[0]?.key, 'cache-control');
      assert.deepEqual(denial.headers[0]?.rawValue, Buffer.from('no-store'));
      assert.equal(denial.headers[0]?.appendAction, OVERWRITE_IF_EXISTS_OR_ADD);
      assert.match(denial.body.toString('latin1'), /^[a-z0-9_]{1,40}$/);
      assert.ok(result.response.length < 128, `small: ${result.response.length} bytes`);
    }
  });

  test('the reason codes are distinct, and cancellation, budget, unavailable evidence and log rejection stay apart', () => {
    const bodies = RESPONSE_REASONS.map((reason) => decodeDenial(denialResponse(reason).response).body.toString('latin1'));
    assert.equal(new Set(bodies).size, RESPONSE_REASONS.length);
    for (const reason of ['verification_cancelled', 'verification_budget_exhausted', 'lifecycle_unavailable', 'lifecycle_not_established', 'identity_unavailable']) {
      assertDeny(respond({ outcome: 'deny', status: 403, reason, failure: { kind: 'x', transient: true } }, received(), live()), reason);
    }
  });

  test('each stage outcome shape maps to its own reason: decoding, preconditions, signature, identity, lifecycle', () => {
    assertDeny(respond({ outcome: 'reject', reason: 'malformed_message' }, [], live()), 'malformed_message');
    assertDeny(respond({ outcome: 'reject', reason: 'empty_message' }, [], live()), 'empty_message');
    assertDeny(respond({ outcome: 'deny', status: 403, reason: 'method_not_allowed' }, [], live()), 'method_not_allowed');
    assertDeny(respond({ outcome: 'deny', status: 403, reason: 'signature_invalid' }, received(), live()), 'signature_invalid');
    assertDeny(
      respond({ outcome: 'deny', status: 403, reason: 'governance_not_trusted', failure: { kind: 'untrusted_governance', transient: false } }, received(), live()),
      'governance_not_trusted',
    );
    assertDeny(
      respond({ outcome: 'deny', status: 403, reason: 'lifecycle_evidence_stale', failure: { kind: 'evidence_stale', transient: false } }, received(), live()),
      'lifecycle_evidence_stale',
    );
  });

  test('nothing internal reaches a denial: failure objects, messages, stacks, headers, URLs, signature material', () => {
    const error = new Error('https://log.example/checkpoint MARKER');
    const outcome = {
      outcome: 'deny',
      status: 403,
      reason: 'lifecycle_not_established',
      failure: { kind: 'log_rejected', transient: false, code: 'LogError', message: error.message, stack: error.stack, error },
      headers: received(),
      url: 'https://api-example.test/accounts/123',
    };
    const result = respond(outcome, received(), live());
    assertDeny(result, 'lifecycle_not_established');
    assertNoLeak(result.response);
  });

  test('a reason that is not a known code, or not a string, is the fixed internal_error denial', () => {
    for (const reason of ['not_a_reason', 'toString', '__proto__', 'constructor', 'signature_invalid ', 'SIGNATURE_INVALID', 403, null, undefined, {}, ['signature_invalid']]) {
      const result = respond({ outcome: 'deny', status: 403, reason }, received(), live());
      assertDeny(result, 'internal_error');
      assertNoLeak(result.response);
    }
    assertDeny(denialResponse('a message with https://secret MARKER'), 'internal_error');
  });

  test('each denial is a fresh copy: changing one does not change the next', () => {
    const first = denialResponse('signature_invalid');
    first.response.fill(0);
    assertDeny(denialResponse('signature_invalid'), 'signature_invalid');
  });
});

describe('response: no continuation without the whole verification', () => {
  const outcomes: [string, unknown][] = [
    ['eligibility (preconditions passed)', { outcome: 'eligible_for_verification', method: 'GET', headers: received() }],
    ['signature-stage success', { outcome: 'signature_stage_passed', keyId: 'k', sdkResult: {} }],
    ['identity-stage success', { outcome: 'identity_stage_passed', signature: {}, identity: { domain: DOMAIN, governanceId: GOVERNANCE } }],
    ['an unknown success-like outcome', { outcome: 'allow', identity: { domain: DOMAIN, governanceId: GOVERNANCE } }],
    ['continue', { outcome: 'continue' }],
    ['outcome missing', { identity: { domain: DOMAIN, governanceId: GOVERNANCE } }],
    ['an empty object', {}],
    ['null', null],
    ['undefined', undefined],
    ['a string', 'verification_passed'],
    ['an array', [passed()]],
    ['a verification_passed without lifecycle', { ...passed(), lifecycle: undefined }],
    ['a verification_passed whose lifecycle is not ACTIVE', passed({}, { loggedState: 'REVOKED' })],
    ['a verification_passed without identity', { ...passed(), identity: undefined }],
    ['a non-string domain', passed({ domain: ['agent.example'] })],
    ['an empty domain', passed({ domain: '' })],
    ['a domain with a space', passed({ domain: 'agent example' })],
    ['a domain with CR LF', passed({ domain: 'agent.example\r\nx-dnsid-verified-domain: evil' })],
    ['a non-ASCII domain', passed({ domain: 'agént.example' })],
    ['an over-long domain', passed({ domain: `${'a'.repeat(250)}.test` })],
    ['a non-string governance ID', passed({ governanceId: 7 })],
  ];
  for (const [name, outcome] of outcomes) {
    test(`${name}: the internal_error 403`, () => {
      const result = respond(outcome, received(), live());
      assertDeny(result, 'internal_error');
      assertNoLeak(result.response);
    });
  }

  test('only the outcome name verification_passed continues: any other name with a complete, ACTIVE-looking body is the internal_error 403', () => {
    for (const name of ['eligible_for_verification', 'signature_stage_passed', 'identity_stage_passed', 'allow', 'continue', 'passed', 'Verification_passed', 'verification_passed ', undefined]) {
      const result = respond({ ...passed(), outcome: name }, received(), live());
      assertDeny(result, 'internal_error');
    }
  });

  test('an outcome whose fields throw when read: the internal_error 403', () => {
    const hostile = {
      outcome: 'verification_passed',
      get identity(): never {
        throw new Error('MARKER');
      },
      lifecycle: { loggedState: 'ACTIVE' },
    };
    assertDeny(respond(hostile, received(), live()), 'internal_error');
    assertDeny(respond(passed(), null as unknown as ReceivedHeader[], live()), 'internal_error');
    assertDeny(respond(passed(), received(), null as unknown as ResponseContext), 'internal_error');
  });
});

describe('response: the verified continuation on the wire', () => {
  test('the continuation carries a typed summary for logging, from the verification result and never from request headers', () => {
    const forged: ReceivedHeader[] = [...received(), { name: 'x-dnsid-verified-domain', value: Buffer.from('forged.example') }];
    const result = respond(passed(), forged, live());
    assertContinue(result);
    assert.equal(result.decision, 'continue');
    if (result.decision !== 'continue') return;
    assert.deepEqual({ ...result.verified }, { domain: passed().identity.domain, governanceId: passed().identity.governanceId, evidenceAgeMs: 1, completenessMode: 'full-scan', materialCache: 'miss' });
    assert.ok(Object.isFrozen(result.verified));
  });

  test('a verification_passed whose completeness mode or material-cache use is missing or not a known, bounded value: the internal_error 403', () => {
    for (const completenessMode of [undefined, '', 'Full Scan', 'x'.repeat(40), 1]) {
      const outcome = passed();
      assertDeny(respond({ ...outcome, lifecycle: { ...outcome.lifecycle, completenessMode } } as never, received(), live()), 'internal_error');
    }
    for (const materialCache of [undefined, '', 'cold', 1]) {
      const outcome = passed();
      assertDeny(respond({ ...outcome, identity: { ...outcome.identity, materialCache } } as never, received(), live()), 'internal_error');
    }
    for (const materialCache of ['hit', 'miss', 'partial', 'off']) {
      const result = respond({ ...passed(), identity: { ...passed().identity, materialCache } } as never, received(), live());
      assertContinue(result);
    }
  });

  test('a verification_passed whose evidence age is missing or not a finite number: the internal_error 403', () => {
    for (const evidenceAgeMs of [undefined, Number.NaN, Number.POSITIVE_INFINITY, '1']) {
      const outcome = passed();
      assertDeny(respond({ ...outcome, lifecycle: { ...outcome.lifecycle, evidenceAgeMs } }, received(), live()), 'internal_error');
    }
  });

  for (const method of ['GET', 'HEAD']) {
    test(`${method}: CONTINUE, exactly the two verified headers (raw_value, overwrite or add), nothing else changed`, () => {
      const headers = received(method);
      const result = respond(passed(), headers, live());
      const continuation = assertContinue(result);
      assert.equal(continuation.status ?? 0, 0, 'CONTINUE');
      assert.deepEqual(
        continuation.setHeaders.map((h) => [h.key, h.rawValue.toString('latin1'), h.appendAction]),
        [
          [VERIFIED_DOMAIN_HEADER, DOMAIN, OVERWRITE_IF_EXISTS_OR_ADD],
          [GOVERNANCE_ID_HEADER, GOVERNANCE, OVERWRITE_IF_EXISTS_OR_ADD],
        ],
      );
      assert.deepEqual(continuation.removeHeaders, [], 'no identity header received, none removed');
      const service = viaService(result.response)['request_headers'].response;
      assert.equal(service.body_mutation, undefined);
      assert.equal(service.trailers, undefined);
      assert.equal(service.clear_route_cache, undefined, 'routing untouched');
      assertNoLeak(result.response);
      // Locally applied (a model of the protocol, not Google): the headers are added, everything else as received.
      const after = applyMutation(asList(headers), continuation);
      assert.deepEqual(valuesOf(after, VERIFIED_DOMAIN_HEADER), [DOMAIN]);
      assert.deepEqual(valuesOf(after, GOVERNANCE_ID_HEADER), [GOVERNANCE]);
      assert.deepEqual(after.slice(0, headers.length), asList(headers), 'method, authority, path, query, signature fields and the rest unchanged');
    });
  }

  test("with the deployment's attestation key: also x-dnsid-attestation, which Demo Bank accepts for exactly this identity; a forged one is removed and replaced", () => {
    const key = Buffer.from('attestation-key-for-this-test-0123456789', 'ascii');
    const forged = `v1.${Math.floor(Date.now() / 1000)}.${'A'.repeat(43)}`;
    const headers = received('GET', [[ATTESTATION_HEADER, forged], ['X-DNSid-Attestation', 'second']]);
    const before = Date.now();
    const result = respond(passed(), headers, { ...live(), attestationKey: key });
    const continuation = assertContinue(result);
    assert.deepEqual(continuation.setHeaders.map((h) => [h.key, h.appendAction]), [
      [VERIFIED_DOMAIN_HEADER, OVERWRITE_IF_EXISTS_OR_ADD],
      [GOVERNANCE_ID_HEADER, OVERWRITE_IF_EXISTS_OR_ADD],
      [ATTESTATION_HEADER, OVERWRITE_IF_EXISTS_OR_ADD],
    ]);
    assert.deepEqual(continuation.removeHeaders, [ATTESTATION_HEADER]);
    const value = continuation.setHeaders[2]?.rawValue.toString('latin1') ?? '';
    assert.match(value, /^v1\.[0-9]+\.[A-Za-z0-9_-]{43}$/);
    const seconds = Number(value.split('.')[1]);
    assert.ok(seconds >= Math.floor(before / 1000) && seconds <= Math.floor(Date.now() / 1000), 'made now');
    assert.equal(Buffer.from(result.response).includes(key), false, 'the key is never in the response');
    const after = applyMutation(asList(headers), continuation);
    assert.deepEqual(valuesOf(after, ATTESTATION_HEADER), [value], "only the verifier's attestation reaches Demo Bank");
    const raw = after.flatMap(([n, v]) => [n, v.toString('latin1')]);
    const identity = { verifiedDomain: DOMAIN, governanceId: GOVERNANCE };
    assert.equal(checkAttestation(raw, identity, key, Date.now()), 'attested');
    assert.equal(checkAttestation(raw, { ...identity, verifiedDomain: 'other-gov2-fixture.test' }, key, Date.now()), 'attestation_invalid');
    assert.equal(checkAttestation(raw, identity, Buffer.from('a-different-key-of-sufficient-length-000', 'ascii'), Date.now()), 'attestation_invalid');
    // Without a key (the in-process tests' services), the two identity headers only, as before.
    assert.equal(assertContinue(respond(passed(), headers, live())).setHeaders.length, 2);
  });

  test('an attestation key that is not usable bytes: the internal_error 403, never an unattested continuation', () => {
    for (const attestationKey of [new Uint8Array(0), 'a-string-key-of-sufficient-length-00000' as never, null as never]) {
      assertDeny(respond(passed(), received(), { ...live(), attestationKey }), 'internal_error');
    }
  });

  test('mixed-case and duplicate forged identity headers and an unknown x-dnsid- suffix: each concrete name removed once, lowercased', () => {
    const headers = received('GET', [
      ['X-DNSid-Verified-Domain', 'evil.example'],
      ['x-dnsid-verified-domain', 'evil2.example'],
      ['X-DNSID-VERIFIED-DOMAIN', 'evil3.example'],
      ['x-DnSiD-governance-id', 'evil-gov.example'],
      ['x-dnsid-governance-id', 'evil-gov2.example'],
      ['X-Dnsid-Agent-Class', 'premium'],
      ['x-dnsid-', 'empty-suffix'],
      ['x-dnsid-future-thing', 'unknown'],
    ]);
    const result = respond(passed(), headers, live());
    const continuation = assertContinue(result);
    assert.deepEqual(continuation.removeHeaders, [
      'x-dnsid-verified-domain',
      'x-dnsid-governance-id',
      'x-dnsid-agent-class',
      'x-dnsid-',
      'x-dnsid-future-thing',
    ]);
    assert.equal(Buffer.from(result.response).toString('latin1').includes('evil'), false, 'no incoming value echoed');
    for (const order of ['removals-first', 'sets-first'] as const) {
      const after = applyMutation(asList(headers), continuation, order);
      assert.equal(after.some(([, value]) => /evil|premium|empty-suffix|unknown/.test(value.toString('latin1'))), false, `${order}: no forged value left`);
      const identity = after.filter(([name]) => name.startsWith('x-dnsid-'));
      if (order === 'removals-first') {
        // Envoy's order (mutation_utils.cc): exactly one authoritative value each.
        assert.deepEqual(identity.map(([n, v]) => [n, v.toString()]), [
          [VERIFIED_DOMAIN_HEADER, DOMAIN],
          [GOVERNANCE_ID_HEADER, GOVERNANCE],
        ]);
      } else {
        // The other order would lose the verified headers, never keep a forged one.
        assert.deepEqual(identity, []);
      }
      assert.deepEqual(valuesOf(after, 'accept'), ['application/json']);
      assert.deepEqual(valuesOf(after, ':path'), ['/accounts/123?view=summary']);
    }
  });

  test('look-alike names that do not start with x-dnsid- are not removed', () => {
    const lookalikes: [string, string][] = [
      ['x-dnsidfoo', '1'],
      ['x-dns-id-verified-domain', '2'],
      ['dnsid-verified-domain', '3'],
      ['xx-dnsid-a', '4'],
      ['x_dnsid_a', '5'],
      ['x-dnsİd-a', '6'], // a non-ASCII capital: Envoy lowercases ASCII only
    ];
    const continuation = assertContinue(respond(passed(), received('GET', lookalikes), live()));
    assert.deepEqual(continuation.removeHeaders, []);
  });

  test('an x-dnsid- name that cannot be named in remove_headers is denied rather than left in place', () => {
    for (const name of ['x-dnsid-a b', 'x-dnsid-é', 'x-dnsid-a:b', 'X-DNSID-"q"']) {
      assertDeny(respond(passed(), received('GET', [[name, 'v']]), live()), 'identity_header_invalid');
    }
  });

  test(`up to ${MAX_REMOVED_HEADERS} distinct names continue; one more is a small fixed denial, not a truncated list`, () => {
    const names = (n: number): [string, string][] => Array.from({ length: n }, (_, i) => [`x-dnsid-h${i}`, 'v']);
    const at = assertContinue(respond(passed(), received('GET', names(MAX_REMOVED_HEADERS)), live()));
    assert.equal(at.removeHeaders.length, MAX_REMOVED_HEADERS);
    const over = respond(passed(), received('GET', names(MAX_REMOVED_HEADERS + 1)), live());
    assertDeny(over, 'identity_headers_excessive');
    assert.ok(over.response.length < 128);
    // Duplicates of one name count once.
    const repeated = Array.from({ length: 500 }, (): [string, string] => ['X-DNSid-Same', 'v']);
    assert.deepEqual(assertContinue(respond(passed(), received('GET', repeated), live())).removeHeaders, ['x-dnsid-same']);
  });

  test(`a continuation over ${MAX_RESPONSE_BYTES} bytes is a small fixed denial, not an oversized or truncated response`, () => {
    const long: [string, string][] = Array.from({ length: 60 }, (_, i) => [`x-dnsid-${'n'.repeat(300)}${i}`, 'v']);
    const result = respond(passed(), received('GET', long), live());
    assertDeny(result, 'response_too_large');
    assert.ok(result.response.length < 128);
  });

  test('the caller’s outcome, received headers and their bytes are left unchanged', () => {
    const headers = received('GET', [['X-DNSid-Verified-Domain', 'evil.example']]);
    const outcome = passed();
    const before = JSON.stringify({ outcome, headers: headers.map((h) => [h.name, [...h.value]]) });
    const frozen = headers.map((h) => Object.freeze({ ...h }));
    Object.freeze(frozen);
    assertContinue(respond(outcome, frozen, live()));
    assertContinue(respond(outcome, headers, live()));
    assert.equal(JSON.stringify({ outcome, headers: headers.map((h) => [h.name, [...h.value]]) }), before);
  });
});

describe('response: the caller’s cancellation and original deadline, checked after the response is built', () => {
  test('cancelled while the continuation is being serialized: the cancellation denial, no continuation', () => {
    const controller = new AbortController();
    let calls = 0;
    const result = respond(passed(), received(), { signal: controller.signal, deadline: performance.now() + 5000 }, {
      continuationSerialized() {
        calls++;
        controller.abort();
      },
    });
    assert.equal(calls, 1);
    assertDeny(result, 'verification_cancelled');
  });

  test('the original deadline passing during construction: the budget denial, no continuation, budget not restarted', () => {
    const deadline = performance.now() + 30;
    const result = respond(passed(), received(), { signal: new AbortController().signal, deadline }, {
      continuationSerialized() {
        while (performance.now() < deadline) {
          // spend the rest of the original budget inside response construction
        }
      },
    });
    assertDeny(result, 'verification_budget_exhausted');
  });

  test('already cancelled, or already past the deadline: denied; cancellation wins when both', () => {
    const aborted = AbortSignal.abort();
    assertDeny(respond(passed(), received(), { signal: aborted, deadline: performance.now() + 5000 }), 'verification_cancelled');
    assertDeny(respond(passed(), received(), { signal: new AbortController().signal, deadline: performance.now() - 1 }), 'verification_budget_exhausted');
    assertDeny(respond(passed(), received(), { signal: aborted, deadline: performance.now() - 1 }), 'verification_cancelled');
  });

  test('a signal that is not an AbortSignal or a deadline that is not a number never continues', () => {
    const fake = { aborted: false } as unknown as AbortSignal;
    assertDeny(respond(passed(), received(), { signal: fake, deadline: performance.now() + 5000 }), 'verification_cancelled');
    assertDeny(respond(passed(), received(), { signal: new AbortController().signal, deadline: Number.NaN }), 'verification_budget_exhausted');
  });

  test('a denial stays its own reason even after cancellation (only success is replaced)', () => {
    assertDeny(respond({ outcome: 'deny', status: 403, reason: 'signature_invalid' }, received(), { signal: AbortSignal.abort(), deadline: 0 }), 'signature_invalid');
  });
});

describe('response: why the shape is checked before it is serialized (the service serializer, characterized)', () => {
  test('PROCESS_METHOD.responseSerialize drops unknown fields and unknown enum names silently, and encodes two branches', () => {
    assert.equal(PROCESS_METHOD.responseSerialize({ continue: true }).length, 0, 'an unknown field becomes an empty message');
    const badEnum = viaService(PROCESS_METHOD.responseSerialize({ immediate_response: { status: { code: 'Nope' } } }));
    assert.deepEqual(badEnum['immediate_response'].status, {}, 'an unknown status name is dropped');
    const both = viaService(
      PROCESS_METHOD.responseSerialize({
        request_headers: { response: { status: 'CONTINUE' } },
        immediate_response: { status: { code: 'Forbidden' } },
      }),
    );
    assert.ok(both['request_headers'] !== undefined && both['immediate_response'] !== undefined, 'both branches on the wire');
  });

  test('the module’s own messages are exactly what was built: re-encoding the decoded continuation gives the same bytes', () => {
    const result = respond(passed(), received('GET', [['X-DNSid-A', '1']]), live());
    assert.equal(result.decision, 'continue');
    const again = PROCESS_METHOD.responseSerialize(viaService(result.response));
    assert.deepEqual(Buffer.from(again), result.response);
    const denial = denialResponse('signature_invalid').response;
    assert.deepEqual(Buffer.from(PROCESS_METHOD.responseSerialize(viaService(denial))), denial);
  });
});
