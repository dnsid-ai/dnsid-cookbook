// The callout's gRPC service over real local connections: grpc-js clients (and a bare HTTP/2 client for framing) on
// loopback, the real service, decoder, preconditions and response layer, and the real SDK verification of offline test
// identities on a test C2SP log (tests/support/identity-fixture.ts). This is NOT DNSid Local, the managed service or
// Google's load balancer: what a local gRPC status shows is this service's behavior, not what Google returns (D-05).
// Where real sockets can't schedule a race reliably, the service's test hooks place the event exactly.

import assert from 'node:assert/strict';
import { constants as h2 } from 'node:http2';
import { describe, test, type TestContext } from 'node:test';

import { createHttpSignaturesProfile, type IdentityResolver } from '@dnsid-ai/sdk';
import {
  InMemoryTrustedC2spCheckpointStore,
  checkpointPath,
  type TrustedC2spCheckpoint,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';
import { makeGenericClientConstructor, credentials, type ClientDuplexStream, type ServerDuplexStream } from '@grpc/grpc-js';

import { processRequestHeaders } from '../../src/callout.ts';
import { PROCESS_METHOD } from '../../src/ext-proc.ts';
import { createVerificationRuntime, governancePolicy, type VerificationRuntime } from '../../src/identity.ts';
import { GOVERNANCE_ID_HEADER, VERIFIED_DOMAIN_HEADER } from '../../src/response.ts';
import {
  MAX_REQUEST_MESSAGE_BYTES,
  MAX_RESPONSE_MESSAGE_BYTES,
  PROCESS_BYTES_SERVICE,
  SHUTDOWN_GRACE_MS,
  SUBMIT_SETTLE_MS,
  VERIFICATION_BUDGET_MS,
  createCalloutService,
  http2StreamOf,
  type CalloutService,
  type CalloutServiceOptions,
  type ServiceHooks,
  type TerminalRecord,
} from '../../src/service.ts';
import { blockedHttp2Call, byteClient, exchange, grpcFrame, grpcMessages, rawHttp2Call, status, type ByteClient } from '../support/grpc-client.ts';
import {
  FIXTURE_GOVERNANCE,
  fixtureBackend,
  fixtureLog,
  fixtureNetwork,
  issueIdentity,
  type FixtureIdentity,
  type FixtureLog,
  type FixtureNetwork,
} from '../support/identity-fixture.ts';
import { FORBIDDEN, decodeContinuation, decodeDenial } from '../support/response-wire.ts';
import { fieldsOf, replaced, serialize, without, type Field } from '../support/signing.ts';

const AGENT = 'agent-gov-fixture.test';
const PATH_AND_QUERY = '/accounts/123?view=summary';
const TARGET = `https://api-example.test${PATH_AND_QUERY}`;

const unused: IdentityResolver = {
  verifyDomain() {
    throw new Error('a test signer never verifies');
  },
};

async function signedAs(identity: FixtureIdentity, method = 'GET', extra: Field[] = []): Promise<Field[]> {
  const profile = createHttpSignaturesProfile({ domain: identity.domain, keyProvider: identity.operational, identityResolver: unused });
  return fieldsOf(await profile.createSignedHttpRequest(new Request(TARGET, { method })), {}, extra);
}

/** The shared checkpoint store, counting the commits that actually happened. */
class CountingStore implements TrustedC2spCheckpointStore {
  readonly #inner = new InMemoryTrustedC2spCheckpointStore();
  commits = 0;
  load(origin: string, signal?: AbortSignal) {
    return this.#inner.load(origin, signal);
  }
  async compareAndSwap(origin: string, expected: TrustedC2spCheckpoint | undefined, candidate: TrustedC2spCheckpoint, signal?: AbortSignal) {
    const swapped = await this.#inner.compareAndSwap(origin, expected, candidate, signal);
    if (swapped) this.commits++;
    return swapped;
  }
}

interface Harness {
  log: FixtureLog;
  network: FixtureNetwork;
  identity: FixtureIdentity;
  runtime: VerificationRuntime;
  store: CountingStore;
  service: CalloutService;
  port: number;
  client: ByteClient;
  records: TerminalRecord[];
  /** Every scope's signal, from the identity stage's observer, in order. */
  scopes: AbortSignal[];
  /** How many verifications the service started. */
  verifications: number;
}

type HarnessOptions = Omit<Partial<CalloutServiceOptions>, 'runtime'> & { hooks?: ServiceHooks };

async function harness(t: TestContext, options: HarnessOptions = {}): Promise<Harness> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const identity = await issueIdentity(log, AGENT);
  network.publish(identity);
  const store = new CountingStore();
  const runtime = createVerificationRuntime({
    governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]),
    backend: fixtureBackend(network, log),
    checkpointStore: store,
  });
  const records: TerminalRecord[] = [];
  const h = { log, network, identity, runtime, store, records, scopes: [] as AbortSignal[], verifications: 0 } as Harness;
  const hooks: ServiceHooks = {
    ...options.hooks,
    observer: (id) => {
      h.verifications++;
      const extra = options.hooks?.observer?.(id);
      return { ...extra, scopeOpened: (scope) => (h.scopes.push(scope.signal), extra?.scopeOpened?.(scope)) };
    },
  };
  h.service = createCalloutService({
    runtime,
    log: options.log ?? ((record) => void records.push(record)),
    shutdownGraceMs: options.shutdownGraceMs ?? 200,
    hooks,
    ...(options.budgetMs === undefined ? {} : { budgetMs: options.budgetMs }),
    ...(options.submitSettleMs === undefined ? {} : { submitSettleMs: options.submitSettleMs }),
  });
  h.port = await h.service.listen('127.0.0.1', 0);
  h.client = byteClient(h.port);
  t.after(async () => {
    h.client.close();
    await h.service.shutdown();
  });
  return h;
}

/** Holds matching network answers until released, ignoring cancellation (a dependency that doesn't honour its signal). */
function hold(match: (what: string) => boolean) {
  let release = () => {};
  const released = new Promise<void>((resolve) => (release = resolve));
  const held: string[] = [];
  return {
    held,
    release: () => release(),
    gate: async (what: string) => {
      if (!match(what)) return;
      held.push(what);
      await released;
    },
  };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(condition: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const end = performance.now() + timeoutMs;
  while (!condition()) {
    if (performance.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}

function assertOneDenial(responses: Buffer[], reason: string): void {
  assert.equal(responses.length, 1, 'exactly one response');
  const denial = decodeDenial(responses[0] as Buffer);
  assert.equal(denial.status, FORBIDDEN);
  assert.equal(denial.body.toString('latin1'), reason);
}

function assertOneContinuation(responses: Buffer[]) {
  assert.equal(responses.length, 1, 'exactly one response');
  return decodeContinuation(responses[0] as Buffer);
}

const RECORD_KEYS = ['elapsedMs', 'event', 'id', 'outcome', 'severity'];

/** One terminal record with exactly the expected fields, and nothing from the request in it. */
function assertRecord(records: TerminalRecord[], expected: Partial<TerminalRecord>, extraKeys: string[] = []): TerminalRecord {
  assert.equal(records.length, 1, `one terminal record: ${JSON.stringify(records)}`);
  const record = records[0] as TerminalRecord;
  for (const [key, value] of Object.entries(expected)) assert.deepEqual((record as unknown as Record<string, unknown>)[key], value, key);
  assert.deepEqual(Object.keys(record).sort(), [...RECORD_KEYS, ...extraKeys].sort());
  assert.equal(record.event, 'ext_proc_stream');
  assert.match(record.id, /^[0-9a-f-]{36}$/);
  assert.ok(Number.isInteger(record.elapsedMs) && record.elapsedMs >= 0);
  assertNoLeak(JSON.stringify(records));
  return record;
}

function assertNoLeak(text: string): void {
  for (const leak of ['accounts', 'view=summary', 'api-example.test', 'sig1', 'signature-input', 'keyid', 'created=', 'Error', 'stack', 'https://', 'checkpoint', 'forged', 'grpc-']) {
    assert.equal(text.includes(leak), false, `"${leak}" in a log record`);
  }
}

describe('service: the method and its limits', () => {
  test('registered with the vendored path and streaming flags; the (de)serializers copy and pass bytes, never decode', () => {
    const method = PROCESS_BYTES_SERVICE.Process;
    assert.equal(method.path, '/envoy.service.ext_proc.v3.ExternalProcessor/Process');
    assert.equal(method.path, PROCESS_METHOD.path);
    assert.equal(method.requestStream, true);
    assert.equal(method.responseStream, true);
    // Bytes the schema's decoder would refuse pass through unchanged, as a copy.
    const malformed = Buffer.from([0x12, 0x05, 0x0a]);
    const copy = method.requestDeserialize(malformed);
    assert.deepEqual(copy, malformed);
    malformed[0] = 0;
    assert.equal(copy[0], 0x12, 'a copy, not a view');
    assert.notEqual(method.requestDeserialize, PROCESS_METHOD.requestDeserialize);
    const bytes = Buffer.from([0x22, 0x00]);
    assert.equal(method.responseSerialize(bytes), bytes, 'no second encoding');
    assert.throws(() => method.responseSerialize({ immediate_response: {} } as never), TypeError);
    assert.throws(() => method.responseSerialize(Buffer.alloc(0)), TypeError);
    assert.throws(() => method.responseSerialize(Buffer.alloc(MAX_RESPONSE_MESSAGE_BYTES + 1)), TypeError);
  });

  test('the documented bounds: a 2,500 ms budget, 128 KiB in, 16 KiB out, a 3 s shutdown grace', () => {
    assert.equal(VERIFICATION_BUDGET_MS, 2500);
    assert.equal(MAX_REQUEST_MESSAGE_BYTES, 131_072);
    assert.equal(MAX_RESPONSE_MESSAGE_BYTES, 16_384);
    assert.equal(SHUTDOWN_GRACE_MS, 3000);
  });

  test('building the service starts no listener; an invalid runtime or bound is refused', () => {
    assert.throws(() => createCalloutService({} as never), TypeError);
    const runtime = createVerificationRuntime({ governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]), backend: fixtureBackend(fixtureNetwork(), fixtureLog()) });
    assert.throws(() => createCalloutService({ runtime, budgetMs: 0 }), TypeError);
    assert.throws(() => createCalloutService({ runtime, shutdownGraceMs: Number.NaN }), TypeError);
    const before = process.getActiveResourcesInfo().filter((r) => r === 'TCPServerWrap').length;
    const service = createCalloutService({ runtime });
    assert.equal(process.getActiveResourcesInfo().filter((r) => r === 'TCPServerWrap').length, before);
    return service.shutdown();
  });
});

describe('service: a signed request from an active, trusted identity continues, over a real local connection', () => {
  for (const method of ['GET', 'HEAD']) {
    test(`${method}: answered while the client's send side is still open; one response, OK, one record`, async (t) => {
      const h = await harness(t);
      const bytes = serialize(await signedAs(h.identity, method));
      const { stream, status: final } = await exchange(h.client, bytes);
      assert.equal(final.code, status.OK);
      const continuation = assertOneContinuation(stream.responses);
      assert.deepEqual(
        continuation.setHeaders.map((x) => [x.key, x.rawValue.toString()]),
        [
          [VERIFIED_DOMAIN_HEADER, AGENT],
          [GOVERNANCE_ID_HEADER, FIXTURE_GOVERNANCE],
        ],
      );
      const record = assertRecord(h.records, { severity: 'INFO', outcome: 'continue_submitted' }, ['verified']);
      assert.deepEqual(Object.keys(record.verified ?? {}).sort(), ['completenessMode', 'domain', 'evidenceAgeMs', 'governanceId', 'materialCache']);
      assert.equal(record.verified?.completenessMode, 'full-scan', 'the test log serves no stream bundles');
      assert.ok(['hit', 'miss', 'partial'].includes(record.verified?.materialCache as string));
      assert.equal(record.verified?.domain, AGENT);
      assert.equal(record.verified?.governanceId, FIXTURE_GOVERNANCE);
      const age = record.verified?.evidenceAgeMs as number;
      assert.ok(Number.isFinite(age) && age >= -5000 && age <= 300_000, `evidence age ${age}`);
      assert.equal(h.service.activeStreams, 0);
    });
  }

  test('the wire bytes are exactly the application response: the transport neither re-encodes nor changes them', async (t) => {
    const h = await harness(t);
    const fields = await signedAs(h.identity, 'GET', [['x-dnsid-verified-domain', 'forged.example']]);
    const bytes = serialize(fields);
    const raw = await rawHttp2Call(h.port, grpcFrame(bytes));
    assert.notEqual(raw, 'destroyed');
    if (raw === 'destroyed') return;
    assert.equal(raw.grpcStatus, status.OK);
    const messages = grpcMessages(raw.data);
    assert.equal(messages.length, 1);
    assert.equal(raw.data[0], 0, 'not compressed');
    // The same request through processRequestHeaders directly (a second, independent verification, so the warm path).
    const direct = await processRequestHeaders(bytes, { runtime: h.runtime, signal: new AbortController().signal, deadline: performance.now() + 2500 });
    assert.equal(direct.decision, 'continue');
    assert.deepEqual(messages[0], direct.response);
    assert.deepEqual(decodeContinuation(messages[0] as Buffer).removeHeaders, ['x-dnsid-verified-domain']);
  });

  test('a normal half-close after the message does not cancel verification', async (t) => {
    const h = await harness(t);
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)), { halfClose: true });
    assert.equal(final.code, status.OK);
    assertOneContinuation(stream.responses);
    assertRecord(h.records, { outcome: 'continue_submitted' }, ['verified']);
    assert.equal(h.scopes.length, 1);
  });

  test('a standard schema client (proto-loader message objects) gets the same continuation', async (t) => {
    const h = await harness(t);
    const Generic = makeGenericClientConstructor({ Process: PROCESS_METHOD }, 'ExternalProcessor');
    const client = new Generic(`127.0.0.1:${h.port}`, credentials.createInsecure());
    t.after(() => client.close());
    const message = PROCESS_METHOD.requestDeserialize(serialize(await signedAs(h.identity)));
    const call = (client as unknown as { Process(): ClientDuplexStream<object, Record<string, unknown>> }).Process();
    const received: Record<string, unknown>[] = [];
    call.on('data', (m: Record<string, unknown>) => received.push(m));
    call.on('error', () => {});
    const done = new Promise((resolve) => call.on('status', resolve));
    call.write(message);
    await done;
    assert.equal(received.length, 1);
    assert.equal((received[0] as Record<string, unknown>)['response'], 'request_headers');
  });

  test('cold, then warm on the same service: both continue, the second reuses shared records and keys', async (t) => {
    const h = await harness(t);
    const cold = await exchange(h.client, serialize(await signedAs(h.identity)));
    const before = h.runtime.sharedMaterial?.stats();
    const warm = await exchange(h.client, serialize(await signedAs(h.identity)));
    const after = h.runtime.sharedMaterial?.stats();
    assert.ok(before !== undefined && after !== undefined);
    assert.equal(after.dnsHits, before.dnsHits + 1);
    assert.deepEqual(assertOneContinuation(warm.stream.responses), assertOneContinuation(cold.stream.responses));
    assert.equal(h.records.length, 2);
    assert.notEqual(h.records[0]?.id, h.records[1]?.id, 'each stream has its own correlation id');
  });

  test('forged identity headers: verification on the request as received, every x-dnsid-* removed, none logged', async (t) => {
    const h = await harness(t);
    const fields = await signedAs(h.identity, 'GET', [
      ['X-DNSid-Verified-Domain', 'forged-bank-admin.example'],
      ['x-dnsid-governance-id', 'forged-governance.example'],
    ]);
    const { stream } = await exchange(h.client, serialize(fields));
    const continuation = assertOneContinuation(stream.responses);
    assert.deepEqual(continuation.removeHeaders, ['x-dnsid-verified-domain', 'x-dnsid-governance-id']);
    const record = assertRecord(h.records, { outcome: 'continue_submitted' }, ['verified']);
    assert.equal(record.verified?.domain, AGENT, 'the record names the verified domain, not the forged header');
  });
});

describe('service: every other request is one immediate 403, then the stream ends', () => {
  test('unsigned and tampered requests', async (t) => {
    const h = await harness(t);
    const fields = await signedAs(h.identity);
    const unsigned = await exchange(h.client, serialize(without(without(fields, 'signature'), 'signature-input')));
    assert.equal(unsigned.status.code, status.OK);
    assertOneDenial(unsigned.stream.responses, 'signature_missing');
    const tampered = await exchange(h.client, serialize(replaced(fields, ':path', '/accounts/124?view=summary')));
    assertOneDenial(tampered.stream.responses, 'signature_invalid');
    assert.deepEqual(h.records.map((r) => [r.severity, r.outcome, r.reason]), [
      ['INFO', 'deny_submitted', 'signature_missing'],
      ['INFO', 'deny_submitted', 'signature_invalid'],
    ]);
    for (const record of h.records) assert.deepEqual(Object.keys(record).sort(), [...RECORD_KEYS, 'reason'].sort());
    assertNoLeak(JSON.stringify(h.records));
  });

  test('a fresh lifecycle rejection: allowed, then the status document reports REVOKED, then refused on the same service', async (t) => {
    const h = await harness(t);
    assertOneContinuation((await exchange(h.client, serialize(await signedAs(h.identity)))).stream.responses);
    h.network.publish(h.identity, 'REVOKED');
    assertOneDenial((await exchange(h.client, serialize(await signedAs(h.identity)))).stream.responses, 'identity_inactive');
    assert.deepEqual(h.records.map((r) => r.outcome), ['continue_submitted', 'deny_submitted']);
  });

  test('malformed protobuf, an empty message and an unsupported message type reach the strict decoder (raw-byte client)', async (t) => {
    const h = await harness(t);
    const cases: [Uint8Array, string][] = [
      [Uint8Array.from([0xff, 0xff, 0xff]), 'malformed_message'],
      [Uint8Array.from([0x12, 0x05, 0x0a]), 'malformed_message'],
      [new Uint8Array(0), 'empty_message'],
      [Uint8Array.from([0x1a, 0x00]), 'unsupported_message_type'],
      // request_headers carrying a header key that isn't UTF-8: refused, never re-encoded with U+FFFD.
      [Uint8Array.from([0x12, 0x08, 0x0a, 0x06, 0x0a, 0x04, 0x0a, 0x02, 0xc3, 0x28]), 'invalid_utf8_string'],
    ];
    for (const [bytes, reason] of cases) {
      const { stream, status: final } = await exchange(h.client, bytes);
      assert.equal(final.code, status.OK, reason);
      assertOneDenial(stream.responses, reason);
    }
    assert.deepEqual(h.records.map((r) => r.reason), cases.map(([, reason]) => reason));
  });

  test('an empty stream (the client closes without a message): no response, INVALID_ARGUMENT, one record', async (t) => {
    const h = await harness(t);
    const stream = h.client.open();
    stream.end();
    const final = await stream.status;
    assert.equal(final.code, status.INVALID_ARGUMENT);
    assert.equal(stream.responses.length, 0);
    assertRecord(h.records, { severity: 'WARNING', outcome: 'empty_stream' });
    assert.equal(h.verifications, 0);
  });

  test('a second message while verification is pending: the first is cancelled, one fixed 403, nothing after', async (t) => {
    let abortedAtSubmission: boolean | undefined;
    const h: Harness = await harness(t, { hooks: { afterSubmit: () => (abortedAtSubmission = h.scopes[0]?.aborted) } });
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const bytes = serialize(await signedAs(h.identity));
    const stream = h.client.open();
    stream.write(bytes);
    await until(() => gate.held.length > 0, 'verification to reach DNS');
    stream.write(bytes);
    const final = await stream.status;
    assert.equal(final.code, status.OK);
    assertOneDenial(stream.responses, 'unexpected_message');
    assert.equal(abortedAtSubmission, true, 'the first verification was cancelled by the time the 403 was submitted');
    assert.equal(h.scopes[0]?.aborted, true);
    gate.release();
    await sleep(100);
    assert.equal(stream.responses.length, 1, 'no late response');
    assert.equal(h.verifications, 1, 'the second message started no verification');
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0, 'no cache fill');
    assertRecord(h.records, { outcome: 'deny_submitted', reason: 'unexpected_message' }, ['reason']);
  });

  test('messages after the response never start another verification or reply', async (t) => {
    const h = await harness(t);
    const bytes = serialize(await signedAs(h.identity));
    const stream = h.client.open();
    stream.write(serialize(without(await signedAs(h.identity), 'signature')));
    await until(() => stream.responses.length === 1, 'the first response');
    stream.write(bytes);
    stream.write(bytes);
    await stream.status;
    await sleep(50);
    assertOneDenial(stream.responses, 'signature_missing');
    assert.equal(h.verifications, 1);
    assert.equal(h.records.length, 1);
  });
});

describe('service: message size limits', () => {
  async function paddedTo(identity: FixtureIdentity, total: number): Promise<Buffer> {
    const fields = await signedAs(identity);
    let padding = total - serialize(fields).length - 20;
    for (;;) {
      const bytes = serialize([...fields, ['x-padding', 'a'.repeat(padding)]]);
      if (bytes.length === total) return bytes;
      padding += total - bytes.length;
    }
  }

  test('a request message of exactly 128 KiB reaches the application; one byte more is RESOURCE_EXHAUSTED with no response', async (t) => {
    const h = await harness(t);
    const atLimit = await paddedTo(h.identity, MAX_REQUEST_MESSAGE_BYTES);
    assert.equal(atLimit.length, MAX_REQUEST_MESSAGE_BYTES);
    const ok = await exchange(h.client, atLimit);
    assert.equal(ok.status.code, status.OK);
    assertOneContinuation(ok.stream.responses);
    const over = await paddedTo(h.identity, MAX_REQUEST_MESSAGE_BYTES + 1);
    const refused = await exchange(h.client, over);
    assert.equal(refused.status.code, status.RESOURCE_EXHAUSTED);
    assert.equal(refused.stream.responses.length, 0);
    await until(() => h.records.length === 2, 'two records');
    assert.equal(h.records[1]?.outcome, 'cancelled', 'the gRPC layer ended the stream before the application saw a message');
    assert.equal(h.verifications, 1);
  });
});

describe('service: gRPC framing and transport failures end the stream without an application response', () => {
  test('a gzip-flagged message that does not decompress: INTERNAL, no response, no verification', async (t) => {
    const h = await harness(t);
    const raw = await rawHttp2Call(h.port, grpcFrame(Buffer.from('not gzip'), { compressed: true }), { headers: { 'grpc-encoding': 'gzip' } });
    assert.notEqual(raw, 'destroyed');
    if (raw === 'destroyed') return;
    assert.equal(raw.grpcStatus, status.INTERNAL);
    assert.equal(grpcMessages(raw.data).length, 0);
    await until(() => h.records.length === 1, 'a record');
    assert.equal(h.records[0]?.outcome, 'cancelled', 'the gRPC layer ended the stream');
    assert.equal(h.verifications, 0);
  });

  test('observed grpc-js 1.14.7 behavior: the compressed flag with identity encoding is read as uncompressed bytes, which the strict decoder then judges', async (t) => {
    const h = await harness(t);
    const raw = await rawHttp2Call(h.port, grpcFrame(Buffer.from([0x1a, 0x00]), { compressed: true }));
    assert.notEqual(raw, 'destroyed');
    if (raw === 'destroyed') return;
    assert.equal(raw.grpcStatus, status.OK);
    assertOneDenial(grpcMessages(raw.data), 'unsupported_message_type');
  });

  test('a truncated frame (the length prefix promises more than is sent) then end of stream: an empty stream', async (t) => {
    const h = await harness(t);
    const raw = await rawHttp2Call(h.port, grpcFrame(Buffer.from([0x1a, 0x00]), { declaredLength: 100 }));
    assert.notEqual(raw, 'destroyed');
    if (raw === 'destroyed') return;
    assert.equal(raw.grpcStatus, status.INVALID_ARGUMENT);
    assert.equal(grpcMessages(raw.data).length, 0);
    assertRecord(h.records, { outcome: 'empty_stream' });
    assert.equal(h.verifications, 0);
  });

  test('a disconnect mid-verification: verification is cancelled, no late response, cache fill or checkpoint commit', async (t) => {
    const h = await harness(t);
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const result = await rawHttp2Call(h.port, grpcFrame(serialize(await signedAs(h.identity))), { destroyAfterMs: 150 });
    assert.equal(result, 'destroyed');
    await until(() => h.records.length === 1, 'a record');
    assertRecord(h.records, { severity: 'WARNING', outcome: 'cancelled' });
    assert.equal(h.scopes[0]?.aborted, true);
    gate.release();
    await sleep(100);
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0);
    assert.equal(h.store.commits, 0);
    assert.equal(h.service.activeStreams, 0);
  });
});

describe('service: one budget per stream, the caller’s earlier deadline, and cancellation', () => {
  test('the application budget runs out during verification: the budget 403, on time, and nothing late', async (t) => {
    const h = await harness(t, { budgetMs: 400 });
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const started = performance.now();
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)));
    const took = (stream.firstResponseAt as number) - started;
    assert.equal(final.code, status.OK);
    assertOneDenial(stream.responses, 'verification_budget_exhausted');
    assert.ok(took >= 390 && took < 800, `answered after ${took.toFixed(1)} ms`);
    const record = assertRecord(h.records, { outcome: 'deny_submitted', reason: 'verification_budget_exhausted' }, ['reason']);
    assert.ok(record.elapsedMs >= 399 && record.elapsedMs < 800, `elapsed ${record.elapsedMs}`);
    assert.equal(h.scopes[0]?.aborted, true);
    gate.release();
    await sleep(100);
    assert.equal(stream.responses.length, 1);
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0);
  });

  test('a stalled warm lifecycle lookup, default 2,500 ms budget: denied at its own deadline', async (t) => {
    const h = await harness(t);
    assertOneContinuation((await exchange(h.client, serialize(await signedAs(h.identity)))).stream.responses);
    const commitsAfterCold = h.store.commits;
    const gate = hold((url) => url === checkpointPath(h.log.prefix));
    h.log.gate = gate.gate;
    const started = performance.now();
    const { stream } = await exchange(h.client, serialize(await signedAs(h.identity)));
    const took = (stream.firstResponseAt as number) - started;
    assertOneDenial(stream.responses, 'verification_budget_exhausted');
    assert.ok(gate.held.length > 0, 'the warm request stalled at the log');
    assert.ok(took >= 2490 && took < 2900, `answered after ${took.toFixed(1)} ms`);
    assert.equal(h.records[1]?.reason, 'verification_budget_exhausted');
    gate.release();
    await sleep(100);
    assert.equal(h.store.commits, commitsAfterCold, 'no checkpoint commit from the abandoned request');
  });

  test('a shorter client deadline: the stream ends with DEADLINE_EXCEEDED, no 403 claimed, nothing late', async (t) => {
    const h = await harness(t);
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)), { deadlineMs: 300 });
    assert.equal(final.code, status.DEADLINE_EXCEEDED);
    assert.equal(stream.responses.length, 0);
    await until(() => h.records.length === 1, 'a record');
    const record = assertRecord(h.records, { severity: 'WARNING', outcome: 'client_deadline_exceeded' });
    assert.ok(record.elapsedMs >= 250 && record.elapsedMs < 700, `elapsed ${record.elapsedMs}`);
    assert.equal(h.scopes[0]?.aborted, true);
    gate.release();
    await sleep(100);
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0);
    assert.equal(h.store.commits, 0);
  });

  test('two same-identity streams with different deadlines stay independent', async (t) => {
    const h = await harness(t);
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const short = h.client.open({ deadlineMs: 300 });
    const long = h.client.open();
    short.write(serialize(await signedAs(h.identity)));
    long.write(serialize(await signedAs(h.identity)));
    assert.equal((await short.status).code, status.DEADLINE_EXCEEDED);
    gate.release();
    assert.equal((await long.status).code, status.OK);
    assert.equal(short.responses.length, 0);
    assertOneContinuation(long.responses);
    await until(() => h.records.length === 2, 'two records');
    assert.deepEqual(h.records.map((r) => r.outcome).sort(), ['client_deadline_exceeded', 'continue_submitted']);
    // One verified identity's material: its TXT answer and its two key documents.
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 3, 'only the stream that succeeded filled the cache');
  });

  test('cancelling one stream while another for the same identity succeeds', async (t) => {
    const h = await harness(t);
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const cancelled = h.client.open();
    const kept = h.client.open();
    cancelled.write(serialize(await signedAs(h.identity)));
    kept.write(serialize(await signedAs(h.identity)));
    await until(() => gate.held.length >= 2, 'both streams to reach DNS');
    cancelled.cancel();
    assert.equal((await cancelled.status).code, status.CANCELLED);
    await until(() => h.records.length === 1, 'the cancelled record');
    assert.equal(h.records[0]?.outcome, 'cancelled');
    gate.release();
    assert.equal((await kept.status).code, status.OK);
    assertOneContinuation(kept.responses);
    assert.equal(cancelled.responses.length, 0);
    await until(() => h.records.length === 2, 'two records');
    assert.equal(h.records[1]?.outcome, 'continue_submitted');
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 3, 'one identity’s TXT answer and two key documents, from the kept stream only');
  });

  test('cancelled during a cold log read: no late response, cache fill or checkpoint commit; the next request succeeds', async (t) => {
    const h = await harness(t);
    const gate = hold((url) => url.startsWith(h.log.prefix));
    h.log.gate = gate.gate;
    const stream = h.client.open();
    stream.write(serialize(await signedAs(h.identity)));
    await until(() => gate.held.length > 0, 'the log read');
    stream.cancel();
    await stream.status;
    await until(() => h.records.length === 1, 'a record');
    gate.release();
    await sleep(150);
    assert.equal(stream.responses.length, 0);
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0);
    assert.equal(h.store.commits, 0);
    delete h.log.gate;
    assertOneContinuation((await exchange(h.client, serialize(await signedAs(h.identity)))).stream.responses);
    assert.ok(h.store.commits >= 1, 'a completed request does commit');
  });

  test('an idle stream that sends nothing is ended at the budget with DEADLINE_EXCEEDED and no response', async (t) => {
    const h = await harness(t, { budgetMs: 200 });
    const stream = h.client.open();
    const final = await stream.status;
    assert.equal(final.code, status.DEADLINE_EXCEEDED);
    assert.equal(stream.responses.length, 0);
    const record = assertRecord(h.records, { outcome: 'idle_timeout' });
    assert.ok(record.elapsedMs >= 195 && record.elapsedMs < 600, `elapsed ${record.elapsedMs}`);
  });
});

describe('service: races at the transport boundary (deterministic hooks)', () => {
  test('the stream closes just before submission: the final check writes nothing and no success is logged', async (t) => {
    let serialized = 0;
    const h = await harness(t, {
      hooks: {
        observer: () => ({ continuationSerialized: () => serialized++ }),
        beforeSubmit: (_id, call) => call.destroy(),
      },
    });
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)), { deadlineMs: 1500 });
    assert.equal(serialized, 1, 'verification passed and a continuation was built');
    assert.equal(stream.responses.length, 0);
    assert.notEqual(final.code, status.OK);
    assertRecord(h.records, { outcome: 'cancelled' });
  });

  const spin = (ms: number) => {
    const end = performance.now() + ms;
    while (performance.now() < end) {
      // hold the event loop: no timer can fire before the final checks
    }
  };

  test('the application budget passes between the decision and submission: the budget 403 replaces the continuation', async (t) => {
    let serialized = 0;
    const h = await harness(t, {
      budgetMs: 1500,
      hooks: {
        observer: () => ({ continuationSerialized: () => serialized++ }),
        beforeSubmit: () => spin(1600),
      },
    });
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)));
    assert.equal(serialized, 1, 'a continuation had been decided');
    assert.equal(final.code, status.OK);
    assertOneDenial(stream.responses, 'verification_budget_exhausted');
    assertRecord(h.records, { outcome: 'deny_submitted', reason: 'verification_budget_exhausted' }, ['reason']);
  });

  test('the caller’s earlier deadline passes between the decision and submission: nothing is written, no 403 claimed', async (t) => {
    const h = await harness(t, { hooks: { beforeSubmit: () => spin(1100) } });
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)), { deadlineMs: 1000 });
    assert.equal(final.code, status.DEADLINE_EXCEEDED);
    assert.equal(stream.responses.length, 0);
    await until(() => h.records.length === 1, 'a record');
    assertRecord(h.records, { outcome: 'client_deadline_exceeded' });
  });

  test('the transport fails after the continuation was written but before the write was accepted: transport_failed, not success', async (t) => {
    const h = await harness(t, { hooks: { afterSubmit: (_id, call) => void call.emit('cancelled', 'cancelled') } });
    await exchange(h.client, serialize(await signedAs(h.identity)));
    await sleep(50);
    assertRecord(h.records, { severity: 'WARNING', outcome: 'transport_failed', attempted: 'continue' }, ['attempted']);
  });

  test('a denial whose write fails is logged as transport_failed with its reason', async (t) => {
    const h = await harness(t, { hooks: { afterSubmit: (_id, call) => void call.emit('error', new Error('write failed')) } });
    await exchange(h.client, serialize(without(await signedAs(h.identity), 'signature')));
    await sleep(50);
    assertRecord(h.records, { outcome: 'transport_failed', attempted: 'deny', reason: 'signature_missing' }, ['attempted', 'reason']);
  });

  test('a stream error during verification: verification is cancelled, no response, one stream_error record', async (t) => {
    let call: ServerDuplexStream<Buffer, Buffer> | undefined;
    const h = await harness(t, {
      hooks: {
        accepted: (_id, c) => (call = c),
        observer: () => ({ lifecycleStarting: () => void call?.emit('error', Object.assign(new Error('x'), { code: status.INTERNAL, details: 'x' })) }),
      },
    });
    const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)));
    assert.equal(final.code, status.INTERNAL);
    assert.equal(stream.responses.length, 0);
    await sleep(50);
    assertRecord(h.records, { outcome: 'stream_error' });
    assert.equal(h.scopes[0]?.aborted, true);
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0);
  });

  test('a throwing or rejecting log sink: the response is still sent once, and nothing goes unhandled', async (t) => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    t.after(() => process.off('unhandledRejection', onUnhandled));
    for (const log of [
      () => {
        throw new Error('log failed');
      },
      () => Promise.reject(new Error('log failed')) as never,
    ]) {
      const h = await harness(t, { log });
      const { stream, status: final } = await exchange(h.client, serialize(await signedAs(h.identity)));
      assert.equal(final.code, status.OK);
      assertOneContinuation(stream.responses);
      assert.equal(h.service.activeStreams, 0);
    }
    await sleep(20);
    assert.deepEqual(unhandled, []);
  });
});

describe('service: a submitted response the transport does not accept is retracted (the HTTP/2 stream is reset)', () => {
  test('the default settle time is 1,000 ms; the accessor finds the HTTP/2 stream under a real call and refuses other shapes', { timeout: 10_000 }, async (t) => {
    assert.equal(SUBMIT_SETTLE_MS, 1000);
    for (const shape of [{}, { call: {} }, { call: { stream: {} } }, { call: { stream: { close() {}, closed: false, destroyed: false } } }]) {
      assert.equal(http2StreamOf(shape as never), undefined);
    }
    let found: unknown;
    const h = await harness(t, { hooks: { accepted: (_id, call) => (found = http2StreamOf(call)) } });
    const { status: final } = await exchange(h.client, serialize(await signedAs(h.identity)));
    assert.equal(final.code, status.OK);
    assert.equal((found as { constructor: { name: string } } | undefined)?.constructor.name, 'ServerHttp2Stream');
    assert.throws(() => createCalloutService({ runtime: h.runtime, submitSettleMs: 0 }), TypeError);
  });

  for (const kind of ['continuation', 'denial'] as const) {
    test(`real HTTP/2 flow control, no client deadline: a blocked ${kind} is reset at the settle time and never delivered after the window opens`, { timeout: 10_000 }, async (t) => {
      const resets: string[] = [];
      let submittedAt = 0;
      const h = await harness(t, {
        submitSettleMs: 300,
        hooks: { afterSubmit: () => (submittedAt = performance.now()), beforeReset: (id) => void resets.push(id) },
      });
      const fields = await signedAs(h.identity);
      const body = grpcFrame(serialize(kind === 'continuation' ? fields : without(fields, 'signature')));
      const blocked = blockedHttp2Call(h.port, body);
      t.after(() => blocked.close());
      await until(() => h.records.length === 1, 'a terminal record');
      const settled = performance.now() - submittedAt;
      assert.ok(submittedAt > 0 && settled >= 290 && settled < 900, `settled after ${settled.toFixed(1)} ms`);
      if (kind === 'continuation') {
        assertRecord(h.records, { severity: 'WARNING', outcome: 'transport_failed', attempted: 'continue' }, ['attempted']);
      } else {
        assertRecord(h.records, { severity: 'WARNING', outcome: 'transport_failed', attempted: 'deny', reason: 'signature_missing' }, ['attempted', 'reason']);
      }
      assert.equal(resets.length, 1, 'reset once');
      assert.equal(h.service.activeStreams, 0);
      await until(() => blocked.rstCode !== undefined, 'the blocked stream to close');
      assert.equal(blocked.rstCode, h2.NGHTTP2_CANCEL, 'the peer sees RST_STREAM CANCEL');
      // Reopening flow control releases nothing: the queued response was discarded with the stream.
      blocked.openWindow();
      await sleep(200);
      assert.deepEqual(blocked.data, [], 'no response bytes, before or after the window opened');
      assert.deepEqual(blocked.trailers, [], 'no grpc-status: OK');
      assert.equal(h.records.length, 1, 'still one record');
      // Only that stream was reset: the same connection carries the next call normally.
      const again = await blocked.callAgain(grpcFrame(serialize(await signedAs(h.identity))));
      assert.equal(again.grpcStatus, status.OK);
      assertOneContinuation(grpcMessages(again.data));
      assert.equal(h.records.length, 2);
      assert.equal(h.records[1]?.outcome, 'continue_submitted');
      assert.equal(h.service.activeStreams, 0);
    });
  }

  test('a write the transport never accepts (deterministic): reset at the settle time; releasing it later sends nothing', { timeout: 10_000 }, async (t) => {
    let release: (() => void) | undefined;
    const resets: string[] = [];
    const h = await harness(t, {
      submitSettleMs: 200,
      hooks: {
        accepted: (_id, call) => {
          const duplex = call as unknown as { _write(chunk: unknown, encoding: string, done: (error?: Error | null) => void): void };
          const write = duplex._write.bind(call);
          duplex._write = (chunk, encoding, done) => void (release = () => write(chunk, encoding, done));
        },
        beforeReset: (id) => void resets.push(id),
      },
    });
    const stream = h.client.open();
    stream.write(serialize(await signedAs(h.identity)));
    const final = await stream.status;
    assert.equal(final.code, status.CANCELLED, 'the stream was reset');
    assertRecord(h.records, { outcome: 'transport_failed', attempted: 'continue' }, ['attempted']);
    assert.equal(resets.length, 1);
    assert.equal(h.service.activeStreams, 0);
    assert.ok(release !== undefined, 'the write was held');
    release();
    await sleep(100);
    assert.equal(stream.responses.length, 0, 'nothing delivered after release');
    assert.equal(h.records.length, 1);
  });

  test('a write that fails: transport_failed, the stream is reset, no response and no OK status', { timeout: 10_000 }, async (t) => {
    const h = await harness(t, {
      hooks: {
        accepted: (_id, call) => {
          const duplex = call as unknown as { _write(chunk: unknown, encoding: string, done: (error?: Error | null) => void): void };
          duplex._write = (_chunk, _encoding, done) => done(new Error('write failed'));
        },
      },
    });
    const stream = h.client.open();
    stream.write(serialize(without(await signedAs(h.identity), 'signature')));
    const final = await stream.status;
    assert.notEqual(final.code, status.OK);
    assert.equal(stream.responses.length, 0);
    await sleep(50);
    assertRecord(h.records, { outcome: 'transport_failed', attempted: 'deny', reason: 'signature_missing' }, ['attempted', 'reason']);
    assert.equal(h.service.activeStreams, 0);
  });

  test('shutdown while a response is blocked by flow control: within the grace period, one transport_failed record, nothing delivered', { timeout: 10_000 }, async (t) => {
    let submitted = false;
    const h = await harness(t, { shutdownGraceMs: 200, hooks: { afterSubmit: () => (submitted = true) } });
    const blocked = blockedHttp2Call(h.port, grpcFrame(serialize(await signedAs(h.identity))));
    t.after(() => blocked.close());
    await until(() => submitted, 'the continuation to be submitted');
    const started = performance.now();
    await h.service.shutdown();
    const took = performance.now() - started;
    assert.ok(took >= 190 && took < 800, `shutdown took ${took.toFixed(1)} ms`);
    assertRecord(h.records, { outcome: 'transport_failed', attempted: 'continue' }, ['attempted']);
    assert.equal(h.service.activeStreams, 0);
    await until(() => blocked.rstCode !== undefined, 'the blocked stream to close');
    assert.deepEqual(blocked.data, []);
    assert.deepEqual(blocked.trailers, []);
  });
});

describe('service: bounded shutdown', () => {
  test('shutdown during a stalled request: after the grace period verification is cancelled and connections close', async (t) => {
    const h = await harness(t, { shutdownGraceMs: 300 });
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const stream = h.client.open();
    stream.write(serialize(await signedAs(h.identity)));
    await until(() => gate.held.length > 0, 'verification to stall');
    const started = performance.now();
    await h.service.shutdown();
    // Synchronously with the forced close: no stream is left to a later transport event.
    assert.equal(h.service.activeStreams, 0);
    assert.equal(h.records.length, 1);
    const took = performance.now() - started;
    assert.ok(took >= 290 && took < 1000, `shutdown took ${took.toFixed(1)} ms`);
    const final = await stream.status;
    assert.notEqual(final.code, status.OK);
    assert.equal(stream.responses.length, 0);
    assertRecord(h.records, { outcome: 'shutdown' });
    assert.equal(h.scopes[0]?.aborted, true, 'cancellation reached verification');
    assert.equal(h.service.activeStreams, 0);
    gate.release();
    await sleep(50);
    assert.equal(h.runtime.sharedMaterial?.stats().admitted, 0);
    // New streams are refused.
    const after = await exchange(h.client, serialize(await signedAs(h.identity)), { deadlineMs: 1000 });
    assert.equal(after.status.code, status.UNAVAILABLE);
  });

  test('a stream in flight when shutdown starts finishes within the grace period, then shutdown completes', async (t) => {
    const h = await harness(t, { shutdownGraceMs: 2000 });
    const gate = hold((what) => what.startsWith('dns:'));
    h.network.gate = gate.gate;
    const stream = h.client.open();
    stream.write(serialize(await signedAs(h.identity)));
    await until(() => gate.held.length > 0, 'verification to start');
    const closing = h.service.shutdown();
    setTimeout(() => gate.release(), 100);
    const final = await stream.status;
    h.client.close();
    await closing;
    assert.equal(final.code, status.OK);
    assertOneContinuation(stream.responses);
    assertRecord(h.records, { outcome: 'continue_submitted' }, ['verified']);
  });

  test('shutdown is idempotent and listen after shutdown is refused', async (t) => {
    const h = await harness(t);
    const first = h.service.shutdown();
    assert.equal(h.service.shutdown(), first);
    await first;
    await assert.rejects(h.service.listen('127.0.0.1', 0), { name: 'ServiceListenError' });
  });
});
