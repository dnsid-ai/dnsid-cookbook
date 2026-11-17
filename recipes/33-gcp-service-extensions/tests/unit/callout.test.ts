// The whole callout, from serialized ProcessingRequest bytes to a serialized ProcessingResponse: the real decoder and
// preconditions, the real SDK verification of offline test identities on a test C2SP log (tests/support/
// identity-fixture.ts), and the response layer. No listener, origin or Google load balancer is involved: where these
// tests apply the emitted mutation, they use a local model of the protocol's semantics, labelled as such.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { createHttpSignaturesProfile, type IdentityResolver } from '@dnsid-ai/sdk';
import { checkpointPath } from '@dnsid-ai/log-c2sp-tlog';

import { processRequestHeaders, type CalloutObserver } from '../../src/callout.ts';
import { createVerificationRuntime, governancePolicy, type VerificationRuntime } from '../../src/identity.ts';
import { GOVERNANCE_ID_HEADER, VERIFIED_DOMAIN_HEADER, type CalloutResponse } from '../../src/response.ts';
import {
  FIXTURE_GOVERNANCE,
  fixtureBackend,
  fixtureLog,
  fixtureNetwork,
  issueIdentity,
  lifecycleEntry,
  type FixtureIdentity,
  type FixtureLog,
  type FixtureNetwork,
} from '../support/identity-fixture.ts';
import { FORBIDDEN, OVERWRITE_IF_EXISTS_OR_ADD, applyMutation, decodeContinuation, decodeDenial, valuesOf, type HeaderList } from '../support/response-wire.ts';
import { fieldsOf, replaced, serialize, without, type Field } from '../support/signing.ts';

const AGENT = 'agent-gov-fixture.test';
const TARGET = 'https://api-example.test/accounts/123?view=summary';

const unused: IdentityResolver = {
  verifyDomain() {
    throw new Error('a test signer never verifies');
  },
};

async function signedAs(identity: FixtureIdentity, method = 'GET', extra: Field[] = []): Promise<Field[]> {
  const profile = createHttpSignaturesProfile({ domain: identity.domain, keyProvider: identity.operational, identityResolver: unused });
  return fieldsOf(await profile.createSignedHttpRequest(new Request(TARGET, { method })), {}, extra);
}

interface World {
  log: FixtureLog;
  network: FixtureNetwork;
  identity: FixtureIdentity;
  runtime: VerificationRuntime;
}

async function world(): Promise<World> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const identity = await issueIdentity(log, AGENT);
  network.publish(identity);
  const runtime = createVerificationRuntime({
    governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]),
    backend: fixtureBackend(network, log),
  });
  return { log, network, identity, runtime };
}

function call(
  w: World,
  bytes: Uint8Array,
  options: { signal?: AbortSignal; deadline?: number; observer?: CalloutObserver } = {},
): Promise<CalloutResponse> {
  return processRequestHeaders(
    bytes,
    { runtime: w.runtime, signal: options.signal ?? new AbortController().signal, deadline: options.deadline ?? performance.now() + 2500 },
    options.observer,
  );
}

function assertDeny(result: CalloutResponse, reason: string): void {
  assert.equal(result.decision, 'deny', `expected ${reason}, got a continuation`);
  assert.equal(result.decision === 'deny' && result.reason, reason);
  const denial = decodeDenial(result.response);
  assert.equal(denial.status, FORBIDDEN);
  assert.deepEqual(
    denial.headers.map((h) => [h.key, h.rawValue.toString('latin1')]),
    [['cache-control', 'no-store']],
  );
  assert.equal(denial.body.toString('latin1'), reason);
  const text = Buffer.from(result.response).toString('latin1');
  for (const leak of [AGENT, 'api-example.test', 'sig1', 'https://', 'Error']) assert.equal(text.includes(leak), false, `"${leak}" in a denial`);
}

function assertContinue(result: CalloutResponse) {
  assert.equal(result.decision, 'continue', result.decision === 'deny' ? `denied: ${result.reason}` : '');
  return decodeContinuation(result.response);
}

const asList = (fields: Field[]): HeaderList =>
  fields.map(([name, value]) => [name, typeof value === 'string' ? Buffer.from(value, 'latin1') : Buffer.from(value)]);

describe('callout: a signed request from an active, trusted identity continues', () => {
  for (const method of ['GET', 'HEAD']) {
    test(`${method}: CONTINUE with the verified domain and governance ID, and nothing else changed`, async () => {
      const w = await world();
      const fields = await signedAs(w.identity, method);
      const bytes = serialize(fields);
      const copy = Buffer.from(bytes);
      const continuation = assertContinue(await call(w, bytes));
      assert.deepEqual(bytes, copy, 'the request bytes are unchanged');
      assert.deepEqual(
        continuation.setHeaders.map((h) => [h.key, h.rawValue.toString('latin1'), h.appendAction]),
        [
          [VERIFIED_DOMAIN_HEADER, AGENT, OVERWRITE_IF_EXISTS_OR_ADD],
          [GOVERNANCE_ID_HEADER, FIXTURE_GOVERNANCE, OVERWRITE_IF_EXISTS_OR_ADD],
        ],
      );
      assert.deepEqual(continuation.removeHeaders, []);
      // Protocol-semantic model, applied locally (not Google's forwarding): the received headers, then the two added.
      const after = applyMutation(asList(fields), continuation);
      assert.deepEqual(after.slice(0, fields.length), asList(fields).map(([n, v]) => [n.toLowerCase(), v]));
      assert.deepEqual(after.slice(fields.length).map(([n, v]) => [n, v.toString()]), [
        [VERIFIED_DOMAIN_HEADER, AGENT],
        [GOVERNANCE_ID_HEADER, FIXTURE_GOVERNANCE],
      ]);
    });
  }

  test('cold, then warm (shared records and keys reused): both continue with the same instructions', async () => {
    const w = await world();
    const cold = assertContinue(await call(w, serialize(await signedAs(w.identity))));
    const before = w.runtime.sharedMaterial?.stats();
    const warm = assertContinue(await call(w, serialize(await signedAs(w.identity))));
    const after = w.runtime.sharedMaterial?.stats();
    assert.ok(before !== undefined && after !== undefined);
    assert.equal(after.dnsHits, before.dnsHits + 1, 'the second request was a warm cache hit');
    assert.deepEqual(warm, cold);
  });

  test('forged, mixed-case, duplicate and unknown x-dnsid-* headers: verification passes on the request as received, then every one is removed', async () => {
    const w = await world();
    const forged: Field[] = [
      ['X-DNSid-Verified-Domain', 'bank-admin.example'],
      ['x-dnsid-verified-domain', 'other.example'],
      ['X-DNSID-GOVERNANCE-ID', 'evil-governance.example'],
      ['x-dnsid-governance-id', 'evil-governance2.example'],
      ['x-dnsid-agent-tier', 'unlimited'],
      ['x-unrelated', 'kept'],
    ];
    const fields = await signedAs(w.identity, 'GET', forged);
    const order: string[] = [];
    const result = await call(w, serialize(fields), {
      observer: {
        lifecycleStarting: () => order.push('verification'),
        continuationSerialized: () => order.push('response serialized'),
      },
    });
    const continuation = assertContinue(result);
    assert.deepEqual(order, ['verification', 'response serialized'], 'verification ran before any mutation was planned');
    assert.deepEqual(continuation.removeHeaders, ['x-dnsid-verified-domain', 'x-dnsid-governance-id', 'x-dnsid-agent-tier']);
    const text = Buffer.from(result.response).toString('latin1');
    for (const value of ['bank-admin', 'other.example', 'evil-governance', 'unlimited']) assert.equal(text.includes(value), false);
    // Protocol-semantic model, applied locally in Envoy's order (removals, then sets). NOT evidence of what Google's
    // load balancer forwards to an origin.
    const after = applyMutation(asList(fields), continuation);
    assert.deepEqual(valuesOf(after, VERIFIED_DOMAIN_HEADER), [AGENT]);
    assert.deepEqual(valuesOf(after, GOVERNANCE_ID_HEADER), [FIXTURE_GOVERNANCE]);
    assert.deepEqual(valuesOf(after, 'x-dnsid-agent-tier'), []);
    assert.deepEqual(valuesOf(after, 'x-unrelated'), ['kept']);
    for (const name of [':method', ':authority', ':path', ':scheme', 'signature', 'signature-input']) {
      assert.deepEqual(valuesOf(after, name), valuesOf(asList(fields), name), `${name} unchanged`);
    }
  });
});

describe('callout: every other request is only an immediate 403', () => {
  test('unsigned', async () => {
    const w = await world();
    const fields = without(without(await signedAs(w.identity), 'signature'), 'signature-input');
    assertDeny(await call(w, serialize(fields)), 'signature_missing');
  });

  test('tampered after signing (the path changed)', async () => {
    const w = await world();
    const fields = replaced(await signedAs(w.identity), ':path', '/accounts/124?view=summary');
    assertDeny(await call(w, serialize(fields)), 'signature_invalid');
  });

  test('tampered signature bytes', async () => {
    const w = await world();
    const fields = await signedAs(w.identity);
    const signature = fields.find(([name]) => name === 'signature')?.[1] as string;
    const flipped = signature.replace(/:([A-Za-z0-9+/])/, (_, c: string) => `:${c === 'A' ? 'B' : 'A'}`);
    assertDeny(await call(w, serialize(replaced(fields, 'signature', flipped))), 'signature_invalid');
  });

  test('an identity under an untrusted governance', async () => {
    const log = fixtureLog();
    const network = fixtureNetwork();
    const identity = await issueIdentity(log, 'agent-other-fixture.test', { governanceId: 'other-fixture.test' });
    network.publish(identity);
    const runtime = createVerificationRuntime({
      governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]),
      backend: fixtureBackend(network, log),
    });
    const w = { log, network, identity, runtime };
    assertDeny(await call(w, serialize(await signedAs(identity))), 'governance_not_trusted');
  });

  test('revoked: by status, then by a log revocation after a success, with no change to the deployment', async () => {
    const w = await world();
    assertContinue(await call(w, serialize(await signedAs(w.identity))));
    w.log.append(await lifecycleEntry(w.identity, 'REVOCATION'));
    // The same runtime (warm cache), the status document still ACTIVE: the log's revocation alone refuses it.
    // The SDK's identity verification reads the same log history, so it refuses it before the lifecycle check.
    assertDeny(await call(w, serialize(await signedAs(w.identity))), 'identity_invalid');
    w.network.publish(w.identity, 'REVOKED');
    assertDeny(await call(w, serialize(await signedAs(w.identity))), 'identity_inactive');
  });

  test('a revocation logged while the request is being verified: lifecycle_not_established', async () => {
    const w = await world();
    const revocation = await lifecycleEntry(w.identity, 'REVOCATION');
    const result = await call(w, serialize(await signedAs(w.identity)), { observer: { lifecycleStarting: () => w.log.append(revocation) } });
    assertDeny(result, 'lifecycle_not_established');
  });

  test('unavailable evidence (the log answers 503 at the lifecycle check): lifecycle_unavailable', async () => {
    const w = await world();
    const result = await call(w, serialize(await signedAs(w.identity)), {
      observer: { lifecycleStarting: () => w.log.override(checkpointPath(w.log.prefix), { status: 503 }) },
    });
    assertDeny(result, 'lifecycle_unavailable');
  });

  test('decoding rejections and precondition denials keep their own reasons', async () => {
    const w = await world();
    assertDeny(await call(w, new Uint8Array(0)), 'empty_message');
    assertDeny(await call(w, Uint8Array.from([0xff, 0xff, 0xff])), 'malformed_message');
    // response_headers (field 3) instead of request_headers.
    assertDeny(await call(w, Uint8Array.from([0x1a, 0x00])), 'unsupported_message_type');
    const fields = await signedAs(w.identity);
    assertDeny(await call(w, serialize(replaced(fields, ':method', 'POST'))), 'method_not_allowed');
    assertDeny(await call(w, serialize(fields, false)), 'body_not_ruled_out');
  });

  test('an invalid context is the internal_error 403, never a continuation', async () => {
    const w = await world();
    const bytes = serialize(await signedAs(w.identity));
    const bad = { runtime: w.runtime, signal: { aborted: false }, deadline: performance.now() + 2500 } as never;
    assertDeny(await processRequestHeaders(bytes, bad), 'internal_error');
    assertDeny(await processRequestHeaders(bytes, null as never), 'internal_error');
  });
});

describe('callout: the caller’s cancellation and original deadline reach past verification into the response', () => {
  test('cancelled after verification passed, while the response is serialized: only the cancellation 403', async () => {
    const w = await world();
    const controller = new AbortController();
    let passedVerification = false;
    const result = await call(w, serialize(await signedAs(w.identity)), {
      signal: controller.signal,
      observer: {
        buildingResult: () => (passedVerification = true),
        continuationSerialized: () => controller.abort(),
      },
    });
    assert.equal(passedVerification, true, 'verification itself had passed');
    assertDeny(result, 'verification_cancelled');
  });

  test('the original deadline passing while the response is built: only the budget 403', async () => {
    const w = await world();
    const deadline = performance.now() + 2000;
    const result = await call(w, serialize(await signedAs(w.identity)), {
      deadline,
      observer: {
        continuationSerialized() {
          while (performance.now() < deadline) {
            // spend what is left of the request's original budget inside response construction
          }
        },
      },
    });
    assertDeny(result, 'verification_budget_exhausted');
  });

  test('cancelled during verification: the cancellation 403, and the response layer never builds a continuation', async () => {
    const w = await world();
    const controller = new AbortController();
    let serialized = 0;
    const result = await call(w, serialize(await signedAs(w.identity)), {
      signal: controller.signal,
      observer: { lifecycleStarting: () => controller.abort(), continuationSerialized: () => serialized++ },
    });
    assertDeny(result, 'verification_cancelled');
    assert.equal(serialized, 0);
  });
});
