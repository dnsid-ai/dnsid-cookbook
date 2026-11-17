// The identity stage with the real SDK identity verifier, offline. Every identity here is a test fixture
// (tests/support/identity-fixture.ts): ephemeral keys, an SDK-signed `_dnsid` record and a C2SP log under test-only
// trust, served by in-memory DNS, HTTPS and log transports. Nothing mocks verifyDomain or a cryptographic result: every
// pass and every refusal below is the SDK's (or this stage's explicit governance check's) decision on that evidence.
// These are not DNSid Local or managed-service identities, and nothing here is live.

import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { describe, test } from 'node:test';

import {
  createHttpSignaturesProfile,
  DNSSECState,
  httpSignatures,
  VerificationCode,
  VerificationError,
  InMemoryIdentityCache,
  VerifiedDomain,
  type IdentityResolver,
} from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { checkpointPath } from '@dnsid-ai/log-c2sp-tlog';

import {
  checkSerializedRequestIdentity,
  createVerificationRuntime,
  governancePolicy,
  verifyRequestIdentity,
  type IdentityDenial,
  type IdentityStageObserver,
  type IdentityStageResult,
  type VerificationBackend,
  type VerificationRuntime,
} from '../../src/identity.ts';
import {
  FIXTURE_GOVERNANCE,
  fixtureBackend,
  fixtureLog,
  fixtureNetwork,
  issueIdentity,
  type FixtureBackendOptions,
  type FixtureIdentity,
  type FixtureLog,
  type FixtureNetwork,
} from '../support/identity-fixture.ts';
import { eligible, fieldsOf, replaced, serialize, without, type Field } from '../support/signing.ts';

const AGENT = 'agent-gov-fixture.test';
const TARGET = 'https://api-example.test/accounts/123?view=summary';

const unused: IdentityResolver = {
  verifyDomain() {
    throw new Error('a test signer never verifies');
  },
};

async function signedBy(provider: LocalKeyProvider, domain: string, url = TARGET): Promise<Field[]> {
  const profile = createHttpSignaturesProfile({ domain, keyProvider: provider, identityResolver: unused });
  return fieldsOf(await profile.createSignedHttpRequest(new Request(url)));
}
const signedAs = (identity: FixtureIdentity, url = TARGET) => signedBy(identity.operational, identity.domain, url);

interface World {
  log: FixtureLog;
  network: FixtureNetwork;
  identity: FixtureIdentity;
  backend: ReturnType<typeof fixtureBackend>;
  runtime: VerificationRuntime;
}

async function world(
  options: {
    governance?: Parameters<typeof governancePolicy>[0];
    backend?: FixtureBackendOptions;
    issue?: Parameters<typeof issueIdentity>[2];
    domain?: string;
  } = {},
): Promise<World> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const identity = await issueIdentity(log, options.domain ?? AGENT, options.issue);
  network.publish(identity);
  const backend = fixtureBackend(network, log, options.backend);
  const runtime = createVerificationRuntime({
    governance: governancePolicy(options.governance ?? [{ governanceId: FIXTURE_GOVERNANCE }]),
    backend,
  });
  return { log, network, identity, backend, runtime };
}

function run(
  runtime: VerificationRuntime,
  fields: Field[],
  options: { signal?: AbortSignal; budgetMs?: number; deadline?: number; observer?: IdentityStageObserver } = {},
): Promise<IdentityStageResult> {
  return verifyRequestIdentity(
    eligible(fields),
    {
      runtime,
      signal: options.signal ?? new AbortController().signal,
      deadline: options.deadline ?? performance.now() + (options.budgetMs ?? 2500),
    },
    options.observer,
  );
}

function assertDenied(result: unknown, reason: string, kind?: string): asserts result is IdentityDenial {
  const denial = result as IdentityDenial;
  assert.equal(denial.outcome, 'deny', `expected a denial, got ${JSON.stringify(result, replacer)}`);
  assert.equal(denial.status, 403);
  assert.equal(denial.reason, reason);
  if (kind !== undefined) assert.equal(denial.failure?.kind, kind);
}
const replacer = (key: string, value: unknown) => (key === 'sdkResult' ? '[VerifiedDomain]' : value);

/** Resolves once `condition` holds, polling each macrotask (bounded). */
async function until(condition: () => boolean): Promise<void> {
  // Bounded by time (4 s), not by a count of turns, which can pass in a few ms under the full suite's parallel load.
  const end = performance.now() + 4_000;
  while (!condition() && performance.now() < end) await new Promise((resolve) => setImmediate(resolve));
  assert.ok(condition(), 'condition never held');
}

function gate(): { wait: Promise<void>; open(): void } {
  let open = () => {};
  const wait = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { wait, open };
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe('identity stage: a valid signed request', () => {
  test('reaches intermediate success with the signature evidence and the verified identity, not authorization', async () => {
    const { runtime, identity, network, log, backend } = await world();
    const result = await run(runtime, await signedAs(identity));
    assert.equal(result.outcome, 'identity_stage_passed', JSON.stringify(result, replacer));
    if (result.outcome !== 'identity_stage_passed') return;

    // The signature stage's result is carried unchanged, with the SDK's evidence.
    assert.equal(result.signature.outcome, 'signature_stage_passed');
    assert.equal(result.signature.keyId, `${AGENT}#${identity.operationalKey.kid}`);
    assert.ok(result.signature.sdkResult instanceof VerifiedDomain);
    assert.equal(result.signature.sdkResult.domain, AGENT);
    assert.equal(result.signature.sdkResult.registryStatus.state, 'ACTIVE');
    assert.deepEqual(result.identity, {
      domain: AGENT,
      governanceId: FIXTURE_GOVERNANCE,
      entityKeyThumbprint: identity.entityThumbprint,
      dnssecState: DNSSECState.UNKNOWN,
      materialCache: 'miss',
    });
    assert.equal('authorized' in result, false);

    // Everything the SDK read: the record, both key sets, the status document and the log.
    assert.deepEqual(network.requests, [`dns:_dnsid.${AGENT}`, identity.ekUrl, identity.kuUrl, identity.statusUrl]);
    assert.deepEqual(log.reads, [checkpointPath(log.prefix), `${log.prefix}/tile/entries/000.p/1`]);
    assert.equal(backend.counters.registries, 1);
    assert.equal(backend.counters.verifiers, 1);
  });

  test('accepts the identity through serialized ext_proc bytes too', async () => {
    const { runtime, identity } = await world();
    const result = await checkSerializedRequestIdentity(serialize(await signedAs(identity)), {
      runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    assert.equal(result.outcome, 'identity_stage_passed');
  });

  test('every request builds its own verifier and registry, and status is fetched each time', async () => {
    const { runtime, identity, network, backend } = await world();
    for (let i = 0; i < 3; i++) assert.equal((await run(runtime, await signedAs(identity))).outcome, 'identity_stage_passed');
    assert.equal(backend.counters.registries, 3);
    assert.equal(backend.counters.verifiers, 3);
    assert.equal(network.requests.filter((url) => url === identity.statusUrl).length, 3);
    const signals = backend.counters.registryRequests.map((request) => request.signal);
    assert.equal(new Set(signals).size, 3);
    assert.ok(signals.every((signal) => signal.aborted), 'each request scope is ended when its request finishes');
  });

  test('DNSSEC UNKNOWN (what the Node resolver reports) and VALID are accepted in auto mode', async () => {
    for (const state of [DNSSECState.UNKNOWN, DNSSECState.VALID, DNSSECState.UNSIGNED]) {
      const { runtime, identity, network } = await world();
      network.setDns(`_dnsid.${AGENT}`, { records: [{ strings: [identity.txt], ttl: 300 }], state });
      const result = await run(runtime, await signedAs(identity));
      assert.equal(result.outcome, 'identity_stage_passed', state);
      if (result.outcome === 'identity_stage_passed') assert.equal(result.identity.dnssecState, state);
    }
  });

  test('a correct governance key pin is accepted', async () => {
    const log = fixtureLog();
    const network = fixtureNetwork();
    const identity = await issueIdentity(log, AGENT);
    network.publish(identity);
    const runtime = createVerificationRuntime({
      governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE, entityKeyThumbprints: [identity.entityThumbprint] }]),
      backend: fixtureBackend(network, log),
    });
    assert.equal((await run(runtime, await signedAs(identity))).outcome, 'identity_stage_passed');
  });
});

describe('identity stage: no identity lookup before the signature stage would make one', () => {
  async function assertNothingLooked(world: World, result: unknown, outcome: string) {
    assert.equal((result as { outcome?: string; reason?: string }).reason ?? (result as { outcome: string }).outcome, outcome);
    assert.deepEqual(world.network.requests, []);
    assert.deepEqual(world.log.reads, []);
    assert.equal(world.backend.counters.registries, 0);
    assert.equal(world.backend.counters.verifiers, 0);
  }

  test('a failed precondition (POST) builds and looks up nothing', async () => {
    const w = await world();
    const fields = replaced(await signedAs(w.identity), ':method', 'POST');
    const result = await checkSerializedRequestIdentity(serialize(fields), {
      runtime: w.runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    await assertNothingLooked(w, result, 'method_not_allowed');
  });

  test('a request without end_of_stream builds and looks up nothing', async () => {
    const w = await world();
    const result = await checkSerializedRequestIdentity(serialize(await signedAs(w.identity), false), {
      runtime: w.runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    assert.equal(result.outcome, 'deny');
    await assertNothingLooked(w, { outcome: 'x' }, 'x');
  });

  test('an unsigned request builds and looks up nothing', async () => {
    const w = await world();
    const fields = without(without(await signedAs(w.identity), 'signature'), 'signature-input');
    await assertNothingLooked(w, await run(w.runtime, fields), 'signature_missing');
  });

  test('an expired signature builds and looks up nothing', async () => {
    const w = await world();
    const created = Math.floor(Date.now() / 1000) - 400;
    const request = await httpSignatures.signHttpMessage(
      new Request(TARGET),
      { components: ['@method', '@authority', '@target-uri'], keyId: `${AGENT}#${w.identity.operationalKey.kid}`, created, label: 'sig1' },
      w.identity.operational,
    );
    await assertNothingLooked(w, await run(w.runtime, fieldsOf(request)), 'signature_expired');
  });

  test('insufficient coverage builds and looks up nothing', async () => {
    const w = await world();
    const request = await httpSignatures.signHttpMessage(
      new Request(TARGET),
      { components: ['@method', '@authority'], keyId: `${AGENT}#${w.identity.operationalKey.kid}`, created: Math.floor(Date.now() / 1000), label: 'sig1' },
      w.identity.operational,
    );
    await assertNothingLooked(w, await run(w.runtime, fieldsOf(request)), 'signature_coverage_insufficient');
  });
});

describe('identity stage: refusals on the evidence', () => {
  test('a tampered identity record (a changed tag) is refused', async () => {
    const w = await world();
    const tampered = w.identity.txt.replace('/status/', '/statuz/');
    assert.notEqual(tampered, w.identity.txt);
    w.network.setDns(`_dnsid.${AGENT}`, { records: [{ strings: [tampered], ttl: 300 }], state: DNSSECState.UNKNOWN });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_invalid', 'invalid');
    assert.equal(w.log.reads.length, 0);
  });

  test('a tampered record signature (sg) is refused', async () => {
    const w = await world();
    const tampered = w.identity.txt.replace(/sg=([A-Za-z0-9_-])/, (_, first: string) => `sg=${first === 'A' ? 'B' : 'A'}`);
    assert.notEqual(tampered, w.identity.txt);
    w.network.setDns(`_dnsid.${AGENT}`, { records: [{ strings: [tampered], ttl: 300 }], state: DNSSECState.UNKNOWN });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.SignatureInvalid);
  });

  test('an operational key the log never bound to the identity is refused, even when the request is signed with it', async () => {
    const w = await world();
    const attacker = await LocalKeyProvider.generate('EdDSA');
    w.network.setHttp(w.identity.kuUrl, { data: { keys: [await attacker.signingKey()] } });
    const result = await run(w.runtime, await signedBy(attacker, AGENT));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.LogError);
  });

  test('a request signed with a key the identity does not publish is refused at the signature stage', async () => {
    const w = await world();
    const other = await LocalKeyProvider.generate('EdDSA');
    assertDenied(await run(w.runtime, await signedBy(other, AGENT)), 'signature_key_unknown');
  });

  test('an identity whose key sets share a key (ek = ku) is refused', async () => {
    const w = await world();
    w.network.setHttp(w.identity.kuUrl, { data: { keys: [w.identity.entityKey] } });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_invalid', 'invalid');
  });

  test('an untrusted governance is refused by the SDK acceptance policy', async () => {
    const w = await world({ domain: 'agent-other-fixture.test', issue: { governanceId: 'other-fixture.test' } });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'governance_not_trusted', 'untrusted_governance');
    assert.equal(result.failure.code, VerificationCode.CounterpartyNotAccepted);
  });

  test('an incorrect governance key pin is refused', async () => {
    const w = await world({ governance: [{ governanceId: FIXTURE_GOVERNANCE, entityKeyThumbprints: ['A'.repeat(43)] }] });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'governance_not_trusted', 'governance_pin_mismatch');
  });

  test('the explicit governance check refuses what an SDK configured without the policy accepted', async () => {
    // The verifier is built without trustedEntities, so only this stage's own check stands between the record and success.
    const w = await world({
      domain: 'agent-other-fixture.test',
      issue: { governanceId: 'other-fixture.test' },
      backend: {
        overrideConfig: ({ verification }) => {
          const { trustedEntities: _omitted, ...rest } = verification ?? {};
          return { verification: rest };
        },
      },
    });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'governance_not_trusted', 'untrusted_governance');
    assert.ok(w.network.requests.includes(w.identity.statusUrl), 'the SDK verification itself completed');
  });

  test('the explicit governance check refuses a wrong key pin the SDK was not given', async () => {
    const w = await world({
      governance: [{ governanceId: FIXTURE_GOVERNANCE, entityKeyThumbprints: ['A'.repeat(43)] }],
      backend: { overrideConfig: () => ({ verification: { trustedEntities: [{ governanceId: FIXTURE_GOVERNANCE }] } }) },
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'governance_not_trusted', 'governance_pin_mismatch');
  });

  for (const state of ['REVOKED', 'RETIRED'] as const) {
    test(`a ${state} status is refused as inactive, told apart from an outage`, async () => {
      const w = await world();
      w.network.publish(w.identity, state);
      const result = await run(w.runtime, await signedAs(w.identity));
      assertDenied(result, 'identity_inactive', 'inactive');
      assert.equal(result.failure.agentState, state);
      assert.equal(result.failure.transient, false);
    });
  }

  test('a missing identity (no _dnsid record) is refused without fetching anything else', async () => {
    const w = await world();
    w.network.setDns(`_dnsid.${AGENT}`, undefined);
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_not_found', 'not_found');
    assert.deepEqual(w.network.requests, [`dns:_dnsid.${AGENT}`]);
  });

  test('DNSSEC FAILED is refused', async () => {
    const w = await world();
    w.network.setDns(`_dnsid.${AGENT}`, { records: [{ strings: [w.identity.txt], ttl: 300 }], state: DNSSECState.FAILED });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.DNSSECFailed);
  });

  test('an identity that requires mutual TLS is refused: the callout has no peer certificate and none is made up', async () => {
    const w = await world({ issue: { policyFlags: 'mtls' } });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.TLSError);
  });

  test('an identity with no ISSUANCE in its log is refused', async () => {
    const w = await world({ issue: { issue: false } });
    w.log.resign(); // an empty log, properly signed
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.LogError);
  });
});

describe('identity stage: outages fail closed and are told apart from inactive identities', () => {
  test('DNS unavailable (SERVFAIL)', async () => {
    const w = await world();
    w.network.setDns(`_dnsid.${AGENT}`, { error: Object.assign(new Error('queryTxt ESERVFAIL'), { code: 'ESERVFAIL' }) });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_unavailable', 'unavailable');
    assert.equal(result.failure.code, VerificationCode.DNSResolution);
    assert.equal(result.failure.transient, true);
  });

  test('status endpoint unreachable', async () => {
    const w = await world();
    w.network.setHttp(w.identity.statusUrl, { error: new VerificationError('connect ECONNRESET', { code: VerificationCode.TLSError, transient: true }) });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_unavailable', 'unavailable');
  });

  test('status endpoint answering 503', async () => {
    const w = await world();
    w.network.setHttp(w.identity.statusUrl, { error: new VerificationError('HTTP 503', { code: VerificationCode.HTTPError, transient: true }) });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_unavailable', 'unavailable');
  });

  test('an operational key set that cannot be fetched', async () => {
    const w = await world();
    w.network.setHttp(w.identity.kuUrl, { error: new VerificationError('connect ETIMEDOUT', { code: VerificationCode.TLSError, transient: true }) });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_unavailable', 'unavailable');
  });

  test('log unavailable: checkpoint 503', async () => {
    const w = await world();
    w.log.override(checkpointPath(w.log.prefix), { status: 503 });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_unavailable', 'unavailable');
    assert.equal(result.failure.code, VerificationCode.LogError);
  });

  test('log unavailable: network failure on the entry bundle', async () => {
    const w = await world();
    w.log.override(`${w.log.prefix}/tile/entries/000.p/1`, { status: 0 });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_unavailable', 'unavailable');
  });
});

describe('identity stage: unknown and untrusted log references fail closed', () => {
  test('an unsupported log method is refused before any log read', async () => {
    const w = await world({ issue: { lr: 'example-log:agent-stream', issue: false } });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.RecordInvalid);
    assert.deepEqual(w.log.reads, []);
  });

  test('a c2sp-tlog reference to a log outside the trusted catalog is refused before any log read', async () => {
    const log = fixtureLog();
    const elsewhere = fixtureLog('https://other-log-fixture.test');
    const network = fixtureNetwork();
    const identity = await issueIdentity(elsewhere, AGENT); // a valid ISSUANCE in a log nobody here trusts
    network.publish(identity);
    const runtime = createVerificationRuntime({
      governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]),
      backend: fixtureBackend(network, log, { untrustedLogs: [elsewhere] }),
    });
    assertDenied(await run(runtime, await signedAs(identity)), 'identity_invalid', 'invalid');
    assert.deepEqual(elsewhere.reads, []);
  });

  test('a log at the trusted prefix whose checkpoint is signed by other keys is refused', async () => {
    const trusted = fixtureLog();
    const impostor = fixtureLog(trusted.prefix);
    const network = fixtureNetwork();
    const identity = await issueIdentity(impostor, AGENT);
    network.publish(identity);
    const runtime = createVerificationRuntime({
      governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]),
      backend: fixtureBackend(network, trusted, { impostor }),
    });
    const result = await run(runtime, await signedAs(identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.equal(result.failure.code, VerificationCode.LogError);
    assert.equal(result.failure.transient, false);
    assert.equal(await runtime.checkpointStore.load(trusted.origin), undefined);
  });
});

describe('identity stage: the shared checkpoint store, through real verification', () => {
  test('accepted checkpoints advance; a rolled-back log is refused and cannot overwrite accepted history', async () => {
    const w = await world();
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
    assert.equal((await w.runtime.checkpointStore.load(w.log.origin))?.treeSize, 1);

    const second = await issueIdentity(w.log, 'second-gov-fixture.test');
    w.network.publish(second);
    assert.equal((await run(w.runtime, await signedAs(second))).outcome, 'identity_stage_passed');
    const accepted = await w.runtime.checkpointStore.load(w.log.origin);
    assert.equal(accepted?.treeSize, 2);

    w.log.entries.pop();
    w.log.resign(); // the log now presents an older (validly signed) checkpoint of size 1
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_invalid', 'invalid');
    assert.deepEqual(await w.runtime.checkpointStore.load(w.log.origin), accepted);
  });
});

describe('identity stage: budget and cancellation', () => {
  test('an already-spent budget builds and looks up nothing', async () => {
    const w = await world();
    assertDenied(await run(w.runtime, await signedAs(w.identity), { deadline: performance.now() - 1 }), 'verification_budget_exhausted');
    assert.equal(w.backend.counters.registries, 0);
    assert.deepEqual(w.network.requests, []);
  });

  test('an already-cancelled request builds and looks up nothing', async () => {
    const w = await world();
    const controller = new AbortController();
    controller.abort();
    assertDenied(await run(w.runtime, await signedAs(w.identity), { signal: controller.signal }), 'verification_cancelled');
    assert.equal(w.backend.counters.registries, 0);
    assert.deepEqual(w.network.requests, []);
  });

  test('cancellation during construction denies at once; the late construction is discarded', async () => {
    const hold = gate();
    let holding = true;
    const w = await world({ backend: { beforeRegistry: () => (holding ? hold.wait : Promise.resolve()) } });
    const controller = new AbortController();
    const pending = run(w.runtime, await signedAs(w.identity), { signal: controller.signal });
    await until(() => w.backend.counters.registries === 1);
    const started = performance.now();
    controller.abort();
    assertDenied(await pending, 'verification_cancelled');
    assert.ok(performance.now() - started < 100);
    holding = false;
    hold.open();
    await sleep(20);
    assert.equal(w.backend.counters.verifiers, 0, 'the abandoned construction never went on to build a verifier');
    assert.deepEqual(w.network.requests, []);
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
  });

  test('construction that ignores cancellation and never finishes is cut off at the original deadline', async () => {
    const w = await world({ backend: { beforeRegistry: () => new Promise(() => {}) } });
    const started = performance.now();
    assertDenied(await run(w.runtime, await signedAs(w.identity), { budgetMs: 200 }), 'verification_budget_exhausted');
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 190 && elapsed < 450, `elapsed ${elapsed}`);
  });

  test('a failed construction denies that request only; the next one builds afresh and succeeds', async () => {
    let failures = 1;
    const w = await world({
      backend: {
        beforeRegistry: async () => {
          if (failures-- > 0) throw new Error('registry construction failed');
        },
      },
    });
    const result = await run(w.runtime, await signedAs(w.identity));
    assertDenied(result, 'identity_unavailable', 'construction_failed');
    assert.equal(JSON.stringify(result).includes('registry construction failed'), false, 'no raw error in the result');
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
    assert.equal(w.backend.counters.registries, 2);
  });

  test('a failed verifier construction is not kept either', async () => {
    let failures = 1;
    const w = await world({
      backend: {
        beforeVerifier: async () => {
          if (failures-- > 0) throw new Error('verifier construction failed');
        },
      },
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_unavailable', 'construction_failed');
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
  });

  test('cancellation during lookup denies at once', async () => {
    const hold = gate();
    const w = await world();
    w.network.gate = (what) => (what === w.identity.statusUrl ? hold.wait : Promise.resolve());
    const controller = new AbortController();
    const pending = run(w.runtime, await signedAs(w.identity), { signal: controller.signal });
    await until(() => w.network.requests.includes(w.identity.statusUrl));
    controller.abort();
    assertDenied(await pending, 'verification_cancelled');
    hold.open();
    await sleep(20);
  });

  test('a DNS lookup that ignores cancellation and never answers is cut off at the deadline', async () => {
    const w = await world();
    w.network.setDns(`_dnsid.${AGENT}`, { hang: true });
    const started = performance.now();
    assertDenied(await run(w.runtime, await signedAs(w.identity), { budgetMs: 200 }), 'verification_budget_exhausted');
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 190 && elapsed < 450, `elapsed ${elapsed}`);
  });

  test('an answer that arrives after the deadline (its dependency ignoring cancellation) never yields success', async () => {
    const w = await world();
    w.network.gate = (what) => (what === w.identity.statusUrl ? sleep(300) : Promise.resolve());
    assertDenied(await run(w.runtime, await signedAs(w.identity), { budgetMs: 150 }), 'verification_budget_exhausted');
    await sleep(200); // the late status answer arrives; nothing changes
  });

  test('concurrent cold requests for one identity: cancelling one leaves the other intact', async () => {
    const hold = gate();
    const w = await world();
    w.network.gate = (what) => (what === w.identity.statusUrl ? hold.wait : Promise.resolve());
    const first = new AbortController();
    const second = new AbortController();
    const a = run(w.runtime, await signedAs(w.identity), { signal: first.signal });
    const b = run(w.runtime, await signedAs(w.identity), { signal: second.signal });
    await until(() => w.network.requests.filter((url) => url === w.identity.statusUrl).length === 2);
    first.abort();
    assertDenied(await a, 'verification_cancelled');
    const [scopeA, scopeB] = w.backend.counters.registryRequests;
    assert.equal(scopeA?.signal.aborted, true);
    assert.equal(scopeB?.signal.aborted, false, 'the other request is still running, its scope untouched');
    hold.open();
    assert.equal((await b).outcome, 'identity_stage_passed');
  });

  test('concurrent cold requests for one identity with different deadlines: the short one runs out, the long one succeeds', async () => {
    const w = await world();
    w.network.gate = (what) => (what === w.identity.statusUrl ? sleep(200) : Promise.resolve());
    const [short, long] = await Promise.all([
      run(w.runtime, await signedAs(w.identity), { budgetMs: 100 }),
      run(w.runtime, await signedAs(w.identity), { budgetMs: 2500 }),
    ]);
    assertDenied(short, 'verification_budget_exhausted');
    assert.equal(long.outcome, 'identity_stage_passed');
    assert.equal(w.backend.counters.verifiers, 2);
  });
});

describe('identity stage: the final success boundary', () => {
  // The real SDK verifier verifies the real fixture identity; its VerifiedDomain is handed on unchanged except that
  // reading `dnssecState`, which only the stage's own result construction reads, first runs `duringResult`. That ends
  // the request at the last step before the stage would return success, after every earlier check has passed.
  async function boundaryWorld(duringResult: () => void) {
    const w = await world();
    const reads = { dnssecState: 0 };
    const real = w.backend;
    const backend: VerificationBackend = {
      name: real.name,
      transportContext: real.transportContext,
      createLogRegistry: (request) => real.createLogRegistry(request),
      async createIdentityVerifier(config, dependencies) {
        const verifier = await real.createIdentityVerifier(config, dependencies);
        return new Proxy(verifier, {
          get(target, property) {
            const value: unknown = Reflect.get(target, property, target);
            if (property !== 'verifyDomain' || typeof value !== 'function') {
              return typeof value === 'function' ? value.bind(target) : value;
            }
            return async (...args: unknown[]) => {
              const verified: VerifiedDomain = await value.apply(target, args);
              return new Proxy(verified, {
                get(domain, field) {
                  if (field === 'dnssecState') {
                    reads.dnssecState++;
                    duringResult();
                  }
                  const fieldValue: unknown = Reflect.get(domain, field, domain);
                  return typeof fieldValue === 'function' ? fieldValue.bind(domain) : fieldValue;
                },
              });
            };
          },
        });
      },
    };
    const runtime = createVerificationRuntime({ governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]), backend });
    return { ...w, runtime, reads };
  }

  function cleanupObserver() {
    const closed: { signal: AbortSignal; lookups: number }[] = [];
    const observer: IdentityStageObserver = { scopeClosed: (scope) => closed.push({ signal: scope.signal, lookups: scope.lookups }) };
    return { closed, observer };
  }

  test('without interference the boundary world succeeds (the hook itself changes nothing)', async () => {
    const w = await boundaryWorld(() => {});
    const result = await run(w.runtime, await signedAs(w.identity));
    assert.equal(result.outcome, 'identity_stage_passed', JSON.stringify(result, replacer));
    assert.equal(w.reads.dnssecState, 1, 'read once, by the result construction only');
  });

  test('cancellation during the final result construction denies, and the scope is cleaned up', async () => {
    const controller = new AbortController();
    const w = await boundaryWorld(() => controller.abort());
    const { closed, observer } = cleanupObserver();
    const timers = () => process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    const before = timers();
    const result = await run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    assertDenied(result, 'verification_cancelled');
    assert.equal(w.reads.dnssecState, 1, 'the request ended during result construction, after the identity was verified');
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.equal(closed.length, 1);
    assert.equal(closed[0]?.signal.aborted, true);
    assert.equal(closed[0]?.lookups, 1);
    assert.equal(timers(), before);
  });

  test('the original deadline passing during the final result construction denies, and the scope is cleaned up', async () => {
    const budgetMs = 1500;
    const deadline = performance.now() + budgetMs;
    const controller = new AbortController();
    // Holds the event loop until the original deadline has passed, so only the final check can see it.
    const w = await boundaryWorld(() => {
      while (performance.now() < deadline + 1) {}
    });
    const { closed, observer } = cleanupObserver();
    const result = await run(w.runtime, await signedAs(w.identity), { signal: controller.signal, deadline, observer });
    assertDenied(result, 'verification_budget_exhausted');
    assert.equal(w.reads.dnssecState, 1);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.equal(closed.length, 1);
    assert.equal(closed[0]?.signal.aborted, true);
  });

  test('the result carries the thumbprint the SDK computed, equal to an independent RFC 7638 computation', async () => {
    const w = await world();
    const result = await run(w.runtime, await signedAs(w.identity));
    assert.equal(result.outcome, 'identity_stage_passed');
    if (result.outcome !== 'identity_stage_passed') return;
    assert.equal(result.identity.entityKeyThumbprint, result.signature.sdkResult.signingKeyThumbprint);
    assert.equal(result.identity.entityKeyThumbprint, w.identity.entityThumbprint);
  });
});

describe('identity stage: cleanup on every exit', () => {
  async function listenersAfter(path: (w: World, signal: AbortSignal, observer: IdentityStageObserver) => Promise<void>) {
    const w = await world();
    const controller = new AbortController();
    const scopes: AbortSignal[] = [];
    const observer: IdentityStageObserver = { scopeClosed: (scope) => scopes.push(scope.signal) };
    await path(w, controller.signal, observer);
    return { listeners: getEventListeners(controller.signal, 'abort').length, scopes };
  }

  test('success leaves no listener on the request signal and ends the scope', async () => {
    const { listeners, scopes } = await listenersAfter(async (w, signal, observer) => {
      assert.equal((await run(w.runtime, await signedAs(w.identity), { signal, observer })).outcome, 'identity_stage_passed');
    });
    assert.equal(listeners, 0);
    assert.equal(scopes.length, 1);
    assert.equal(scopes[0]?.aborted, true);
  });

  test('a denial leaves no listener', async () => {
    const { listeners } = await listenersAfter(async (w, signal, observer) => {
      w.network.publish(w.identity, 'REVOKED');
      assertDenied(await run(w.runtime, await signedAs(w.identity), { signal, observer }), 'identity_inactive');
    });
    assert.equal(listeners, 0);
  });

  test('a budget exhaustion leaves no listener', async () => {
    const { listeners } = await listenersAfter(async (w, signal, observer) => {
      w.network.setDns(`_dnsid.${AGENT}`, { hang: true });
      assertDenied(await run(w.runtime, await signedAs(w.identity), { signal, observer, budgetMs: 100 }), 'verification_budget_exhausted');
    });
    assert.equal(listeners, 0);
  });

  test('the verifier gets a request-local cache (not the SDK default, which keeps log readers on timers), emptied at the end', async () => {
    const w = await world();
    const seen: (VerifiedDomain | null)[] = [];
    w.network.gate = async (what) => {
      if (what === w.identity.statusUrl) seen.push(w.backend.counters.caches[0]?.get(AGENT) ?? null);
    };
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
    assert.equal(w.backend.counters.caches.length, 1);
    const cache = w.backend.counters.caches[0];
    assert.ok(cache !== undefined && !(cache instanceof InMemoryIdentityCache));
    assert.deepEqual(seen, [null], 'nothing cached before the identity was verified');
    assert.equal(cache.get(AGENT), null, 'emptied when the request ended');
    // A second request gets a cache of its own.
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
    assert.notEqual(w.backend.counters.caches[1], cache);
  });

  test('no timer outlives a request', async () => {
    const w = await world();
    const timers = () => process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    await run(w.runtime, await signedAs(w.identity)); // warm module-level state
    const before = timers();
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'identity_stage_passed');
    w.network.publish(w.identity, 'REVOKED');
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_inactive');
    assert.equal(timers(), before);
  });
});
