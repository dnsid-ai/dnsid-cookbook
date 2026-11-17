// The lifecycle and freshness stage, offline. Integrated cases use the real SDK identity verifier and the real SDK C2SP
// reader on the fixture identities and test log of tests/support/identity-fixture.ts, whose lifecycle events (ISSUANCE,
// REVOCATION, RETIREMENT) are signed with the SDK's prepared-event writer and whose checkpoints are signed and witnessed
// by test keys. Nothing mocks verifyNonRevocation's verification: every pass and refusal below is the SDK's decision on
// that evidence, or this stage's own check of what the SDK returned. The `checkLoggedStateEvidence` cases at the end are
// validation-unit inputs to the stage's standalone validator: they were NOT verified by the SDK. These are not DNSid
// Local or managed-service identities, and nothing here is live.

import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { describe, test, type TestContext } from 'node:test';

import { createHttpSignaturesProfile, VerificationCode, type IdentityResolver, type LoggedStateEvidence, type VerifiedDomain } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import {
  checkpointPath,
  entryBundlePath,
  InMemoryTrustedC2spCheckpointStore,
  type TrustedC2spCheckpoint,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';

import { createVerificationRuntime, governancePolicy, verifyRequestIdentity, type VerificationRuntime } from '../../src/identity.ts';
import {
  checkLoggedStateEvidence,
  checkSerializedRequestVerification,
  MAX_EVIDENCE_AGE_MS,
  MAX_EVIDENCE_FUTURE_MS,
  verifyRequest,
  type LifecycleDenial,
  type VerificationObserver,
  type VerificationResult,
} from '../../src/lifecycle.ts';
import {
  FIXTURE_GOVERNANCE,
  fixtureBackend,
  fixtureLog,
  fixtureNetwork,
  issueIdentity,
  lifecycleEntry,
  MANAGED_CHECKPOINT_MAX_AGE_MS,
  type FixtureIdentity,
  type FixtureLog,
  type FixtureNetwork,
} from '../support/identity-fixture.ts';
import { eligible, fieldsOf, serialize, type Field } from '../support/signing.ts';

const AGENT = 'agent-gov-fixture.test';
const SECOND = 'second-other-gov-fixture.test';
/** The second identity's governance: the fixture publishes one accountable-entity key set per governance ID. */
const SECOND_GOVERNANCE = 'other-gov-fixture.test';
const TARGET = 'https://api-example.test/accounts/123?view=summary';

const unused: IdentityResolver = {
  verifyDomain() {
    throw new Error('a test signer never verifies');
  },
};

async function signedBy(provider: LocalKeyProvider, domain: string): Promise<Field[]> {
  const profile = createHttpSignaturesProfile({ domain, keyProvider: provider, identityResolver: unused });
  return fieldsOf(await profile.createSignedHttpRequest(new Request(TARGET)));
}
const signedAs = (identity: FixtureIdentity) => signedBy(identity.operational, identity.domain);

interface World {
  log: FixtureLog;
  network: FixtureNetwork;
  identity: FixtureIdentity;
  backend: ReturnType<typeof fixtureBackend>;
  runtime: VerificationRuntime;
}

async function world(options: { checkpointStore?: TrustedC2spCheckpointStore; policyFlags?: string } = {}): Promise<World> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const identity = await issueIdentity(
    log,
    AGENT,
    options.policyFlags === undefined ? {} : { policyFlags: options.policyFlags },
  );
  network.publish(identity);
  const backend = fixtureBackend(network, log);
  const runtime = createVerificationRuntime({
    governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }, { governanceId: SECOND_GOVERNANCE }]),
    backend,
    ...(options.checkpointStore === undefined ? {} : { checkpointStore: options.checkpointStore }),
  });
  return { log, network, identity, backend, runtime };
}

/** A second identity in the same log, published, so one identity's revocation can be shown not to affect another. */
async function secondIdentity(w: World): Promise<FixtureIdentity> {
  const second = await issueIdentity(w.log, SECOND, { governanceId: SECOND_GOVERNANCE });
  w.network.publish(second);
  return second;
}

function run(
  runtime: VerificationRuntime,
  fields: Field[],
  options: { signal?: AbortSignal; budgetMs?: number; deadline?: number; observer?: VerificationObserver } = {},
): Promise<VerificationResult> {
  return verifyRequest(
    eligible(fields),
    {
      runtime,
      signal: options.signal ?? new AbortController().signal,
      deadline: options.deadline ?? performance.now() + (options.budgetMs ?? 2500),
    },
    options.observer,
  );
}

const replacer = (key: string, value: unknown) => (key === 'sdkResult' ? '[VerifiedDomain]' : value);

function assertDenied(result: unknown, reason: string, kind?: string): asserts result is LifecycleDenial {
  const denial = result as LifecycleDenial;
  assert.equal(denial.outcome, 'deny', `expected a denial, got ${JSON.stringify(result, replacer)}`);
  assert.equal(denial.status, 403);
  assert.equal(denial.reason, reason, JSON.stringify(result, replacer));
  if (kind !== undefined) assert.equal(denial.failure?.kind, kind, JSON.stringify(result, replacer));
}

function assertPassed(result: VerificationResult): asserts result is Extract<VerificationResult, { outcome: 'verification_passed' }> {
  assert.equal(result.outcome, 'verification_passed', JSON.stringify(result, replacer));
}

/** Another identity's valid ISSUANCE for `w.log`, held back: the log is re-signed without it, for a test to append. */
async function withheldIssuance(w: World, domain: string): Promise<Uint8Array> {
  await issueIdentity(w.log, domain, { governanceId: SECOND_GOVERNANCE });
  const entry = w.log.entries.pop();
  assert.ok(entry !== undefined);
  w.log.resign();
  return entry;
}

/**
 * Resolves once `condition` holds, polling each macrotask, bounded by time (4 s) rather than by a count of turns: under the
 * full suite's parallel load, 2,000 turns could pass in ~20 ms, before the awaited verification step had started.
 */
async function until(condition: () => boolean): Promise<void> {
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
const never = () => new Promise<never>(() => {});

/**
 * Observes one request's lifecycle stage: when it starts, the log reads it makes (with each read's signal and whether it
 * was live at the time), and what the SDK's verifyNonRevocation returned or threw. The SDK call itself runs unchanged.
 * `onStart` runs as the stage begins (after identity verification, before the non-revocation read); `onRead` runs
 * before each of the stage's log reads, and may delay it.
 */
function lifecycleProbe(
  w: World,
  hooks: {
    onStart?: () => void;
    onRead?: (url: string, signal: AbortSignal | undefined) => Promise<void>;
    observer?: VerificationObserver;
  } = {},
) {
  const probe = {
    started: 0,
    startedAt: undefined as number | undefined,
    scopeSignal: undefined as AbortSignal | undefined,
    reads: [] as { url: string; signal: AbortSignal | undefined; liveAtRead: boolean }[],
    calls: [] as Date[],
    evidence: undefined as LoggedStateEvidence | undefined,
    error: undefined as unknown,
    closed: 0,
  };
  w.log.gate = async (url, signal) => {
    if (probe.started === 0) return;
    probe.reads.push({ url, signal, liveAtRead: signal !== undefined && !signal.aborted });
    await hooks.onRead?.(url, signal);
  };
  const observer: VerificationObserver = {
    ...hooks.observer,
    lifecycleStarting(scope, verified: VerifiedDomain) {
      probe.started++;
      probe.startedAt = performance.now();
      probe.scopeSignal = scope.signal;
      const original = verified.verifyNonRevocation.bind(verified);
      // Observation only: the SDK's own method runs with the stage's argument and its result or error is passed on.
      Object.defineProperty(verified, 'verifyNonRevocation', {
        configurable: true,
        value: async (at?: Date) => {
          if (at !== undefined) probe.calls.push(at);
          try {
            probe.evidence = await original(at);
            return probe.evidence;
          } catch (error) {
            probe.error = error;
            throw error;
          }
        },
      });
      hooks.onStart?.();
    },
    scopeClosed(scope) {
      probe.closed++;
      hooks.observer?.scopeClosed?.(scope);
    },
  };
  return { probe, observer };
}

/** Date mocked at a whole second, so witness times (whole seconds) give exact evidence ages. Timers stay real. */
const T0 = 1_900_000_000_000;
function mockDate(t: TestContext, now = T0) {
  t.mock.timers.enable({ apis: ['Date'], now });
  return (ms: number) => t.mock.timers.setTime(ms);
}

// ---------- integrated: real SDK verification ----------

describe('lifecycle: fresh ACTIVE evidence', () => {
  test('passes, with the identity metadata and a bounded freshness summary from the SDK evidence', async () => {
    const w = await world();
    const { probe, observer } = lifecycleProbe(w);
    const before = Date.now();
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    const after = Date.now();
    assertPassed(result);
    assert.equal(probe.started, 1);
    assert.ok(probe.reads.length >= 2, 'the log was read again for non-revocation, after identity verification');
    const evidence = probe.evidence;
    assert.ok(evidence !== undefined);
    assert.equal(evidence.loggedState, 'ACTIVE');
    assert.equal(result.identity.domain, AGENT);
    assert.equal(result.identity.governanceId, FIXTURE_GOVERNANCE);
    assert.equal(result.identity.entityKeyThumbprint, result.signature.sdkResult.signingKeyThumbprint);
    assert.deepEqual(Object.keys(result.lifecycle).sort(), [
      'completeThrough',
      'completenessMode',
      'evidenceAgeMs',
      'freshnessTime',
      'historyEnd',
      'logReference',
      'loggedState',
    ]);
    assert.equal(result.lifecycle.loggedState, 'ACTIVE');
    assert.equal(result.lifecycle.logReference, w.identity.lr);
    assert.equal(result.lifecycle.historyEnd, `${w.identity.lr}@0`);
    assert.equal(result.lifecycle.completeThrough, '1');
    assert.equal(result.lifecycle.completenessMode, 'full-scan');
    // The freshness time is the evidence's verified witness time, not verifiedAt or the ISSUANCE time.
    assert.equal(result.lifecycle.freshnessTime, evidence.freshnessTime.toISOString());
    assert.notEqual(evidence.freshnessTime.getTime(), result.signature.sdkResult.verifiedAt.getTime());
    assert.ok(result.lifecycle.evidenceAgeMs >= 0 && result.lifecycle.evidenceAgeMs <= after - evidence.freshnessTime.getTime());
    // verifyNonRevocation was called once, at the time of the call (not the signature's created time).
    assert.equal(probe.calls.length, 1);
    const at = probe.calls[0]?.getTime() ?? Number.NaN;
    assert.ok(at >= before && at <= after, 'evaluated at the current time');
    assert.equal(Object.isFrozen(result.lifecycle), true);
    assert.equal(JSON.stringify(result.lifecycle).includes('checkpoint'), false, 'no checkpoint bytes in the summary');
  });

  test('runs the non-revocation check although the record does not request log checking (no fl=logchk)', async () => {
    const w = await world();
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertPassed(result);
    assert.equal(result.signature.sdkResult.requiresLogCheck(), false);
    assert.equal(probe.calls.length, 1);
    assert.ok(probe.reads.length > 0);
  });

  test('and when it does (fl=logchk)', async () => {
    const w = await world({ policyFlags: 'logchk' });
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertPassed(result);
    assert.equal(result.signature.sdkResult.requiresLogCheck(), true);
    assert.equal(probe.calls.length, 1);
  });

  test('passes through serialized ext_proc bytes too', async () => {
    const w = await world();
    const result = await checkSerializedRequestVerification(serialize(await signedAs(w.identity)), {
      runtime: w.runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    assert.equal(result.outcome, 'verification_passed');
  });

  test('the identity stage alone still returns its intermediate result', async () => {
    const w = await world();
    const result = await verifyRequestIdentity(eligible(await signedAs(w.identity)), {
      runtime: w.runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    assert.equal(result.outcome, 'identity_stage_passed');
  });
});

describe('lifecycle: revoked and retired identities', () => {
  test('a REVOKED status is refused by the identity stage; the lifecycle check never starts', async () => {
    const w = await world();
    w.network.publish(w.identity, 'REVOKED');
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'identity_inactive', 'inactive');
    assert.equal(probe.started, 0);
    assert.equal(probe.closed, 1);
  });

  test('a RETIRED status is refused by the identity stage', async () => {
    const w = await world();
    w.network.publish(w.identity, 'RETIRED');
    const { probe, observer } = lifecycleProbe(w);
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'identity_inactive', 'inactive');
    assert.equal(probe.started, 0);
  });

  test('ACTIVE status with a revocation already in the authenticated log: identity verification itself refuses it', async () => {
    const w = await world();
    w.log.append(await lifecycleEntry(w.identity, 'REVOCATION'));
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    // The SDK's key-continuity verification reads the same history, so this case never reaches the new check.
    assert.equal(result.outcome, 'deny');
    assert.equal((result as { reason: string }).reason, 'identity_invalid');
    assert.equal(probe.started, 0);
  });

  test('a revocation logged after identity verification, status still ACTIVE, is refused at the lifecycle check; another identity still passes', async () => {
    const w = await world();
    const second = await secondIdentity(w);
    const revocation = await lifecycleEntry(w.identity, 'REVOCATION');
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.append(revocation) });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_not_established', 'log_rejected');
    assert.equal(result.failure.code, VerificationCode.LogError);
    assert.equal(result.failure.transient, false);
    assert.equal(probe.started, 1, 'the identity, governance and status checks had all passed');
    assert.equal(probe.evidence, undefined, 'the SDK returned no proof boundary');
    assert.ok(probe.error !== undefined, 'the SDK refused it');
    assert.equal(JSON.stringify(result).includes('revoked'), false, 'no SDK message in the result');
    // The second identity, in the same log after the revocation, still passes on fresh evidence.
    const other = await run(w.runtime, await signedAs(second));
    assertPassed(other);
    assert.equal(other.lifecycle.completeThrough, '3');
    // And the revoked identity stays refused (now by identity verification, which reads the same log).
    assert.equal((await run(w.runtime, await signedAs(w.identity))).outcome, 'deny');
  });

  test('a retirement logged after identity verification is refused at the lifecycle check', async () => {
    const w = await world();
    const retirement = await lifecycleEntry(w.identity, 'RETIREMENT');
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.append(retirement) });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_not_established', 'log_rejected');
    assert.equal(probe.started, 1);
  });
});

describe('lifecycle: missing, tampered, incomplete and unavailable evidence fail closed', () => {
  /** `entry` with one character of its first signature value changed: same shape, signature no longer valid. */
  function withForgedSignature(entry: Uint8Array): Uint8Array {
    const text = new TextDecoder().decode(entry);
    const sig = /"sig":"([A-Za-z0-9_-]+)"/.exec(text)?.[1];
    assert.ok(sig !== undefined);
    const forged = `${sig.slice(0, 10)}${sig[10] === 'A' ? 'B' : 'A'}${sig.slice(11)}`;
    return new TextEncoder().encode(text.replace(sig, forged));
  }

  test('a logged entry tampered under its signed checkpoint is refused', async () => {
    const w = await world();
    const url = entryBundlePath(w.log.prefix, 0, 1);
    const bundle = await w.log.fetcher.fetchBounded(url, 1 << 20, { timeoutMs: 1000 });
    const tampered = new Uint8Array(bundle);
    const at = new TextDecoder().decode(bundle).indexOf('"sig":"') + 12;
    tampered[at] = tampered[at] === 0x41 ? 0x42 : 0x41;
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.override(url, { status: 200, body: tampered }) });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_evidence_invalid', 'evidence_invalid');
    assert.equal(probe.started, 1);
    assert.equal(probe.evidence, undefined);
  });

  test('a REVOCATION with a forged signature is not authenticated evidence: the SDK skips it and the identity stays ACTIVE', async () => {
    // Anyone can append to a log. An entry the identity's entity key did not sign proves nothing, so it neither revokes
    // the identity nor counts as its history; the checkpoint still covers it.
    const w = await world();
    const forged = withForgedSignature(await lifecycleEntry(w.identity, 'REVOCATION'));
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.append(forged) });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertPassed(result);
    assert.equal(result.lifecycle.completeThrough, '2');
    assert.equal(result.lifecycle.historyEnd, `${w.identity.lr}@0`, 'the history still ends at the ISSUANCE');
    assert.equal(probe.evidence?.loggedState, 'ACTIVE');
  });

  test('a tampered checkpoint signature is refused', async () => {
    const w = await world();
    const url = checkpointPath(w.log.prefix);
    const text = new TextDecoder().decode(await w.log.fetcher.fetchBounded(url, 1 << 16, { timeoutMs: 1000 }));
    const lines = text.split('\n');
    const logLine = lines.findIndex((line) => line.startsWith(`— ${w.log.origin} `));
    const [dash, name, signature] = lines[logLine]!.split(' ');
    const bytes = Buffer.from(signature!, 'base64');
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
    lines[logLine] = `${dash} ${name} ${bytes.toString('base64')}`;
    const tampered = new TextEncoder().encode(lines.join('\n'));
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.override(url, { status: 200, body: tampered }) });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_evidence_invalid', 'evidence_invalid');
    assert.equal(probe.started, 1);
    assert.equal(probe.evidence, undefined);
  });

  test('missing evidence (the checkpoint is gone) is refused', async () => {
    const w = await world();
    const { probe, observer } = lifecycleProbe(w, {
      onStart: () => w.log.override(checkpointPath(w.log.prefix), { status: 404 }),
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_not_established', 'log_rejected');
    assert.equal(probe.evidence, undefined);
  });

  test('incomplete history (a checkpoint over entries the log does not serve) is refused', async () => {
    const w = await world();
    const entry = await withheldIssuance(w, SECOND);
    const { probe, observer } = lifecycleProbe(w, {
      onStart: () => {
        w.log.append(entry);
        w.log.override(entryBundlePath(w.log.prefix, 0, 2), { status: 404 });
      },
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_not_established', 'log_rejected');
    assert.equal(probe.evidence, undefined);
  });

  test('an unavailable log (503) is refused as unavailable, told apart from a refusal', async () => {
    const w = await world();
    const { observer } = lifecycleProbe(w, {
      onStart: () => w.log.override(checkpointPath(w.log.prefix), { status: 503 }),
    });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_unavailable', 'log_unavailable');
    assert.equal(result.failure.transient, true);
  });

  test('a network failure on the entry bundle is refused as unavailable', async () => {
    const w = await world();
    const { observer } = lifecycleProbe(w, {
      onStart: () => w.log.override(entryBundlePath(w.log.prefix, 0, 1), { status: 0 }),
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_unavailable', 'log_unavailable');
  });

  test('the SDK’s genuine evidence passes the standalone proof-boundary check, and is refused for another log reference', async () => {
    const w = await world();
    const { probe, observer } = lifecycleProbe(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity), { observer }));
    const real = probe.evidence;
    assert.ok(real !== undefined);
    assert.equal(checkLoggedStateEvidence(real, w.identity.lr, Date.now()).ok, true);
    assert.deepEqual(checkLoggedStateEvidence(real, `${w.identity.lr}x`, Date.now()), { ok: false, kind: 'evidence_invalid' });
  });
});

describe('lifecycle: evidence freshness at the decision (Date mocked; timers real)', () => {
  // Every identity here is issued at T0 - 60 s; the log is then re-signed with a witness time W after that, and the
  // request is made at W + age. The SDK's own limit for non-revocation evidence is 600 s with zero future skew.
  async function freshnessWorld(t: TestContext, witnessAt: number) {
    const setTime = mockDate(t, T0);
    const w = await world();
    setTime(witnessAt);
    w.log.resign({ witnessAgeSeconds: 0 });
    return { w, setTime };
  }

  test('evidence exactly 300,000 ms old passes', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + MAX_EVIDENCE_AGE_MS);
    const result = await run(w.runtime, await signedAs(w.identity));
    assertPassed(result);
    assert.equal(result.lifecycle.evidenceAgeMs, 300_000);
    assert.equal(result.lifecycle.freshnessTime, new Date(W).toISOString());
  });

  test('evidence 300,001 ms old is refused as stale', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + MAX_EVIDENCE_AGE_MS + 1);
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_evidence_stale', 'evidence_stale');
    assert.ok(probe.evidence !== undefined, 'the SDK accepted it (within its own 600 s limit)');
    assert.equal(probe.evidence.freshnessTime.getTime(), W);
  });

  test('evidence 400 s old: the SDK accepts it under its 600 s limit, the stage refuses it as stale', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + 400_000);
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_evidence_stale', 'evidence_stale');
    assert.equal(probe.evidence?.loggedState, 'ACTIVE');
    assert.ok(400_000 < MANAGED_CHECKPOINT_MAX_AGE_MS);
  });

  test('evidence beyond the SDK limit (700 s) is refused by the SDK itself', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + 700_000);
    const { probe, observer } = lifecycleProbe(w);
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_not_established', 'log_rejected');
    assert.equal(probe.evidence, undefined);
  });

  test('evidence that becomes stale during verification is refused: age is judged at the decision', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + 299_000);
    let advanced = false;
    const { probe, observer } = lifecycleProbe(w, {
      onRead: async () => {
        if (!advanced) {
          advanced = true;
          setTime(W + 301_000); // two seconds pass while the log is read
        }
      },
    });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_evidence_stale', 'evidence_stale');
    assert.equal(probe.evidence?.freshnessTime.getTime(), W, 'fresh (299 s) when the check started');
  });

  test('a future witness time within the stage’s 5 s allowance is still refused by the SDK’s zero-skew policy', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + 10_000);
    // Re-signed during the check with a witness time 3 s ahead of the decision clock.
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.resign({ witnessAgeSeconds: -3 }) });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_evidence_invalid', 'evidence_invalid');
    assert.equal(probe.evidence, undefined, 'the SDK returned no evidence: it was not accepted by managed-policy verification');
  });

  test('identity evidence expiring at the decision is refused even when the log evidence is fresh', async (t) => {
    const W = T0 + 100_000;
    const { w, setTime } = await freshnessWorld(t, W);
    setTime(W + 1_000);
    // The log is re-witnessed while it is read, so its evidence is fresh, but the DNS TTL has run out by then.
    const { observer } = lifecycleProbe(w, {
      onRead: async () => {
        setTime(W + 1_000 + 300_000);
        w.log.resign({ witnessAgeSeconds: 0 });
      },
    });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'identity_evidence_expired', 'identity_evidence_expired');
    assert.equal(result.failure.code, VerificationCode.DNSResolution);
  });
});

describe('lifecycle: one budget, one scope', () => {
  test('identity verification uses part of the budget; a slow log gets only the remainder', { timeout: 5_000 }, async () => {
    const w = await world();
    w.network.gate = (what) => (what === w.identity.statusUrl ? sleep(400) : Promise.resolve());
    const { probe, observer } = lifecycleProbe(w, { onRead: () => never() });
    const started = performance.now();
    const result = await run(w.runtime, await signedAs(w.identity), { budgetMs: 1000, observer });
    const ended = performance.now();
    assertDenied(result, 'verification_budget_exhausted');
    assert.ok(probe.startedAt !== undefined && probe.startedAt - started >= 390, 'the lifecycle check started after the slow status');
    assert.ok(ended - started >= 990 && ended - started < 1300, `ended at ${ended - started} ms, the original 1000 ms deadline`);
    assert.ok(ended - (probe.startedAt ?? 0) < 650, 'the lifecycle check got only the remaining budget');
  });

  test('cancellation during the non-revocation check denies at once', async () => {
    const w = await world();
    const controller = new AbortController();
    const { probe, observer } = lifecycleProbe(w, {
      onRead: (_url, signal) =>
        new Promise<void>((resolve, reject) => {
          signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
          setTimeout(resolve, 5_000).unref();
        }),
    });
    const pending = run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    await until(() => probe.reads.length > 0);
    const stopped = performance.now();
    controller.abort();
    assertDenied(await pending, 'verification_cancelled');
    assert.ok(performance.now() - stopped < 100);
    assert.equal(probe.reads[0]?.signal?.aborted, true, 'the log read saw the cancellation');
  });

  test('a log read that ignores cancellation is cut off when the request is cancelled', { timeout: 5_000 }, async () => {
    const w = await world();
    const controller = new AbortController();
    const { probe, observer } = lifecycleProbe(w, { onRead: () => never() });
    const pending = run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    await until(() => probe.reads.length > 0);
    const stopped = performance.now();
    controller.abort();
    assertDenied(await pending, 'verification_cancelled');
    assert.ok(performance.now() - stopped < 100);
  });

  test('a log read that ignores cancellation is cut off at the original deadline, and its late answer changes nothing', async () => {
    const w = await world();
    const { observer } = lifecycleProbe(w, { onRead: () => sleep(400) });
    const started = performance.now();
    assertDenied(await run(w.runtime, await signedAs(w.identity), { budgetMs: 250, observer }), 'verification_budget_exhausted');
    assert.ok(performance.now() - started < 380);
    await sleep(450);
  });

  /** Replaces the call with one that ignores every signal: it settles (with the SDK's real answer) only after `delayMs`. */
  function deafLifecycle(delayMs: number | undefined): VerificationObserver {
    return {
      lifecycleStarting(_scope, verified) {
        const original = verified.verifyNonRevocation.bind(verified);
        Object.defineProperty(verified, 'verifyNonRevocation', {
          configurable: true,
          value: async (at?: Date) => {
            const evidence = await original(at);
            if (delayMs === undefined) return never();
            await sleep(delayMs);
            return evidence;
          },
        });
      },
    };
  }

  test('a non-revocation call that ignores cancellation altogether is cut off when the request is cancelled', { timeout: 5_000 }, async () => {
    const w = await world();
    const controller = new AbortController();
    let started = false;
    const deaf = deafLifecycle(undefined);
    const observer: VerificationObserver = {
      lifecycleStarting(scope, verified) {
        deaf.lifecycleStarting?.(scope, verified);
        started = true;
      },
    };
    const pending = run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    await until(() => started);
    await sleep(50);
    const stopped = performance.now();
    controller.abort();
    assertDenied(await pending, 'verification_cancelled');
    assert.ok(performance.now() - stopped < 100);
  });

  test('a non-revocation call that ignores the deadline is cut off at it; its late ACTIVE answer is not a success', { timeout: 5_000 }, async () => {
    const w = await world();
    const started = performance.now();
    const result = await run(w.runtime, await signedAs(w.identity), { budgetMs: 300, observer: deafLifecycle(600) });
    const elapsed = performance.now() - started;
    assertDenied(result, 'verification_budget_exhausted');
    assert.ok(elapsed >= 290 && elapsed < 450, `elapsed ${elapsed}`);
    await sleep(650); // the late answer arrives; nothing changes
  });

  test('concurrent cold requests for one identity: cancelling one during its lifecycle check leaves the other intact', async () => {
    const w = await world();
    const hold = gate();
    const first = new AbortController();
    const second = new AbortController();
    const scopes: AbortSignal[] = [];
    const reads: AbortSignal[] = [];
    w.log.gate = async (_url, signal) => {
      if (scopes.length === 0) return;
      if (signal !== undefined && !reads.includes(signal)) reads.push(signal);
      await hold.wait;
    };
    const observer: VerificationObserver = { lifecycleStarting: (scope) => scopes.push(scope.signal) };
    const a = run(w.runtime, await signedAs(w.identity), { signal: first.signal, observer });
    const b = run(w.runtime, await signedAs(w.identity), { signal: second.signal, observer });
    await until(() => scopes.length === 2 && reads.length >= 2);
    first.abort();
    assertDenied(await a, 'verification_cancelled');
    assert.equal(scopes.filter((signal) => signal.aborted).length, 1, 'only the cancelled request’s scope ended');
    hold.open();
    assertPassed(await b);
  });

  test('concurrent cold requests with different deadlines: the short one runs out during its lifecycle check, the long one passes', async () => {
    const w = await world();
    let lifecycles = 0;
    w.log.gate = async () => {
      if (lifecycles > 0) await sleep(250);
    };
    const observer: VerificationObserver = { lifecycleStarting: () => lifecycles++ };
    const [short, long] = await Promise.all([
      run(w.runtime, await signedAs(w.identity), { budgetMs: 400, observer }),
      run(w.runtime, await signedAs(w.identity), { budgetMs: 2500, observer }),
    ]);
    // Both identity stages read the log too (fast until the first lifecycle check starts); only the short one runs out.
    assertDenied(short, 'verification_budget_exhausted');
    assertPassed(long);
  });

  test('cancellation immediately before a lifecycle checkpoint commit writes nothing', async () => {
    const inner = new InMemoryTrustedC2spCheckpointStore();
    const controller = new AbortController();
    let lifecycle = false;
    let cancelledAtCommit = 0;
    const store: TrustedC2spCheckpointStore = {
      load: (origin, signal) => inner.load(origin, signal),
      compareAndSwap(origin, expected, candidate, signal) {
        if (lifecycle) {
          cancelledAtCommit++;
          controller.abort();
        }
        return inner.compareAndSwap(origin, expected, candidate, signal);
      },
    };
    const w = await world({ checkpointStore: store });
    // Another identity's ISSUANCE grows the log once identity verification is done, so the lifecycle read has a newer
    // checkpoint to commit.
    const entry = await withheldIssuance(w, SECOND);
    const observer: VerificationObserver = {
      lifecycleStarting: () => {
        lifecycle = true;
        w.log.append(entry);
      },
    };
    const result = await run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    assertDenied(result, 'verification_cancelled');
    assert.equal(cancelledAtCommit, 1);
    const stored: TrustedC2spCheckpoint | undefined = await inner.load(w.log.origin);
    assert.equal(stored?.treeSize, 1, 'the identity stage’s checkpoint stands; the lifecycle one was not written');
  });
});

describe('lifecycle: the final success boundary', () => {
  test('without interference the hook changes nothing', async () => {
    const w = await world();
    let built = 0;
    assertPassed(await run(w.runtime, await signedAs(w.identity), { observer: { buildingResult: () => built++ } }));
    assert.equal(built, 1);
  });

  test('cancellation while the success result is built denies', async () => {
    const w = await world();
    const controller = new AbortController();
    const result = await run(w.runtime, await signedAs(w.identity), {
      signal: controller.signal,
      observer: { buildingResult: () => controller.abort() },
    });
    assertDenied(result, 'verification_cancelled');
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  });

  test('the original deadline passing while the success result is built denies', async () => {
    const w = await world();
    const deadline = performance.now() + 1500;
    const result = await run(w.runtime, await signedAs(w.identity), {
      deadline,
      observer: {
        buildingResult: () => {
          while (performance.now() < deadline + 1) {}
        },
      },
    });
    assertDenied(result, 'verification_budget_exhausted');
  });
});

describe('lifecycle: the request scope lives until the decision and ends exactly once on every exit', () => {
  async function exit(
    path: 'success' | 'denial' | 'cancellation' | 'exception',
  ): Promise<{ probe: ReturnType<typeof lifecycleProbe>['probe']; listeners: number; timersBefore: number; timersAfter: number; threw: boolean }> {
    const w = await world();
    const controller = new AbortController();
    const revocation = await lifecycleEntry(w.identity, 'REVOCATION');
    const timers = () => process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    const { probe, observer } = lifecycleProbe(w, {
      onStart: () => {
        if (path === 'denial') w.log.append(revocation);
      },
      onRead: async () => {
        if (path === 'cancellation') controller.abort();
      },
      observer: {
        buildingResult: () => {
          if (path === 'exception') throw new Error('result construction failed');
        },
      },
    });
    const timersBefore = timers();
    let threw = false;
    try {
      await run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    } catch {
      threw = true;
    }
    return { probe, listeners: getEventListeners(controller.signal, 'abort').length, timersBefore, timersAfter: timers(), threw };
  }

  for (const path of ['success', 'denial', 'cancellation', 'exception'] as const) {
    test(`${path}: the reader's signal was live when the check started, and ended with the request`, async () => {
      const { probe, listeners, threw, timersBefore, timersAfter } = await exit(path);
      assert.equal(threw, path === 'exception');
      assert.equal(probe.started, 1);
      assert.ok(probe.reads.length > 0);
      assert.equal(probe.reads[0]?.liveAtRead, true, 'the first lifecycle read carried a live signal');
      for (const read of probe.reads) assert.equal(read.signal?.aborted, true, 'every lifecycle read signal ended with the request');
      assert.equal(probe.scopeSignal?.aborted, true);
      assert.equal(probe.closed, 1, 'disposed exactly once');
      assert.equal(listeners, 0);
      assert.ok(timersAfter <= timersBefore, `timers ${timersBefore} -> ${timersAfter}`);
    });
  }

  test('the SDK result from a disposed scope cannot be used for the check (why the stage runs inside the scope)', async () => {
    const w = await world();
    const result = await verifyRequestIdentity(eligible(await signedAs(w.identity)), {
      runtime: w.runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    assert.equal(result.outcome, 'identity_stage_passed');
    if (result.outcome !== 'identity_stage_passed') return;
    await assert.rejects(result.signature.sdkResult.verifyNonRevocation(new Date()), { code: VerificationCode.RecordInvalid, transient: true });
  });

  // The shared records-and-keys cache and its warm-path lifecycle cases: tests/unit/material-cache.test.ts.
});

// ---------- the standalone validator (validation-unit inputs, NOT verified by the SDK) ----------

describe('checkLoggedStateEvidence: validation-unit inputs (not SDK-verified evidence)', () => {
  const LR = 'c2sp-tlog:public:https://log-fixture.test#stream-unit';
  const ORIGIN = 'log-fixture.test';
  const NOW = T0;
  const checkpointText = (origin: string, size: number) =>
    `${origin}\n${size}\n${Buffer.alloc(32, 7).toString('base64')}\n\n— ${origin} ${Buffer.alloc(68, 1).toString('base64')}\n`;
  const base = (): LoggedStateEvidence => ({
    logReference: LR,
    loggedState: 'ACTIVE',
    historyStart: `${LR}@0`,
    historyEnd: `${LR}@1`,
    completeThrough: '2',
    completenessMode: 'full-scan',
    checkpoint: new TextEncoder().encode(checkpointText(ORIGIN, 2)),
    freshnessTime: new Date(NOW - 1_000),
  });
  const check = (evidence: unknown, now = NOW) => checkLoggedStateEvidence(evidence, LR, now);
  const invalid = { ok: false, kind: 'evidence_invalid' };

  test('a well-formed boundary passes, with its age', () => {
    assert.deepEqual(check(base()), { ok: true, freshnessMs: NOW - 1_000, ageMs: 1_000 });
  });

  test('age: exactly 300,000 ms passes; 300,001 ms is stale', () => {
    assert.equal(check({ ...base(), freshnessTime: new Date(NOW - 300_000) }).ok, true);
    assert.deepEqual(check({ ...base(), freshnessTime: new Date(NOW - 300_001) }), { ok: false, kind: 'evidence_stale' });
  });

  test('future: exactly 5,000 ms ahead passes the standalone check; 5,001 ms is future-dated', () => {
    assert.deepEqual(check({ ...base(), freshnessTime: new Date(NOW + MAX_EVIDENCE_FUTURE_MS) }), {
      ok: true,
      freshnessMs: NOW + 5_000,
      ageMs: -5_000,
    });
    assert.deepEqual(check({ ...base(), freshnessTime: new Date(NOW + 5_001) }), { ok: false, kind: 'evidence_future' });
  });

  test('invalid dates and non-dates are invalid', () => {
    assert.deepEqual(check({ ...base(), freshnessTime: new Date(Number.NaN) }), invalid);
    assert.deepEqual(check({ ...base(), freshnessTime: new Date(NOW).toISOString() }), invalid);
    assert.deepEqual(check({ ...base(), freshnessTime: NOW }), invalid);
    assert.deepEqual(check(base(), Number.NaN), invalid);
  });

  for (const field of ['loggedState', 'logReference', 'historyStart', 'historyEnd', 'completeThrough', 'completenessMode', 'checkpoint', 'freshnessTime'] as const) {
    test(`missing ${field} is invalid`, () => {
      const evidence: Partial<LoggedStateEvidence> = base();
      delete evidence[field];
      assert.deepEqual(check(evidence), invalid);
    });
  }

  test('a logged state other than ACTIVE is inactive, told apart from malformed evidence', () => {
    for (const state of ['REVOKED', 'RETIRED', 'PENDING', 'PROVISIONING', 'VERIFYING']) {
      assert.deepEqual(check({ ...base(), loggedState: state }), { ok: false, kind: 'inactive', loggedState: state });
    }
    for (const state of ['active', 'UNKNOWN', '', undefined, 1]) {
      assert.deepEqual(check({ ...base(), loggedState: state }), invalid, String(state));
    }
  });

  test('not an object is invalid', () => {
    for (const value of [undefined, null, 'ACTIVE', 1]) assert.deepEqual(check(value), invalid);
  });

  test('a boundary for another log reference is invalid', () => {
    assert.deepEqual(check({ ...base(), logReference: `${LR}-other` }), invalid);
    assert.deepEqual(checkLoggedStateEvidence(base(), `${LR}-other`, NOW), invalid);
  });

  test('historyEnd must be an entry of that log within the complete prefix', () => {
    assert.deepEqual(check({ ...base(), historyEnd: `${LR}-other@1` }), invalid);
    assert.deepEqual(check({ ...base(), historyEnd: `${LR}@2` }), invalid);
    assert.deepEqual(check({ ...base(), historyEnd: `${LR}@01` }), invalid);
    assert.deepEqual(check({ ...base(), historyEnd: LR }), invalid);
  });

  test('historyStart must be a bound entry reference, not after historyEnd in the same log', () => {
    assert.deepEqual(check({ ...base(), historyStart: `${LR}@1` }).ok, true);
    assert.deepEqual(check({ ...base(), historyStart: `${LR}@2` }), invalid);
    assert.deepEqual(check({ ...base(), historyStart: 'not a reference' }), invalid);
    assert.deepEqual(check({ ...base(), historyStart: 'c2sp-tlog:public:https://old-fixture.test#earlier' }), invalid);
    assert.equal(check({ ...base(), historyStart: 'c2sp-tlog:public:https://old-fixture.test#earlier@4' }).ok, true);
  });

  test('completeThrough must be a canonical positive decimal', () => {
    for (const value of ['0', '01', '-1', '2.0', ' 2', '']) {
      assert.deepEqual(check({ ...base(), completeThrough: value }), invalid, value);
    }
  });

  test('completenessMode must be named', () => {
    assert.deepEqual(check({ ...base(), completenessMode: '' }), invalid);
  });

  test('the checkpoint must be that log’s, at the complete size', () => {
    assert.deepEqual(check({ ...base(), checkpoint: new Uint8Array() }), invalid);
    assert.deepEqual(check({ ...base(), checkpoint: new TextEncoder().encode(checkpointText('other-fixture.test', 2)) }), invalid);
    assert.deepEqual(check({ ...base(), checkpoint: new TextEncoder().encode(checkpointText(ORIGIN, 3)) }), invalid);
    assert.deepEqual(check({ ...base(), checkpoint: new Uint8Array([0xff, 0xfe]) }), invalid);
    assert.deepEqual(check({ ...base(), checkpoint: checkpointText(ORIGIN, 2) }), invalid);
  });

  test('the bounds are the documented ones', () => {
    assert.equal(MAX_EVIDENCE_AGE_MS, 300_000);
    assert.equal(MAX_EVIDENCE_FUTURE_MS, 5_000);
  });
});
