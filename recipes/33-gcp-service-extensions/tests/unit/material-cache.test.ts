// The shared identity-material cache (src/material-cache.ts), offline. Integrated cases run the real SDK identity
// verifier and the real SDK C2SP reader on the fixture identities and test log of tests/support/identity-fixture.ts: a
// cache hit only replaces a DNS answer or a key-document fetch, and everything after it (record signature, key sets,
// governance, key binding and continuity, the status document, non-revocation and freshness) is the SDK's and the
// stages' own verification, run again. The focused cases at the end call the cache and a request's view directly. These
// are not DNSid Local or managed-service identities, and nothing here is live.

import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { describe, test, type TestContext } from 'node:test';

import {
  createHttpSignaturesProfile,
  DNSSECState,
  IdentityManager,
  JWKS_MAX_RESPONSE_BYTES,
  STATUS_MAX_RESPONSE_BYTES,
  VerificationCode,
  VerificationError,
  type IdentityResolver,
  type JsonFetchOptions,
  type VerifiedDomain,
} from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import {
  checkpointPath,
  InMemoryTrustedC2spCheckpointStore,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';

import {
  createVerificationRuntime,
  governancePolicy,
  PRODUCTION_BACKEND,
  StrictLogRegistry,
  verifyRequestIdentity,
  type GovernanceEntry,
  type VerificationRuntime,
} from '../../src/identity.ts';
import { verifyRequest, type LifecycleDenial, type VerificationObserver, type VerificationResult } from '../../src/lifecycle.ts';
import { DEFAULT_MATERIAL_CACHE_LIMITS, SharedMaterialCache } from '../../src/material-cache.ts';
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
import { eligible, fieldsOf, replaced, type Field } from '../support/signing.ts';

const AGENT = 'agent-gov-fixture.test';
const SECOND = 'second-other-gov-fixture.test';
/** Another identity under the first one's governance: same `ek` URL. */
const PEER = 'peer-gov-fixture.test';
/** The second identity's governance: the fixture publishes one accountable-entity key set per governance ID. */
const SECOND_GOVERNANCE = 'other-gov-fixture.test';
const TARGET = 'https://api-example.test/accounts/123?view=summary';
const DNS_NAME = `_dnsid.${AGENT}`;

/** The exact options the SDK fetches each key document with (IdentityManager, @dnsid-ai/sdk 0.37.0). */
const EK_OPTIONS: JsonFetchOptions = { allowedHost: FIXTURE_GOVERNANCE, domainBoundary: true, maxResponseBytes: JWKS_MAX_RESPONSE_BYTES };
const KU_OPTIONS: JsonFetchOptions = { allowedHost: AGENT, maxResponseBytes: JWKS_MAX_RESPONSE_BYTES };

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
  cache: SharedMaterialCache;
  context: string;
}

const BOTH_GOVERNANCES: GovernanceEntry[] = [{ governanceId: FIXTURE_GOVERNANCE }, { governanceId: SECOND_GOVERNANCE }];

async function world(
  options: { checkpointStore?: TrustedC2spCheckpointStore; cache?: SharedMaterialCache; ttl?: number } = {},
): Promise<World> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const identity = await issueIdentity(log, AGENT);
  network.publish(identity);
  if (options.ttl !== undefined) setTtl(network, identity, options.ttl);
  const backend = fixtureBackend(network, log);
  const cache = options.cache ?? new SharedMaterialCache();
  const runtime = createVerificationRuntime({
    governance: governancePolicy(BOTH_GOVERNANCES),
    backend,
    sharedMaterial: cache,
    ...(options.checkpointStore === undefined ? {} : { checkpointStore: options.checkpointStore }),
  });
  return { log, network, identity, backend, runtime, cache, context: backend.transportContext };
}

function setTtl(network: FixtureNetwork, identity: FixtureIdentity, ttl: number): void {
  network.setDns(`_dnsid.${identity.domain}`, { records: [{ strings: [identity.txt], ttl }], state: DNSSECState.UNKNOWN });
}

async function secondIdentity(w: World): Promise<FixtureIdentity> {
  const second = await issueIdentity(w.log, SECOND, { governanceId: SECOND_GOVERNANCE });
  w.network.publish(second);
  return second;
}

function run(
  runtime: VerificationRuntime,
  fields: Field[],
  options: { signal?: AbortSignal; budgetMs?: number; observer?: VerificationObserver; revalidate?: boolean } = {},
): Promise<VerificationResult> {
  return verifyRequest(
    eligible(fields),
    {
      runtime,
      signal: options.signal ?? new AbortController().signal,
      deadline: performance.now() + (options.budgetMs ?? 2500),
      ...(options.revalidate === undefined ? {} : { revalidate: options.revalidate }),
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

/** The network requests made from now on. */
function requestsFrom(w: World): () => string[] {
  const start = w.network.requests.length;
  return () => w.network.requests.slice(start);
}

/** A successful request that fills the cache with the identity's TXT answer and both key documents. */
async function populate(w: World, identity: FixtureIdentity = w.identity): Promise<string> {
  const result = await run(w.runtime, await signedAs(identity));
  assertPassed(result);
  return result.identity.materialCache;
}

function kinds(cache: SharedMaterialCache): string[] {
  return cache.describe().map((entry) => `${entry.kind} ${entry.name}`).sort();
}

/** Observes the lifecycle stage: when it starts, the verified result it got, and its log reads (which may be delayed). */
function lifecycleProbe(
  w: World,
  hooks: { onStart?: () => void; onRead?: (url: string, signal: AbortSignal | undefined) => Promise<void> } = {},
) {
  const probe = { started: 0, verified: undefined as VerifiedDomain | undefined, reads: 0, nonRevocationCalls: 0 };
  w.log.gate = async (url, signal) => {
    if (probe.started === 0) return;
    probe.reads++;
    await hooks.onRead?.(url, signal);
  };
  const observer: VerificationObserver = {
    lifecycleStarting(_scope, verified) {
      probe.started++;
      probe.verified = verified;
      const original = verified.verifyNonRevocation.bind(verified);
      Object.defineProperty(verified, 'verifyNonRevocation', {
        configurable: true,
        value: (at?: Date) => {
          probe.nonRevocationCalls++;
          return original(at);
        },
      });
      hooks.onStart?.();
    },
  };
  return { probe, observer };
}

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
const never = () => new Promise<never>(() => {});

/** Date mocked at a whole second; timers and `performance.now()` stay real. */
const T0 = 1_900_000_000_000;
function mockDate(t: TestContext, now = T0) {
  t.mock.timers.enable({ apis: ['Date'], now });
  return (ms: number) => t.mock.timers.setTime(ms);
}

// ---------- the warm path: real SDK verification on every hit ----------

describe('material cache: a warm request reuses records and keys and verifies everything again', () => {
  test('the second request fetches no TXT answer and no key document; the status document and the lifecycle evidence are fetched and verified again', async () => {
    const w = await world();
    const cold = requestsFrom(w);
    assert.equal(await populate(w), 'miss', 'the cold request is recorded as a cache miss');
    assert.deepEqual(cold(), [DNS_NAME.replace(/^/, 'dns:'), w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl]);
    assert.deepEqual(kinds(w.cache), [
      `dns ${DNS_NAME}`,
      `operational_keys ${w.identity.kuUrl}`,
      `record_signing_keys ${w.identity.ekUrl}`,
    ]);
    for (const entry of w.cache.describe()) assert.ok(entry.remainingMs > 0 && entry.remainingMs <= 300_000, `${entry.name} ${entry.remainingMs}`);

    const warm = requestsFrom(w);
    const logReadsBefore = w.log.reads.length;
    const { probe, observer } = lifecycleProbe(w);
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertPassed(result);
    assert.deepEqual(warm(), [w.identity.statusUrl], 'only the status document went to the network');
    assert.equal(result.identity.materialCache, 'hit', 'the warm request is recorded as a cache hit');
    assert.ok(w.log.reads.length > logReadsBefore, 'the log was read again');
    assert.equal(probe.nonRevocationCalls, 1, 'non-revocation was verified again');
    assert.equal(result.lifecycle.loggedState, 'ACTIVE');
    assert.ok(probe.verified !== undefined && probe.verified.dnsTTL < 300, `the SDK got a reduced TTL: ${probe.verified?.dnsTTL}`);
    assert.ok(probe.verified.lastStatusCheckAt.getTime() >= result.signature.sdkResult.verifiedAt.getTime());
    const stats = w.cache.stats();
    assert.equal(stats.dnsHits, 1);
    assert.equal(stats.keyHits, 2);
    assert.equal(stats.admitted, 3, 'the warm request admitted nothing: hits are never re-admitted');
  });

  test('cache hits still enforce the trusted governance list and key pins', async () => {
    const w = await world();
    await populate(w);
    const second = await secondIdentity(w);
    const shared = { backend: w.backend, sharedMaterial: w.cache };
    const untrusting = createVerificationRuntime({ governance: governancePolicy([{ governanceId: SECOND_GOVERNANCE }]), ...shared });
    const pinned = createVerificationRuntime({
      governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE, entityKeyThumbprints: [second.entityThumbprint] }]),
      ...shared,
    });
    const requests = requestsFrom(w);
    assertDenied(await run(untrusting, await signedAs(w.identity)), 'governance_not_trusted', 'untrusted_governance');
    assertDenied(await run(pinned, await signedAs(w.identity)), 'governance_not_trusted', 'governance_pin_mismatch');
    assert.equal(requests().filter((url) => url.startsWith('dns:')).length, 0, 'both were cache hits');
    assert.equal(w.cache.stats().dnsHits, 2);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
  });

  test('cache hits still verify the request signature', async () => {
    const w = await world();
    await populate(w);
    const impostor = await LocalKeyProvider.generate('EdDSA');
    assertDenied(await run(w.runtime, await signedBy(impostor, AGENT)), 'signature_key_unknown');
    const fields = await signedAs(w.identity);
    assertDenied(await run(w.runtime, replaced(fields, ':path', '/accounts/999?view=summary')), 'signature_invalid');
    assert.equal(w.cache.stats().dnsHits, 2);
    assertPassed(await run(w.runtime, fields));
  });

  test('cache hits still enforce identity evidence expiry at the decision (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    await populate(w);
    // Ten seconds of the TXT answer's reuse are left; the SDK gets a TTL of at most 10 s, so its own expiry is earlier.
    setTime(T0 + 290_000);
    w.log.resign();
    const { probe, observer } = lifecycleProbe(w, {
      onStart: () => {
        setTime(T0 + 301_000);
        w.log.resign();
      },
    });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assert.ok(probe.verified !== undefined && probe.verified.dnsTTL <= 10, `TTL ${probe.verified?.dnsTTL}`);
    assert.equal(w.cache.stats().dnsHits, 1);
    assertDenied(result, 'identity_evidence_expired', 'identity_evidence_expired');
    assert.equal(result.failure.code, VerificationCode.DNSResolution);
  });

  test('cache hits still enforce lifecycle evidence freshness (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    // Witnessed after the ISSUANCE (T0 - 60 s), 199 s before the populating request: still fresh then.
    setTime(T0 + 200_000);
    w.log.resign({ witnessAgeSeconds: 199 });
    await populate(w);
    setTime(T0 + 350_000); // the witness time is now 349 s old: within the SDK's 600 s, beyond the stage's 300 s
    const result = await run(w.runtime, await signedAs(w.identity));
    assert.equal(w.cache.stats().dnsHits, 1);
    assertDenied(result, 'lifecycle_evidence_stale', 'evidence_stale');
  });
});

describe('material cache: after the cache is populated, lifecycle failures keep their fail-closed result and reason', () => {
  async function warmWorld() {
    const w = await world();
    const second = await secondIdentity(w);
    await populate(w);
    await populate(w, second);
    return { w, second };
  }

  async function assertSecondUnaffected(w: World, second: FixtureIdentity) {
    delete w.log.gate;
    const hitsBefore = w.cache.stats().dnsHits;
    assertPassed(await run(w.runtime, await signedAs(second)));
    assert.equal(w.cache.stats().dnsHits, hitsBefore + 1, 'the other identity was a cache hit too');
  }

  test('a REVOKED status document is refused; the status was fetched, not cached', async () => {
    const { w, second } = await warmWorld();
    w.network.publish(w.identity, 'REVOKED');
    const requests = requestsFrom(w);
    const hits = w.cache.stats().dnsHits;
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_inactive', 'inactive');
    assert.deepEqual(requests(), [w.identity.statusUrl], 'a warm request: only the status document was fetched');
    assert.equal(w.cache.stats().dnsHits, hits + 1);
    await assertSecondUnaffected(w, second);
  });

  test('a revocation newly logged and authenticated, status still ACTIVE, is refused at the lifecycle check (the generic log denial)', async () => {
    const { w, second } = await warmWorld();
    const revocation = await lifecycleEntry(w.identity, 'REVOCATION');
    const { probe, observer } = lifecycleProbe(w, { onStart: () => w.log.append(revocation) });
    const hits = w.cache.stats().dnsHits;
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assert.equal(w.cache.stats().dnsHits, hits + 1, 'a warm request');
    assertDenied(result, 'lifecycle_not_established', 'log_rejected');
    assert.equal(result.failure.transient, false);
    assert.equal(probe.started, 1);
    // The next request reads the revocation during identity verification, as on the cold path.
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_invalid');
    await assertSecondUnaffected(w, second);
  });

  test('stale log evidence is refused (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const { w, second } = await warmWorld();
    // Re-witnessed after the ISSUANCEs (T0 - 60 s), 199 s before a request that passes on it and refreshes the cache.
    setTime(T0 + 200_000);
    w.log.resign({ witnessAgeSeconds: 199 });
    assertPassed(await run(w.runtime, await signedAs(w.identity), { revalidate: true }));
    assertPassed(await run(w.runtime, await signedAs(second), { revalidate: true }));
    setTime(T0 + 350_000);
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'lifecycle_evidence_stale', 'evidence_stale');
    w.log.resign();
    await assertSecondUnaffected(w, second);
  });

  test('an unavailable log is refused as unavailable', async () => {
    const { w, second } = await warmWorld();
    const { observer } = lifecycleProbe(w, { onStart: () => w.log.override(checkpointPath(w.log.prefix), { status: 503 }) });
    const result = await run(w.runtime, await signedAs(w.identity), { observer });
    assertDenied(result, 'lifecycle_unavailable', 'log_unavailable');
    assert.equal(result.failure.transient, true);
    w.log.override(checkpointPath(w.log.prefix), undefined);
    await assertSecondUnaffected(w, second);
  });

  test('a stalled log is cut off at the request’s own original deadline', { timeout: 5_000 }, async () => {
    const { w, second } = await warmWorld();
    const { probe, observer } = lifecycleProbe(w, { onRead: () => never() });
    const started = performance.now();
    const result = await run(w.runtime, await signedAs(w.identity), { budgetMs: 600, observer });
    const elapsed = performance.now() - started;
    assertDenied(result, 'verification_budget_exhausted');
    assert.equal(probe.started, 1);
    assert.ok(elapsed >= 590 && elapsed < 900, `elapsed ${elapsed} ms`);
    await assertSecondUnaffected(w, second);
  });
});

// ---------- ADD-05: concurrency, cancellation and deadlines with a cache ----------

describe('material cache: concurrent requests stay independent', () => {
  for (const order of ['cold short, cached long', 'cached short, cold long'] as const) {
    test(`concurrent cold (revalidating) and cached requests for one identity with different deadlines: ${order}`, async () => {
      const w = await world();
      await populate(w);
      let lifecycles = 0;
      w.log.gate = async () => {
        if (lifecycles > 0) await sleep(250);
      };
      const observer: VerificationObserver = { lifecycleStarting: () => lifecycles++ };
      const coldIsShort = order === 'cold short, cached long';
      const requests = requestsFrom(w);
      const [short, long] = await Promise.all([
        run(w.runtime, await signedAs(w.identity), { budgetMs: 400, observer, revalidate: coldIsShort }),
        run(w.runtime, await signedAs(w.identity), { budgetMs: 2500, observer, revalidate: !coldIsShort }),
      ]);
      assertDenied(short, 'verification_budget_exhausted');
      assertPassed(long);
      assert.equal(requests().filter((url) => url === `dns:${DNS_NAME}`).length, 1, 'exactly one of them went to DNS');
      assert.equal(w.cache.stats().dnsHits, 1, 'and the other was a hit');
    });
  }

  test('cancelling one of two concurrent cached requests during its lifecycle check leaves the other intact', async () => {
    const w = await world();
    await populate(w);
    const hold = gate();
    const first = new AbortController();
    const scopes: AbortSignal[] = [];
    w.log.gate = async () => {
      if (scopes.length > 0) await hold.wait;
    };
    const observer: VerificationObserver = { lifecycleStarting: (scope) => scopes.push(scope.signal) };
    const a = run(w.runtime, await signedAs(w.identity), { signal: first.signal, observer });
    const b = run(w.runtime, await signedAs(w.identity), { observer });
    await until(() => scopes.length === 2);
    first.abort();
    assertDenied(await a, 'verification_cancelled');
    assert.equal(scopes.filter((signal) => signal.aborted).length, 1);
    hold.open();
    assertPassed(await b);
    assert.equal(w.cache.stats().dnsHits, 2);
  });

  test('cancelling the request that filled the cache, after it finished, breaks nothing for later requests', async () => {
    const w = await world();
    const filler = new AbortController();
    let fillerScope: AbortSignal | undefined;
    assertPassed(
      await run(w.runtime, await signedAs(w.identity), {
        signal: filler.signal,
        observer: { scopeOpened: (scope) => (fillerScope = scope.signal) },
      }),
    );
    filler.abort();
    assert.equal(fillerScope?.aborted, true, 'the filler’s scope (verifier, registry, reader) is gone');
    assert.equal(getEventListeners(filler.signal, 'abort').length, 0);
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [w.identity.statusUrl, w.identity.statusUrl]);
  });

  test('a cached request’s slow lifecycle read is stopped at its own original deadline; a concurrent one is not', { timeout: 5_000 }, async () => {
    const w = await world();
    await populate(w);
    let lifecycles = 0;
    w.log.gate = async () => {
      if (lifecycles > 0) await sleep(450);
    };
    const observer: VerificationObserver = { lifecycleStarting: () => lifecycles++ };
    const started = performance.now();
    const short = run(w.runtime, await signedAs(w.identity), { budgetMs: 300, observer }).then((result) => ({
      result,
      elapsed: performance.now() - started,
    }));
    const long = run(w.runtime, await signedAs(w.identity), { budgetMs: 4000, observer });
    const ended = await short;
    assertDenied(ended.result, 'verification_budget_exhausted');
    assert.ok(ended.elapsed < 450, `the short request ended at ${ended.elapsed} ms`);
    assertPassed(await long);
    assert.equal(w.cache.stats().dnsHits, 2);
  });

  test('cancellation immediately before a lifecycle checkpoint commit on a cached request writes nothing', async () => {
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
    await issueIdentity(w.log, SECOND, { governanceId: SECOND_GOVERNANCE });
    const entry = w.log.entries.pop();
    assert.ok(entry !== undefined);
    w.log.resign();
    await populate(w);
    const before = (await inner.load(w.log.origin))?.treeSize;
    const observer: VerificationObserver = {
      lifecycleStarting: () => {
        lifecycle = true;
        w.log.append(entry);
      },
    };
    const result = await run(w.runtime, await signedAs(w.identity), { signal: controller.signal, observer });
    assertDenied(result, 'verification_cancelled');
    assert.equal(w.cache.stats().dnsHits, 1, 'a cached request');
    assert.equal(cancelledAtCommit, 1);
    assert.equal((await inner.load(w.log.origin))?.treeSize, before, 'the newer checkpoint was not written');
  });

  test('a request cancelled before its fetches complete publishes no late fill', async () => {
    const w = await world();
    const hold = gate();
    const controller = new AbortController();
    w.network.gate = async (what) => {
      if (what === w.identity.kuUrl) await hold.wait;
    };
    const pending = run(w.runtime, await signedAs(w.identity), { signal: controller.signal });
    await until(() => w.network.requests.includes(w.identity.kuUrl));
    controller.abort();
    assertDenied(await pending, 'verification_cancelled');
    hold.open(); // the operational key document arrives after the request ended
    await sleep(20);
    assert.equal(w.cache.size, 0, 'nothing was admitted: not the TXT answer, not the record-signing keys, not the late fill');
    delete w.network.gate;
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl]);
    assert.equal(w.cache.size, 3);
  });

  test('an older concurrent fill never replaces a newer accepted entry', async () => {
    const w = await world();
    const hold = gate();
    let held = false;
    w.network.gate = async (what) => {
      if (what === w.identity.statusUrl && !held) {
        held = true;
        await hold.wait;
      }
    };
    // A fetches the TXT answer (TTL 300) and both key documents, then waits on its status document.
    const a = run(w.runtime, await signedAs(w.identity));
    await until(() => held && w.network.requests.includes(w.identity.kuUrl));
    // The TTL changes; B fetches everything afresh, passes and is admitted first.
    setTtl(w.network, w.identity, 120);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    const dnsEntry = () => w.cache.describe().find((entry) => entry.kind === 'dns');
    assert.ok((dnsEntry()?.remainingMs ?? 0) <= 120_000);
    hold.open();
    assertPassed(await a);
    assert.equal(w.cache.stats().supersededFills, 3, 'all three of A’s older fills were refused');
    assert.ok((dnsEntry()?.remainingMs ?? Infinity) <= 120_000, 'B’s newer TXT answer stands');
  });

  for (const held of ['TXT answer', 'operational key document'] as const) {
    test(`an old ${held}, read before newer material was admitted and delivered after it, is refused`, async () => {
      const w = await world();
      const what = held === 'TXT answer' ? `dns:${DNS_NAME}` : w.identity.kuUrl;
      const hold = gate();
      let captured = false;
      // The old material: TTL 300 and an operational key certificate ending in 60 s. The fixture reads A's answer, then
      // holds it before returning: the data in flight is already the old data.
      const oldNotAfter = new Date(Date.now() + 60_000);
      w.network.certificateNotAfter = (url) => (url === w.identity.kuUrl && !captured ? oldNotAfter : undefined);
      w.network.delivered = async (seen) => {
        if (seen === what && !captured) {
          captured = true;
          await hold.wait;
        }
      };
      const a = run(w.runtime, await signedAs(w.identity));
      await until(() => captured);
      // The newer material: TTL 120, a certificate valid for a day. B fetches it, passes and is admitted while A waits.
      setTtl(w.network, w.identity, 120);
      assertPassed(await run(w.runtime, await signedAs(w.identity)));
      const entry = (kind: string) => w.cache.describe().find((each) => each.kind === kind);
      assert.ok((entry('dns')?.remainingMs ?? Infinity) <= 120_000);
      assert.ok((entry('operational_keys')?.remainingMs ?? 0) > 60_000);
      hold.open();
      assertPassed(await a);
      // A's fetches started before B's: as many as A made before it was held (one, or all three) are refused.
      assert.equal(w.cache.stats().supersededFills, held === 'TXT answer' ? 1 : 3);
      assert.ok((entry('dns')?.remainingMs ?? Infinity) <= 120_000, 'B’s newer TXT answer stands');
      assert.ok((entry('operational_keys')?.remainingMs ?? 0) > 60_000, 'B’s newer operational key document stands');
    });
  }

  test('an old TXT answer delivered after the newer entry was evicted is still refused', async () => {
    const w = await world({ cache: new SharedMaterialCache({ ...DEFAULT_MATERIAL_CACHE_LIMITS, maxEntries: 3 }) });
    const second = await secondIdentity(w);
    const hold = gate();
    let captured = false;
    w.network.delivered = async (seen) => {
      if (seen === `dns:${DNS_NAME}` && !captured) {
        captured = true;
        await hold.wait;
      }
    };
    const a = run(w.runtime, await signedAs(w.identity));
    await until(() => captured);
    setTtl(w.network, w.identity, 120);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.equal(w.cache.describe().filter((each) => each.domain === AGENT).length, 3, 'B’s newer material is in');
    await populate(w, second);
    assert.equal(w.cache.describe().filter((each) => each.domain === AGENT).length, 0, 'and evicted by another identity');
    assert.equal(w.cache.stats().evicted, 3);
    assert.equal(w.cache.ordering().guards, 3, 'each evicted entry left its order behind');
    hold.open();
    assertPassed(await a);
    assert.equal(w.cache.stats().supersededFills, 1, 'A’s older TXT answer was refused with no entry left to compare');
    assert.ok(!w.cache.describe().some((each) => each.kind === 'dns' && each.name === DNS_NAME));
    // A's key documents were fetched after B's and are newer: admitted.
    assert.equal(w.cache.describe().filter((each) => each.domain === AGENT && each.kind !== 'dns').length, 2);
  });

  test('a fetch in flight when the cache is cleared is not admitted afterwards; a later one is', async () => {
    const w = await world();
    const hold = gate();
    let captured = false;
    w.network.delivered = async (seen) => {
      if (seen === `dns:${DNS_NAME}` && !captured) {
        captured = true;
        await hold.wait;
      }
    };
    const a = run(w.runtime, await signedAs(w.identity));
    await until(() => captured);
    w.cache.clear();
    hold.open();
    assertPassed(await a);
    assert.equal(w.cache.stats().supersededFills, 1, 'the TXT answer fetched before clear() was refused');
    assert.equal(w.cache.describe().filter((each) => each.kind === 'dns').length, 0);
    await populate(w);
    assert.equal(w.cache.describe().filter((each) => each.kind === 'dns').length, 1);
  });

  test('ordering guards stay within the entry limit; the floor that replaces dropped guards only refuses older fills', async () => {
    const w = await world({ cache: new SharedMaterialCache({ ...DEFAULT_MATERIAL_CACHE_LIMITS, maxEntries: 3 }) });
    const second = await secondIdentity(w);
    const peer = await issueIdentity(w.log, PEER, { entity: w.identity.entity });
    w.network.publish(peer);
    // Three identities, nine keys, room for three entries: guards for six removed keys would exceed the bound.
    for (let round = 0; round < 4; round++) {
      await populate(w);
      await populate(w, peer);
      await populate(w, second);
      assert.ok(w.cache.ordering().guards <= 3, `round ${round}: ${w.cache.ordering().guards} guards`);
    }
    assert.ok(w.cache.ordering().floor > 0, 'dropped guards raised the floor');
    assert.equal(w.cache.size, 3, 'fetches started after the floor are still admitted');
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(second)));
    assert.deepEqual(requests(), [second.statusUrl], 'and served');
    w.cache.clear();
    assert.deepEqual(w.cache.ordering().guards, 0);
    await populate(w);
    assert.equal(w.cache.size, 3, 'a fetch started after clear() is admitted');
  });
});

// ---------- expiry ----------

describe('material cache: expiry comes from the original evidence and is never extended', () => {
  test('TXT reuse: the TTL handed out decreases on every hit, and under one second left is a miss (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    await populate(w);
    const ttls: number[] = [];
    for (const at of [0, 10_000, 100_000, 298_000]) {
      setTime(T0 + at);
      const hit = w.cache.lookupDns(w.context, DNS_NAME);
      assert.ok(hit !== undefined, `hit at +${at}`);
      ttls.push(hit.records[0]!.ttl);
    }
    assert.ok(ttls[0]! < 300, `never the original TTL again: ${ttls[0]}`);
    assert.ok(ttls[1]! <= 290 && ttls[2]! <= 200 && ttls[3]! <= 2, ttls.join(','));
    for (let i = 1; i < ttls.length; i++) assert.ok(ttls[i]! < ttls[i - 1]!, ttls.join(','));
    setTime(T0 + 299_001);
    assert.equal(w.cache.lookupDns(w.context, DNS_NAME), undefined);
  });

  test('key reuse ends at the original evidence expiry, and a later request fetches again (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    await populate(w);
    setTime(T0 + 299_999);
    assert.ok(w.cache.lookupKey(w.context, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS) !== undefined);
    setTime(T0 + 300_000);
    assert.equal(w.cache.lookupKey(w.context, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS), undefined);
    assert.equal(w.cache.lookupKey(w.context, AGENT, 'operational_keys', w.identity.kuUrl, KU_OPTIONS), undefined);
    w.log.resign();
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl], 'renewed fetches');
    for (const entry of w.cache.describe()) assert.ok(entry.remainingMs > 299_000, 'fresh lifetimes from the new fetches');
  });

  test('moving the wall clock backwards does not lengthen reuse (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    await populate(w);
    setTime(T0 + 60_000);
    const before = Math.max(...w.cache.describe().map((entry) => entry.remainingMs));
    const ttlBefore = w.cache.lookupDns(w.context, DNS_NAME)?.records[0]?.ttl;
    setTime(T0 - 3_600_000);
    const after = Math.max(...w.cache.describe().map((entry) => entry.remainingMs));
    const ttlAfter = w.cache.lookupDns(w.context, DNS_NAME)?.records[0]?.ttl;
    assert.ok(before <= 240_000, `before ${before}`);
    assert.ok(after <= 300_000, `the monotonic clock still bounds it: ${after}`);
    assert.ok(ttlBefore !== undefined && ttlAfter !== undefined && ttlAfter < 300, `${ttlBefore} -> ${ttlAfter}`);
  });

  test('a zero-TTL TXT answer is never reused, and neither are key documents bound to it', async () => {
    const w = await world({ ttl: 0 });
    await populate(w);
    assert.equal(w.cache.size, 0);
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl]);
  });

  test('certificate expiry bounds key reuse; a hit carries the original certificate metadata (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    w.network.certificateNotAfter = (url) => (url === w.identity.ekUrl ? new Date(Date.now() + 60_000) : undefined);
    await populate(w);
    const byKind = Object.fromEntries(w.cache.describe().map((entry) => [entry.kind, entry.remainingMs]));
    assert.ok(byKind.record_signing_keys! <= 60_000, JSON.stringify(byKind));
    assert.ok(byKind.operational_keys! <= 60_000, 'bounded by the identity’s evidence expiry, which includes that certificate');
    assert.ok(byKind.dns! > 290_000);
    const hit = w.cache.lookupKey(w.context, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS);
    assert.equal(hit?.tlsCert.notAfter.getTime(), T0 + 60_000, 'the original notAfter, not a synthetic one');
    setTime(T0 + 60_000);
    w.log.resign();
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl], 'keys fetched again, TXT still a hit');
  });

  test('revalidation bypasses every cached document and refreshes the entries', async () => {
    const w = await world();
    await populate(w);
    const requests = requestsFrom(w);
    const before = w.cache.stats();
    assertPassed(await run(w.runtime, await signedAs(w.identity), { revalidate: true }));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl]);
    const after = w.cache.stats();
    assert.equal(after.dnsHits + after.keyHits, before.dnsHits + before.keyHits);
    assert.equal(after.admitted, before.admitted + 3);
    assert.equal(w.cache.size, 3);
  });

  test('a failed refresh never serves expired material (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world();
    await populate(w);
    setTime(T0 + 300_000);
    w.log.resign();
    w.network.setHttp(w.identity.ekUrl, {
      error: new VerificationError('fixture: unreachable', { code: VerificationCode.TLSError, transient: true }),
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity)), 'identity_unavailable', 'unavailable');
    assert.equal(w.cache.lookupKey(w.context, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS), undefined);
    assert.ok(!kinds(w.cache).some((entry) => entry.startsWith('record_signing_keys')));
  });

  test('a failed revalidation is not answered from live cached material either', async () => {
    const w = await world();
    await populate(w);
    w.network.setHttp(w.identity.ekUrl, {
      error: new VerificationError('fixture: unreachable', { code: VerificationCode.TLSError, transient: true }),
    });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { revalidate: true }), 'identity_unavailable', 'unavailable');
  });

  test('changing returned data changes nothing cached', async () => {
    const w = await world();
    await populate(w);
    const first = w.cache.lookupKey(w.context, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS);
    const original = JSON.stringify(first);
    const data = first?.data as { keys: Record<string, unknown>[] };
    data.keys[0]!.x = 'AAAA';
    data.keys.push({ kty: 'OKP' });
    first!.tlsCert.notAfter.setTime(0);
    first!.tlsCert.san.push('attacker.example');
    assert.equal(JSON.stringify(w.cache.lookupKey(w.context, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS)), original);
    const dns = w.cache.lookupDns(w.context, DNS_NAME);
    dns!.records[0]!.strings[0] = 'v=tampered';
    assert.notEqual(w.cache.lookupDns(w.context, DNS_NAME)?.records[0]?.strings[0], 'v=tampered');
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
  });

  test('eviction keeps the cache within its entry and byte limits, least recently used first', async () => {
    const byEntries = await world({ cache: new SharedMaterialCache({ ...DEFAULT_MATERIAL_CACHE_LIMITS, maxEntries: 4 }) });
    const second = await secondIdentity(byEntries);
    await populate(byEntries);
    await populate(byEntries, second);
    assert.equal(byEntries.cache.size, 4);
    assert.equal(byEntries.cache.stats().evicted, 2);
    assert.deepEqual(
      kinds(byEntries.cache).filter((entry) =>
        [DNS_NAME, byEntries.identity.ekUrl, byEntries.identity.kuUrl].some((name) => entry.endsWith(` ${name}`)),
      ),
      [`operational_keys ${byEntries.identity.kuUrl}`],
      'the first identity’s TXT answer and record-signing keys went first',
    );
    const requests = requestsFrom(byEntries);
    assertPassed(await run(byEntries.runtime, await signedAs(byEntries.identity)));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, byEntries.identity.ekUrl, byEntries.identity.statusUrl]);

    const sizes = byEntries.cache.describe().map((entry) => entry.bytes);
    const maxBytes = Math.max(...sizes) * 2;
    const byBytes = await world({ cache: new SharedMaterialCache({ ...DEFAULT_MATERIAL_CACHE_LIMITS, maxBytes }) });
    const other = await secondIdentity(byBytes);
    await populate(byBytes);
    await populate(byBytes, other);
    assert.ok(byBytes.cache.bytes <= maxBytes, `${byBytes.cache.bytes} <= ${maxBytes}`);
    assert.ok(byBytes.cache.stats().evicted > 0);
  });

  test('limits must be positive integers', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => new SharedMaterialCache({ ...DEFAULT_MATERIAL_CACHE_LIMITS, maxEntries: bad }), RangeError);
      assert.throws(() => new SharedMaterialCache({ ...DEFAULT_MATERIAL_CACHE_LIMITS, keyReuseCapMs: bad }), RangeError);
    }
    assert.deepEqual(DEFAULT_MATERIAL_CACHE_LIMITS, { maxEntries: 256, maxBytes: 4_194_304, dnsReuseCapMs: 300_000, keyReuseCapMs: 300_000 });
  });

  test('the cache adds no timer or listener to a request', async () => {
    const w = await world();
    await populate(w);
    const timers = () => process.getActiveResourcesInfo().filter((kind) => kind === 'Timeout').length;
    const before = timers();
    const controller = new AbortController();
    assertPassed(await run(w.runtime, await signedAs(w.identity), { signal: controller.signal }));
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.ok(timers() <= before, `${before} -> ${timers()}`);
  });
});

// ---------- admission and isolation ----------

describe('material cache: what is admitted, and where it may be reused', () => {
  test('status documents are never cached: three warm requests fetch the status three times', async () => {
    const w = await world();
    await populate(w);
    const requests = requestsFrom(w);
    for (let i = 0; i < 3; i++) assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [w.identity.statusUrl, w.identity.statusUrl, w.identity.statusUrl]);
    assert.ok(!w.cache.describe().some((entry) => entry.name === w.identity.statusUrl));
  });

  test('only a request whose whole verification passed admits anything', async () => {
    const w = await world();
    // The identity stage alone passing is not enough.
    const identityOnly = await verifyRequestIdentity(eligible(await signedAs(w.identity)), {
      runtime: w.runtime,
      signal: new AbortController().signal,
      deadline: performance.now() + 2500,
    });
    assert.equal(identityOnly.outcome, 'identity_stage_passed');
    assert.equal(w.cache.size, 0);
    // Nor a lifecycle denial after it.
    const { observer } = lifecycleProbe(w, { onStart: () => w.log.override(checkpointPath(w.log.prefix), { status: 503 }) });
    assertDenied(await run(w.runtime, await signedAs(w.identity), { observer }), 'lifecycle_unavailable');
    w.log.override(checkpointPath(w.log.prefix), undefined);
    assert.equal(w.cache.size, 0);
    // Nor a governance refusal.
    const untrusting = createVerificationRuntime({
      governance: governancePolicy([{ governanceId: SECOND_GOVERNANCE }]),
      backend: w.backend,
      sharedMaterial: w.cache,
    });
    assertDenied(await run(untrusting, await signedAs(w.identity)), 'governance_not_trusted');
    assert.equal(w.cache.size, 0);
    // Nor a success whose deadline passed at the final boundary.
    const deadline = performance.now() + 1500;
    const late = await verifyRequest(
      eligible(await signedAs(w.identity)),
      { runtime: w.runtime, signal: new AbortController().signal, deadline },
      {
        buildingResult: () => {
          while (performance.now() < deadline + 1) {}
        },
      },
    );
    assertDenied(late, 'verification_budget_exhausted');
    assert.equal(w.cache.size, 0);
    await populate(w);
    assert.equal(w.cache.size, 3);
  });

  test('another transport context never reuses the material: a second test backend, and production', async () => {
    const w = await world();
    await populate(w);
    const otherBackend = fixtureBackend(w.network, w.log);
    assert.notEqual(otherBackend.transportContext, w.context);
    assert.notEqual(PRODUCTION_BACKEND.transportContext, w.context);
    const other = createVerificationRuntime({ governance: governancePolicy(BOTH_GOVERNANCES), backend: otherBackend, sharedMaterial: w.cache });
    const requests = requestsFrom(w);
    assertPassed(await run(other, await signedAs(w.identity)));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl]);
    assert.equal(w.cache.lookupDns(PRODUCTION_BACKEND.transportContext, DNS_NAME), undefined);
    assert.equal(w.cache.lookupKey(PRODUCTION_BACKEND.transportContext, AGENT, 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS), undefined);
  });

  test('two identities under one governance share an ek URL but not an entry: each keeps its own evidence expiry (Date mocked)', async (t) => {
    const setTime = mockDate(t);
    const w = await world({ ttl: 30 });
    // The SDK takes exactly one current key from an `ek` document, so identities sharing one share its key.
    const peer = await issueIdentity(w.log, PEER, { entity: w.identity.entity });
    w.network.publish(peer);
    assert.equal(peer.ekUrl, w.identity.ekUrl, 'one record-signing key document URL for the governance');
    await populate(w);
    const peerCold = requestsFrom(w);
    await populate(w, peer);
    assert.deepEqual(peerCold(), [`dns:_dnsid.${PEER}`, peer.ekUrl, peer.kuUrl, peer.statusUrl], 'the peer fetched the ek URL itself');
    const signing = w.cache.describe().filter((each) => each.kind === 'record_signing_keys');
    assert.deepEqual(signing.map((each) => `${each.domain} ${each.name}`).sort(), [`${AGENT} ${w.identity.ekUrl}`, `${PEER} ${peer.ekUrl}`]);
    const remaining = Object.fromEntries(signing.map((each) => [each.domain, each.remainingMs]));
    assert.ok(remaining[AGENT]! <= 30_000, `the agent’s ends with its 30 s TXT answer: ${remaining[AGENT]}`);
    assert.ok(remaining[PEER]! > 30_000, `the peer’s does not: ${remaining[PEER]}`);
    assert.equal(w.cache.lookupKey(w.context, 'unrelated-gov-fixture.test', 'record_signing_keys', w.identity.ekUrl, EK_OPTIONS), undefined);

    setTime(T0 + 31_000);
    const requests = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(w.identity)));
    assert.deepEqual(requests(), [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl], 'the agent fetches again');
    const peerWarm = requestsFrom(w);
    assertPassed(await run(w.runtime, await signedAs(peer)));
    assert.deepEqual(peerWarm(), [peer.statusUrl], 'the peer’s own entries are still live');
  });

  test('a cached key document serves only a fetch with the same role, URL, host restriction, boundary and size bound', async () => {
    const w = await world();
    await populate(w);
    const lookup = (role: 'record_signing_keys' | 'operational_keys', url: string, options: JsonFetchOptions) =>
      w.cache.lookupKey(w.context, AGENT, role, url, options);
    assert.ok(lookup('record_signing_keys', w.identity.ekUrl, EK_OPTIONS) !== undefined);
    assert.equal(lookup('record_signing_keys', w.identity.ekUrl, { ...EK_OPTIONS, maxResponseBytes: JWKS_MAX_RESPONSE_BYTES * 2 }), undefined);
    assert.equal(lookup('record_signing_keys', w.identity.ekUrl, { ...EK_OPTIONS, domainBoundary: false }), undefined);
    assert.equal(lookup('record_signing_keys', w.identity.ekUrl, { ...EK_OPTIONS, allowedHost: 'other.example' }), undefined);
    assert.equal(lookup('operational_keys', w.identity.ekUrl, EK_OPTIONS), undefined);
    assert.ok(lookup('operational_keys', w.identity.kuUrl, KU_OPTIONS) !== undefined);
    assert.equal(lookup('operational_keys', w.identity.kuUrl, { ...KU_OPTIONS, domainBoundary: true }), undefined);
  });

  test('production construction routes the SDK’s DNS and HTTPS through the request’s cache wrapper (no network)', async () => {
    const seen: { dns: string[]; wrapped: number; base?: unknown } = { dns: [], wrapped: 0 };
    const verifier = await PRODUCTION_BACKEND.createIdentityVerifier(
      { verification: { trustedEntities: [{ governanceId: FIXTURE_GOVERNANCE }], statusCheckInterval: 0 } },
      {
        logRegistry: new StrictLogRegistry(),
        cache: { get: () => null, put: () => {}, evict: () => {} },
        transport: (base) => {
          seen.wrapped++;
          seen.base = base;
          return {
            dnsResolver: {
              fetchTXT: async (name) => {
                seen.dns.push(name);
                return [[], DNSSECState.UNKNOWN];
              },
            },
            fetchJson: () => Promise.reject(new Error('no HTTPS in this test')),
          };
        },
      },
    );
    assert.equal(seen.wrapped, 1);
    const base = seen.base as { dnsResolver?: { fetchTXT?: unknown }; fetchJson?: unknown };
    assert.equal(typeof base.dnsResolver?.fetchTXT, 'function');
    assert.equal(typeof base.fetchJson, 'function');
    assert.deepEqual(verifier.config.transport, {});
    await assert.rejects(verifier.verifyDomain('agent-example.com'), { code: VerificationCode.RecordNotFound });
    assert.deepEqual(seen.dns, ['_dnsid.agent-example.com'], 'the verifier used the wrapped resolver');
  });

  test('the no-cache control: a runtime without the cache fetches everything on every request', async () => {
    const w = await world();
    const uncached = createVerificationRuntime({ governance: governancePolicy(BOTH_GOVERNANCES), backend: w.backend, sharedMaterial: false });
    assert.equal(uncached.sharedMaterial, undefined);
    const requests = requestsFrom(w);
    assertPassed(await run(uncached, await signedAs(w.identity)));
    assertPassed(await run(uncached, await signedAs(w.identity)));
    const cold = [`dns:${DNS_NAME}`, w.identity.ekUrl, w.identity.kuUrl, w.identity.statusUrl];
    assert.deepEqual(requests(), [...cold, ...cold]);
  });
});

describe('material cache: a request’s view identifies key documents positively', () => {
  async function viewWorld(txtFor?: (identity: FixtureIdentity) => Promise<string>) {
    const log = fixtureLog();
    const identity = await issueIdentity(log, AGENT);
    const txt = txtFor === undefined ? identity.txt : await txtFor(identity);
    const cache = new SharedMaterialCache();
    const calls: string[] = [];
    const view = cache.view('unit', { signal: new AbortController().signal });
    const transport = view.wrap({
      dnsResolver: { fetchTXT: async () => [[{ strings: [txt], ttl: 300 }], DNSSECState.UNKNOWN] },
      fetchJson: async (url) => {
        calls.push(url);
        return { data: { keys: [identity.entityKey] }, tlsCert: { notAfter: new Date(Date.now() + 86_400_000), san: [] } };
      },
    });
    return { identity, cache, calls, transport };
  }

  test('a key-document URL alone is not identification: before this request resolved the record, nothing is looked up', async () => {
    const { identity, cache, calls, transport } = await viewWorld();
    await transport.fetchJson(identity.ekUrl, EK_OPTIONS);
    await transport.fetchJson(identity.ekUrl, EK_OPTIONS);
    assert.equal(calls.length, 2);
    assert.equal(cache.stats().keyMisses, 0, 'not even a lookup');
  });

  test('a key-document URL that is also the record’s status URL is never cached', async () => {
    const { cache, calls, transport } = await viewWorld(async (identity) => {
      // A record (signed by the SDK) whose `su` is its `ek` URL.
      const publisher = new IdentityManager(
        {
          identity: {
            domain: AGENT,
            governanceId: FIXTURE_GOVERNANCE,
            logRef: identity.lr,
            statusUrl: identity.ekUrl,
            ekUrl: identity.ekUrl,
            kuUrl: identity.kuUrl,
          },
        },
        { keyProvider: identity.operational, entityKeyProvider: identity.entity },
      );
      return publisher.createTxtRecord();
    });
    await transport.dnsResolver.fetchTXT(DNS_NAME);
    const ekUrl = `https://${FIXTURE_GOVERNANCE}/.well-known/dnsid/ek.json`;
    await transport.fetchJson(ekUrl, EK_OPTIONS);
    await transport.fetchJson(ekUrl, EK_OPTIONS);
    assert.equal(calls.length, 2);
    assert.equal(cache.stats().keyMisses, 0, 'not identified as a key document');
  });

  test('after the record is resolved: the status URL, another URL serving keys, and other options all bypass the cache', async () => {
    const { identity, cache, calls, transport } = await viewWorld();
    await transport.dnsResolver.fetchTXT(DNS_NAME);
    await transport.fetchJson(identity.statusUrl, { maxResponseBytes: STATUS_MAX_RESPONSE_BYTES });
    await transport.fetchJson(identity.statusUrl, EK_OPTIONS);
    await transport.fetchJson(`https://${FIXTURE_GOVERNANCE}/other-keys.json`, EK_OPTIONS);
    await transport.fetchJson(identity.ekUrl, { ...EK_OPTIONS, domainBoundary: false });
    await transport.fetchJson(identity.ekUrl, { ...EK_OPTIONS, maxResponseBytes: 1024 });
    await transport.fetchJson(identity.kuUrl, EK_OPTIONS);
    assert.equal(cache.stats().keyMisses, 0, 'none was identified as a key document');
    await transport.fetchJson(identity.ekUrl, EK_OPTIONS);
    await transport.fetchJson(identity.kuUrl, KU_OPTIONS);
    assert.equal(cache.stats().keyMisses, 2, 'the SDK’s exact ek and ku fetches were');
    assert.equal(calls.length, 8);
    assert.equal(cache.size, 0, 'and nothing is admitted without a verified identity');
  });
});

describe('material cache: admission matches what the SDK verified', () => {
  /** A real VerifiedDomain for the fixture identity (from a passing request), and a fixed certificate expiry. */
  async function verifiedWorld() {
    const w = await world({ cache: new SharedMaterialCache() });
    const notAfter = new Date(Date.now() + 86_400_000);
    w.network.certificateNotAfter = () => notAfter;
    let verified: VerifiedDomain | undefined;
    assertPassed(await run(w.runtime, await signedAs(w.identity), { observer: { lifecycleStarting: (_scope, v) => (verified = v) } }));
    assert.ok(verified !== undefined);
    return { w, verified };
  }

  async function fetchAll(transport: ReturnType<ReturnType<SharedMaterialCache['view']>['wrap']>, identity: FixtureIdentity) {
    await transport.dnsResolver.fetchTXT(DNS_NAME);
    await transport.fetchJson(identity.ekUrl, EK_OPTIONS);
    await transport.fetchJson(identity.kuUrl, KU_OPTIONS);
  }

  test('the material this identity’s verification used is admitted', async () => {
    const { w, verified } = await verifiedWorld();
    const cache = new SharedMaterialCache();
    const view = cache.view('unit', { signal: new AbortController().signal });
    await fetchAll(view.wrap(w.network), w.identity);
    view.admit(verified);
    assert.equal(cache.size, 3);
  });

  test('another record or other keys for the same domain and URLs are not admitted for it', async () => {
    const { w, verified } = await verifiedWorld();
    // Another identity at the same name and URLs (new keys, a new signed record), served in place of the verified one.
    const other = await issueIdentity(fixtureLog(), AGENT);
    w.network.publish(other);
    const cache = new SharedMaterialCache();
    const view = cache.view('unit', { signal: new AbortController().signal });
    await fetchAll(view.wrap(w.network), other);
    view.admit(verified);
    assert.equal(cache.size, 0);
  });

  test('a request that ended admits nothing, and admits once only', async () => {
    const { w, verified } = await verifiedWorld();
    const cache = new SharedMaterialCache();
    const controller = new AbortController();
    const ended = cache.view('unit', { signal: controller.signal });
    await fetchAll(ended.wrap(w.network), w.identity);
    controller.abort();
    ended.admit(verified);
    assert.equal(cache.size, 0);
    const once = cache.view('unit', { signal: new AbortController().signal });
    await fetchAll(once.wrap(w.network), w.identity);
    once.discard();
    once.admit(verified);
    assert.equal(cache.size, 0, 'discarded fills are gone');
  });
});
