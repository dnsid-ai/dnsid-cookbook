// The local mode's request path (local/stack.ts: the local edge, the production verifier service and Demo Bank) and its
// client (local/client.ts), with the verifier on the REAL-SDK FIXTURE NETWORK (offline test identities on a test C2SP
// log, in-memory DNS and HTTPS: tests/support/identity-fixture.ts), so every outcome can be arranged: allowed; unsigned,
// tampered, untrusted, revoked (status, and the log alone), unavailable and stale evidence refused; forged identity
// headers replaced; nothing refused reaching Demo Bank. The judgments `make verify` applies (local/recipe.ts `judge`)
// are checked against these real observations, and against altered ones.
//
// The local edge is a forwarding harness, not Google's load balancer: nothing here says what Google forwards.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, test, type TestContext } from 'node:test';

import { runCase, type CaseName, type Observation } from '../../local/client.ts';
import { startLocalEdge } from '../../local/edge.ts';
import { judge } from '../../local/recipe.ts';
import { startLocalStack, UNTRUSTED_GOVERNANCE, type Component, type Ready } from '../../local/stack.ts';
import { listen } from '../../origin/server.ts';
import { governancePolicy } from '../../src/identity.ts';
import { createSigner, type Signer } from '../../scripts/live/signer.ts';
import { checkpointPath } from '@dnsid-ai/log-c2sp-tlog';
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

const ALICE = 'alice.test';
const BOB = 'bob.test';

interface Path {
  readonly ready: Ready;
  readonly log: FixtureLog;
  readonly network: FixtureNetwork;
  readonly alice: FixtureIdentity;
  readonly bob: FixtureIdentity;
  readonly aliceSigner: Signer;
  readonly bobSigner: Signer;
  readonly records: { component: Component; record: Record<string, unknown> }[];
  origin(): Record<string, unknown>[];
}

async function localPath(t: TestContext): Promise<Path> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const alice = await issueIdentity(log, ALICE);
  // One governance, one accountable-entity key document (as under DNSid Local).
  const bob = await issueIdentity(log, BOB, { entity: alice.entity });
  network.publish(alice);
  network.publish(bob);
  const records: Path['records'] = [];
  const stack = await startLocalStack({
    backend: fixtureBackend(network, log),
    governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]),
    log: (component, record) => void records.push({ component, record: record as Record<string, unknown> }),
    shutdownGraceMs: 200,
  });
  t.after(() => stack.stop());
  return {
    ready: { pid: process.pid, startedAt: new Date().toISOString(), ...stack.ready },
    log,
    network,
    alice,
    bob,
    aliceSigner: await createSigner(ALICE, alice.operational),
    bobSigner: await createSigner(BOB, bob.operational),
    records,
    origin: () => records.filter((r) => r.component === 'origin').map((r) => r.record),
  };
}

const bodyOf = (o: Observation) => JSON.parse(o.body) as { bank: string; synthetic: boolean; caller: { verifiedDomain: string; governanceId: string } };

function assertDenied(o: Observation, reason: string) {
  assert.equal(o.status, 403, JSON.stringify(o));
  assert.equal(o.cacheControl, 'no-store');
  assert.equal(o.body, reason);
}

describe('the local request path, on the fixture network', () => {
  test('a valid identity is allowed: GET gets Demo Bank\'s data for the verified identity, HEAD gets 200 with no body', async (t) => {
    const path = await localPath(t);
    const get = await runCase('signed-get', path.ready, path.aliceSigner);
    assert.equal(get.status, 200, JSON.stringify(get));
    assert.equal(get.edge, 'trusted');
    assert.deepEqual(bodyOf(get).caller, { verifiedDomain: ALICE, governanceId: FIXTURE_GOVERNANCE });
    assert.equal(bodyOf(get).synthetic, true);
    const head = await runCase('signed-head', path.ready, path.aliceSigner);
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    assert.deepEqual(
      path.origin().map((r) => [r['method'], r['outcome'], r['verifiedDomain'], r['governanceId']]),
      [
        ['GET', 'served', ALICE, FIXTURE_GOVERNANCE],
        ['HEAD', 'served', ALICE, FIXTURE_GOVERNANCE],
      ],
    );
    const edge = path.records.filter((r) => r.component === 'edge').map((r) => [r.record['edge'], r.record['outcome'], r.record['status']]);
    assert.deepEqual(edge, [
      ['trusted', 'forwarded', 200],
      ['trusted', 'forwarded', 200],
    ]);
  });

  test('forged x-dnsid-* identity headers are replaced: Demo Bank sees only the verified identity', async (t) => {
    const path = await localPath(t);
    const forged = await runCase('forged-headers', path.ready, path.aliceSigner);
    assert.equal(forged.status, 200, JSON.stringify(forged));
    assert.deepEqual(bodyOf(forged).caller, { verifiedDomain: ALICE, governanceId: FIXTURE_GOVERNANCE });
    assert.equal(path.origin().length, 1);
    assert.equal(path.origin()[0]?.['verifiedDomain'], ALICE);
  });

  const refusals: [string, (path: Path) => Promise<Observation>, string][] = [
    ['an unsigned request', (p) => runCase('unsigned', p.ready, undefined), 'signature_missing'],
    ['a request changed after signing', (p) => runCase('tampered', p.ready, p.aliceSigner), 'signature_invalid'],
    ['a valid identity whose governance the verifier does not trust', (p) => runCase('untrusted-governance', p.ready, p.aliceSigner), 'governance_not_trusted'],
    [
      'a revoked identity (status document REVOKED)',
      (p) => {
        p.network.publish(p.bob, 'REVOKED');
        return runCase('signed-get', p.ready, p.bobSigner);
      },
      'identity_inactive',
    ],
    [
      'an identity revoked in the log alone (status document still ACTIVE)',
      async (p) => {
        p.log.append(await lifecycleEntry(p.bob, 'REVOCATION'));
        return runCase('signed-get', p.ready, p.bobSigner);
      },
      // The identity stage's own read of the log (the SDK's ISSUANCE and key-binding checks) refuses it first, on a
      // request that finds nothing cached; the lifecycle stage's reason for it is covered by tests/unit/lifecycle.test.ts.
      'identity_invalid',
    ],
    [
      'an identity whose log evidence is unavailable',
      (p) => {
        p.log.override(checkpointPath(p.log.prefix), { status: 0 });
        return runCase('signed-get', p.ready, p.aliceSigner);
      },
      'identity_unavailable',
    ],
    [
      'an identity whose log evidence is stale (witnessed 400 s ago; the limit is 300 s)',
      (p) => {
        p.log.resign({ witnessAgeSeconds: 400 });
        return runCase('signed-get', p.ready, p.aliceSigner);
      },
      // Refused by the SDK's log checks in the identity stage, before the 300 s freshness limit is applied
      // (tests/unit/lifecycle.test.ts covers that limit on its own).
      'identity_invalid',
    ],
    [
      'an identity whose status document is unavailable',
      (p) => {
        p.network.setHttp(p.alice.statusUrl, { hang: true });
        return runCase('signed-get', p.ready, p.aliceSigner);
      },
      'verification_budget_exhausted',
    ],
  ];
  for (const [what, send, reason] of refusals) {
    test(`refused, and nothing reaches Demo Bank: ${what} (${reason})`, async (t) => {
      const path = await localPath(t);
      const observed = await send(path);
      assertDenied(observed, reason);
      assert.deepEqual(path.origin(), []);
      const edge = path.records.filter((r) => r.component === 'edge').map((r) => r.record['outcome']);
      assert.deepEqual(edge, ['denied']);
    });
  }

  test('the untrusted edge\'s verifier trusts only a governance no identity uses', async (t) => {
    const path = await localPath(t);
    await runCase('untrusted-governance', path.ready, path.aliceSigner);
    const verifier = path.records.filter((r) => r.component === 'verifier').map((r) => [r.record['verifier'], r.record['reason']]);
    assert.deepEqual(verifier, [['untrusted', 'governance_not_trusted']]);
    assert.notEqual(UNTRUSTED_GOVERNANCE, FIXTURE_GOVERNANCE);
    assert.match(UNTRUSTED_GOVERNANCE, /\.test$/);
  });

  test('the edge answers a `..` path with a redirect and never asks the verifier', async (t) => {
    const path = await localPath(t);
    const { h1 } = await import('../../scripts/live/http.ts');
    const { fingerprintOf } = await import('../../scripts/lib/pinned-tls.ts');
    const { port, certificatePem } = path.ready.edges.trusted;
    const target = { host: '127.0.0.1', port, pin: { certificatePem, fingerprint256: fingerprintOf(certificatePem) } };
    const reply = await h1(target, { method: 'GET', path: '/x/../accounts' });
    assert.equal(reply.status, 301);
    assert.equal(reply.headers['location'], '/accounts');
    assert.deepEqual(path.records.filter((r) => r.component === 'verifier'), []);
    assert.deepEqual(path.origin(), []);
  });
});

describe('the local edge without a verifier', () => {
  test('a verifier that does not answer gets the 500 the load balancer gives, and nothing reaches Demo Bank', async (t) => {
    const reached: unknown[] = [];
    const origin = await listen('127.0.0.1', 0, { attestationKey: randomBytes(32), log: (r) => void reached.push(r), shutdownGraceMs: 100 });
    t.after(() => origin.stop());
    // A port nothing listens on: the gRPC call fails at once.
    const closed = await listen('127.0.0.1', 0, { attestationKey: randomBytes(32), log: () => {}, shutdownGraceMs: 100 });
    const deadPort = closed.port;
    await closed.stop();
    const edge = await startLocalEdge({ name: 'trusted', verifierPort: deadPort, originPort: origin.port });
    t.after(() => edge.stop());
    const ready: Ready = {
      pid: process.pid,
      host: '127.0.0.1',
      originPort: origin.port,
      edges: {
        trusted: { port: edge.port, certificatePem: edge.certificatePem, verifierPort: deadPort },
        untrusted: { port: edge.port, certificatePem: edge.certificatePem, verifierPort: deadPort },
      },
      governanceId: FIXTURE_GOVERNANCE,
      startedAt: '',
    };
    const observed = await runCase('unsigned', ready, undefined);
    assert.equal(observed.status, 500);
    assert.deepEqual(reached, []);
  });
});

describe('make verify\'s judgments (local/recipe.ts judge), on real observations', () => {
  async function observeAll(t: TestContext) {
    const path = await localPath(t);
    path.network.publish(path.bob, 'REVOKED');
    const window = async (signer: Signer | undefined, cases: CaseName[]) => {
      const before = path.origin().length;
      const observed: Observation[] = [];
      for (const name of cases) observed.push(await runCase(name, path.ready, signer));
      return { observed, reached: path.origin().slice(before).map((r) => ({ component: 'origin', ...r })) };
    };
    const unsigned = await window(undefined, ['unsigned']);
    const alice = await window(path.aliceSigner, ['signed-get', 'signed-head', 'tampered', 'forged-headers', 'untrusted-governance']);
    const bob = await window(path.bobSigner, ['signed-get']);
    return {
      observations: { unsigned: unsigned.observed, alice: alice.observed, bob: bob.observed },
      reached: { unsigned: unsigned.reached, alice: alice.reached, bob: bob.reached },
    };
  }

  test('every check passes for the expected outcomes', async (t) => {
    const { observations, reached } = await observeAll(t);
    const checks = judge(FIXTURE_GOVERNANCE, observations, reached);
    assert.equal(checks.length, 9);
    for (const check of checks) assert.ok(check.pass, `${check.name}: ${check.detail}`);
  });

  test('each wrong outcome fails its check', async (t) => {
    const { observations, reached } = await observeAll(t);
    const allowedGet = observations.alice[0] as Observation;
    const failing = (name: string, altered: Parameters<typeof judge>[1], alteredReached = reached) => {
      const checks = judge(FIXTURE_GOVERNANCE, altered, alteredReached);
      assert.ok(checks.some((check) => !check.pass && check.name.includes(name)), `${name} should fail`);
    };
    // The revoked identity allowed.
    failing('revoked', { ...observations, bob: [{ ...allowedGet, domain: BOB }] });
    // The revoked identity refused for a reason that isn't about its lifecycle or evidence.
    const bobDenied = observations.bob[0] as Observation;
    failing('revoked', { ...observations, bob: [{ ...bobDenied, body: 'signature_invalid' }] });
    failing('revoked', { ...observations, bob: [{ ...bobDenied, body: 'governance_not_trusted' }] });
    // A forged identity reaching Demo Bank.
    const forged = observations.alice.map((o) => (o.case === 'forged-headers' ? { ...o, body: o.body.replace(`"verifiedDomain":"${ALICE}"`, '"verifiedDomain":"forged-identity.test"') } : o));
    failing('forged', { ...observations, alice: forged });
    // An unsigned request allowed.
    failing('unsigned', { ...observations, unsigned: [{ ...allowedGet, case: 'unsigned', domain: null }] });
    // A different governance than DNSid Local's.
    assert.ok(judge('other-governance.test', observations, reached).some((c) => !c.pass));
    // A refused request reaching Demo Bank anyway.
    failing('nothing refused reached', observations, { ...reached, bob: [{ component: 'origin', outcome: 'served' } as (typeof reached.bob)[number]] });
    // An HTML 403 (not the verifier's) for the untrusted case.
    const html = observations.alice.map((o) => (o.case === 'untrusted-governance' ? { ...o, cacheControl: null, body: '<html>Forbidden</html>' } : o));
    failing('untrusted governance', { ...observations, alice: html });
    // A missing observation (the client stopped early).
    failing('HEAD', { ...observations, alice: observations.alice.filter((o) => o.case !== 'signed-head') });
  });
});
