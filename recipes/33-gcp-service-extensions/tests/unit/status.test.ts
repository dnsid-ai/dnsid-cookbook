// The live tests' lifecycle reads (scripts/live/status.ts) on offline fixture identities, a test C2SP log and the real
// SDK: the status document, and the authenticated log history that tells a revocation apart when the verifier's own log
// read refuses the identity first (identity_invalid) and SDK 0.37.0 reports only a LogError.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { entryBundlePath } from '@dnsid-ai/log-c2sp-tlog';
import { readAgentStatus, readLifecycleEvidence, readLoggedLifecycle } from '../../scripts/live/status.ts';
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

const AGENT = 'agent-gov-fixture.test';
const OTHER = 'other-gov2-fixture.test';
const OTHER_GOVERNANCE = 'gov2-fixture.test';
const TRUSTED = `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`;

interface World {
  log: FixtureLog;
  network: FixtureNetwork;
  agent: FixtureIdentity;
  other: FixtureIdentity;
}

async function world(): Promise<World> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const agent = await issueIdentity(log, AGENT);
  const other = await issueIdentity(log, OTHER, { governanceId: OTHER_GOVERNANCE });
  network.publish(agent);
  network.publish(other);
  return { log, network, agent, other };
}

const logged = (w: World, domain = AGENT, trusted = TRUSTED, timeoutMs?: number) =>
  readLoggedLifecycle(domain, trusted, fixtureBackend(w.network, w.log), timeoutMs);

describe('the authenticated log history (readLoggedLifecycle)', () => {
  test('an active identity: ACTIVE, from its verified history', async () => {
    const w = await world();
    const got = await logged(w);
    assert.equal(got.kind, 'logged');
    assert.equal(got.kind === 'logged' && got.state, 'ACTIVE');
    assert.equal(got.kind === 'logged' && got.events, 1);
  });

  test('a signed REVOCATION in the log, status still ACTIVE: REVOKED with its reason, where the full verification only says LogError', async () => {
    const w = await world();
    w.log.append(await lifecycleEntry(w.agent, 'REVOCATION'));
    const got = await logged(w);
    assert.equal(got.kind, 'logged', JSON.stringify(got));
    assert.equal(got.kind === 'logged' && got.state, 'REVOKED');
    assert.equal(got.kind === 'logged' && got.reason, 'keyCompromise');
    assert.equal(got.kind === 'logged' && got.events, 2);
    // The status document alone has nothing to say: the identity's own verification fails on the log first.
    const status = await readAgentStatus(AGENT, TRUSTED, fixtureBackend(w.network, w.log));
    assert.deepEqual({ kind: status.kind, reason: status.kind === 'unknown' ? status.reason : '' }, { kind: 'unknown', reason: 'LogError' });
    // The other identity in the same log is unaffected.
    const other = await logged(w, OTHER);
    assert.equal(other.kind === 'logged' && other.state, 'ACTIVE');
  });

  test('revoked in the log and in the status document: both sources say REVOKED', async () => {
    const w = await world();
    w.log.append(await lifecycleEntry(w.agent, 'REVOCATION'));
    w.network.publish(w.agent, 'REVOKED');
    // Several times: the two reads must not cut each other short whichever finishes first.
    for (let i = 0; i < 5; i++) {
      const evidence = await readLifecycleEvidence(AGENT, TRUSTED, fixtureBackend(w.network, w.log));
      assert.equal(evidence.log.kind === 'logged' && evidence.log.state, 'REVOKED', JSON.stringify(evidence));
      assert.equal(evidence.status.kind === 'state' && evidence.status.state, 'REVOKED', JSON.stringify(evidence));
    }
  });

  test('a status-only revocation: the status document says REVOKED and the log ACTIVE', async () => {
    const w = await world();
    w.network.publish(w.agent, 'REVOKED');
    const evidence = await readLifecycleEvidence(AGENT, TRUSTED, fixtureBackend(w.network, w.log));
    assert.equal(evidence.status.kind === 'state' && evidence.status.state, 'REVOKED');
    assert.equal(evidence.log.kind === 'logged' && evidence.log.state, 'ACTIVE');
  });

  test('a logged RETIREMENT is RETIRED, never REVOKED', async () => {
    const w = await world();
    w.log.append(await lifecycleEntry(w.agent, 'RETIREMENT'));
    const got = await logged(w);
    assert.equal(got.kind === 'logged' && got.state, 'RETIRED', JSON.stringify(got));
    assert.equal(got.kind === 'logged' && got.reason, undefined);
  });

  test('a REVOCATION with a forged signature is not evidence: the identity stays ACTIVE', async () => {
    const w = await world();
    const entry = await lifecycleEntry(w.agent, 'REVOCATION');
    const text = new TextDecoder().decode(entry);
    const sig = /"sig":"([A-Za-z0-9_-]+)"/.exec(text)?.[1] as string;
    w.log.append(new TextEncoder().encode(text.replace(sig, `${sig.slice(0, 10)}${sig[10] === 'A' ? 'B' : 'A'}${sig.slice(11)}`)));
    const got = await logged(w);
    assert.equal(got.kind === 'logged' && got.state, 'ACTIVE', JSON.stringify(got));
  });

  test('a tampered log, an unreachable log, an unresolvable name, an untrusted governance ID and a timeout give no evidence', async () => {
    // Tampered under its signed checkpoint.
    let w = await world();
    w.log.append(await lifecycleEntry(w.agent, 'REVOCATION'));
    const url = entryBundlePath(w.log.prefix, 0, w.log.entries.length);
    const bundle = await w.log.fetcher.fetchBounded(url, 1 << 20, { timeoutMs: 1000 });
    const tampered = new Uint8Array(bundle);
    const at = new TextDecoder().decode(bundle).lastIndexOf('"sig":"') + 12;
    tampered[at] = tampered[at] === 0x41 ? 0x42 : 0x41;
    w.log.override(url, { status: 200, body: tampered });
    let got = await logged(w);
    assert.equal(got.kind, 'unknown', `tampered: ${JSON.stringify(got)}`);
    // The log unreachable.
    w = await world();
    w.log.append(await lifecycleEntry(w.agent, 'REVOCATION'));
    w.log.override(entryBundlePath(w.log.prefix, 0, w.log.entries.length), { status: 0 });
    got = await logged(w);
    assert.equal(got.kind, 'unknown', `unreachable: ${JSON.stringify(got)}`);
    // No identity at that name.
    got = await logged(w, 'nobody-gov-fixture.test');
    assert.equal(got.kind, 'unknown');
    assert.match(got.kind === 'unknown' ? got.reason : '', /could not be resolved to its log: RecordNotFound/);
    // Revoked in the log, but under a governance ID not trusted here.
    w = await world();
    w.log.append(await lifecycleEntry(w.other, 'REVOCATION'));
    got = await logged(w, OTHER, FIXTURE_GOVERNANCE);
    assert.equal(got.kind, 'unknown', `untrusted: ${JSON.stringify(got)}`);
    assert.match(got.kind === 'unknown' ? got.reason : '', /not under a trusted governance ID/);
    // A log that never answers: bounded.
    w = await world();
    w.log.gate = () => new Promise(() => {});
    const started = Date.now();
    got = await logged(w, AGENT, TRUSTED, 300);
    assert.equal(got.kind, 'unknown');
    assert.match(got.kind === 'unknown' ? got.reason : '', /within 300 ms/);
    assert.ok(Date.now() - started < 5_000);
  });
});
