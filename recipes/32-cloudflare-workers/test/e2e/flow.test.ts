import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';
import { startLocalRegistry } from './local-registry.ts';
import { createWorkerHarness, ENROLLED, STRANGER, REVOKED } from './worker-harness.ts';

// Deliberately separate from the fast Worker tests: this suite owns real local services.
describe('built Workers with DNSid Local', { concurrency: false }, () => {
  let local: Awaited<ReturnType<typeof startLocalRegistry>> | undefined;
  let workers: Awaited<ReturnType<typeof createWorkerHarness>>;

  before(async () => {
    if (process.env.DNSID_RECIPE_STATE) {
      const settings = JSON.parse(await readFile(process.env.DNSID_RECIPE_STATE, 'utf8'));
      workers = await createWorkerHarness({ ...settings, logPolicyUrl: process.env.DNSID_LOG_POLICY_URL });
    } else {
      local = await startLocalRegistry([ENROLLED, STRANGER, REVOKED]);
      await local.revoke(REVOKED);
      workers = await createWorkerHarness(local);
    }
  }, { timeout: 600_000 });

  after(async () => {
    try {
      await workers?.close();
    } finally {
      await local?.stop();
    }
  }, { timeout: 180_000 });

  it('rejects direct origin calls without the shared secret, even with forged identity headers', async () => {
    const response = await fetch(`${workers.originUrl}/echo`, {
      headers: { 'DNSid-Agent': ENROLLED, 'DNSid-Accountable-Entity': 'enrolled.test' },
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: 'origin_auth_required' });
  });

  it('forwards verified identity on cold and warm requests', async () => {
    for (let request = 0; request < 2; request++) {
      const response = await workers.viaEgress('egress-enrolled', '/echo');
      assert.equal(response.status, 200, await response.clone().text());
      assert.deepEqual(await response.json(), { method: 'GET', path: '/echo', agent: ENROLLED, entity: 'enrolled.test', body: '' });
      assert.deepEqual(workers.originSeen.at(-1), {
        agent: ENROLLED, entity: 'enrolled.test', auth: 'origin-secret',
      });
    }
  });

  it('relays the origin status, headers, and body unchanged for another verified identity', async () => {
    const response = await workers.viaEgress('egress-stranger', '/denied');
    assert.equal(response.status, 403);
    assert.equal(response.headers.get('x-test-origin'), 'denied');
    assert.deepEqual(await response.json(), { error: 'origin_denied' });
    assert.equal(workers.originSeen.at(-1)?.agent, STRANGER);
    assert.equal(workers.originSeen.at(-1)?.entity, 'stranger.test');
  });

  it('rejects a revoked identity before contacting the origin', async () => {
    const count = workers.originSeen.length;
    const response = await workers.viaEgress('egress-revoked', '/echo');
    assert.equal(response.status, 401);
    assert.match((await response.json() as { error: string }).error, /^verification_failed:StatusNotActive$/);
    assert.equal(workers.originSeen.length, count);
  });

  it('preserves the signed method, path, query, and body', async () => {
    const response = await workers.viaEgress('egress-enrolled', '/echo?mode=test', { method: 'POST', body: 'hello origin' });
    assert.equal(response.status, 200, await response.clone().text());
    assert.deepEqual(await response.json(), { method: 'POST', path: '/echo?mode=test', agent: ENROLLED, entity: 'enrolled.test', body: 'hello origin' });
  });

  it('rejects unsigned requests without contacting the origin', async () => {
    const count = workers.originSeen.length;
    const response = await workers.unsigned();
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: 'unsigned', message: 'request is not signed' });
    assert.equal(workers.originSeen.length, count);
  });

  it('rejects reuse of a signed request without contacting the origin again', async () => {
    const original = await workers.viaEgress('egress-enrolled', '/echo');
    assert.equal(original.status, 200);
    await original.arrayBuffer();
    const count = workers.originSeen.length;
    const response = await workers.replayLastRequest();
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: 'replay', message: 'nonce already used' });
    assert.equal(workers.originSeen.length, count);
  });
});
