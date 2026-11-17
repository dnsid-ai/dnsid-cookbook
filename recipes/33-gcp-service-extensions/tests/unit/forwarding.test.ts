// The verifier and the origin together, locally: the real gRPC callout service (real decoder, preconditions, SDK
// verification of offline test identities on a test C2SP log, response layer) and Demo Bank's real listener, joined by
// the TEST FORWARDING HARNESS in tests/support/forwarding-harness.ts. The harness is not Google's load balancer and not
// Envoy: these tests show what this code does with what reaches it, not what Google forwards.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, test, type TestContext } from 'node:test';

import { createHttpSignaturesProfile, type IdentityResolver } from '@dnsid-ai/sdk';

import { listen, type OriginRecord } from '../../origin/server.ts';
import { createVerificationRuntime, governancePolicy } from '../../src/identity.ts';
import { ATTESTATION_HEADER } from '../../src/attestation.ts';
import { GOVERNANCE_ID_HEADER, VERIFIED_DOMAIN_HEADER } from '../../src/response.ts';
import { createCalloutService, type TerminalRecord } from '../../src/service.ts';
import { forwardThroughVerifier, type Forwarded } from '../support/forwarding-harness.ts';
import { byteClient } from '../support/grpc-client.ts';
import { call } from '../support/http-client.ts';
import { FIXTURE_GOVERNANCE, fixtureBackend, fixtureLog, fixtureNetwork, issueIdentity, type FixtureIdentity, type FixtureNetwork } from '../support/identity-fixture.ts';
import { valuesOf } from '../support/response-wire.ts';
import { fieldsOf, replaced, without, type Field } from '../support/signing.ts';

const AGENT = 'agent-gov-fixture.test';
const AUTHORITY = 'api-example.test';

const unused: IdentityResolver = {
  verifyDomain() {
    throw new Error('a test signer never verifies');
  },
};

async function signed(identity: FixtureIdentity, method = 'GET', path = '/accounts?view=summary', extra: Field[] = []): Promise<Field[]> {
  const profile = createHttpSignaturesProfile({ domain: identity.domain, keyProvider: identity.operational, identityResolver: unused });
  return fieldsOf(await profile.createSignedHttpRequest(new Request(`https://${AUTHORITY}${path}`, { method })), {}, extra);
}

interface Stack {
  identity: FixtureIdentity;
  network: FixtureNetwork;
  verifierRecords: TerminalRecord[];
  originRecords: OriginRecord[];
  originPort: number;
  send(fields: Field[]): Promise<Forwarded>;
}

async function stack(t: TestContext): Promise<Stack> {
  const log = fixtureLog();
  const network = fixtureNetwork();
  const identity = await issueIdentity(log, AGENT);
  network.publish(identity);
  const runtime = createVerificationRuntime({ governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]), backend: fixtureBackend(network, log) });
  const verifierRecords: TerminalRecord[] = [];
  const attestationKey = randomBytes(32);
  const service = createCalloutService({ runtime, attestationKey, log: (record) => void verifierRecords.push(record), shutdownGraceMs: 200 });
  const verifierPort = await service.listen('127.0.0.1', 0);
  const client = byteClient(verifierPort);
  const originRecords: OriginRecord[] = [];
  const origin = await listen('127.0.0.1', 0, { attestationKey, log: (record) => void originRecords.push(record), shutdownGraceMs: 200 });
  t.after(async () => {
    client.close();
    await service.shutdown();
    await origin.stop();
  });
  return {
    identity,
    network,
    verifierRecords,
    originRecords,
    originPort: origin.port,
    send: (fields) => forwardThroughVerifier(client, origin.port, fields),
  };
}

function assertServed(result: Forwarded, method: string): Extract<Forwarded, { kind: 'forwarded' }> {
  assert.equal(result.kind, 'forwarded', JSON.stringify(result));
  const forwarded = result as Extract<Forwarded, { kind: 'forwarded' }>;
  assert.equal(forwarded.status, 200);
  assert.equal(forwarded.headers['cache-control'], 'no-store');
  if (method === 'HEAD') assert.equal(forwarded.body, '');
  else assert.deepEqual(JSON.parse(forwarded.body).caller, { verifiedDomain: AGENT, governanceId: FIXTURE_GOVERNANCE });
  return forwarded;
}

function assertDenied(result: Forwarded, reason: string): void {
  assert.deepEqual(result, { kind: 'denied', status: 403, reason });
}

describe('verifier + origin: signed requests from an active, trusted identity reach the origin', () => {
  for (const method of ['GET', 'HEAD']) {
    test(`${method}: continued by the verifier, served by the origin with the verified identity`, async (t) => {
      const s = await stack(t);
      assertServed(await s.send(await signed(s.identity, method)), method);
      assert.deepEqual(s.verifierRecords.map((r) => r.outcome), ['continue_submitted']);
      assert.equal(s.originRecords.length, 1);
      assert.deepEqual({ ...s.originRecords[0], id: '' }, {
        severity: 'INFO',
        event: 'origin_request',
        id: '',
        method,
        route: 'accounts',
        status: 200,
        outcome: 'served',
        verifiedDomain: AGENT,
        governanceId: FIXTURE_GOVERNANCE,
      });
    });
  }

  test('forged identity headers are replaced by the verified values; other x-dnsid-* headers are removed', async (t) => {
    const s = await stack(t);
    const forged: Field[] = [
      [VERIFIED_DOMAIN_HEADER, 'victim.example'],
      ['X-DNSid-Verified-Domain', 'second.example'],
      [GOVERNANCE_ID_HEADER, 'forged-governance.example'],
      ['x-dnsid-role', 'admin'],
      [ATTESTATION_HEADER, `v1.${Math.floor(Date.now() / 1000)}.${'A'.repeat(43)}`],
    ];
    const result = assertServed(await s.send(await signed(s.identity, 'GET', '/accounts', forged)), 'GET');
    assert.deepEqual(valuesOf(result.sent, VERIFIED_DOMAIN_HEADER), [AGENT]);
    assert.deepEqual(valuesOf(result.sent, GOVERNANCE_ID_HEADER), [FIXTURE_GOVERNANCE]);
    // The verifier's own attestation of that identity, the forged one removed: Demo Bank accepted it (served).
    assert.equal(valuesOf(result.sent, ATTESTATION_HEADER).length, 1);
    assert.notEqual(valuesOf(result.sent, ATTESTATION_HEADER)[0], forged.at(-1)?.[1]);
    assert.deepEqual(result.sent.filter(([name]) => name.startsWith('x-dnsid-')).map(([name]) => name).sort(), [ATTESTATION_HEADER, GOVERNANCE_ID_HEADER, VERIFIED_DOMAIN_HEADER]);
    assert.equal(s.originRecords[0]?.verifiedDomain, AGENT);
    assert.equal(s.originRecords[0]?.governanceId, FIXTURE_GOVERNANCE);
    assert.equal(JSON.stringify(s.originRecords).includes('victim'), false);
  });
});

describe('verifier + origin: refused requests produce no origin request', () => {
  test('unsigned, tampered after signing, and a signed POST: 403 from the verifier, origin untouched', async (t) => {
    const s = await stack(t);
    const good = await signed(s.identity);
    const unsigned = without(without(good, 'signature'), 'signature-input');
    assertDenied(await s.send(unsigned), 'signature_missing');
    // Unsigned, carrying identity headers of its own: still refused, the headers never reach the origin.
    assertDenied(await s.send([...unsigned, [VERIFIED_DOMAIN_HEADER, AGENT], [GOVERNANCE_ID_HEADER, FIXTURE_GOVERNANCE]]), 'signature_missing');
    assertDenied(await s.send(replaced(good, ':path', '/accounts?view=full')), 'signature_invalid');
    assertDenied(await s.send(replaced(good, ':authority', 'other-example.test')), 'signature_invalid');
    assertDenied(await s.send(replaced(good, ':method', 'HEAD')), 'signature_invalid');
    assertDenied(await s.send(await signed(s.identity, 'POST', '/accounts')), 'method_not_allowed');
    assert.equal(s.originRecords.length, 0);
    assert.equal(s.verifierRecords.length, 6);
    assert.ok(s.verifierRecords.every((r) => r.outcome === 'deny_submitted'));
  });

  for (const status of ['REVOKED', 'RETIRED'] as const) {
    test(`lifecycle: allowed while ACTIVE, then the status document reports ${status}: 403, origin untouched`, async (t) => {
      const s = await stack(t);
      assertServed(await s.send(await signed(s.identity)), 'GET');
      s.network.publish(s.identity, status);
      assertDenied(await s.send(await signed(s.identity)), 'identity_inactive');
      assert.equal(s.originRecords.length, 1, 'only the request before the change reached the origin');
      assert.deepEqual(s.verifierRecords.map((r) => r.outcome), ['continue_submitted', 'deny_submitted']);
    });
  }

  test('an identity that is not published (no DNSid record): 403, origin untouched', async (t) => {
    const s = await stack(t);
    const stranger = await issueIdentity(fixtureLog(), 'stranger-gov-fixture.test');
    const result = await s.send(await signed(stranger));
    assert.equal(result.kind, 'denied');
    assert.equal(s.originRecords.length, 0);
  });
});

describe('verifier + origin: what the origin does on its own', () => {
  test('a direct request without the identity context is refused by the origin (its own check, not authentication)', async (t) => {
    const s = await stack(t);
    const reply = await call(s.originPort, 'GET', '/accounts');
    assert.equal(reply.status, 403);
    assert.equal(reply.body, '{"error":"identity_context_required"}');
    assert.deepEqual(s.originRecords.map((r) => r.outcome), ['identity_missing']);
    assert.equal(s.verifierRecords.length, 0);
  });

  test('replay within the signature window (decision D-06, a documented limitation, not a protection): the same signed request is served twice', async (t) => {
    const s = await stack(t);
    const captured = await signed(s.identity);
    assertServed(await s.send(captured), 'GET');
    assertServed(await s.send(captured), 'GET');
    assert.deepEqual(s.verifierRecords.map((r) => r.outcome), ['continue_submitted', 'continue_submitted']);
    assert.deepEqual(s.originRecords.map((r) => r.outcome), ['served', 'served']);
  });
});
