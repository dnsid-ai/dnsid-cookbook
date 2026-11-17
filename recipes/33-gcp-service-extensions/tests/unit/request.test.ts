// scripts/live/request.ts (one request against a deployment, shown and checked; the demo's commands use it) against
// the FIXTURE EDGE (tests/support/live-edge.ts: the real verifier and Demo Bank behind a local HTTPS listener, NOT
// Google's load balancer). Each step is seen to pass where the edge behaves as planned and to fail where it doesn't;
// the key and the signature values never reach its output.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';

import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

import { assembleDeployOut } from '../../scripts/lib/deploy-tool.ts';
import { inventoryFrom } from '../../scripts/lib/inventory.ts';
import { FORGED_IDENTITY, main, runStep, type StepOptions } from '../../scripts/live/request.ts';
import { deployOutInputs, deploymentListings } from '../support/deploy-fixtures.ts';
import { readLifecycleEvidence } from '../../scripts/live/status.ts';
import { FIXTURE_GOVERNANCE, fixtureBackend, fixtureLog, fixtureNetwork, issueIdentity, lifecycleEntry, type FixtureIdentity, type FixtureLog, type FixtureNetwork } from '../support/identity-fixture.ts';
import { fixtureEdge, type FixtureEdge } from '../support/live-edge.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const AGENT = 'agent-gov-fixture.test';
const OTHER = 'other-gov2-fixture.test';
const OTHER_GOVERNANCE = 'gov2-fixture.test';
/** The demo's second agent, revoked for it: same governance as the agent, its own key file. */
const SECOND = 'second-gov-fixture.test';

interface Stage {
  readonly edge: FixtureEdge;
  readonly options: StepOptions;
  readonly keyD: string;
  readonly secondKeyD: string;
  readonly deployOut: string;
  readonly network: FixtureNetwork;
  readonly log: FixtureLog;
  readonly second: FixtureIdentity;
}

async function stage(t: TestContext): Promise<Stage> {
  const dir = mkdtempSync(join(tmpdir(), 'request-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const keyFile = join(dir, 'agent.jwk');
  writeFileSync(keyFile, JSON.stringify(jwk), { mode: 0o600 });
  const log = fixtureLog();
  const network = fixtureNetwork();
  const agent = await issueIdentity(log, AGENT, { operational: await LocalKeyProvider.fromFile(keyFile) });
  const other = await issueIdentity(log, OTHER, { governanceId: OTHER_GOVERNANCE });
  const secondJwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  const secondKeyFile = join(dir, 'second.jwk');
  writeFileSync(secondKeyFile, JSON.stringify(secondJwk), { mode: 0o600 });
  const second = await issueIdentity(log, SECOND, { entity: agent.entity, operational: await LocalKeyProvider.fromFile(secondKeyFile) });
  network.publish(agent);
  network.publish(other);
  network.publish(second);
  const edge = await fixtureEdge(t, { network, log, trusted: [FIXTURE_GOVERNANCE, OTHER_GOVERNANCE], untrusted: 'untrusted-governance.invalid' });
  const out = assembleDeployOut({
    ...deployOutInputs(edge.certificate, `https://127.0.0.1:${edge.port}`),
    governance: `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`,
    inventory: inventoryFrom(deploymentListings(), 'deploy.sh', new Date().toISOString()),
  });
  const deployOut = join(dir, 'deploy-out.json');
  writeFileSync(deployOut, JSON.stringify(out));
  const revoked = async () => ({ kind: 'state' as const, state: 'REVOKED', at: new Date().toISOString() });
  return {
    edge,
    keyD: String(jwk.d),
    secondKeyD: String(secondJwk.d),
    deployOut,
    network,
    log,
    second,
    options: {
      out,
      agent: AGENT,
      keyFile,
      other: OTHER,
      agentStatus: revoked,
      revokedAgent: SECOND,
      revokedKeyFile: secondKeyFile,
      lifecycle: (domain) => readLifecycleEvidence(domain, out.trusted_governance, fixtureBackend(network, log)),
    },
  };
}

function assertNoSecrets(lines: readonly string[], keyD: string) {
  const text = lines.join('\n');
  assert.equal(text.includes(keyD), false, 'the private key reached the output');
  assert.doesNotMatch(text, /sig1=|signature-input|keyid=/i);
}

describe('scripts/live/request.ts on the planned edge', () => {
  test('every step sees what it expects, and prints what it sent and what came back', async (t) => {
    const s = await stage(t);
    const unsigned = await runStep('unsigned', s.options);
    assert.ok(unsigned.ok, unsigned.lines.join('\n'));
    assert.match(unsigned.lines.join('\n'), /← 403 .*cache-control: no-store\n {2}refused by the verifier: signature_missing\n✓ as expected/);

    const signed = await runStep('signed', s.options);
    assert.ok(signed.ok, signed.lines.join('\n'));
    assert.match(signed.lines.join('\n'), new RegExp(`Demo Bank \\(synthetic data\\) served the request for: ${AGENT} \\(governance ${FIXTURE_GOVERNANCE}\\)`));

    const tampered = await runStep('tampered', s.options);
    assert.ok(tampered.ok, tampered.lines.join('\n'));
    assert.match(tampered.lines.join('\n'), /refused by the verifier: signature_invalid/);

    const forged = await runStep('forged', s.options);
    assert.ok(forged.ok, forged.lines.join('\n'));
    assert.equal(forged.lines.join('\n').includes(`served the request for: ${FORGED_IDENTITY}`), false);

    const claim = await runStep('claim', s.options);
    assert.ok(claim.ok, claim.lines.join('\n'));
    assert.match(claim.lines.join('\n'), /refused by the verifier: signature_(key_unknown|invalid)/);

    const status = await runStep('status', s.options);
    assert.ok(status.ok, status.lines.join('\n'));
    assert.match(status.lines.join('\n'), new RegExp(`← ${OTHER}: REVOKED`));

    for (const shown of [unsigned, signed, tampered, forged, claim, status]) assertNoSecrets(shown.lines, s.keyD);
    // Only the refused requests and the two allowed ones: the status step sent nothing to the edge.
    assert.equal(s.edge.requests.length, 5);
    assert.equal(s.edge.originRecords.filter((r) => r.outcome === 'served').length, 2);
  });
});

describe('scripts/live/request.ts revoked: a freshly signed request from the revoked agent, and its lifecycle evidence', () => {
  test('before the revocation the second agent is served; after it, refused, with the revocation identified (log, status, both)', async (t) => {
    for (const how of ['log', 'status', 'both'] as const) {
      const s = await stage(t);
      // Before: the same agent and key are served (setup.md shows this before revoking it).
      const before = await runStep('signed', { ...s.options, agent: SECOND, keyFile: s.options.revokedKeyFile as string });
      assert.ok(before.ok, before.lines.join('\n'));
      if (how !== 'status') s.log.append(await lifecycleEntry(s.second, 'REVOCATION'));
      if (how !== 'log') s.network.publish(s.second, 'REVOKED');
      const shown = await runStep('revoked', s.options);
      const text = shown.lines.join('\n');
      assert.ok(shown.ok, `${how}: ${text}`);
      assert.match(text, new RegExp(`→ GET .*/accounts  \\(freshly signed as ${SECOND}, the revoked agent\\)\n← 403 .*\n {2}refused by the verifier: identity_(invalid|inactive)`));
      if (how !== 'status') assert.match(text, /← its authenticated log history: REVOKED \(keyCompromise\) since [^,]+, 2 event\(s\)/);
      if (how !== 'log') assert.match(text, /← its DNSid status document: REVOKED/);
      assert.match(text, /revocation identified by the (status document|authenticated log history)\n✓ as expected/);
      // The active agent, right after: still served (the demo's control).
      const active = await runStep('signed', s.options);
      assert.ok(active.ok, active.lines.join('\n'));
      assertNoSecrets(shown.lines, s.secondKeyD);
      assertNoSecrets(shown.lines, s.keyD);
    }
  });

  test('not revoked, retired, or refused for another reason: UNEXPECTED', async (t) => {
    let s = await stage(t);
    let shown = await runStep('revoked', s.options);
    assert.equal(shown.ok, false);
    assert.match(shown.lines.join('\n'), /still allowed\n✗ UNEXPECTED/);
    s = await stage(t);
    s.log.append(await lifecycleEntry(s.second, 'RETIREMENT'));
    shown = await runStep('revoked', s.options);
    assert.equal(shown.ok, false);
    assert.match(shown.lines.join('\n'), /← its authenticated log history: RETIRED.*\n.*RETIRED is never a revocation/);
    s = await stage(t);
    s.edge.down = true;
    shown = await runStep('revoked', s.options);
    assert.equal(shown.ok, false);
    assert.match(shown.lines.join('\n'), /not a revocation/);
  });

  test('without the revoked agent or its key: exit 2, nothing sent', async (t) => {
    const s = await stage(t);
    const lines: string[] = [];
    const env = { DEPLOY_OUT: s.deployOut, DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.options.keyFile };
    assert.equal(await main(['revoked'], env, (l) => void lines.push(l)), 2);
    assert.match(lines.join('\n'), /DNSID_REVOKED_AGENT_ID/);
    assert.equal(await main(['revoked'], { ...env, DNSID_REVOKED_AGENT_ID: SECOND }, (l) => void lines.push(l)), 2);
    assert.match(lines.join('\n'), /DNSID_REVOKED_AGENT_KEY_FILE is not set/);
    assert.equal(s.edge.requests.length, 0);
  });
});

describe('scripts/live/request.ts on a broken edge: each step says UNEXPECTED', () => {
  const fails = (shown: { ok: boolean; lines: string[] }) => {
    assert.equal(shown.ok, false, shown.lines.join('\n'));
    assert.match(shown.lines.at(-1) as string, /^✗ UNEXPECTED: expected /);
  };

  test('no verification at all: unsigned, tampered and claimed requests reach Demo Bank', async (t) => {
    const s = await stage(t);
    s.edge.fault = 'forward-everything';
    fails(await runStep('unsigned', s.options));
    fails(await runStep('tampered', s.options));
    fails(await runStep('claim', s.options));
  });

  test('forged identity headers reach Demo Bank', async (t) => {
    const s = await stage(t);
    s.edge.fault = 'keep-forged-headers';
    fails(await runStep('forged', s.options));
  });

  test('Demo Bank served the forged identity, or another agent than the signer', async (t) => {
    const s = await stage(t);
    for (const shownAs of [FORGED_IDENTITY, OTHER]) {
      const body = JSON.stringify({ bank: 'Demo Bank', synthetic: true, caller: { verifiedDomain: shownAs, governanceId: FIXTURE_GOVERNANCE } });
      const send = async () => ({ status: 200, headers: { 'cache-control': 'no-store' }, body, ms: 1 });
      fails(await runStep('forged', { ...s.options, send }));
      fails(await runStep('signed', { ...s.options, send }));
    }
  });

  test("a 403 that isn't the verifier's", async (t) => {
    const s = await stage(t);
    s.edge.fault = 'html-denials';
    fails(await runStep('unsigned', s.options));
    fails(await runStep('tampered', s.options));
  });

  test('the verifier down: the signed request gets the load balancer\'s 500', async (t) => {
    const s = await stage(t);
    s.edge.down = true;
    const signed = await runStep('signed', s.options);
    fails(signed);
    assert.match(signed.lines.join('\n'), /← 500/);
  });

  test('the other agent ACTIVE, RETIRED, or its status unreadable', async (t) => {
    const s = await stage(t);
    for (const status of [
      { kind: 'state' as const, state: 'ACTIVE', at: 'now' },
      { kind: 'state' as const, state: 'RETIRED', at: 'now' },
      { kind: 'unknown' as const, reason: 'the status document could not be read', at: 'now' },
    ]) {
      fails(await runStep('status', { ...s.options, agentStatus: async () => status }));
    }
  });
});

describe('scripts/live/request.ts as an executable', () => {
  test('missing or invalid inputs exit 2 with a reason, sending nothing', async (t) => {
    const s = await stage(t);
    const run = async (argv: string[], env: Record<string, string | undefined>) => {
      const lines: string[] = [];
      const code = await main(argv, env, (line) => void lines.push(line));
      return { code, text: lines.join('\n') };
    };
    const env = { DEPLOY_OUT: s.deployOut, DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.options.keyFile };
    assert.deepEqual(await run(['bogus'], env), { code: 2, text: 'request: usage: node scripts/live/request.ts unsigned|signed|tampered|forged|revoked | claim <agent> | status <agent>' });
    assert.deepEqual(await run(['status'], env), { code: 2, text: "request: status needs the other agent's domain" });
    assert.deepEqual(await run(['unsigned'], {}), { code: 2, text: 'request: DEPLOY_OUT is not set: the deployment record scripts/deploy.sh wrote' });
    assert.equal((await run(['signed'], { ...env, DNSID_AGENT_KEY_FILE: undefined })).code, 2);
    assert.equal((await run(['signed'], { ...env, DNSID_AGENT_ID: 'not a domain' })).code, 2);
    const badKey = join(tmpdir(), `request-bad-key-${process.pid}`);
    writeFileSync(badKey, 'not a key');
    t.after(() => rmSync(badKey, { force: true }));
    assert.equal((await run(['signed'], { ...env, DNSID_AGENT_KEY_FILE: badKey })).code, 2);
    assert.equal((await run(['claim', 'not a domain'], env)).code, 2);
    assert.equal(s.edge.requests.length, 0);
  });

  test('`node scripts/live/request.ts signed` against the edge: exit 0, and the key never printed', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const child = spawn(process.execPath, [join(ROOT, 'scripts/live/request.ts'), 'signed'], {
      env: { PATH: process.env['PATH'] ?? '', DEPLOY_OUT: s.deployOut, DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.options.keyFile as string },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (c: Buffer) => (output += c.toString()));
    child.stderr.on('data', (c: Buffer) => (output += c.toString()));
    const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
    // The fixture identity resolves only inside this process, so the child's own verifier lookup isn't involved: the
    // edge (in this process) verifies; the child only signs and sends.
    assert.equal(code, 0, output);
    assert.match(output, /✓ as expected: 200 with Demo Bank's data/);
    assertNoSecrets([output], s.keyD);
  });
});
