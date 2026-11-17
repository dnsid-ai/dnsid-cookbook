// The live tests' own tests (scripts/live/), against a FIXTURE EDGE (tests/support/live-edge.ts: the real verifier and
// Demo Bank behind a local HTTPS listener, NOT Google's load balancer) and a SIMULATED cloud (the governance change,
// the outage, the inventory and the request logs). Each case is seen to pass where the edge behaves as planned and to
// fail where it doesn't; a case that throws, an unknown answer, missing evidence or a failed restoration never passes.
// Agent keys are generated for the test and written to a temporary key file, as the portal would export them.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';

import { LocalKeyProvider } from '@dnsid-ai/sdk/node';
import { entryBundlePath } from '@dnsid-ai/log-c2sp-tlog';

import { accountsFor } from '../../origin/server.ts';
import { assembleDeployOut } from '../../scripts/lib/deploy-tool.ts';
import type { DeployOut } from '../../scripts/lib/deploy-out.ts';
import { inventoryFrom } from '../../scripts/lib/inventory.ts';
import { CASES, casesFor, isEdgeContentRefusal, type Clients } from '../../scripts/live/cases.ts';
import { commandRunner, connectCloud, originConfigFrom, verificationRecordsFrom, verifierConfigFrom, type Cloud } from '../../scripts/live/cloud.ts';
import { grpcCall, h1, h2, plain, type Exchange } from '../../scripts/live/http.ts';
import { checkAgentId, loadKeyProvider } from '../../scripts/live/signer.ts';
import { readLifecycleEvidence, type LifecycleEvidence } from '../../scripts/live/status.ts';
import { logWaitFromSetting, parseMode, RECOVERY_FILE, RecoveryError, runLive, type Report } from '../../scripts/live/test-live.ts';
import { createVerificationRuntime, governancePolicy } from '../../src/identity.ts';
import { createCalloutService } from '../../src/service.ts';
import { deployOutInputs, deploymentListings } from '../support/deploy-fixtures.ts';
import { FIXTURE_GOVERNANCE, fixtureBackend, fixtureLog, fixtureNetwork, issueIdentity, lifecycleEntry, type FixtureIdentity, type FixtureLog, type FixtureNetwork } from '../support/identity-fixture.ts';
import { fixtureEdge, type FixtureEdge } from '../support/live-edge.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const AGENT = 'agent-gov-fixture.test';
const OTHER = 'other-gov2-fixture.test';
const OTHER_GOVERNANCE = 'gov2-fixture.test';
const UNTRUSTED = 'untrusted-governance.invalid';

const EXPECTED_LIVE = [
  'deny-unsigned',
  'allow-trusted',
  'evidence-freshness',
  'deny-malformed-signature',
  'deny-tampered',
  'app-account-policy',
  'deny-other-identity',
  'deny-expired-signature',
  'fidelity-http1',
  'fidelity-http2',
  'fidelity-escaped-path',
  'fidelity-query-order',
  'fidelity-duplicate-headers',
  'deny-body-on-get',
  'deny-body-on-get-chunked',
  'deny-body-on-get-h2',
  'strip-spoofed-identity-headers',
  'replay-within-window',
  'deny-method',
  'deny-cache-reuse',
  'deny-bypass-run-app',
  'deny-bypass-http',
  'deny-bypass-uncovered-rule',
  'deny-bypass-dotdot',
  'deny-bypass-verifier',
  'deny-bypass-rewrite',
  'deny-untrusted-governance',
  'deny-verifier-down',
  'verification-timing',
  'deny-forged-identity',
];

interface Stage {
  edge: FixtureEdge;
  network: FixtureNetwork;
  log: FixtureLog;
  agent: FixtureIdentity;
  keyFile: string;
  keyD: string;
  out: DeployOut;
  dir: string;
}

/** The fixture edge, an agent whose key is in a key file, a second identity, and a DEPLOY_OUT that points at the edge. */
async function stage(t: TestContext): Promise<Stage> {
  const dir = mkdtempSync(join(tmpdir(), 'live-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const keyFile = join(dir, 'agent.jwk');
  writeFileSync(keyFile, JSON.stringify(jwk), { mode: 0o600 });
  const log = fixtureLog();
  const network = fixtureNetwork();
  const agent = await issueIdentity(log, AGENT, { operational: await LocalKeyProvider.fromFile(keyFile) });
  const other = await issueIdentity(log, OTHER, { governanceId: OTHER_GOVERNANCE });
  network.publish(agent);
  network.publish(other);
  const edge = await fixtureEdge(t, { network, log, trusted: [FIXTURE_GOVERNANCE, OTHER_GOVERNANCE], untrusted: UNTRUSTED });
  const inputs = deployOutInputs(edge.certificate, `https://127.0.0.1:${edge.port}`);
  const out = assembleDeployOut({
    ...inputs,
    governance: `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`,
    inventory: inventoryFrom(deploymentListings(), 'deploy.sh', new Date().toISOString()),
  });
  return { edge, network, log, agent, keyFile, keyD: String(jwk.d), out, dir };
}

/**
 * run.app and plain HTTP go to local stand-ins: Cloud Run's 404 for a disabled default URL (to a GET and to a gRPC
 * call alike), and no port 80. With `stage`, Demo Bank's run.app URL, while the simulated cloud has it open, reaches the
 * fixture's Demo Bank directly, as Cloud Run would.
 */
function clients(overrides: { runApp?: (url: string) => Exchange; http?: () => Exchange; grpc?: Clients['grpc']; stage?: Stage } = {}): Clients {
  const notFound: Exchange = { status: 404, headers: { 'content-type': 'text/html' }, body: '<html>Error: Page not found</html>', ms: 1 };
  return {
    h1,
    h2,
    async plain(url, spec) {
      if (url.startsWith('http://')) return overrides.http?.() ?? { headers: {}, body: '', error: 'ECONNREFUSED: connect ECONNREFUSED', ms: 1 };
      const s = overrides.stage;
      const origin = s?.out.bypass_routes.origin_run_app.find((base) => url.startsWith(`${base}/`));
      if (s !== undefined && origin !== undefined && s.edge.originExposed) return plain(`http://127.0.0.1:${s.edge.originPort}${url.slice(origin.length)}`, spec);
      return overrides.runApp?.(url) ?? notFound;
    },
    grpc: overrides.grpc ?? (async (url) => overrides.runApp?.(url) ?? notFound),
  };
}

/** A simulated cloud over the fixture edge: governance and scaling changes act on the edge, logs come from its records. */
function cloud(
  s: Stage,
  faults: {
    restoreFails?: 'governance' | 'scaling' | 'log-evidence' | 'origin-exposure';
    /** Opening Demo Bank's URL is accepted but never takes effect. */
    exposureIgnored?: boolean;
    originNoise?: boolean;
    logsSilent?: boolean;
    logsLateReads?: number;
    hideControl?: boolean;
    /** The verifier's records: some never arrive, or lose a field, or the full-scan setting never takes effect. */
    records?: 'drop-last' | 'no-elapsed' | 'over-budget' | 'scan-ignored' | 'unreadable' | 'all-hit';
  } = {},
): Cloud & { calls: string[] } {
  let reads = 0;
  const calls: string[] = [];
  let logEvidence: string | undefined;
  return {
    calls,
    login: 'simulated',
    async inventory() {
      calls.push('inventory');
      return inventoryFrom(deploymentListings(), 'test-live.sh', new Date().toISOString());
    },
    async setVerifierScaling(mode) {
      calls.push(`scaling ${mode}`);
      if (mode === 'auto' && faults.restoreFails === 'scaling') throw new Error('simulated: the update was refused');
      s.edge.down = mode === 'zero';
    },
    async setGovernance(value) {
      calls.push(`governance ${value}`);
      if (value !== UNTRUSTED && faults.restoreFails === 'governance') throw new Error('simulated: the update was refused');
      s.edge.governance = value === UNTRUSTED ? 'untrusted' : 'trusted';
    },
    async setLogEvidence(mode) {
      calls.push(`log-evidence ${mode}`);
      if (mode === 'default' && faults.restoreFails === 'log-evidence') throw new Error('simulated: the update was refused');
      logEvidence = mode === 'full-scan' ? 'full-scan' : undefined;
      // Each update is a new revision: its instances start with nothing cached.
      await s.edge.newRevision();
    },
    async verifierConfig() {
      calls.push('describe');
      return { governance: s.edge.governance === 'trusted' ? s.out.trusted_governance : UNTRUSTED, scaling: s.edge.down ? 'zero' : 'auto', logEvidence };
    },
    async setOriginExposure(mode) {
      calls.push(`origin-exposure ${mode}`);
      if (mode === 'closed' && faults.restoreFails === 'origin-exposure') throw new Error('simulated: the update was refused');
      if (mode === 'open' && faults.exposureIgnored) return;
      s.edge.originExposed = mode === 'open';
    },
    async originConfig() {
      calls.push('describe-origin');
      return s.edge.originExposed ? { ingress: 'all', defaultUrlDisabled: false } : { ingress: 'internal-and-cloud-load-balancing', defaultUrlDisabled: true };
    },
    async originRequests(since, until) {
      if (faults.logsSilent) return 0;
      // A slow log: the first reads show nothing at all.
      if (faults.logsLateReads !== undefined && reads++ < faults.logsLateReads) return 0;
      // A log that never received the last request: records stop before the control.
      const last = faults.hideControl ? s.edge.originRecords.length - 1 : s.edge.originRecords.length;
      const n = s.edge.originRecords.slice(0, last).filter((r) => r.at >= since && r.at <= until).length;
      return faults.originNoise ? n + 1 : n;
    },
    async verificationRecords(since, until, domain) {
      if (faults.records === 'unreadable') throw new Error('simulated: logging.read refused');
      // The fixture's test log has no stream bundles: every real record says full-scan. Outside the full-scan setting
      // they are shown as the deployed default would be (trusted-index), unless the setting is to be seen as ignored.
      const found = s.edge.verifierRecords
        .filter((r) => r.outcome === 'continue_submitted' && r.verified?.domain === domain && r.at >= since && r.at <= until)
        .map((r) => ({
          jsonPayload: {
            ...r,
            ...(faults.records === 'no-elapsed' ? { elapsedMs: undefined } : {}),
            ...(faults.records === 'over-budget' ? { elapsedMs: 2_600 } : {}),
            verified: {
              ...r.verified,
              completenessMode: logEvidence === 'full-scan' && faults.records !== 'scan-ignored' ? 'full-scan' : 'trusted-index',
              // As if every revision had been warmed before its first measured request.
              ...(faults.records === 'all-hit' ? { materialCache: 'hit' } : {}),
            },
          },
          timestamp: r.at,
        }));
      return verificationRecordsFrom(faults.records === 'drop-last' ? found.slice(0, -1) : found);
    },
    close() {},
  };
}

const fast = { sleep: async () => {}, settle: { timeoutMs: 3_000, intervalMs: 50 }, logWaitMs: 500, quietGapMs: 100, log: process.env['LIVE_TEST_DEBUG'] ? (l: string) => console.error(l) : () => {} };

async function live(
  s: Stage,
  options: {
    mode?: 'live' | 'allow' | 'revoked';
    cloud?: Cloud | undefined;
    http?: Clients;
    agent?: string;
    otherAgent?: string | undefined;
    interrupt?: AbortSignal;
    cloudTimeoutMs?: number;
    settleGraceMs?: number;
    recoveryFile?: string;
  } = {},
): Promise<Report> {
  return runLive({
    // The agent's status document and log history, read the way the live tests do, from the fixture network and log
    // instead of the internet.
    lifecycle: (domain) => readLifecycleEvidence(domain, s.out.trusted_governance, fixtureBackend(s.network, s.log)),
    ...(options.interrupt === undefined ? {} : { interrupt: options.interrupt }),
    ...(options.cloudTimeoutMs === undefined ? {} : { cloudTimeoutMs: options.cloudTimeoutMs }),
    settleGraceMs: options.settleGraceMs ?? 1_000,
    ...(options.recoveryFile === undefined ? {} : { recoveryFile: options.recoveryFile }),
    mode: options.mode ?? 'live',
    out: s.out,
    agent: options.agent ?? AGENT,
    keyFile: s.keyFile,
    otherAgent: 'otherAgent' in options ? options.otherAgent : OTHER,
    cloud: 'cloud' in options ? options.cloud : cloud(s),
    http: options.http ?? clients({ stage: s }),
    ...fast,
  });
}

const byId = (report: Report) => Object.fromEntries(report.cases.map((c) => [c.id, c]));
const failing = (report: Report) => report.cases.filter((c) => !c.pass).map((c) => c.id);

describe('the live cases against a fixture edge that behaves as planned', () => {
  test('MODE=live: every live case, with the matrix IDs, passes; each record has its EDGE or ADD row, what was expected and seen', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const report = await live(s, { cloud: c });
    assert.deepEqual(report.cases.map((r) => r.id), EXPECTED_LIVE);
    assert.deepEqual(failing(report), [], JSON.stringify(report.cases.filter((r) => !r.pass), null, 1));
    for (const r of report.cases) {
      assert.match(r.edge, /^(EDGE-0[1-9]|EDGE-10|ADD-0[1-9])$/);
      assert.ok(r.expect.length > 10 && r.got.length > 0 && r.detail.length > 0, r.id);
      assert.equal(typeof r.ms, 'number');
    }
    assert.equal(report.restoration_failed, false);
    // The deployment was changed and put back, in that order, and is back as it was.
    assert.deepEqual(
      c.calls.filter((x) => x !== 'inventory'),
      // Each restoration is read back from the verifier's configuration before and after the edge shows it.
      [
        `governance ${UNTRUSTED}`,
        `governance ${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`,
        'describe',
        'describe',
        'scaling zero',
        'scaling auto',
        'describe',
        'describe',
        'log-evidence full-scan',
        'log-evidence default',
        'describe',
        'describe',
        'origin-exposure open',
        'origin-exposure closed',
        'describe-origin',
        'describe-origin',
      ],
    );
    assert.equal(s.edge.down, false);
    assert.equal(s.edge.governance, 'trusted');
    const cases = byId(report);
    assert.match(cases['deny-unsigned']?.detail ?? '', /Demo Bank's request log: 0 request\(s\) during this case/);
    assert.match(cases['allow-trusted']?.detail ?? '', /5 more GETs 200,200,200,200,200 in [\d/]+ ms round trip/);
    // The verifier's own records, one per served request, each complete.
    const record = '\\d+ ms, (trusted-index|full-scan), cache (hit|miss|partial), evidence -?\\d+ ms old';
    assert.match(cases['evidence-freshness']?.detail ?? '', new RegExp(`^verifier records: #1 ${record}; #2 ${record}; #3 ${record}$`));
    assert.match(cases['verification-timing']?.detail ?? '', new RegExp(`^deployed configuration: #1 ${record}(; #\\d ${record}){4}; new revision's first request: \\d+ ms, full-scan, cache miss, evidence -?\\d+ ms old; full scan \\(200,200,200\\): #1 \\d+ ms, full-scan, cache \\w+, evidence -?\\d+ ms old(; #\\d \\d+ ms, full-scan, [^;]+){2}; DNSID_LOG_EVIDENCE removed: 200 `));
    assert.match(cases['deny-verifier-down']?.detail ?? '', /verifier at zero instances: 500 /);
    assert.match(cases['deny-untrusted-governance']?.detail ?? '', /403 verifier denial governance_not_trusted/);
    assert.match(cases['fidelity-http2']?.detail ?? '', /over h2/);
    assert.match(cases['replay-within-window']?.detail ?? '', /replay within the window is accepted, as documented/);
    // Demo Bank itself refused the forged identity, and its URL is closed again.
    assert.equal(cases['deny-forged-identity']?.got, '403 then 403,403 then 404');
    assert.match(
      cases['deny-forged-identity']?.detail ?? '',
      /opened: 403 Demo Bank error "\{\\"error\\":\\"identity_context_required\\"\}" .*; forged identity, no attestation: 403 Demo Bank error "\{\\"error\\":\\"identity_attestation_required\\"\}" .*; forged identity, forged attestation: 403 Demo Bank error "\{\\"error\\":\\"identity_attestation_invalid\\"\}" .*; closed again: 404 /,
    );
    assert.equal(s.edge.originExposed, false);
    assert.deepEqual(s.edge.originRecords.filter((r) => r.outcome.startsWith('attestation_')).map((r) => [r.outcome, r.verifiedDomain]), [
      ['attestation_missing', undefined],
      ['attestation_invalid', undefined],
    ]);
  });

  test("an edge that behaves as Google's did on the live deployment of 2026-11-14: content refused with its own 400 before the verifier, %61 decoded before the verifier and Demo Bank; those cases pass and say so", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    s.edge.refusesContent = true;
    s.edge.decodesUnreserved = true;
    const report = await live(s, { cloud: undefined });
    const cases = byId(report);
    for (const id of ['deny-body-on-get', 'deny-body-on-get-chunked', 'deny-body-on-get-h2', 'fidelity-escaped-path']) assert.equal(cases[id]?.pass, true, JSON.stringify(cases[id]));
    assert.match(cases['deny-body-on-get']?.detail ?? '', /^400 load balancer refusal over http\/1\.1/);
    assert.match(cases['deny-body-on-get-h2']?.detail ?? '', /GET \+ DATA: 400 load balancer refusal over h2 .*HEAD \+ DATA: 400 load balancer refusal \(no body\) over h2/);
    assert.equal(cases['fidelity-escaped-path']?.got, '200,404,403,200');
    assert.match(cases['fidelity-escaped-path']?.detail ?? '', /the load balancer decoded %61 before the verifier and Demo Bank: a signer signs the normalized path$/);
    // The refusals were the edge's own: no request with content reached the verifier.
    assert.equal(s.edge.verifierRecords.filter((r) => r.reason === 'body_indicated' || r.reason === 'body_not_ruled_out').length, 0);
  });

  test('MODE=allow runs allow-trusted alone; MODE=revoked runs deny-revoked alone', async (t) => {
    const s = await stage(t);
    const allow = await live(s, { mode: 'allow', cloud: undefined });
    assert.deepEqual(allow.cases.map((r) => [r.id, r.pass]), [['allow-trusted', true]]);
    s.network.publish(s.agent, 'REVOKED');
    const revoked = await live(s, { mode: 'revoked', cloud: undefined });
    assert.deepEqual(revoked.cases.map((r) => [r.id, r.edge, r.pass]), [['deny-revoked', 'EDGE-05', true]]);
    assert.match(revoked.cases[0]?.detail ?? '', /403 verifier denial identity_inactive .*status document reports REVOKED/);
    assert.deepEqual(casesFor('live').filter((c) => c.id === 'deny-revoked'), []);
  });

  test("no platform login: the cases that change the deployment, and those that need Demo Bank's log as evidence, fail and say why; the inventory is deploy.sh's; the rest pass", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const report = await live(s, { cloud: undefined });
    assert.deepEqual(failing(report), ['deny-unsigned', 'evidence-freshness', 'deny-malformed-signature', 'deny-tampered', 'deny-untrusted-governance', 'deny-verifier-down', 'verification-timing', 'deny-forged-identity']);
    const cases = byId(report);
    assert.match(cases['deny-forged-identity']?.detail ?? '', /needs the platform login to open and close Demo Bank's own URL/);
    assert.match(cases['deny-untrusted-governance']?.detail ?? '', /needs the platform login/);
    assert.match(cases['evidence-freshness']?.detail ?? '', /needs the platform login to read the verifier's log records/);
    assert.match(cases['verification-timing']?.detail ?? '', /needs the platform login/);
    assert.match(cases['deny-bypass-uncovered-rule']?.detail ?? '', /inventory from deploy\.sh at /);
    for (const id of ['deny-unsigned', 'deny-malformed-signature', 'deny-tampered']) {
      // The edge's answer was right; the evidence that Demo Bank wasn't invoked is what's missing.
      assert.match(cases[id]?.detail ?? '', /403 verifier denial/, id);
      assert.match(cases[id]?.detail ?? '', /request log not read \(no platform login\): the evidence that Demo Bank was not invoked is missing/, id);
    }
    assert.equal(report.origin_log_control, undefined);
    assert.equal(report.cloud_login, 'none');
  });
});

describe('the live cases catch an edge that does not behave as planned', () => {
  test('no verification at all: every denial case fails', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    s.edge.fault = 'forward-everything';
    const report = await live(s, { cloud: undefined });
    const failed = failing(report);
    for (const id of ['deny-unsigned', 'deny-malformed-signature', 'deny-tampered', 'deny-other-identity', 'deny-expired-signature', 'deny-body-on-get', 'deny-body-on-get-chunked', 'deny-body-on-get-h2', 'deny-method', 'deny-cache-reuse', 'fidelity-duplicate-headers']) {
      assert.ok(failed.includes(id), id);
    }
  });

  test('forged identity headers reaching Demo Bank fail strip-spoofed-identity-headers', async (t) => {
    const s = await stage(t);
    s.edge.fault = 'keep-forged-headers';
    const report = await live(s, { cloud: undefined });
    assert.equal(byId(report)['strip-spoofed-identity-headers']?.pass, false);
  });

  test('a `..` path forwarded instead of redirected fails deny-bypass-dotdot', async (t) => {
    const s = await stage(t);
    s.edge.fault = 'forward-dotdot';
    assert.equal(byId(await live(s, { cloud: undefined }))['deny-bypass-dotdot']?.pass, false);
  });

  test("denials that aren't the verifier's own (an HTML 403) fail every denial case", async (t) => {
    const s = await stage(t);
    s.edge.fault = 'html-denials';
    const failed = failing(await live(s, { cloud: undefined }));
    for (const id of ['deny-unsigned', 'deny-malformed-signature', 'deny-tampered', 'deny-expired-signature', 'deny-method', 'deny-body-on-get']) assert.ok(failed.includes(id), id);
  });

  test('an edge that keeps %61 passes fidelity-escaped-path the other way; one that verifies the path as sent and gives Demo Bank it decoded fails', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const kept = byId(await live(s, { cloud: undefined }))['fidelity-escaped-path'];
    assert.equal(kept?.pass, true, kept?.detail);
    assert.equal(kept?.got, '200,404,404,403');
    assert.match(kept?.detail ?? '', /the load balancer kept %61: the verifier and Demo Bank saw the path as sent$/);
    s.edge.fault = 'decode-for-origin-only';
    const split = byId(await live(s, { cloud: undefined }))['fidelity-escaped-path'];
    assert.equal(split?.pass, false);
    assert.match(split?.detail ?? '', /\/%61ccounts signed as sent: 200 Demo Bank data.*the verifier and Demo Bank did not see the same path$/);
  });

  test("a 400 is the load balancer's refusal only when it isn't Demo Bank's (no-store JSON) or a verifier denial", () => {
    const lb: Exchange = { status: 400, headers: { 'content-type': 'text/html; charset=UTF-8' }, body: '<html>Error 400 (Bad Request)</html>', ms: 1 };
    assert.equal(isEdgeContentRefusal(lb), true);
    assert.equal(isEdgeContentRefusal({ ...lb, body: '' }), true);
    assert.equal(isEdgeContentRefusal({ ...lb, status: 403 }), false);
    assert.equal(isEdgeContentRefusal({ ...lb, status: 200 }), false);
    assert.equal(isEdgeContentRefusal({ ...lb, headers: { 'content-type': 'application/json; charset=utf-8' } }), false);
    assert.equal(isEdgeContentRefusal({ ...lb, headers: { ...lb.headers, 'cache-control': 'no-store' } }), false);
  });

  test('a cached response served to unsigned requests fails deny-cache-reuse', async (t) => {
    const s = await stage(t);
    s.edge.fault = 'cache';
    assert.equal(byId(await live(s, { cloud: undefined }))['deny-cache-reuse']?.pass, false);
  });

  test('HTTP/2 content the end of stream does not reveal (always set) fails deny-body-on-get-h2; length headers still deny the HTTP/1.1 ones', async (t) => {
    const s = await stage(t);
    s.edge.fault = 'eos-always';
    const cases = byId(await live(s, { cloud: undefined }));
    assert.equal(cases['deny-body-on-get-h2']?.pass, false);
    assert.match(cases['deny-body-on-get']?.detail ?? '', /body_indicated/);
    assert.match(cases['deny-body-on-get-chunked']?.detail ?? '', /body_indicated/);
  });

  test("an open run.app URL, an answer on port 80, or Demo Bank's data on the verifier's URL fails the bypass case", async (t) => {
    const s = await stage(t);
    const bank: Exchange = { status: 200, headers: { 'cache-control': 'no-store' }, body: '{"bank":"Demo Bank","synthetic":true}', ms: 1 };
    let report = await live(s, { cloud: undefined, http: clients({ runApp: () => bank }) });
    assert.equal(byId(report)['deny-bypass-run-app']?.pass, false);
    assert.equal(byId(report)['deny-bypass-verifier']?.pass, false);
    report = await live(s, { cloud: undefined, http: clients({ http: () => bank }) });
    assert.equal(byId(report)['deny-bypass-http']?.pass, false);
    const grpc: Exchange = { status: 200, headers: { 'content-type': 'application/grpc' }, body: '', ms: 1 };
    report = await live(s, { cloud: undefined, http: clients({ runApp: () => grpc }) });
    assert.equal(byId(report)['deny-bypass-verifier']?.pass, false);
    // A grpc-status alone (a trailers-only answer), or a 200 carrying a message, is an answer too.
    const status: Exchange = { status: 200, headers: { 'grpc-status': '0' }, body: '', ms: 1 };
    const message: Exchange = { status: 200, headers: {}, body: '\u0000\u0000\u0000\u0000\u0002\u0008\u0001', ms: 1 };
    for (const answer of [status, message]) {
      report = await live(s, { cloud: undefined, http: clients({ grpc: async () => answer }) });
      assert.equal(byId(report)['deny-bypass-verifier']?.pass, false, JSON.stringify(answer));
    }
  });

  test("the disabled verifier URL as Google's front end answered it on the live deployment of 2026-11-14 (404 to GET /, an empty 200 with no gRPC framing or status to the gRPC call) is closed; an empty 200 to GET / is not", async (t) => {
    const s = await stage(t);
    const notFound: Exchange = { status: 404, headers: {}, body: '', ms: 1 };
    const empty: Exchange = { status: 200, headers: {}, body: '', protocol: 'h2', ms: 1 };
    let verifier = byId(await live(s, { cloud: undefined, http: clients({ runApp: () => notFound, grpc: async () => empty }) }))['deny-bypass-verifier'];
    assert.equal(verifier?.pass, true, verifier?.detail);
    assert.match(verifier?.detail ?? '', /ExternalProcessor\/Process gRPC: 200 body "" over h2 in 1 ms; content-type null, grpc-status null/);
    verifier = byId(await live(s, { cloud: undefined, http: clients({ runApp: () => empty, grpc: async () => notFound }) }))['deny-bypass-verifier'];
    assert.equal(verifier?.pass, false);
  });

  test("the disabled verifier URL as Google's front end answered the gRPC call on the second live deployment of 2026-11-14 (an empty trailers-only 200, content-type application/grpc, grpc-status 12) is closed; the verifier's own grpc-status 12 is not", { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const notFound: Exchange = { status: 404, headers: {}, body: '', ms: 1 };
    const front: Exchange = { status: 200, headers: { 'content-type': 'application/grpc', 'grpc-status': '12' }, body: '', protocol: 'h2', ms: 1 };
    let verifier = byId(await live(s, { cloud: undefined, http: clients({ runApp: () => notFound, grpc: async () => front }) }))['deny-bypass-verifier'];
    assert.equal(verifier?.pass, true, verifier?.detail);
    assert.match(verifier?.detail ?? '', /content-type "application\/grpc", grpc-status "12"/);
    // Any other status, a message, or the verifier's own content type is an answer.
    for (const answer of [
      { ...front, headers: { ...front.headers, 'grpc-status': '0' } },
      { ...front, headers: { ...front.headers, 'grpc-status': '13' } },
      { ...front, body: '\u0000\u0000\u0000\u0000\u0002\u0008\u0001' },
      { ...front, headers: { ...front.headers, 'content-type': 'application/grpc+proto' } },
    ]) {
      verifier = byId(await live(s, { cloud: undefined, http: clients({ runApp: () => notFound, grpc: async () => answer }) }))['deny-bypass-verifier'];
      assert.equal(verifier?.pass, false, JSON.stringify(answer));
    }
    // The real verifier on loopback, asked for a method it doesn't serve, answers grpc-status 12 itself: not closed.
    const service = createCalloutService({
      runtime: createVerificationRuntime({ governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]), backend: fixtureBackend(s.network, s.log) }),
      log: () => {},
      shutdownGraceMs: 100,
    });
    const port = await service.listen('127.0.0.1', 0);
    t.after(() => service.shutdown());
    const own = await grpcCall(`http://127.0.0.1:${port}`, '/envoy.service.ext_proc.v3.ExternalProcessor/Unknown');
    assert.equal(own.headers['grpc-status'], '12', JSON.stringify(own));
    verifier = byId(await live(s, { cloud: undefined, http: clients({ runApp: () => notFound, grpc: async () => own }) }))['deny-bypass-verifier'];
    assert.equal(verifier?.pass, false, verifier?.detail);
  });

  test('an uncovered forwarding rule, a URL rewrite or Cloud CDN in the inventory fails its case', async (t) => {
    const s = await stage(t);
    const listings = deploymentListings();
    const n = 'dnsid-gse-0a1b2c3d';
    const self = 'https://www.googleapis.com/compute/v1/projects/sandbox-project-1';
    listings.forwardingRules.push({ name: 'side', selfLink: `${self}/global/forwardingRules/side`, target: `${self}/global/targetHttpsProxies/${n}-https-proxy`, IPAddress: '198.51.100.9', portRange: '443-443', loadBalancingScheme: 'EXTERNAL_MANAGED' });
    (listings.urlMaps[0] as Record<string, unknown>)['defaultRouteAction'] = { urlRewrite: { pathPrefixRewrite: '/' } };
    (listings.backendServices[0] as Record<string, unknown>)['enableCDN'] = true;
    const c = cloud(s);
    c.inventory = async () => inventoryFrom(listings, 'test-live.sh', new Date().toISOString());
    const cases = byId(await live(s, { cloud: c }));
    assert.equal(cases['deny-bypass-uncovered-rule']?.pass, false);
    assert.equal(cases['deny-bypass-rewrite']?.pass, false);
    assert.equal(cases['deny-cache-reuse']?.pass, false);
  });

  test('a DNSid CUSTOM policy with HTTP rules covers only matching requests: not counted, so the coverage case fails', async (t) => {
    const s = await stage(t);
    for (const rules of [[{ to: { operations: [{ paths: [{ exact: '/health' }] }] } }], [{ when: 'request.path != "/accounts"' }], 'unexpected']) {
      const listings = deploymentListings();
      (listings.policies[0] as Record<string, unknown>)['httpRules'] = rules;
      const c = cloud(s);
      c.inventory = async () => inventoryFrom(listings, 'test-live.sh', new Date().toISOString());
      const report = await live(s, { cloud: c, mode: 'live' });
      const coverage = byId(report)['deny-bypass-uncovered-rule'];
      assert.equal(coverage?.pass, false, JSON.stringify(rules));
      assert.match(coverage?.detail ?? '', /not counted for having HTTP rules or none recorded: [^;]*authz-policy \(1\)/);
    }
  });

  test('a recorded inventory whose policy entries lack the HTTP rule count is not taken as coverage', async (t) => {
    const s = await stage(t);
    const recorded = s.out.inventory as unknown as { policies: Record<string, unknown>[] };
    const out = { ...s.out, inventory: { ...recorded, policies: recorded.policies.map(({ httpRules: _, ...rest }) => rest) } } as unknown as DeployOut;
    const report = await runLive({ mode: 'live', out, agent: AGENT, keyFile: s.keyFile, otherAgent: OTHER, cloud: undefined, http: clients(), ...fast, lifecycle: async () => ({ status: { kind: 'unknown', reason: 'unused', at: '' }, log: { kind: 'unknown', reason: 'unused', at: '' } }) });
    assert.equal(byId(report)['deny-bypass-uncovered-rule']?.pass, false);
    assert.match(byId(report)['deny-bypass-uncovered-rule']?.detail ?? '', /\(unrecorded\)/);
  });

  test("an exposed verifier that refuses GET / but answers gRPC on ExternalProcessor/Process fails deny-bypass-verifier", { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    // The real verifier service, plaintext HTTP/2 on loopback, standing in for a run.app URL left open.
    const service = createCalloutService({
      runtime: createVerificationRuntime({ governance: governancePolicy([{ governanceId: FIXTURE_GOVERNANCE }]), backend: fixtureBackend(s.network, s.log) }),
      log: () => {},
      shutdownGraceMs: 100,
    });
    const port = await service.listen('127.0.0.1', 0);
    t.after(() => service.shutdown());
    const local = `http://127.0.0.1:${port}`;
    const get = await plain(`${local}/`, { method: 'GET' });
    assert.ok(get.error !== undefined || (get.status ?? 0) >= 300, `GET / is refused: ${JSON.stringify(get)}`);
    const exposed = clients({ runApp: (url) => (url.endsWith('/') ? get : { headers: {}, body: '', error: 'unused', ms: 0 }), grpc: (_url, path) => grpcCall(local, path) });
    const report = await live(s, { cloud: undefined, http: exposed });
    const verifier = byId(report)['deny-bypass-verifier'];
    assert.equal(verifier?.pass, false);
    assert.match(verifier?.detail ?? '', /envoy\.service\.ext_proc\.v3\.ExternalProcessor\/Process gRPC: 200 /);
    // Cloud Run's 404 to both the GET and the gRPC call: closed.
    assert.equal(byId(await live(s, { cloud: undefined }))['deny-bypass-verifier']?.pass, true);
  });

  const QUIET = ['deny-unsigned', 'deny-malformed-signature', 'deny-tampered', 'deny-verifier-down'];

  test("Demo Bank's log showing a request during a denial or the outage, or never showing the control, fails those cases", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    let failed = failing(await live(s, { cloud: cloud(s, { originNoise: true }) }));
    for (const id of QUIET) assert.ok(failed.includes(id), id);
    const report = await live(s, { cloud: cloud(s, { logsSilent: true }) });
    failed = failing(report);
    for (const id of QUIET) assert.ok(failed.includes(id), id);
    assert.match(byId(report)['deny-verifier-down']?.detail ?? '', /did not show the control request .* so its silence proves nothing/);
  });

  test('the outage window is checked: a request reaching Demo Bank while the verifier is down fails deny-verifier-down', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const set = c.setVerifierScaling.bind(c);
    // While down, something reaches Demo Bank (as a fail-open load balancer would): its log shows it.
    c.setVerifierScaling = async (mode, signal) => {
      await set(mode, signal);
      if (mode === 'zero') s.edge.originRecords.push({ ...s.edge.originRecords[0]!, at: new Date().toISOString() });
    };
    const cases = byId(await live(s, { cloud: c }));
    assert.equal(cases['deny-verifier-down']?.pass, false);
    assert.match(cases['deny-verifier-down']?.detail ?? '', /Demo Bank's request log: 1 request\(s\) during this case/);
    assert.equal(cases['deny-unsigned']?.pass, true);
  });

  test('a slow log is waited for: the control appears after some reads, and the windows are then judged', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const report = await live(s, { cloud: cloud(s, { logsLateReads: 3 }) });
    assert.deepEqual(failing(report), []);
    assert.equal(report.origin_log_control?.ok, true);
    for (const id of QUIET) assert.match(byId(report)[id]?.detail ?? '', /request log: 0 request\(s\) during this case/, id);
  });

  test("an earlier allowed request in the log is not the control: a log that never received the final control proves nothing", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    // Every record but the last (the control's) is in the log: allow-trusted's and the restorations' requests are there.
    const report = await live(s, { cloud: cloud(s, { hideControl: true }) });
    for (const id of QUIET) assert.ok(failing(report).includes(id), id);
    assert.ok(report.origin_log_control !== undefined && report.origin_log_control.started_at > (byId(report)['deny-verifier-down']?.finished_at ?? ''));
  });

  test('a restoration that fails is reported: the case fails and the report says the deployment was not restored', { timeout: 120_000 }, async (t) => {
    for (const restoreFails of ['governance', 'scaling'] as const) {
      const s = await stage(t);
      const report = await live(s, { cloud: cloud(s, { restoreFails }) });
      const id = restoreFails === 'governance' ? 'deny-untrusted-governance' : 'deny-verifier-down';
      assert.equal(byId(report)[id]?.pass, false);
      assert.match(byId(report)[id]?.detail ?? '', /RESTORATION FAILED: simulated: the update was refused/);
      assert.equal(report.restoration_failed, true);
    }
  });

  test('a governance change or an outage that never shows at the edge fails, and is still restored', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    c.setGovernance = async (value) => void c.calls.push(`governance ${value}`); // the change never takes effect
    c.setVerifierScaling = async (mode) => void c.calls.push(`scaling ${mode}`);
    const cases = byId(await live(s, { cloud: c }));
    assert.equal(cases['deny-untrusted-governance']?.pass, false);
    assert.equal(cases['deny-verifier-down']?.pass, false);
    assert.ok(c.calls.includes(`governance ${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`) && c.calls.includes('scaling auto'));
  });

  test('deny-revoked passes only with the status document reporting REVOKED: RETIRED or another inactive state gives the same 403 and fails', async (t) => {
    const s = await stage(t);
    s.network.publish(s.agent, 'REVOKED');
    let report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, true, report.cases[0]?.detail);
    assert.match(report.cases[0]?.detail ?? '', /403 verifier denial identity_inactive .*status document reports REVOKED \(read [^)]+\); authenticated log history ends ACTIVE, 1 event\(s\) \(read [^)]+\): revocation identified by the status document$/);
    assert.equal(report.cases[0]?.got, '403 identity_inactive status=REVOKED log=ACTIVE');
    for (const state of ['RETIRED'] as const) {
      s.network.publish(s.agent, state);
      report = await live(s, { mode: 'revoked', cloud: undefined });
      assert.equal(report.cases[0]?.pass, false, state);
      assert.match(report.cases[0]?.detail ?? '', new RegExp(`identity_inactive .*status document reports ${state} \\(read [^)]+\\).*: not evidence of revocation`));
    }
  });

  test('deny-revoked: a signed REVOCATION in the log, status still ACTIVE, is refused by the log check first (identity_invalid) and identified by the authenticated history', async (t) => {
    const s = await stage(t);
    s.log.append(await lifecycleEntry(s.agent, 'REVOCATION'));
    const report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, true, report.cases[0]?.detail);
    assert.equal(report.cases[0]?.got, '403 identity_invalid status=unknown log=REVOKED');
    assert.match(report.cases[0]?.detail ?? '', /authenticated log history ends REVOKED \(keyCompromise\) since [^,]+, 2 event\(s\).*: revocation identified by the authenticated log history$/);
  });

  test('deny-revoked: revoked in the log and the status document together (what a portal revocation changes) passes', async (t) => {
    const s = await stage(t);
    s.log.append(await lifecycleEntry(s.agent, 'REVOCATION'));
    s.network.publish(s.agent, 'REVOKED');
    const report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, true, report.cases[0]?.detail);
    assert.match(report.cases[0]?.got ?? '', /^403 identity_(invalid|inactive) status=REVOKED log=REVOKED$/);
  });

  test('deny-revoked: a logged RETIREMENT, a tampered or unreachable log, and a log refusal without log evidence are not revocations', async (t) => {
    // Retired in the log: the same identity_invalid, but RETIRED.
    let s = await stage(t);
    s.log.append(await lifecycleEntry(s.agent, 'RETIREMENT'));
    let report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, false);
    assert.match(report.cases[0]?.detail ?? '', /identity_invalid .*log history ends RETIRED.*not evidence of revocation .*RETIRED is never a revocation/);
    // The edge refuses for identity_invalid, but the history the judge reads can't be verified (tampered or unreachable).
    for (const fault of ['tampered', 'unreachable'] as const) {
      s = await stage(t);
      s.log.append(await lifecycleEntry(s.agent, 'REVOCATION'));
      // The edge has already answered when the judge reads: only then does the log change.
      const verify = async (domain: string): Promise<LifecycleEvidence> => {
        const url = entryBundlePath(s.log.prefix, 0, s.log.entries.length);
        if (fault === 'unreachable') s.log.override(url, { status: 0 });
        else {
          const bundle = await s.log.fetcher.fetchBounded(url, 1 << 20, { timeoutMs: 1000 });
          const tampered = new Uint8Array(bundle);
          const at = new TextDecoder().decode(bundle).lastIndexOf('"sig":"') + 12;
          tampered[at] = tampered[at] === 0x41 ? 0x42 : 0x41;
          s.log.override(url, { status: 200, body: tampered });
        }
        return readLifecycleEvidence(domain, s.out.trusted_governance, fixtureBackend(s.network, s.log));
      };
      report = await runLive({ mode: 'revoked', out: s.out, agent: AGENT, keyFile: s.keyFile, otherAgent: undefined, cloud: undefined, http: clients(), ...fast, lifecycle: verify });
      assert.equal(report.cases[0]?.pass, false, fault);
      assert.match(report.cases[0]?.detail ?? '', /identity_invalid .*log history not established: .*not evidence of revocation \(identity_invalid needs the authenticated log history to show REVOKED\)/, fault);
    }
    // identity_invalid with a status document saying REVOKED but a log showing ACTIVE: the status can't explain a log refusal.
    s = await stage(t);
    s.log.append(await lifecycleEntry(s.agent, 'REVOCATION'));
    report = await runLive({
      mode: 'revoked', out: s.out, agent: AGENT, keyFile: s.keyFile, otherAgent: undefined, cloud: undefined, http: clients(), ...fast,
      lifecycle: async () => ({ status: { kind: 'state', state: 'REVOKED', at: 'now' }, log: { kind: 'logged', state: 'ACTIVE', events: 1, at: 'now' } }),
    });
    assert.equal(report.cases[0]?.pass, false);
    // Sources that contradict each other: one says REVOKED, the other RETIRED. Never counted, whichever reason the edge gave.
    for (const [publish, lifecycle] of [
      ['REVOKED', { status: { kind: 'state', state: 'REVOKED', at: 'now' }, log: { kind: 'logged', state: 'RETIRED', events: 2, at: 'now' } }],
      [undefined, { status: { kind: 'state', state: 'RETIRED', at: 'now' }, log: { kind: 'logged', state: 'REVOKED', reason: 'keyCompromise', events: 2, at: 'now' } }],
    ] as const) {
      s = await stage(t);
      if (publish === undefined) s.log.append(await lifecycleEntry(s.agent, 'REVOCATION'));
      else s.network.publish(s.agent, publish);
      report = await runLive({ mode: 'revoked', out: s.out, agent: AGENT, keyFile: s.keyFile, otherAgent: undefined, cloud: undefined, http: clients(), ...fast, lifecycle: async () => lifecycle as LifecycleEvidence });
      assert.equal(report.cases[0]?.pass, false, JSON.stringify(lifecycle));
      assert.match(report.cases[0]?.detail ?? '', /RETIRED is never a revocation/);
    }
  });

  test('deny-revoked: an identity_inactive denial whose status document cannot be read is not evidence of revocation', async (t) => {
    const s = await stage(t);
    s.network.publish(s.agent, 'REVOKED');
    const report = await runLive({
      mode: 'revoked',
      out: s.out,
      agent: AGENT,
      keyFile: s.keyFile,
      otherAgent: undefined,
      cloud: undefined,
      http: clients(),
      ...fast,
      lifecycle: async () => ({
        status: { kind: 'unknown', reason: 'StatusUnavailable (transient)', at: new Date().toISOString() },
        log: { kind: 'logged', state: 'REVOKED', reason: 'keyCompromise', events: 2, at: new Date().toISOString() },
      }),
    });
    assert.equal(report.cases[0]?.pass, false);
    assert.match(report.cases[0]?.detail ?? '', /status document not read: StatusUnavailable/);
    const throwing = await runLive({ mode: 'revoked', out: s.out, agent: AGENT, keyFile: s.keyFile, otherAgent: undefined, cloud: undefined, http: clients(), ...fast, lifecycle: async () => Promise.reject(new Error('simulated lookup failure')) });
    assert.equal(throwing.cases[0]?.pass, false);
    assert.match(throwing.cases[0]?.detail ?? '', /simulated lookup failure/);
  });

  test('deny-revoked passes only on a revocation reason: an allowed agent, an outage or another denial is not evidence of revocation', async (t) => {
    const s = await stage(t);
    let report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, false);
    assert.match(report.cases[0]?.detail ?? '', /still allowed/);
    s.edge.down = true;
    report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, false);
    assert.match(report.cases[0]?.detail ?? '', /the load balancer failed .*not a revocation/);
    s.edge.down = false;
    s.network.setHttp(s.agent.statusUrl, undefined); // status unavailable: a denial, but not a revocation
    report = await live(s, { mode: 'revoked', cloud: undefined });
    assert.equal(report.cases[0]?.pass, false);
    // The verifier's refusal is a log-check reason, but nothing behind it shows a revocation.
    assert.equal(report.cases[0]?.got, '403 identity_invalid status=unknown log=ACTIVE');
    assert.match(report.cases[0]?.detail ?? '', /not evidence of revocation/);
  });

  test("app-account-policy fails when another agent's account is served, or refused by the verifier rather than Demo Bank", async (t) => {
    const s = await stage(t);
    const [theirs] = accountsFor(OTHER);
    const [own] = accountsFor(AGENT);
    // An origin that serves any account: the request for the other agent's account is answered with the agent's own.
    const permissive: Clients = { ...clients(), h1: (target, spec) => h1(target, spec.path.endsWith(`/${theirs?.id}`) ? { ...spec, path: spec.path.replace(`/${theirs?.id}`, `/${own?.id}`) } : spec) };
    let cases = byId(await live(s, { cloud: undefined, http: permissive }));
    assert.equal(cases['app-account-policy']?.pass, false);
    // A refusal by the verifier is not the application's decision.
    const byVerifier: Clients = {
      ...clients(),
      h1: async (target, spec) => (spec.path.endsWith(`/${theirs?.id}`) ? { status: 403, headers: { 'cache-control': 'no-store' }, body: 'signature_invalid', ms: 1 } : h1(target, spec)),
    };
    cases = byId(await live(s, { cloud: undefined, http: byVerifier }));
    assert.equal(cases['app-account-policy']?.pass, false);
    cases = byId(await live(s, { cloud: undefined }));
    assert.equal(cases['app-account-policy']?.pass, true, cases['app-account-policy']?.detail);
    assert.match(cases['app-account-policy']?.detail ?? '', /another agent's account: 403 .*account_not_permitted/);
  });

  test('without OTHER_AGENT_ID, deny-other-identity is missing evidence: it fails and says so', async (t) => {
    const s = await stage(t);
    const report = await live(s, { otherAgent: undefined, cloud: undefined });
    assert.equal(byId(report)['deny-other-identity']?.pass, false);
    assert.match(byId(report)['deny-other-identity']?.detail ?? '', /OTHER_AGENT_ID not given/);
  });

  test('a case that throws is a failure with what went wrong, and only known case IDs reach the report', async (t) => {
    const s = await stage(t);
    const broken: Clients = { ...clients(), h2: async () => Promise.reject(new Error('simulated client failure')) };
    const report = await live(s, { cloud: undefined, http: broken });
    assert.equal(byId(report)['fidelity-http2']?.pass, false);
    assert.match(byId(report)['fidelity-http2']?.detail ?? '', /the case could not complete: simulated client failure/);
    assert.equal(byId(report)['fidelity-http2']?.got, 'error');
    const ids = new Set(CASES.map((c) => c.id));
    for (const r of report.cases) assert.ok(ids.has(r.id));
  });
});

describe('changes to the deployment: interruption, stalled commands and recovery (simulated cloud)', () => {
  const ORIGINAL = `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`;
  const recovery = (s: Stage) => join(s.dir, RECOVERY_FILE);
  const pending = (s: Stage) => (existsSync(recovery(s)) ? (JSON.parse(readFileSync(recovery(s), 'utf8')) as { pending: unknown[] }).pending : []);
  /** A command that never answers and ignores its signal: only the run's own bound gets it unstuck. */
  const never = () => new Promise<void>(() => {});
  /** A command that waits for its signal, as gcloud killed on it does (at once when it is already aborted). */
  const untilAborted = (signal?: AbortSignal) =>
    new Promise<void>((_, reject) => {
      if (signal?.aborted) reject(new Error('simulated: killed'));
      signal?.addEventListener('abort', () => reject(new Error('simulated: killed')), { once: true });
    });

  for (const phase of ['the change command', 'the wait for its effect', 'the restoring command'] as const) {
    for (const kind of ['governance', 'scaling'] as const) {
      test(`interrupted during ${phase} (${kind}): the restoring update is applied, the record goes, nothing else is changed or run`, { timeout: 60_000 }, async (t) => {
        const s = await stage(t);
        const c = cloud(s);
        const interrupt = new AbortController();
        const setGovernance = c.setGovernance.bind(c);
        const setScaling = c.setVerifierScaling.bind(c);
        let recordedDuringChange: unknown[] = [];
        const act = async (changing: boolean, apply: () => Promise<void>, signal?: AbortSignal) => {
          if (changing) recordedDuringChange = pending(s);
          if (changing && phase === 'the change command') {
            interrupt.abort();
            return untilAborted(signal);
          }
          if (changing && phase === 'the wait for its effect') {
            // Applied, but never seen at the edge; the interruption comes while the run is watching for it.
            setTimeout(() => interrupt.abort(), 100);
            return;
          }
          if (!changing && phase === 'the restoring command') {
            interrupt.abort();
            await new Promise((r) => setTimeout(r, 50));
          }
          await apply();
        };
        if (kind === 'governance') {
          c.setGovernance = (value, signal) => act(value === UNTRUSTED, () => setGovernance(value, signal), signal);
        } else {
          c.setVerifierScaling = (mode, signal) => act(mode === 'zero', () => setScaling(mode, signal), signal);
        }
        const report = await live(s, { cloud: c, interrupt: interrupt.signal, recoveryFile: recovery(s) });
        const id = kind === 'governance' ? 'deny-untrusted-governance' : 'deny-verifier-down';
        // The change was on record before it was made, and the record went once it was undone.
        assert.deepEqual(recordedDuringChange, [kind === 'governance' ? { kind, restore: ORIGINAL } : { kind, restore: 'auto' }]);
        assert.equal(existsSync(recovery(s)), false);
        assert.equal(report.interrupted, true);
        assert.equal(report.restoration_failed, false);
        assert.equal(byId(report)[id]?.pass, false);
        // Interrupted or not, the restoration is confirmed before the record goes.
        if (phase !== 'the change command') assert.match(byId(report)[id]?.detail ?? '', /\(interrupted: the restoration was still confirmed before stopping\)/);
        // Exactly one restoring update for this change (in the scaling runs, the governance case before it ran normally).
        const restore = kind === 'governance' ? `governance ${ORIGINAL}` : 'scaling auto';
        assert.deepEqual(c.calls.filter((x) => x === restore), [restore]);
        assert.equal(s.edge.governance, 'trusted');
        assert.equal(s.edge.down, false);
        if (kind === 'governance') {
          // The outage case comes after it: not run, and the verifier's scaling never touched.
          assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
          assert.match(byId(report)['deny-verifier-down']?.detail ?? '', /not run: the run was interrupted/);
          assert.equal(c.calls.some((x) => x.startsWith('scaling')), false);
        }
        assert.equal(report.origin_log_control, undefined);
        for (const quiet of ['deny-unsigned', 'deny-tampered']) assert.match(byId(report)[quiet]?.detail ?? '', /interrupted before the control request/);
      });
    }
  }

  test('a change command that ignores its bound is waited for until it stops: its late effect is restored, not left behind, and the run goes on', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const events: string[] = [];
    const setGovernance = c.setGovernance.bind(c);
    c.setGovernance = async (value, signal) => {
      if (value !== UNTRUSTED) {
        events.push('restoring update');
        return setGovernance(value, signal);
      }
      // Ignores its signal: abandoned at 300 ms, it applies the change at 700 ms and only then ends.
      await new Promise((r) => setTimeout(r, 700));
      await setGovernance(value);
      events.push('change landed');
    };
    const report = await live(s, { cloud: c, cloudTimeoutMs: 300, settleGraceMs: 2_000, recoveryFile: recovery(s) });
    assert.deepEqual(events, ['change landed', 'restoring update']);
    const governance = byId(report)['deny-untrusted-governance'];
    assert.equal(governance?.pass, false);
    assert.match(governance?.detail ?? '', /the change failed: the governance change: no answer within 300 ms, abandoned/);
    assert.equal(s.edge.governance, 'trusted');
    assert.equal(report.restoration_failed, false);
    assert.equal(byId(report)['deny-verifier-down']?.pass, true);
    assert.equal(existsSync(recovery(s)), false);
  });

  test('a change command that never stops: its outcome is unknown, so the record is kept and no further change is made; the next run restores it first', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const setGovernance = c.setGovernance.bind(c);
    let land: (() => Promise<void>) | undefined;
    c.setGovernance = (value, signal) => {
      if (value !== UNTRUSTED) return setGovernance(value, signal);
      land = () => setGovernance(value);
      return never();
    };
    const report = await live(s, { cloud: c, cloudTimeoutMs: 300, settleGraceMs: 300, recoveryFile: recovery(s) });
    assert.equal(report.restoration_failed, true);
    assert.match(
      byId(report)['deny-untrusted-governance']?.detail ?? '',
      /RESTORATION FAILED: RECOVERY INCOMPLETE: the governance change: no answer within 300 ms, abandoned; it had not stopped 300 ms later, so whether it takes effect is unknown/,
    );
    assert.deepEqual(pending(s), [{ kind: 'governance', restore: ORIGINAL }]);
    assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
    assert.equal(c.calls.some((x) => x.startsWith('scaling')), false);
    // The abandoned command lands after all, once the run has finished: the kept record has the next run undo it first.
    await land?.();
    assert.equal(s.edge.governance, 'untrusted');
    const next = await live(s, { mode: 'allow', cloud: cloud(s), recoveryFile: recovery(s) });
    assert.equal(s.edge.governance, 'trusted');
    assert.equal(existsSync(recovery(s)), false);
    assert.equal(next.cases[0]?.pass, true);
  });

  test('a killed change the platform still applies after the restoring update shows in the read-back: the update is applied again', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const setGovernance = c.setGovernance.bind(c);
    let restores = 0;
    c.setGovernance = async (value, signal) => {
      if (value === UNTRUSTED) return untilAborted(signal);
      restores += 1;
      await setGovernance(value, signal);
      // The killed command's request, already accepted, completes after the first restoring update.
      if (restores === 1) await setGovernance(UNTRUSTED);
    };
    const report = await live(s, { cloud: c, cloudTimeoutMs: 300, recoveryFile: recovery(s) });
    assert.equal(restores, 2);
    assert.equal(s.edge.governance, 'trusted');
    assert.equal(report.restoration_failed, false);
    assert.equal(existsSync(recovery(s)), false);
    assert.equal(byId(report)['deny-verifier-down']?.pass, true);
  });

  test('a change that keeps landing after the restoring update: restoration failed, the record is kept', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const setGovernance = c.setGovernance.bind(c);
    c.setGovernance = async (value, signal) => {
      if (value === UNTRUSTED) return untilAborted(signal);
      await setGovernance(value, signal);
      await setGovernance(UNTRUSTED);
    };
    const report = await live(s, { cloud: c, cloudTimeoutMs: 300, recoveryFile: recovery(s) });
    assert.match(
      byId(report)['deny-untrusted-governance']?.detail ?? '',
      /RESTORATION FAILED: restoring governance: the restoring update succeeded twice, but the verifier's configuration shows DNSID_TRUSTED_GOVERNANCE=untrusted-governance\.invalid/,
    );
    assert.equal(report.restoration_failed, true);
    assert.deepEqual(pending(s), [{ kind: 'governance', restore: ORIGINAL }]);
    assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
  });

  test('a change that lands again while the edge is watched is caught by the read-back after it: the record is kept', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const read = c.verifierConfig.bind(c);
    let reads = 0;
    c.verifierConfig = async (signal) => {
      reads += 1;
      if (reads === 2) s.edge.governance = 'untrusted';
      return read(signal);
    };
    const report = await live(s, { cloud: c, recoveryFile: recovery(s) });
    assert.match(
      byId(report)['deny-untrusted-governance']?.detail ?? '',
      /RESTORATION FAILED: restoring governance: changed again after the restoration: the verifier's configuration shows DNSID_TRUSTED_GOVERNANCE=untrusted-governance\.invalid/,
    );
    assert.equal(report.restoration_failed, true);
    assert.deepEqual(pending(s), [{ kind: 'governance', restore: ORIGINAL }]);
    assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
  });

  test('a restoring update that succeeds but is never seen at the edge: restoration not confirmed, the record is kept', { timeout: 60_000 }, async (t) => {
    for (const kind of ['governance', 'scaling'] as const) {
      const s = await stage(t);
      const c = cloud(s);
      // The platform reports the update and the configuration as restored; the edge never behaves as before.
      if (kind === 'governance') {
        const setGovernance = c.setGovernance.bind(c);
        c.setGovernance = async (value, signal) => (value === UNTRUSTED ? setGovernance(value, signal) : void c.calls.push(`governance ${value}`));
        c.verifierConfig = async () => ({ governance: ORIGINAL, scaling: 'auto', logEvidence: undefined });
      } else {
        const setScaling = c.setVerifierScaling.bind(c);
        c.setVerifierScaling = async (mode, signal) => (mode === 'zero' ? setScaling(mode, signal) : void c.calls.push(`scaling ${mode}`));
        c.verifierConfig = async () => ({ governance: ORIGINAL, scaling: 'auto', logEvidence: undefined });
      }
      const report = await live(s, { cloud: c, recoveryFile: recovery(s) });
      const id = kind === 'governance' ? 'deny-untrusted-governance' : 'deny-verifier-down';
      assert.equal(byId(report)[id]?.pass, false);
      assert.match(byId(report)[id]?.detail ?? '', /RESTORATION NOT CONFIRMED at the edge: /);
      assert.equal(report.restoration_failed, true);
      assert.deepEqual(pending(s), [kind === 'governance' ? { kind, restore: ORIGINAL } : { kind, restore: 'auto' }]);
      if (kind === 'governance') assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
    }
  });

  test("a restoring update whose read-back fails or never answers: restoration not confirmed, the record is kept", { timeout: 60_000 }, async (t) => {
    for (const fault of ['refused', 'silent'] as const) {
      const s = await stage(t);
      const c = cloud(s);
      c.verifierConfig = fault === 'refused' ? async () => Promise.reject(new Error('simulated: describe refused')) : () => never() as never;
      const report = await live(s, { cloud: c, cloudTimeoutMs: 300, settleGraceMs: 100, recoveryFile: recovery(s) });
      assert.match(
        byId(report)['deny-untrusted-governance']?.detail ?? '',
        fault === 'refused'
          ? /RESTORATION FAILED: restoring governance: the restoring update succeeded, but reading the verifier's governance back: simulated: describe refused/
          : /RESTORATION FAILED: restoring governance: the restoring update succeeded, but reading the verifier's governance back: no answer within 300 ms, abandoned/,
      );
      assert.equal(s.edge.governance, 'trusted');
      assert.equal(report.restoration_failed, true);
      assert.deepEqual(pending(s), [{ kind: 'governance', restore: ORIGINAL }]);
      assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
    }
  });

  test('interrupted while the restoration is being confirmed: confirming goes on, and the record stays until it is confirmed', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const interrupt = new AbortController();
    const setGovernance = c.setGovernance.bind(c);
    let recordAtInterrupt: unknown[] = [];
    let restoredUpdate = false;
    c.setGovernance = async (value, signal) => {
      if (value === UNTRUSTED) return setGovernance(value, signal);
      c.calls.push(`governance ${value}`);
      restoredUpdate = true;
      // The edge takes 250 ms to behave as before; the interruption comes 50 ms in.
      setTimeout(() => {
        recordAtInterrupt = pending(s);
        interrupt.abort();
      }, 50);
      setTimeout(() => (s.edge.governance = 'trusted'), 250);
    };
    c.verifierConfig = async () => ({ governance: restoredUpdate ? ORIGINAL : UNTRUSTED, scaling: 'auto', logEvidence: undefined });
    const report = await live(s, { cloud: c, interrupt: interrupt.signal, recoveryFile: recovery(s) });
    assert.deepEqual(recordAtInterrupt, [{ kind: 'governance', restore: ORIGINAL }]);
    assert.equal(report.interrupted, true);
    assert.match(
      byId(report)['deny-untrusted-governance']?.detail ?? '',
      /restored to [^:]+: 200 Demo Bank data .*\(interrupted: the restoration was still confirmed before stopping\)/,
    );
    assert.equal(report.restoration_failed, false);
    assert.equal(existsSync(recovery(s)), false);
    assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
  });

  test('a real gcloud that is killed but takes its grace to stop, landing its change meanwhile: the restoration waits for it, then undoes it', { timeout: 90_000 }, async (t) => {
    const s = await stage(t);
    const dir = join(s.dir, 'grace');
    mkdirSync(dir);
    const program = join(dir, 'gcloud');
    // TEST ONLY: a simulated gcloud whose change, once killed, takes a second to stop and lands as it goes.
    writeFileSync(
      program,
      `#!/usr/bin/env bash
echo "start $*" >> "${dir}/calls"
case "$*" in
  *"DNSID_TRUSTED_GOVERNANCE=${UNTRUSTED}"*)
    trap 'kill $! 2>/dev/null; sleep 1; printf %s "${UNTRUSTED}" > "${dir}/governance"; echo "late change landed" >> "${dir}/calls"; exit 143' TERM
    sleep 60 & wait; exit 0 ;;
  *"DNSID_TRUSTED_GOVERNANCE="*) all="$*"; printf '%s' "\${all##*DNSID_TRUSTED_GOVERNANCE=}" > "${dir}/governance"; exit 0 ;;
  *"--scaling=0"*) touch "${dir}/zero"; exit 0 ;;
  *"--scaling=auto"*) rm -f "${dir}/zero"; exit 0 ;;
  *"DNSID_LOG_EVIDENCE=full-scan"*|*"--remove-env-vars=DNSID_LOG_EVIDENCE"*) exit 0 ;;
  *"--ingress=all --default-url"*) touch "${dir}/exposed"; exit 0 ;;
  *"--ingress=internal-and-cloud-load-balancing --no-default-url"*) rm -f "${dir}/exposed"; exit 0 ;;
  *"run services describe ${s.out.resources['origin_service']} "*)
    if [ -e "${dir}/exposed" ]; then a='{"run.googleapis.com/ingress":"all"}'; else a='{"run.googleapis.com/ingress":"internal-and-cloud-load-balancing","run.googleapis.com/default-url-disabled":"true"}'; fi
    printf '{"metadata":{"annotations":%s}}' "$a"
    exit 0 ;;
  *"run services describe"*)
    if [ -e "${dir}/zero" ]; then a='{"run.googleapis.com/scalingMode":"manual","run.googleapis.com/manualInstanceCount":"0"}'; else a='{}'; fi
    printf '{"metadata":{"annotations":%s},"spec":{"template":{"spec":{"containers":[{"env":[{"name":"DNSID_TRUSTED_GOVERNANCE","value":"%s"}]}]}}}}' "$a" "$(cat "${dir}/governance" 2>/dev/null || printf %s "${ORIGINAL}")"
    exit 0 ;;
  *"logging read"*|*" list "*) echo "[]"; exit 0 ;;
esac
exit 3
`,
      { mode: 0o755 },
    );
    const real = await connectCloud(s.out, { PATH: process.env['PATH'] ?? '', HOME: tmpdir(), GOOGLE_OAUTH_ACCESS_TOKEN: 'simulated-token' }, commandRunner(program));
    assert.ok(real !== undefined);
    t.after(() => real.close());
    const report = await live(s, { cloud: real, cloudTimeoutMs: 500, settleGraceMs: 8_000, recoveryFile: recovery(s) });
    const calls = readFileSync(join(dir, 'calls'), 'utf8').split('\n');
    const landed = calls.indexOf('late change landed');
    const restoring = calls.findIndex((l) => l.includes(`DNSID_TRUSTED_GOVERNANCE=${ORIGINAL}`));
    assert.ok(landed >= 0 && restoring > landed, calls.join('\n'));
    assert.equal(readFileSync(join(dir, 'governance'), 'utf8'), ORIGINAL);
    assert.match(byId(report)['deny-untrusted-governance']?.detail ?? '', /the change failed: the governance change: no answer within 500 ms, abandoned/);
    assert.equal(report.restoration_failed, false, JSON.stringify(report.cases.filter((c) => /RESTORATION/.test(c.detail)), null, 1));
    assert.equal(existsSync(recovery(s)), false);
  });

  test('a restoring command that never answers: restoration failed, the record is kept, and no further change is made', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s);
    const setGovernance = c.setGovernance.bind(c);
    c.setGovernance = (value, signal) => (value === UNTRUSTED ? setGovernance(value, signal) : never());
    const report = await live(s, { cloud: c, cloudTimeoutMs: 300, recoveryFile: recovery(s) });
    assert.equal(report.restoration_failed, true);
    assert.match(byId(report)['deny-untrusted-governance']?.detail ?? '', /RESTORATION FAILED: restoring governance: no answer within 300 ms, abandoned/);
    assert.deepEqual(pending(s), [{ kind: 'governance', restore: ORIGINAL }]);
    assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
    assert.match(byId(report)['deny-verifier-down']?.detail ?? '', /no further change is made/);
    assert.equal(c.calls.some((x) => x.startsWith('scaling')), false);
  });

  test('a restoration refused outright also keeps the record and stops further changes', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s, { restoreFails: 'governance' });
    const report = await live(s, { cloud: c, recoveryFile: recovery(s) });
    assert.equal(report.restoration_failed, true);
    assert.deepEqual(pending(s), [{ kind: 'governance', restore: ORIGINAL }]);
    assert.equal(byId(report)['deny-verifier-down']?.got, 'not run');
  });

  test('a change left by an earlier run is restored before anything else, and its record removed', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    writeFileSync(recovery(s), JSON.stringify({ pending: [{ kind: 'scaling', restore: 'auto' }, { kind: 'governance', restore: ORIGINAL }] }));
    s.edge.down = true;
    s.edge.governance = 'untrusted';
    const c = cloud(s);
    const report = await live(s, { mode: 'allow', cloud: c, recoveryFile: recovery(s) });
    assert.deepEqual(c.calls.slice(0, 4), ['scaling auto', 'describe', `governance ${ORIGINAL}`, 'describe']);
    assert.equal(existsSync(recovery(s)), false);
    assert.equal(report.cases[0]?.pass, true);
  });

  test('a change left by an earlier run that cannot be restored stops the run before any case, keeping the record', async (t) => {
    const s = await stage(t);
    const record = JSON.stringify({ pending: [{ kind: 'governance', restore: ORIGINAL }] });
    writeFileSync(recovery(s), record);
    await assert.rejects(live(s, { mode: 'allow', cloud: undefined, recoveryFile: recovery(s) }), (e: Error) => e instanceof RecoveryError && /needs the platform login/.test(e.message));
    assert.equal(readFileSync(recovery(s), 'utf8'), record);
    const c = cloud(s, { restoreFails: 'governance' });
    await assert.rejects(live(s, { mode: 'allow', cloud: c, recoveryFile: recovery(s) }), (e: Error) => e instanceof RecoveryError && /restoring governance failed/.test(e.message));
    assert.equal(readFileSync(recovery(s), 'utf8'), record);
    // The restoring update succeeds, but the verifier's configuration never reads back as restored.
    const unconfirmed = cloud(s);
    unconfirmed.verifierConfig = async () => ({ governance: UNTRUSTED, scaling: 'auto', logEvidence: undefined });
    await assert.rejects(
      live(s, { mode: 'allow', cloud: unconfirmed, recoveryFile: recovery(s) }),
      (e: Error) => e instanceof RecoveryError && /restoring governance failed: restoring governance: the restoring update succeeded twice, but the verifier's configuration shows DNSID_TRUSTED_GOVERNANCE=untrusted-governance\.invalid/.test(e.message),
    );
    assert.equal(readFileSync(recovery(s), 'utf8'), record);
    writeFileSync(recovery(s), '{"pending":[{"kind":"scaling","restore":"zero"}]}');
    await assert.rejects(live(s, { mode: 'allow', cloud: cloud(s), recoveryFile: recovery(s) }), /does not list changes to restore/);
    writeFileSync(recovery(s), '{"pending":[{"kind":"origin-exposure","restore":"open"}]}');
    await assert.rejects(live(s, { mode: 'allow', cloud: cloud(s), recoveryFile: recovery(s) }), /does not list changes to restore/);
  });

  test("deny-forged-identity: a Demo Bank that trusts the identity headers by their presence (as before the attestation) fails it; the URL is still closed again", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const base = clients({ stage: s });
    const runApp = s.out.bypass_routes.origin_run_app[0] as string;
    const trusting: Clients = {
      ...base,
      async plain(url, spec) {
        const claimed = (spec.headers ?? []).find(([name]) => name === 'x-dnsid-verified-domain')?.[1];
        if (s.edge.originExposed && url.startsWith(`${runApp}/`) && claimed !== undefined) {
          const body = JSON.stringify({ bank: 'Demo Bank', synthetic: true, accounts: accountsFor(claimed), caller: { verifiedDomain: claimed, governanceId: FIXTURE_GOVERNANCE } });
          return { status: 200, headers: { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8' }, body, ms: 1, protocol: 'http/1.1' };
        }
        return base.plain(url, spec);
      },
    };
    const c = cloud(s);
    const report = await live(s, { cloud: c, http: trusting, recoveryFile: recovery(s) });
    const r = byId(report)['deny-forged-identity'];
    assert.equal(r?.pass, false);
    assert.equal(r?.got, '403 then 200,200 then 404');
    assert.match(r?.detail ?? '', /forged identity, no attestation: 200 Demo Bank data/);
    assert.equal(report.restoration_failed, false);
    assert.equal(s.edge.originExposed, false);
    assert.equal(existsSync(recovery(s)), false);
  });

  test("deny-forged-identity: Demo Bank's URL that never opens fails the case (never opened), and is still closed and confirmed", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const c = cloud(s, { exposureIgnored: true });
    const report = await live(s, { cloud: c, recoveryFile: recovery(s) });
    const r = byId(report)['deny-forged-identity'];
    assert.equal(r?.pass, false);
    assert.match(r?.detail ?? '', /never opened: 404 .*forged identity, no attestation: not sent; forged identity, forged attestation: not sent; closed again: 404/);
    assert.deepEqual(c.calls.filter((x) => x.includes('origin')), ['origin-exposure open', 'origin-exposure closed', 'describe-origin', 'describe-origin']);
    assert.equal(report.restoration_failed, false);
  });

  test("deny-forged-identity: Demo Bank's URL that can't be closed again is a failed restoration, and the record is kept", { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const report = await live(s, { cloud: cloud(s, { restoreFails: 'origin-exposure' }), recoveryFile: recovery(s) });
    const r = byId(report)['deny-forged-identity'];
    assert.equal(r?.pass, false);
    assert.match(r?.detail ?? '', /RESTORATION FAILED: simulated: the update was refused/);
    assert.equal(report.restoration_failed, true);
    assert.deepEqual(pending(s), [{ kind: 'origin-exposure', restore: 'closed' }]);
    assert.equal(s.edge.originExposed, true);
  });

  test("Demo Bank's URL left open by an earlier run is closed first, confirmed in Demo Bank's configuration, and its record removed", { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    writeFileSync(recovery(s), JSON.stringify({ pending: [{ kind: 'origin-exposure', restore: 'closed' }] }));
    s.edge.originExposed = true;
    const c = cloud(s);
    const lines: string[] = [];
    const report = await runLive({
      lifecycle: (domain) => readLifecycleEvidence(domain, s.out.trusted_governance, fixtureBackend(s.network, s.log)),
      settleGraceMs: 1_000,
      recoveryFile: recovery(s),
      mode: 'allow',
      out: s.out,
      agent: AGENT,
      keyFile: s.keyFile,
      otherAgent: OTHER,
      cloud: c,
      http: clients({ stage: s }),
      ...fast,
      log: (line) => void lines.push(line),
    });
    assert.deepEqual(c.calls.slice(0, 2), ['origin-exposure closed', 'describe-origin']);
    assert.equal(s.edge.originExposed, false);
    assert.equal(existsSync(recovery(s)), false);
    assert.ok(lines.some((l) => l.includes("restored what an earlier run left changed: origin-exposure, back to closed (confirmed in Demo Bank's configuration)")), lines.join('\n'));
    assert.equal(report.cases[0]?.pass, true);
  });
});

describe("the verifier's configuration read back from Cloud Run (gcloud run services describe)", () => {
  const service = (annotations: Record<string, string>, env: { name: string; value?: string }[]) => ({ metadata: { annotations }, spec: { template: { spec: { containers: [{ image: 'x', env }] } } } });
  test('scaling: no scaling annotations or automatic is automatic; manual with zero instances is zero; any other manual scaling is neither', () => {
    const gov = [{ name: 'DNSID_TRUSTED_GOVERNANCE', value: 'a.example,b.example' }];
    assert.deepEqual(verifierConfigFrom(service({}, gov)), { governance: 'a.example,b.example', scaling: 'auto', logEvidence: undefined });
    assert.equal(verifierConfigFrom(service({ 'run.googleapis.com/scalingMode': 'automatic' }, gov)).scaling, 'auto');
    assert.equal(verifierConfigFrom(service({ 'run.googleapis.com/scalingMode': 'manual', 'run.googleapis.com/manualInstanceCount': '0' }, gov)).scaling, 'zero');
    assert.equal(verifierConfigFrom(service({ 'run.googleapis.com/scalingMode': 'manual', 'run.googleapis.com/manualInstanceCount': '1' }, gov)).scaling, 'other');
    assert.equal(verifierConfigFrom(service({ 'run.googleapis.com/scalingMode': 'manual' }, gov)).scaling, 'other');
  });

  test("the log mode is the container's DNSID_LOG_EVIDENCE, undefined when absent", () => {
    assert.equal(verifierConfigFrom(service({}, [{ name: 'DNSID_LOG_EVIDENCE', value: 'full-scan' }])).logEvidence, 'full-scan');
    assert.equal(verifierConfigFrom(service({}, [{ name: 'DNSID_TRUSTED_GOVERNANCE', value: 'a.example' }])).logEvidence, undefined);
  });

  test('governance is the container\'s DNSID_TRUSTED_GOVERNANCE, undefined when absent; anything not shaped like a service is an error', () => {
    assert.equal(verifierConfigFrom(service({}, [{ name: 'PORT', value: '8080' }])).governance, undefined);
    for (const bad of [null, {}, [], { spec: { template: { spec: { containers: [] } } } }, 'text']) assert.throws(() => verifierConfigFrom(bad), /no containers/);
  });
});

describe("Demo Bank's exposure read back from Cloud Run (gcloud run services describe)", () => {
  test('ingress and the default URL from the service annotations; closed only as deployed; anything not shaped like a service is an error', () => {
    const service = (annotations: Record<string, string>) => ({ metadata: { annotations } });
    assert.deepEqual(originConfigFrom(service({ 'run.googleapis.com/ingress': 'internal-and-cloud-load-balancing', 'run.googleapis.com/default-url-disabled': 'true' })), {
      ingress: 'internal-and-cloud-load-balancing',
      defaultUrlDisabled: true,
    });
    assert.deepEqual(originConfigFrom(service({ 'run.googleapis.com/ingress': 'all' })), { ingress: 'all', defaultUrlDisabled: false });
    assert.deepEqual(originConfigFrom(service({ 'run.googleapis.com/default-url-disabled': 'false' })), { ingress: undefined, defaultUrlDisabled: false });
    assert.deepEqual(originConfigFrom({ metadata: {} }), { ingress: undefined, defaultUrlDisabled: false });
    for (const bad of [null, {}, [], 'text', { metadata: null }]) assert.throws(() => originConfigFrom(bad), /no metadata/);
  });
});

describe("the verifier's own records (Cloud Logging): read, validated, waited for", () => {
  test('records are read field by field, oldest first; a field of the wrong type is left out, never defaulted', () => {
    const records = verificationRecordsFrom([
      { timestamp: '2026-11-13T00:00:02Z', jsonPayload: { elapsedMs: 40, verified: { evidenceAgeMs: 1200, completenessMode: 'trusted-index', materialCache: 'hit' } } },
      { timestamp: '2026-11-13T00:00:01Z', jsonPayload: { elapsedMs: '40', verified: { evidenceAgeMs: null, completenessMode: 7 } } },
      { jsonPayload: {} },
    ]);
    assert.deepEqual(records, [
      { timestamp: '' },
      { timestamp: '2026-11-13T00:00:01Z' },
      { timestamp: '2026-11-13T00:00:02Z', elapsedMs: 40, evidenceAgeMs: 1200, completenessMode: 'trusted-index', materialCache: 'hit' },
    ]);
  });

  test('LIVE_LOG_WAIT_S: whole seconds from 1 to 1800, 120 when absent', () => {
    assert.equal(logWaitFromSetting(undefined), 120_000);
    assert.equal(logWaitFromSetting('1'), 1_000);
    assert.equal(logWaitFromSetting('1800'), 1_800_000);
    for (const bad of ['0', '1801', '1.5', '-1', 'ten', ' 5']) assert.throws(() => logWaitFromSetting(bad), /LIVE_LOG_WAIT_S/, bad);
  });

  test('evidence-freshness and verification-timing fail on a missing, incomplete, over-budget or unreadable record, and when the full-scan setting is not seen in the records', { timeout: 120_000 }, async (t) => {
    const expectations: [NonNullable<NonNullable<Parameters<typeof cloud>[1]>['records']>, RegExp, boolean][] = [
      ['drop-last', /2 verifier record\(s\) for 3 served request\(s\) after \d+ ms/, true],
      ['no-elapsed', /record #1: no elapsed time/, true],
      ['over-budget', /record #1: elapsed 2600 ms, over the 2500 ms budget/, true],
      ['unreadable', /the verifier's log records could not be read: simulated: logging.read refused/, true],
      ['scan-ignored', /3 record\(s\) not read by full scan: the setting had not taken effect/, false],
      ['all-hit', /new revision's first request: \d+ ms, full-scan, cache hit, evidence -?\d+ ms old \(not cold: cache hit, so no cold verification was measured\)/, false],
    ];
    for (const [records, message, freshnessFails] of expectations) {
      const s = await stage(t);
      const c = cloud(s, { records });
      const report = await live(s, { cloud: c });
      const cases = byId(report);
      assert.equal(cases['evidence-freshness']?.pass, !freshnessFails, `${records}: ${cases['evidence-freshness']?.detail}`);
      assert.equal(cases['verification-timing']?.pass, false, `${records}: ${cases['verification-timing']?.detail}`);
      assert.match(freshnessFails ? (cases['evidence-freshness']?.detail ?? '') : (cases['verification-timing']?.detail ?? ''), message, String(records));
      // Whatever the evidence, the log mode was put back and confirmed.
      assert.equal(report.restoration_failed, false, String(records));
      assert.deepEqual(c.calls.filter((x) => x.startsWith('log-evidence')), ['log-evidence full-scan', 'log-evidence default'], String(records));
    }
  });

  test('a log mode that cannot be put back: restoration failed, the record kept', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const report = await live(s, { cloud: cloud(s, { restoreFails: 'log-evidence' }), recoveryFile: join(s.dir, RECOVERY_FILE) });
    assert.equal(byId(report)['verification-timing']?.pass, false);
    assert.match(byId(report)['verification-timing']?.detail ?? '', /RESTORATION FAILED: simulated: the update was refused/);
    assert.equal(report.restoration_failed, true);
    assert.deepEqual(JSON.parse(readFileSync(join(s.dir, RECOVERY_FILE), 'utf8')).pending, [{ kind: 'log-evidence', restore: 'default' }]);
  });
});

describe('gcloud commands are bounded', () => {
  function sleeper(t: TestContext): { program: string; pidFile: string } {
    const dir = mkdtempSync(join(tmpdir(), 'runner-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const program = join(dir, 'gcloud');
    // TEST ONLY: a gcloud that hangs.
    writeFileSync(program, `#!/usr/bin/env bash\necho $$ > "${join(dir, 'pid')}"\nexec sleep 60\n`, { mode: 0o755 });
    return { program, pidFile: join(dir, 'pid') };
  }
  const alive = (pid: number) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };

  test('a command past its time is killed and reported as a failure', async (t) => {
    const { program, pidFile } = sleeper(t);
    const started = performance.now();
    const result = await commandRunner(program, 300)(['run', 'services', 'update'], process.env);
    assert.ok(performance.now() - started < 10_000);
    assert.equal(result.code, null);
    assert.match(result.stderr, /ran out of time or was interrupted/);
    assert.equal(alive(Number(readFileSync(pidFile, 'utf8'))), false);
  });

  test("a command whose caller's signal aborts is killed too; one already aborted never starts", async (t) => {
    const { program, pidFile } = sleeper(t);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 200);
    const result = await commandRunner(program, 60_000)(['x'], process.env, controller.signal);
    assert.equal(result.code, null);
    assert.equal(alive(Number(readFileSync(pidFile, 'utf8'))), false);
    rmSync(pidFile);
    const skipped = await commandRunner(program, 60_000)(['x'], process.env, AbortSignal.abort());
    assert.equal(skipped.code, null);
    assert.equal(existsSync(pidFile), false);
  });
});

describe('inputs and key handling', () => {
  test('MODE is live, allow or revoked (live when unset); agent IDs must be domain names', () => {
    assert.equal(parseMode(undefined), 'live');
    assert.equal(parseMode('revoked'), 'revoked');
    assert.throws(() => parseMode('all'), /MODE must be live, allow or revoked/);
    assert.equal(checkAgentId('X', 'Agent-Example.COM.'), 'agent-example.com');
    assert.throws(() => checkAgentId('DNSID_AGENT_ID', 'not an id'), /DNSID_AGENT_ID is not a DNSid agent ID/);
    assert.throws(() => checkAgentId('DNSID_AGENT_ID', undefined));
  });

  test('a private JWK and a PKCS #8 PEM key file are read; anything else is refused with a message that quotes nothing of the file', async (t) => {
    const dir = mkdtempSync(join(tmpdir(), 'keys-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = join(dir, 'agent.pem');
    writeFileSync(pem, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    const fromPem = await loadKeyProvider(pem);
    assert.equal((await fromPem.signingKey()).x, privateKey.export({ format: 'jwk' }).x);
    const secret = 'SECRET-LOOKING-CONTENT-123';
    const bad = join(dir, 'bad');
    writeFileSync(bad, `{"kty":"OKP","crv":"Ed25519","d":"${secret}"}`);
    await assert.rejects(loadKeyProvider(bad), (error: Error) => !error.message.includes(secret) && /not a usable private key/.test(error.message));
    writeFileSync(bad, `garbage ${secret}`);
    await assert.rejects(loadKeyProvider(bad), (error: Error) => !error.message.includes(secret));
    await assert.rejects(loadKeyProvider(join(dir, 'missing')), /DNSID_AGENT_KEY_FILE cannot be read/);
  });
});

describe('scripts/test-live.sh', () => {
  function cli(env: Record<string, string>): Promise<{ code: number | null; out: string }> {
    return new Promise((resolve) => {
      const child = spawn('bash', [join(ROOT, 'scripts/test-live.sh')], { cwd: tmpdir(), env: { PATH: process.env['PATH'] ?? '', HOME: tmpdir(), ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (c: Buffer) => (out += c.toString('utf8')));
      child.stderr.on('data', (c: Buffer) => (out += c.toString('utf8')));
      const guard = setTimeout(() => child.kill('SIGKILL'), 90_000);
      child.on('close', (code) => {
        clearTimeout(guard);
        resolve({ code, out });
      });
    });
  }

  test('MODE=allow and MODE=revoked through the real command: report.json as the contract says, and the key never printed', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const deployOut = join(s.dir, 'deploy.json');
    writeFileSync(deployOut, JSON.stringify(s.out));
    const env = { DEPLOY_OUT: deployOut, LIVE_OUT: join(s.dir, 'live'), DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.keyFile };
    let r = await cli({ ...env, MODE: 'allow' });
    assert.equal(r.code, 0, r.out);
    let report = JSON.parse(readFileSync(join(s.dir, 'live/report.json'), 'utf8')) as Report;
    assert.deepEqual(Object.keys(report.cases[0] ?? {}).slice(0, 6), ['id', 'edge', 'expect', 'got', 'pass', 'detail']);
    assert.equal(report.cases[0]?.id, 'allow-trusted');
    assert.equal(report.cases[0]?.pass, true);
    assert.equal(r.out.includes(s.keyD), false);
    assert.equal(readFileSync(join(s.dir, 'live/report.json'), 'utf8').includes(s.keyD), false);

    r = await cli({ ...env, MODE: 'revoked' });
    assert.equal(r.code, 1, r.out);
    report = JSON.parse(readFileSync(join(s.dir, 'live/report.json'), 'utf8')) as Report;
    assert.deepEqual(report.cases.map((c) => [c.id, c.pass]), [['deny-revoked', false]]);
  });

  /**
   * scripts/test-live.sh with a simulated gcloud on PATH: logs and listings are empty, the change to an untrusted
   * governance list hangs, and other updates are kept in a state file that `run services describe` reports. With
   * `hangReadBack`, describe hangs too once the restoring update has been made.
   */
  async function stalledRun(t: TestContext, s: Stage, hangReadBack = false) {
    const deployOut = join(s.dir, 'deploy.json');
    writeFileSync(deployOut, JSON.stringify(s.out));
    const state = join(s.dir, 'gcloud');
    mkdirSync(join(state, 'bin'), { recursive: true });
    writeFileSync(join(state, 'calls'), '');
    // TEST ONLY: a simulated gcloud.
    writeFileSync(
      join(state, 'bin/gcloud'),
      `#!/usr/bin/env bash
echo "$*" >> "${state}/calls"
case "$*" in
  *"auth application-default print-access-token"*) echo simulated-token; exit 0 ;;
  *"logging read"*|*" list "*) echo "[]"; exit 0 ;;
  *"DNSID_TRUSTED_GOVERNANCE=${UNTRUSTED}"*) echo $$ > "${state}/stalled"; exec sleep 120 ;;
  *"run services update"*"DNSID_TRUSTED_GOVERNANCE="*) all="$*"; printf '%s' "\${all##*DNSID_TRUSTED_GOVERNANCE=}" > "${state}/governance"; exit 0 ;;
  *"run services update"*) exit 0 ;;
  *"run services describe"*)
    if [ ${hangReadBack ? 1 : 0} = 1 ] && [ -e "${state}/governance" ]; then echo $$ > "${state}/reading"; exec sleep 120; fi
    printf '{"metadata":{"annotations":{}},"spec":{"template":{"spec":{"containers":[{"env":[{"name":"DNSID_TRUSTED_GOVERNANCE","value":"%s"}]}]}}}}' "$(cat "${state}/governance" 2>/dev/null)"
    exit 0 ;;
esac
exit 3
`,
      { mode: 0o755 },
    );
    const liveOut = join(s.dir, 'live');
    const child = spawn('bash', [join(ROOT, 'scripts/test-live.sh')], {
      cwd: tmpdir(),
      // The simulated logs are empty: a one-second wait for records that never come keeps the run moving.
      env: { PATH: `${join(state, 'bin')}:${process.env['PATH'] ?? ''}`, HOME: tmpdir(), DEPLOY_OUT: deployOut, LIVE_OUT: liveOut, DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.keyFile, OTHER_AGENT_ID: OTHER, LIVE_LOG_WAIT_S: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const run = { out: '', state, liveOut, child, exited: new Promise<number | null>((resolve) => child.on('close', (code) => resolve(code))) };
    child.stdout.on('data', (c: Buffer) => (run.out += c.toString('utf8')));
    child.stderr.on('data', (c: Buffer) => (run.out += c.toString('utf8')));
    t.after(() => {
      child.kill('SIGKILL');
      // If the run died without killing them, the simulated gcloud's sleeps would outlive the test.
      for (const pidFile of ['stalled', 'reading']) {
        if (!existsSync(join(state, pidFile))) continue;
        try {
          process.kill(Number(readFileSync(join(state, pidFile), 'utf8')), 'SIGKILL');
        } catch {
          // already gone
        }
      }
    });
    return run;
  }

  async function waitFor(file: string, what: string, out: () => string): Promise<void> {
    const deadline = performance.now() + 90_000;
    while (!existsSync(file) && performance.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    assert.ok(existsSync(file), `${what}: ${out()}`);
  }

  test('SIGTERM while a change is stalled: the stalled gcloud is killed, the change restored and confirmed, the report written, exit 130', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const run = await stalledRun(t, s);
    await waitFor(join(run.state, 'stalled'), 'the change never started', () => run.out);
    const stalled = Number(readFileSync(join(run.state, 'stalled'), 'utf8'));
    // Recorded before it was made.
    assert.deepEqual(JSON.parse(readFileSync(join(run.liveOut, RECOVERY_FILE), 'utf8')).pending, [{ kind: 'governance', restore: `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}` }]);
    run.child.kill('SIGTERM');
    const code = await run.exited;
    assert.equal(code, 130, run.out);
    assert.match(run.out, /SIGTERM: stopping; restoring and confirming any change in progress first/);
    let gone = false;
    try {
      process.kill(stalled, 0);
    } catch {
      gone = true;
    }
    assert.ok(gone, 'the stalled gcloud was killed');
    const calls = readFileSync(join(run.state, 'calls'), 'utf8');
    assert.match(calls, new RegExp(`--update-env-vars=\\^\\|\\^DNSID_TRUSTED_GOVERNANCE=${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`));
    // The restoration was read back, before and after the edge showed it.
    assert.equal(calls.split('\n').filter((l) => l.includes('run services describe')).length, 2);
    assert.doesNotMatch(calls, /--scaling=/);
    assert.equal(existsSync(join(run.liveOut, RECOVERY_FILE)), false);
    const report = JSON.parse(readFileSync(join(run.liveOut, 'report.json'), 'utf8')) as Report;
    assert.equal(report.interrupted, true);
    assert.equal(report.restoration_failed, false);
    assert.equal(report.cases.find((c) => c.id === 'deny-verifier-down')?.got, 'not run');
    assert.equal(run.out.includes(s.keyD) || run.out.includes('simulated-token'), false);
  });

  test('a second SIGTERM while the restoration is being confirmed: exit 4 at once, the record kept for the next run', { timeout: 120_000 }, async (t) => {
    const s = await stage(t);
    const run = await stalledRun(t, s, true);
    await waitFor(join(run.state, 'stalled'), 'the change never started', () => run.out);
    run.child.kill('SIGTERM');
    // The restoring update is made; reading it back hangs.
    await waitFor(join(run.state, 'reading'), 'the restoration was never read back', () => run.out);
    assert.equal(readFileSync(join(run.state, 'governance'), 'utf8'), `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}`);
    run.child.kill('SIGTERM');
    const code = await run.exited;
    assert.equal(code, 4, run.out);
    assert.match(run.out, /SIGTERM again: stopping now\. Anything not restored is listed in .*pending-restore\.json; the next run restores it first/);
    assert.deepEqual(JSON.parse(readFileSync(join(run.liveOut, RECOVERY_FILE), 'utf8')).pending, [{ kind: 'governance', restore: `${FIXTURE_GOVERNANCE},${OTHER_GOVERNANCE}` }]);
    assert.equal(existsSync(join(run.liveOut, 'report.json')), false);
  });

  test('a change an earlier run left unrestored, and no login to restore it: exit 4, no report, the record kept', { timeout: 60_000 }, async (t) => {
    const s = await stage(t);
    const deployOut = join(s.dir, 'deploy.json');
    writeFileSync(deployOut, JSON.stringify(s.out));
    const liveOut = join(s.dir, 'live');
    mkdirSync(join(s.dir, 'bin'), { recursive: true });
    mkdirSync(liveOut);
    // TEST ONLY: a gcloud with no login.
    writeFileSync(join(s.dir, 'bin/gcloud'), '#!/usr/bin/env bash\necho "no credentials" >&2\nexit 1\n', { mode: 0o755 });
    const record = JSON.stringify({ pending: [{ kind: 'scaling', restore: 'auto' }] });
    writeFileSync(join(liveOut, RECOVERY_FILE), record);
    const r = await cli({ PATH: `${join(s.dir, 'bin')}:${process.env['PATH'] ?? ''}`, DEPLOY_OUT: deployOut, LIVE_OUT: liveOut, DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.keyFile, MODE: 'allow' });
    assert.equal(r.code, 4, r.out);
    assert.match(r.out, /an earlier run left the deployment changed: scaling \(back to auto\); restoring it needs the platform login/);
    assert.equal(readFileSync(join(liveOut, RECOVERY_FILE), 'utf8'), record);
    assert.equal(existsSync(join(liveOut, 'report.json')), false);
  });

  test('a missing or invalid input exits 2 with no report', async (t) => {
    const s = await stage(t);
    const deployOut = join(s.dir, 'deploy.json');
    writeFileSync(deployOut, JSON.stringify(s.out));
    const base = { DEPLOY_OUT: deployOut, LIVE_OUT: join(s.dir, 'live'), DNSID_AGENT_ID: AGENT, DNSID_AGENT_KEY_FILE: s.keyFile };
    const cases: [Record<string, string>, RegExp][] = [
      [{ MODE: 'everything' }, /MODE must be live, allow or revoked/],
      [{ DNSID_AGENT_ID: '' }, /DNSID_AGENT_ID is not a DNSid agent ID/],
      [{ DNSID_AGENT_KEY_FILE: '' }, /DNSID_AGENT_KEY_FILE is required/],
      [{ DNSID_AGENT_KEY_FILE: join(s.dir, 'missing') }, /DNSID_AGENT_KEY_FILE cannot be read/],
      [{ OTHER_AGENT_ID: AGENT }, /OTHER_AGENT_ID must be a different identity/],
      [{ DEPLOY_OUT: join(s.dir, 'none.json') }, /DEPLOY_OUT: cannot read/],
    ];
    for (const [change, message] of cases) {
      const r = await cli({ ...base, ...change });
      assert.equal(r.code, 2, `${JSON.stringify(change)}: ${r.out}`);
      assert.match(r.out, message);
      assert.equal(existsSync(join(s.dir, 'live/report.json')), false);
    }
    writeFileSync(deployOut, JSON.stringify({ ...s.out, endpoint: 'http://127.0.0.1' }));
    const r = await cli({ ...base, MODE: 'allow' });
    assert.equal(r.code, 2);
    assert.match(r.out, /DEPLOY_OUT: endpoint is not https/);
  });
});
