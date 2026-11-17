// scripts/deploy.sh and scripts/teardown.sh, run for real against SIMULATED cloud and Terraform commands
// (tests/support/fake-cli.ts) and a local HTTPS endpoint standing in for the load balancer. Nothing here reaches Google
// Cloud, a Terraform provider or a registry; what is checked is the scripts' own behavior: inputs and defaults, where
// state goes, how authentication is routed, the order of the stages, the bounded waits, DEPLOY_OUT, and what happens
// after a failure at each point (and on a retry, an interruption, or a teardown that can't be confirmed).

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';

import { parseDeployOut } from '../../scripts/lib/deploy-out.ts';
import { deploymentListings, stageOutputs } from '../support/deploy-fixtures.ts';
import { fakeCli, type Call, type FakeCli } from '../support/fake-cli.ts';
import { selfSignedCertificate } from '../support/local-https.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DEPLOY = join(ROOT, 'scripts/deploy.sh');
const TEARDOWN = join(ROOT, 'scripts/teardown.sh');
const TOKEN = 'test-token-not-a-secret-0123456789';

const BOOTSTRAP_RESOURCES = [
  'google_project_service.required["compute.googleapis.com"]',
  'google_compute_global_address.edge',
  'google_artifact_registry_repository.images',
  'google_storage_bucket.build',
  'google_service_account.build',
  'google_artifact_registry_repository_iam_member.build_writer',
  'google_storage_bucket_iam_member.build_objects',
];
const SERVICE_RESOURCES = [
  'google_cloud_run_v2_service.verifier',
  'google_cloud_run_v2_service.origin',
  'google_compute_global_forwarding_rule.https',
  'google_network_services_authz_extension.dnsid',
  'google_network_security_authz_policy.dnsid',
];

interface Endpoint {
  port: number;
  cert: string;
  /** What the endpoint answers: the verifier's denial, or the load balancer's 500. */
  mode: 'ready' | 'failing';
  requests: number;
  /** When set, decides per request (1-based count) whether it gets the load balancer's 500 regardless of `mode`. */
  failsAt?: (request: number) => boolean;
  /**
   * When set, decides per request whether Demo Bank answers it (its own 403 for a missing identity): the load balancer
   * forwarded it without the authorization policy, as one of Google's front ends did on 2026-11-14.
   */
  bypassAt?: (request: number) => boolean;
}

async function endpoint(t: TestContext): Promise<Endpoint> {
  const certificate = selfSignedCertificate('127.0.0.1');
  const state: Endpoint = { port: 0, cert: certificate.cert, mode: 'ready', requests: 0 };
  const server: Server = createServer({ key: certificate.key, cert: certificate.cert }, (req, res) => {
    state.requests += 1;
    if (state.mode === 'ready' && req.url === '/accounts' && state.bypassAt?.(state.requests) === true) {
      res.writeHead(403, { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8' });
      res.end('{"error":"identity_context_required"}');
    } else if (state.mode === 'ready' && req.url === '/accounts' && state.failsAt?.(state.requests) !== true) {
      res.writeHead(403, { 'cache-control': 'no-store' });
      res.end('signature_missing');
    } else {
      res.writeHead(500, { 'content-type': 'text/html' });
      res.end('<html>error</html>');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  state.port = (server.address() as AddressInfo).port;
  return state;
}

interface World {
  cli: FakeCli;
  home: string;
  stateDir: string;
  deployOut: string;
  ep: Endpoint;
  env: Record<string, string>;
}

async function world(t: TestContext, extra: Record<string, string> = {}): Promise<World> {
  const cli = fakeCli(t);
  const ep = await endpoint(t);
  const home = mkdtempSync(join(tmpdir(), 'deploy-home-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const { bootstrap, service } = stageOutputs(ep.cert, `https://127.0.0.1:${ep.port}`);
  cli.write('outputs-bootstrap.json', JSON.stringify(bootstrap));
  cli.write('outputs-service.json', JSON.stringify(service));
  cli.write('resources-bootstrap', BOOTSTRAP_RESOURCES.join('\n'));
  cli.write('resources-service', SERVICE_RESOURCES.join('\n'));
  const listings = deploymentListings();
  cli.write('listing-compute-forwarding-rules.json', JSON.stringify(listings.forwardingRules));
  cli.write('listing-compute-target-https-proxies.json', JSON.stringify(listings.httpsProxies));
  cli.write('listing-compute-target-http-proxies.json', JSON.stringify(listings.httpProxies));
  cli.write('listing-compute-url-maps.json', JSON.stringify(listings.urlMaps));
  cli.write('listing-compute-backend-services.json', JSON.stringify(listings.backendServices));
  cli.write('listing-compute-network-endpoint-groups.json', JSON.stringify(listings.negs));
  cli.write('listing-network-security-authz-policies.json', JSON.stringify(listings.policies));
  const stateDir = join(home, 'state');
  const env: Record<string, string> = {
    PATH: `${cli.bin}:${process.env['PATH'] ?? ''}`,
    HOME: home,
    TMPDIR: tmpdir(),
    FAKE_CLI_STATE: cli.dir,
    GOOGLE_CLOUD_PROJECT: 'sandbox-project-1',
    STATE_DIR: stateDir,
    DEPLOY_OUT: join(home, 'out', 'deploy.json'),
    GOOGLE_OAUTH_ACCESS_TOKEN: TOKEN,
    ...extra,
  };
  return { cli, home, stateDir, deployOut: env['DEPLOY_OUT'] as string, ep, env };
}

interface Ran {
  code: number | null;
  signal: NodeJS.Signals | null;
  out: string;
}

function run(script: string, env: Record<string, string>, options: { cwd?: string; killWhen?: () => boolean } = {}): Promise<Ran> {
  return new Promise((resolve) => {
    const child = spawn('bash', [script], { cwd: options.cwd ?? tmpdir(), env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
    let timer: NodeJS.Timeout | undefined;
    if (options.killWhen) {
      timer = setInterval(() => {
        if (options.killWhen?.()) {
          clearInterval(timer);
          child.kill('SIGTERM');
        }
      }, 20);
    }
    const guard = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.on('close', (code, signal) => {
      clearTimeout(guard);
      if (timer) clearInterval(timer);
      resolve({ code, signal, out });
    });
  });
}

const deploy = (w: World, env: Record<string, string> = {}) => run(DEPLOY, { ...w.env, ...env });
const teardown = (w: World, env: Record<string, string> = {}) => run(TEARDOWN, { ...w.env, ...env });
const gcloud = (calls: Call[]) => calls.filter((c) => c.tool === 'gcloud');
const terraform = (calls: Call[]) => calls.filter((c) => c.tool === 'terraform');
const stateOf = (w: World, stage: string) => {
  const file = join(w.stateDir, stage, 'terraform.tfstate');
  return existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean) : [];
};
const json = (file: string) => JSON.parse(readFileSync(file, 'utf8'));

describe('deploy.sh: inputs, defaults and where things go', () => {
  test('the project is required; a malformed project, region or governance list is refused before anything runs', async (t) => {
    const w = await world(t);
    const cases: [Record<string, string>, RegExp][] = [
      [{ GOOGLE_CLOUD_PROJECT: '' }, /GOOGLE_CLOUD_PROJECT is required/],
      [{ GOOGLE_CLOUD_PROJECT: 'Bad_Project' }, /not a Google Cloud project ID/],
      [{ GOOGLE_CLOUD_REGION: 'Central US' }, /not a Google Cloud region name/],
      [{ DNSID_TRUSTED_GOVERNANCE: '' }, /DNSID_TRUSTED_GOVERNANCE is empty/],
      [{ DNSID_TRUSTED_GOVERNANCE: '   ' }, /DNSID_TRUSTED_GOVERNANCE is empty/],
      [{ DNSID_TRUSTED_GOVERNANCE: ' , ' }, /DNSID_TRUSTED_GOVERNANCE is empty/],
      [{ DNSID_TRUSTED_GOVERNANCE: 'dnsid-sandbox.io,not a domain' }, /isn't a governance ID/],
      [{ DNSID_TRUSTED_GOVERNANCE: '10.0.0.1' }, /isn't a governance ID/],
    ];
    for (const [env, message] of cases) {
      const r = await deploy(w, env);
      assert.equal(r.code, 2, `${JSON.stringify(env)}: ${r.out}`);
      assert.match(r.out, message);
    }
    assert.deepEqual(w.cli.calls(), []);
    assert.equal(existsSync(w.stateDir), false);
  });

  test('the region defaults to us-central1 and the governance to dnsid-sandbox.io, and reach both stages', async (t) => {
    const w = await world(t);
    assert.equal('DNSID_TRUSTED_GOVERNANCE' in w.env, false, 'the default is for an absent variable');
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(json(join(w.stateDir, 'bootstrap/terraform.tfvars.json')), {
      project_id: 'sandbox-project-1',
      region: 'us-central1',
      deployment_name: json(join(w.stateDir, 'deployment.json')).name,
    });
    const service = json(join(w.stateDir, 'service/terraform.tfvars.json'));
    assert.equal(service.region, 'us-central1');
    assert.equal(service.trusted_governance, 'dnsid-sandbox.io');
    assert.match(service.verifier_image, /\/verifier@sha256:[0-9a-f]{64}$/);
    assert.match(service.origin_image, /\/origin@sha256:[0-9a-f]{64}$/);
  });

  test('given inputs are passed through unchanged', async (t) => {
    const w = await world(t, { GOOGLE_CLOUD_REGION: 'europe-west4', DNSID_TRUSTED_GOVERNANCE: 'dnsid-sandbox.io,example.org' });
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    const service = json(join(w.stateDir, 'service/terraform.tfvars.json'));
    assert.equal(service.region, 'europe-west4');
    assert.equal(service.trusted_governance, 'dnsid-sandbox.io,example.org');
    const submit = gcloud(w.cli.calls()).find((c) => c.args[1] === 'submit');
    assert.ok(submit?.args.includes('--region=europe-west4'));
  });

  test('STATE_DIR and DEPLOY_OUT default outside the repository, under HOME, per project', async (t) => {
    const w = await world(t);
    const env = { ...w.env };
    delete env['STATE_DIR'];
    delete env['DEPLOY_OUT'];
    const r = await run(DEPLOY, env);
    assert.equal(r.code, 0, r.out);
    const dir = join(w.home, '.local/state/dnsid-gcp-service-extensions/sandbox-project-1');
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    parseDeployOut(readFileSync(join(dir, 'deploy-out.json'), 'utf8'));
    assert.ok(existsSync(join(dir, 'bootstrap/terraform.tfstate')));
  });

  test('a STATE_DIR inside the integration directory is refused', async (t) => {
    const w = await world(t, { STATE_DIR: join(ROOT, 'docs', 'not-here') });
    const r = await deploy(w);
    assert.equal(r.code, 2);
    assert.match(r.out, /STATE_DIR must be outside the integration's directory/);
    assert.equal(existsSync(join(ROOT, 'docs', 'not-here')), false);
  });
});

describe('deploy.sh: a deployment from nothing (simulated)', () => {
  test('two stages with separate state at explicit backend paths, the build with its own identity and storage, then DEPLOY_OUT', async (t) => {
    const w = await world(t);
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    const calls = w.cli.calls();
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    assert.match(name, /^dnsid-gse-[0-9a-f]{8}$/);

    // Each stage is initialized with its own backend path under STATE_DIR, providers as locked, data outside the tree.
    for (const stage of ['bootstrap', 'service']) {
      const init = terraform(calls).find((c) => c.stage === stage && c.args[0] === 'init');
      assert.ok(init?.args.includes(`-backend-config=path=${w.stateDir}/${stage}/terraform.tfstate`), stage);
      assert.ok(init?.args.includes('-lockfile=readonly'));
      assert.equal(init?.env?.TF_DATA_DIR, `${w.stateDir}/${stage}/tfdata`);
    }
    assert.deepEqual(stateOf(w, 'bootstrap'), BOOTSTRAP_RESOURCES);
    assert.deepEqual(stateOf(w, 'service'), SERVICE_RESOURCES);
    assert.deepEqual(readdirSync(join(ROOT, 'infra/bootstrap')).sort(), ['.terraform.lock.hcl', 'main.tf', 'outputs.tf', 'tests', 'variables.tf', 'versions.tf']);

    // The order: bootstrap applied, then the build, then the service stage, then the inventory.
    const order = calls.map((c) => (c.tool === 'terraform' ? `tf:${c.stage}:${c.args[0]}` : `gcloud:${c.args.slice(0, 2).join(' ')}`));
    const at = (label: string) => order.indexOf(label);
    assert.ok(at('tf:bootstrap:apply') < at('gcloud:builds submit'));
    assert.ok(at('gcloud:builds submit') < at('tf:service:apply'));
    assert.ok(at('tf:service:apply') < at('gcloud:compute forwarding-rules'));

    // The build: the deployment's own identity, source bucket and log location, tagged images, the uploaded allowlist.
    const submit = gcloud(calls).find((c) => c.args[1] === 'submit') as Call;
    const bucket = `gs://dnsid-gse-0a1b2c3d-build`;
    assert.ok(submit.args.includes('--service-account=projects/sandbox-project-1/serviceAccounts/dnsid-gse-0a1b2c3d-build@sandbox-project-1.iam.gserviceaccount.com'));
    assert.ok(submit.args.includes(`--gcs-source-staging-dir=${bucket}/source`));
    assert.ok(submit.args.includes(`--gcs-log-dir=${bucket}/logs`));
    assert.ok(submit.args.includes('--async'));
    const subs = (submit.args.find((a) => a.startsWith('--substitutions=')) as string).slice('--substitutions='.length);
    assert.match(subs, new RegExp(`^_VERIFIER_IMAGE=us-central1-docker\\.pkg\\.dev/sandbox-project-1/dnsid-gse-0a1b2c3d/verifier:[0-9a-f]{12}-1,_ORIGIN_IMAGE=[^,]+/origin:[0-9a-f]{12}-1,_DEPLOYMENT=${name}$`));
    assert.match(readFileSync(join(w.stateDir, 'builds/builds.tsv'), 'utf8'), /^[0-9a-f-]{36}\t[0-9a-f]{64}\t/);
    assert.equal(existsSync(join(w.stateDir, 'builds/context')), false, 'the uploaded copy is removed afterwards');

    // DEPLOY_OUT: valid, private, written once the endpoint answered with the verifier's denial.
    const out = parseDeployOut(readFileSync(w.deployOut, 'utf8'));
    assert.equal(statSync(w.deployOut).mode & 0o777, 0o600);
    assert.equal(out.endpoint, `https://127.0.0.1:${w.ep.port}`);
    assert.equal(out.images.verifier, json(join(w.stateDir, 'service/terraform.tfvars.json')).verifier_image);
    assert.equal((out.inventory as { source: string }).source, 'deploy.sh');
    assert.ok(w.ep.requests >= 1);
    for (const key of ['total_s', 'bootstrap_s', 'images_s', 'service_s', 'inventory_s', 'ready_s']) assert.equal(typeof out.timing[key], 'number', key);
    assert.equal(json(join(w.stateDir, 'deployment.json')).phase, 'ready');
    assert.match(r.out, /Deployed dnsid-gse-[0-9a-f]{8} in \d+s/);
    assert.equal(existsSync(join(w.stateDir, '.lock')), false);
  });

  test('state, records and certificate material are private', async (t) => {
    const w = await world(t);
    assert.equal((await deploy(w)).code, 0);
    for (const path of ['deployment.json', 'bootstrap/terraform.tfvars.json', 'service/certificate.pem', 'builds/images.json']) {
      assert.equal(statSync(join(w.stateDir, path)).mode & 0o077, 0, path);
    }
    for (const dir of ['', 'bootstrap', 'service', 'builds']) assert.equal(statSync(join(w.stateDir, dir)).mode & 0o777, 0o700, dir);
  });

  test('not advertised before the endpoint answers: a load balancer error until the bounded wait runs out is a failure, and no DEPLOY_OUT', async (t) => {
    const w = await world(t);
    w.ep.mode = 'failing';
    const r = await deploy(w);
    assert.equal(r.code, 1);
    assert.match(r.out, /did not answer unsigned requests with the verifier's denial steadily for 180s within 1800s \(last: HTTP 500/);
    assert.match(r.out, /DEPLOY FAILED during: ready/);
    assert.equal(existsSync(w.deployOut), false);
    assert.ok(w.ep.requests > 1);
  });

  test('ready only after the denial held on every probe for 180 s, in bursts of 8 on new connections: the first denials are not enough', async (t) => {
    const w = await world(t);
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    // A burst of 8 every 5 s from the first denials until 180 s have passed: 37 rounds, 296 denials in a row, each its own request.
    assert.equal(w.ep.requests, 296);
    assert.match(r.out, /first denials \(\d+s\): HTTP 403 cache-control="no-store" body="signature_missing" \(8\/8 verifier denials\); now every probe for 180s must be one/);
    assert.match(r.out, /Ready: HTTP 403 cache-control="no-store" body="signature_missing" \(8\/8 verifier denials\) \(296 denials in a row over 180s; Demo Bank answered 0 earlier probe round\(s\)\)/);
    assert.ok(Number(parseDeployOut(readFileSync(w.deployOut, 'utf8')).timing['ready_s']) >= 180);
  });

  test("a load balancer still settling (the live deployment of 2026-11-14: a 403, then 500s among 403s) isn't ready until it holds; each failure starts the window again", async (t) => {
    const w = await world(t);
    // The first round is all denials, request 10 (round 2) and request 50 (round 7) get the load balancer's 500, then it holds.
    w.ep.failsAt = (n) => n === 10 || n === 50;
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /not steady yet \(\d+s\): after 8 denial\(s\) in a row: HTTP 500 .*\(7\/8 verifier denials\)/);
    assert.match(r.out, /not steady yet \(\d+s\): after 32 denial\(s\) in a row: HTTP 500/);
    // 7 rounds until the last failure, then 37 rounds of denials.
    assert.equal(w.ep.requests, 7 * 8 + 296);
    assert.match(r.out, /\(296 denials in a row over 180s; Demo Bank answered 0 earlier probe round\(s\)\)/);
  });

  test("Demo Bank answering an unsigned probe (the eighth live deployment, 2026-11-14: the policy not yet in force on some front end) isn't ready: the policy must then hold for 600 s", async (t) => {
    const w = await world(t);
    // Round 1 is all denials; one probe of round 2 reaches Demo Bank; then every probe is the verifier's denial.
    w.ep.bypassAt = (n) => n === 12;
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    assert.match(
      r.out,
      /the authorization policy is not in force yet \(\d+s\): Demo Bank answered an unsigned request: HTTP 403 cache-control="no-store" body="\{\\"error\\":\\"identity_context_required\\"\}" \(7\/8 verifier denials, 1 answered by Demo Bank\); once it holds, every probe for 600s must be the verifier's denial/,
    );
    // 2 rounds until the bypass, then 121 rounds (600 s, every 5 s) of denials, not the usual 37.
    assert.equal(w.ep.requests, 2 * 8 + 121 * 8);
    assert.match(r.out, /\(968 denials in a row over 600s; Demo Bank answered 1 earlier probe round\(s\)\)/);
    assert.ok(Number(parseDeployOut(readFileSync(w.deployOut, 'utf8')).timing['ready_s']) >= 600);
  });

  test('Demo Bank answering now and then never lets readiness pass: a failure at the bounded wait, and no DEPLOY_OUT', async (t) => {
    const w = await world(t);
    // One probe in every 100 rounds reaches Demo Bank: the 600 s hold never completes.
    w.ep.bypassAt = (n) => n % 800 === 5;
    const r = await deploy(w);
    assert.equal(r.code, 1);
    assert.match(r.out, /did not answer unsigned requests with the verifier's denial steadily for 600s within 1800s/);
    assert.match(r.out, /DEPLOY FAILED during: ready/);
    assert.equal(existsSync(w.deployOut), false);
  });

  test('an endpoint that never holds the denial for 180 s is a failure at the bounded wait, and no DEPLOY_OUT', async (t) => {
    const w = await world(t);
    w.ep.failsAt = (n) => n % 160 === 0;
    const r = await deploy(w);
    assert.equal(r.code, 1);
    assert.match(r.out, /did not answer unsigned requests with the verifier's denial steadily for 180s within 1800s/);
    assert.match(r.out, /DEPLOY FAILED during: ready/);
    assert.equal(existsSync(w.deployOut), false);
  });

  test("an endpoint presenting another certificate never counts as ready (the deployment's own certificate is pinned)", async (t) => {
    const w = await world(t);
    const { service } = stageOutputs(selfSignedCertificate('127.0.0.1').cert, `https://127.0.0.1:${w.ep.port}`);
    w.cli.write('outputs-service.json', JSON.stringify(service));
    const r = await deploy(w);
    assert.equal(r.code, 1);
    assert.match(r.out, /last: connection: /);
    assert.equal(existsSync(w.deployOut), false);
    assert.equal(w.ep.requests, 0, 'nothing was sent over the unverified connection');
  });
});

describe('deploy.sh and teardown.sh: authentication, without a key file or a second login', () => {
  const noTokens = (env: Record<string, string>) => {
    const copy = { ...env };
    delete copy['GOOGLE_OAUTH_ACCESS_TOKEN'];
    delete copy['CLOUDSDK_AUTH_ACCESS_TOKEN_FILE'];
    return copy;
  };
  const neverExposed = (w: World, r: Ran, token: string) => {
    assert.equal(r.out.includes(token), false, 'the token was printed');
    for (const call of w.cli.calls()) assert.equal(call.args.join(' ').includes(token), false, `the token was in arguments: ${call.args.join(' ')}`);
  };

  test('Application Default Credentials: Terraform reads them itself; gcloud gets a token minted from them, in a private file', async (t) => {
    const w = await world(t, { FAKE_ADC_TOKEN: 'adc-minted-token-0123456789' });
    const r = await run(DEPLOY, noTokens(w.env));
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Login: Application Default Credentials/);
    for (const call of terraform(w.cli.calls())) assert.equal(call.env?.GOOGLE_OAUTH_ACCESS_TOKEN, null);
    const g = gcloud(w.cli.calls()).filter((c) => c.args[0] !== 'auth');
    assert.ok(g.length > 0);
    for (const call of g) {
      assert.equal(call.token, 'adc-minted-token-0123456789\n');
      assert.equal(call.tokenMode, '600');
    }
    neverExposed(w, r, 'adc-minted-token-0123456789');
    // The private directory holding the token is gone afterwards.
    assert.equal(existsSync(g[0]?.tokenFile as string), false);
  });

  test('a short-lived token in GOOGLE_OAUTH_ACCESS_TOKEN: Terraform uses it; gcloud gets it in a private file', async (t) => {
    const w = await world(t);
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Login: a short-lived access token/);
    for (const call of terraform(w.cli.calls())) assert.equal(call.env?.GOOGLE_OAUTH_ACCESS_TOKEN, TOKEN);
    for (const call of gcloud(w.cli.calls())) {
      assert.equal(call.token, TOKEN);
      assert.equal(call.tokenMode, '600');
    }
    assert.equal(gcloud(w.cli.calls()).some((c) => c.args[0] === 'auth'), false, 'no other login is attempted');
    neverExposed(w, r, TOKEN);
  });

  test('a token file in CLOUDSDK_AUTH_ACCESS_TOKEN_FILE: gcloud reads it; Terraform gets its content', async (t) => {
    const w = await world(t);
    const file = join(w.home, 'token');
    writeFileSync(file, 'file-token-0123456789\n', { mode: 0o600 });
    const r = await run(DEPLOY, { ...noTokens(w.env), CLOUDSDK_AUTH_ACCESS_TOKEN_FILE: file });
    assert.equal(r.code, 0, r.out);
    for (const call of terraform(w.cli.calls())) assert.equal(call.env?.GOOGLE_OAUTH_ACCESS_TOKEN, 'file-token-0123456789');
    for (const call of gcloud(w.cli.calls())) assert.equal(call.tokenFile, file);
    neverExposed(w, r, 'file-token-0123456789');
  });

  test('no login at all: a clear instruction, exit 2, nothing created', async (t) => {
    const w = await world(t);
    const r = await run(DEPLOY, noTokens(w.env));
    assert.equal(r.code, 2);
    assert.match(r.out, /no Google Cloud login: run `gcloud auth application-default login`/);
    assert.equal(terraform(w.cli.calls()).length, 0);
  });

  test('an unreadable or empty token file is refused', async (t) => {
    const w = await world(t);
    const empty = join(w.home, 'empty');
    writeFileSync(empty, '');
    for (const file of [join(w.home, 'missing'), empty]) {
      const r = await run(DEPLOY, { ...noTokens(w.env), CLOUDSDK_AUTH_ACCESS_TOKEN_FILE: file });
      assert.equal(r.code, 2);
      assert.match(r.out, /CLOUDSDK_AUTH_ACCESS_TOKEN_FILE (names a file that can't be read|is empty)/);
    }
  });

  test('neither script refers to a key file, a credentials setting or a service-account login', () => {
    for (const file of ['scripts/deploy.sh', 'scripts/teardown.sh', 'scripts/test-live.sh', 'scripts/lib/common.sh', 'scripts/live/cloud.ts']) {
      const text = readFileSync(join(ROOT, file), 'utf8');
      assert.doesNotMatch(text, /activate-service-account|GOOGLE_APPLICATION_CREDENTIALS|key-file|credentials\s*=/, file);
    }
  });
});

describe('failures, recovery and teardown (simulated)', () => {
  const recordOf = (w: World) => json(join(w.stateDir, 'deployment.json'));

  test('failure after the bootstrap stage: the inventory is kept, a rerun resumes the same deployment, teardown removes everything', async (t) => {
    const w = await world(t, { FAKE_SUBMIT_FAIL: '1' });
    const failed = await deploy(w);
    assert.equal(failed.code, 1);
    assert.match(failed.out, /the image build could not be submitted/);
    assert.match(failed.out, /DEPLOY FAILED during: images[\s\S]*Retry \(resumes\): {2}scripts\/deploy\.sh {6}Remove it all: {2}scripts\/teardown\.sh/);
    assert.deepEqual(stateOf(w, 'bootstrap'), BOOTSTRAP_RESOURCES);
    assert.deepEqual(stateOf(w, 'service'), []);
    assert.equal(existsSync(w.deployOut), false);
    const name = recordOf(w).name;

    const resumed = await deploy({ ...w, env: { ...w.env, FAKE_SUBMIT_FAIL: '' } });
    assert.equal(resumed.code, 0, resumed.out);
    assert.match(resumed.out, new RegExp(`Resuming deployment ${name}`));
    assert.equal(recordOf(w).name, name);

    const down = await teardown(w);
    assert.equal(down.code, 0, down.out);
    assert.deepEqual(stateOf(w, 'service'), []);
    assert.equal(existsSync(join(w.stateDir, 'deployment.json')), false);
    const last = json(join(w.stateDir, 'last-teardown.json'));
    assert.equal(last.deployment, name);
    assert.equal(last.removed.length, BOOTSTRAP_RESOURCES.length + SERVICE_RESOURCES.length);
    // Service before bootstrap.
    const destroys = terraform(w.cli.calls()).filter((c) => c.args[0] === 'destroy').map((c) => c.stage);
    assert.deepEqual(destroys, ['service', 'bootstrap']);
  });

  test('a failed image build: its log is shown, nothing is published, and teardown removes the bootstrap stage', async (t) => {
    const w = await world(t, { FAKE_BUILD_STATUSES: 'WORKING,FAILURE' });
    const failed = await deploy(w);
    assert.equal(failed.code, 1);
    assert.match(failed.out, /build [0-9a-f-]{36}: FAILURE/);
    assert.match(failed.out, /fake build log: step validate failed/);
    assert.equal(existsSync(join(w.stateDir, 'builds/images.json')), false);
    assert.deepEqual(stateOf(w, 'service'), []);
    const down = await teardown(w);
    assert.equal(down.code, 0, down.out);
    assert.deepEqual(stateOf(w, 'bootstrap'), []);
  });

  test('a build that never finishes is cancelled at the bounded wait', async (t) => {
    const w = await world(t, { FAKE_BUILD_STATUSES: 'WORKING' });
    const failed = await deploy(w);
    assert.equal(failed.code, 1);
    assert.match(failed.out, /still WORKING after 2700s; cancelling it/);
    assert.ok(gcloud(w.cli.calls()).some((c) => c.args[1] === 'cancel'));
  });

  test('a rerun after an interrupted wait waits for the same build instead of submitting another', async (t) => {
    const w = await world(t, { FAKE_BUILD_STATUSES: 'WORKING' });
    const ledger = join(w.stateDir, 'builds/builds.tsv');
    const interrupted = await run(DEPLOY, w.env, { killWhen: () => existsSync(ledger) && readFileSync(ledger, 'utf8').length > 0 });
    assert.equal(interrupted.code, 143, interrupted.out);
    assert.match(interrupted.out, /DEPLOY FAILED during: images \(exit 143\)/);
    assert.equal(existsSync(join(w.stateDir, '.lock')), false, 'the lock is released');
    const [id] = w.cli.read('submitted').trim().split('\n');
    // The build then finishes on its own.
    const build = JSON.parse(w.cli.read(`builds/${id}`));
    build.statuses = ['SUCCESS'];
    w.cli.write(`builds/${id}`, JSON.stringify(build));
    const resumed = await deploy(w);
    assert.equal(resumed.code, 0, resumed.out);
    assert.match(resumed.out, new RegExp(`Waiting for build ${id}, started earlier for this source`));
    assert.equal(w.cli.read('submitted').trim().split('\n').length, 1);
  });

  test('interrupted between submitting the build and recording it: teardown still finds the build by its tag and stops it', async (t) => {
    const w = await world(t, { FAKE_BUILD_STATUSES: 'WORKING' });
    // The fake records the submission before the script can record the id; killing then leaves the ledger without it.
    const interrupted = await run(DEPLOY, w.env, { killWhen: () => w.cli.exists('submitted') });
    assert.equal(interrupted.code, 143, interrupted.out);
    const [id] = w.cli.read('submitted').trim().split('\n');
    const r = await teardown(w);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, new RegExp(`build ${id}: CANCELLED`));
    assert.ok(gcloud(w.cli.calls()).some((c) => c.args[1] === 'cancel' && c.args[2] === id));
  });

  test('a build that succeeded before an interruption is reused, not rebuilt', async (t) => {
    const w = await world(t);
    assert.equal((await deploy(w)).code, 0);
    const again = await deploy(w);
    assert.equal(again.code, 0, again.out);
    assert.match(again.out, /already built and published: reusing them/);
    assert.equal(w.cli.read('submitted').trim().split('\n').length, 1);
  });

  test('a failure partway through the service stage: what it created is in its state, and teardown removes it all', async (t) => {
    const w = await world(t, { FAKE_TF_FAIL_APPLY_SERVICE: '2', FAKE_TF_PARTIAL_SERVICE: SERVICE_RESOURCES.slice(0, 2).join(',') });
    const failed = await deploy(w);
    assert.equal(failed.code, 1);
    assert.match(failed.out, /terraform apply \(service\) failed; retrying once in 30 s/);
    assert.match(failed.out, /DEPLOY FAILED during: service/);
    assert.deepEqual(stateOf(w, 'service'), SERVICE_RESOURCES.slice(0, 2));
    assert.equal(existsSync(w.deployOut), false);
    const down = await teardown(w);
    assert.equal(down.code, 0, down.out);
    assert.match(down.out, /service stage: removing 2 resource\(s\)/);
    assert.deepEqual(stateOf(w, 'service'), []);
    assert.deepEqual(stateOf(w, 'bootstrap'), []);
  });

  test('a transient apply failure is retried once and then succeeds', async (t) => {
    const w = await world(t, { FAKE_TF_FAIL_APPLY_BOOTSTRAP: '1' });
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    assert.equal(terraform(w.cli.calls()).filter((c) => c.stage === 'bootstrap' && c.args[0] === 'apply').length, 2);
  });

  // The tail of a real bootstrap failure (2026-11-14): the login could enable none of the APIs that weren't on already,
  // and Network Security wasn't. Identifiers removed; the first line is the provider's error heading.
  const ENABLE_REFUSED = [
    'Error: Error when reading or editing Project Service sandbox-project-1/networksecurity.googleapis.com: googleapi: Error 403: Permission denied to enable service [networksecurity.googleapis.com]',
    'Details:',
    '[',
    '  {',
    '    "@type": "type.googleapis.com/google.rpc.ErrorInfo",',
    '    "domain": "serviceusage.googleapis.com",',
    '    "metadata": {',
    '      "permission": "serviceusage.services.enable",',
    '      "service": "serviceusage.googleapis.com"',
    '    },',
    '    "reason": "AUTH_PERMISSION_DENIED"',
    '  }',
    ']',
    ', forbidden',
    '',
    '  with google_project_service.required["networksecurity.googleapis.com"],',
    '  on main.tf line 31, in resource "google_project_service" "required":',
    '  31: resource "google_project_service" "required" {',
    '',
  ].join('\n');

  test('an API the login may not enable: not retried, the API and the command that enables it are named, a rerun resumes', async (t) => {
    const w = await world(t, { FAKE_TF_FAIL_APPLY_BOOTSTRAP: '1' });
    w.cli.write('enable-refused.log', ENABLE_REFUSED);
    const env = { FAKE_TF_FAIL_LOG_BOOTSTRAP: join(w.cli.dir, 'enable-refused.log') };
    const failed = await deploy(w, env);
    assert.equal(failed.code, 1, failed.out);
    assert.equal(terraform(w.cli.calls()).filter((c) => c.stage === 'bootstrap' && c.args[0] === 'apply').length, 1);
    assert.doesNotMatch(failed.out, /retrying once/);
    assert.match(failed.out, /The login may not enable these APIs in project sandbox-project-1 \(permission serviceusage\.services\.enable\):\n  networksecurity\.googleapis\.com\n/);
    assert.match(failed.out, /\n  gcloud services enable networksecurity\.googleapis\.com --project=sandbox-project-1\n/);
    assert.match(failed.out, /DEPLOY FAILED during: bootstrap/);
    assert.equal(gcloud(w.cli.calls()).some((c) => c.args[0] === 'builds'), false, 'nothing after the bootstrap stage runs');
    assert.equal(existsSync(w.deployOut), false);
    // Once someone enables it, the same command resumes the same deployment.
    const name = json(join(w.stateDir, 'deployment.json')).name;
    const again = await deploy(w, env);
    assert.equal(again.code, 0, again.out);
    assert.equal(json(join(w.stateDir, 'deployment.json')).name, name);
  });

  test('a failure that mentions the permission but names no API it was refused is retried as before', async (t) => {
    const w = await world(t, { FAKE_TF_FAIL_APPLY_BOOTSTRAP: '1' });
    w.cli.write('other.log', 'Error: Error 403: caller lacks serviceusage.services.enable on another resource\n');
    const r = await deploy(w, { FAKE_TF_FAIL_LOG_BOOTSTRAP: join(w.cli.dir, 'other.log') });
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /terraform apply \(bootstrap\) failed; retrying once in 30 s/);
    assert.equal(terraform(w.cli.calls()).filter((c) => c.stage === 'bootstrap' && c.args[0] === 'apply').length, 2);
  });

  test('a STATE_DIR holding a deployment in another project or region is refused', async (t) => {
    const w = await world(t, { FAKE_SUBMIT_FAIL: '1' });
    await deploy(w);
    for (const env of [{ GOOGLE_CLOUD_PROJECT: 'other-project-2' }, { GOOGLE_CLOUD_REGION: 'europe-west4' }]) {
      const r = await deploy(w, env);
      assert.equal(r.code, 2);
      assert.match(r.out, /STATE_DIR already holds deployment dnsid-gse-[0-9a-f]{8} in another project or region/);
    }
    const r = await teardown(w, { GOOGLE_CLOUD_PROJECT: 'other-project-2' });
    assert.equal(r.code, 2);
    assert.match(r.out, /another project than GOOGLE_CLOUD_PROJECT; refusing/);
  });

  test('one command at a time per STATE_DIR: a live lock holder refuses the second, a stale lock is taken over', async (t) => {
    const w = await world(t);
    mkdirSync(join(w.stateDir, '.lock'), { recursive: true });
    writeFileSync(join(w.stateDir, '.lock/pid'), String(process.pid));
    const busy = await deploy(w);
    assert.equal(busy.code, 3);
    assert.match(busy.out, /another deploy or teardown \(process \d+\) is using this STATE_DIR/);
    writeFileSync(join(w.stateDir, '.lock/pid'), '999999');
    const stale = await deploy(w);
    assert.equal(stale.code, 0, stale.out);
    assert.match(stale.out, /taking over a lock left by a process that is no longer running/);
  });
});

describe('teardown.sh (simulated)', () => {
  async function deployed(t: TestContext, extra: Record<string, string> = {}): Promise<World> {
    const w = await world(t, extra);
    const r = await deploy(w);
    assert.equal(r.code, 0, r.out);
    return w;
  }

  test('a complete deployment: service then bootstrap, a final inventory, what was removed, and the state goes; a second run finds nothing', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Removed deployment dnsid-gse-[0-9a-f]{8}:\n {2}service: google_cloud_run_v2_service\.verifier/);
    assert.match(r.out, /Confirmed: nothing named dnsid-gse-[0-9a-f]{8} remains/);
    assert.match(r.out, /Kept on purpose: the enabled APIs/);
    for (const kind of ['compute-forwarding-rules', 'compute-addresses', 'run-services', 'artifacts-repositories', 'storage-buckets', 'iam-service-accounts', 'network-security-authz-policies', 'service-extensions-authz-extensions']) {
      assert.ok(gcloud(w.cli.calls()).some((c) => c.args.slice(0, c.args.indexOf('list')).join('-') === kind && c.args.some((a) => a.startsWith('--filter='))), kind);
    }
    for (const gone of ['deployment.json', 'bootstrap', 'service', 'builds', 'deploy-out.json']) assert.equal(existsSync(join(w.stateDir, gone)), false, gone);
    const again = await teardown(w);
    assert.equal(again.code, 0);
    assert.match(again.out, /Nothing to tear down: no deployment state/);
  });

  test("only the deployment's own state and builds are touched: no delete commands, other deployments' builds left alone", async (t) => {
    const w = await deployed(t);
    // Another deployment's build, still running, in the same project.
    w.cli.write('builds/11111111-2222-3333-4444-5555aaaa5555', JSON.stringify({ statuses: ['WORKING'], subs: {} }));
    w.cli.write('ongoing', '11111111-2222-3333-4444-5555aaaa5555 dnsid-gse-ffffffff\n');
    const r = await teardown(w);
    assert.equal(r.code, 0, r.out);
    const calls = gcloud(w.cli.calls());
    assert.equal(calls.some((c) => c.args.includes('delete')), false);
    assert.equal(calls.some((c) => c.args[1] === 'cancel' && c.args[2]?.startsWith('11111111')), false);
  });

  test('a build still running is cancelled and seen to stop before anything is removed', async (t) => {
    const w = await deployed(t);
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    const id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    w.cli.write(`builds/${id}`, JSON.stringify({ statuses: ['WORKING'], subs: {} }));
    w.cli.write('ongoing', `${id} ${name}\n`);
    const r = await teardown(w);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, new RegExp(`build ${id}: CANCELLED`));
    const order = w.cli.calls().map((c) => (c.tool === 'terraform' ? `tf:${c.args[0]}` : `g:${c.args[1]}`));
    assert.ok(order.indexOf('g:cancel') < order.indexOf('tf:destroy'));
  });

  test('a build that cannot be confirmed stopped: nothing is removed, the state is kept, exit 1', async (t) => {
    const w = await deployed(t);
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    const id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    w.cli.write(`builds/${id}`, JSON.stringify({ statuses: ['WORKING'], subs: {} }));
    w.cli.write('ongoing', `${id} ${name}\n`);
    // The cancel doesn't take: the fake keeps reporting WORKING.
    const sticky = w.cli.read('bin/gcloud').replace("build.statuses = ['CANCELLED'];", '');
    writeFileSync(join(w.cli.bin, 'gcloud'), sticky, { mode: 0o755 });
    const r = await teardown(w);
    assert.equal(r.code, 1);
    assert.match(r.out, new RegExp(`could not be confirmed stopped, so nothing was removed: ${id} \\(WORKING\\)`));
    assert.match(r.out, /TEARDOWN NOT COMPLETE/);
    assert.deepEqual(stateOf(w, 'service'), SERVICE_RESOURCES);
    assert.deepEqual(stateOf(w, 'bootstrap'), BOOTSTRAP_RESOURCES);
  });

  test("the project's builds can't be listed: nothing is removed, exit 1", async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_BUILDS_LIST_FAIL: '1' });
    assert.equal(r.code, 1);
    assert.match(r.out, /a running build can't be ruled out/);
    assert.deepEqual(stateOf(w, 'service'), SERVICE_RESOURCES);
  });

  test('a removal that fails twice keeps the state and says so; a retry later completes', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_TF_FAIL_DESTROY_SERVICE: '2' });
    assert.equal(r.code, 1);
    assert.match(r.out, /terraform destroy \(service\) failed twice/);
    assert.match(r.out, /TEARDOWN NOT COMPLETE \(during: removing the service stage/);
    assert.deepEqual(stateOf(w, 'service'), SERVICE_RESOURCES);
    assert.deepEqual(stateOf(w, 'bootstrap'), BOOTSTRAP_RESOURCES, 'the bootstrap stage is not touched while the service stage remains');
    const retry = await teardown(w);
    assert.equal(retry.code, 0, retry.out);
  });

  test('a destroy that reports success but leaves resources in the state is not confirmed', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_TF_DESTROY_KEEPS_SERVICE: '1' });
    assert.equal(r.code, 1);
    assert.match(r.out, /after destroy, the service stage's state still lists: google_cloud_run_v2_service\.verifier/);
    assert.ok(existsSync(join(w.stateDir, 'deployment.json')));
  });

  test('anything left in the final inventory, or a listing that fails, means not confirmed: state kept, exit 1; a disabled API is not a failure', async (t) => {
    const w = await deployed(t);
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    w.cli.write('leftover-compute-addresses', `${name}-ip\n`);
    let r = await teardown(w);
    assert.equal(r.code, 1);
    assert.match(r.out, new RegExp(`NOT CONFIRMED: addresses remaining: ${name}-ip`));
    assert.ok(existsSync(join(w.stateDir, 'deployment.json')), 'the record is kept for the retry');
    rmSync(join(w.cli.dir, 'leftover-compute-addresses'));
    r = await teardown(w, { FAKE_INVENTORY_FAIL: 'iam-service-accounts' });
    assert.equal(r.code, 1);
    assert.match(r.out, /NOT CONFIRMED: service accounts could not be listed: ERROR: \(gcloud\) PERMISSION_DENIED/);
    r = await teardown(w, { FAKE_INVENTORY_DISABLED: 'service-extensions-authz-extensions' });
    assert.equal(r.code, 0, r.out);
  });

  test('a teardown lists what exists before removing it, the same way it confirms nothing is left, after a complete or a partial deployment', async (t) => {
    for (const partial of [false, true]) {
      const w = await world(t, partial ? { FAKE_BUILD_STATUSES: 'WORKING,FAILURE' } : {});
      const up = await deploy(w);
      assert.equal(up.code, partial ? 1 : 0, up.out);
      const name = json(join(w.stateDir, "deployment.json")).name as string;
      // What Google's APIs list for the deployment while it exists, and which stage's destroy removes it.
      w.cli.write('leftover-compute-addresses', `${name}-ip\n`);
      w.cli.write('leftover-storage-buckets', `${name}-build\n`);
      w.cli.write('iam-artifacts-repositories', `roles/artifactregistry.writer serviceAccount:${name}-build@p.iam.gserviceaccount.com\n`);
      w.cli.write('owned-bootstrap', 'leftover-compute-addresses\nleftover-storage-buckets\niam-artifacts-repositories\n');
      if (!partial) {
        w.cli.write('leftover-run-services', `${name}-verifier\n${name}-origin\n`);
        w.cli.write('owned-service', 'leftover-run-services\n');
      }
      const down = await teardown(w);
      assert.equal(down.code, 0, down.out);
      const before = down.out.slice(down.out.indexOf('before removal, listed by name:'), down.out.indexOf('stage: '));
      assert.match(before, new RegExp(`addresses: ${name}-ip`));
      assert.match(before, new RegExp(`storage buckets: ${name}-build`));
      assert.match(before, new RegExp(`grants on the repository: roles/artifactregistry.writer serviceAccount:${name}-build@`));
      if (partial) assert.doesNotMatch(before, /Cloud Run services/);
      else assert.match(before, new RegExp(`Cloud Run services: ${name}-verifier ${name}-origin`));
      // Listed before the first destroy.
      assert.ok(down.out.indexOf('before removal') < down.out.indexOf('stage: removing'), down.out);
      assert.match(down.out, /Confirmed: nothing named .* remains/);
      const last = json(join(w.stateDir, 'last-teardown.json'));
      assert.ok((last.found_before as string[]).includes(`addresses: ${name}-ip`), JSON.stringify(last));
      assert.deepEqual(last.remaining_after, []);
      assert.equal((last.removed as string[]).length, BOOTSTRAP_RESOURCES.length + (partial ? 0 : SERVICE_RESOURCES.length));
    }
  });

  test('a listing that fails before removal is reported, not fatal; the final confirmation still decides', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_INVENTORY_FAIL: 'compute-url-maps' });
    assert.equal(r.code, 1);
    assert.match(r.out, /URL maps: could not be listed: ERROR: \(gcloud\) PERMISSION_DENIED/);
    assert.match(r.out, /NOT CONFIRMED: URL maps could not be listed/);
    assert.equal(terraform(w.cli.calls()).filter((c) => c.args[0] === 'destroy').length, 2, 'removal went ahead');
  });

  test('project IAM bindings naming the deployment are part of the final confirmation', async (t) => {
    const w = await deployed(t);
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    w.cli.write('iam-projects', `roles/viewer serviceAccount:${name}-build@p.iam.gserviceaccount.com\n`);
    const r = await teardown(w);
    assert.equal(r.code, 1);
    assert.match(r.out, new RegExp(`NOT CONFIRMED: project IAM bindings remaining: roles/viewer serviceAccount:${name}-build@`));
    // A login that may not read the project's IAM policy is told so; the teardown doesn't fail on it.
    rmSync(join(w.cli.dir, 'iam-projects'));
    const refused = await teardown(w, { FAKE_INVENTORY_FAIL: 'projects' });
    assert.equal(refused.code, 0, refused.out);
    assert.match(refused.out, /Note: project IAM bindings could not be listed \(the deployment grants none\): ERROR: \(gcloud\) PERMISSION_DENIED/);
  });

  test('a project IAM policy that cannot be read is recorded and reported as not inspected, never as confirmed', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_INVENTORY_FAIL: 'projects' });
    assert.equal(r.code, 0, r.out);
    const confirmed = r.out.slice(r.out.indexOf('Confirmed: nothing named'));
    const listed = confirmed.slice(0, confirmed.indexOf('Not inspected'));
    assert.match(listed, /service accounts/);
    assert.doesNotMatch(listed, /project IAM bindings/, 'the confirmation names only what was listed');
    assert.match(confirmed, /Not inspected \(recorded in .*last-teardown\.json; this teardown doesn't confirm them\):\n  project IAM bindings: could not be listed: ERROR: \(gcloud\) PERMISSION_DENIED/);
    const last = json(join(w.stateDir, 'last-teardown.json'));
    assert.deepEqual(last.not_checked_after, [{ kind: 'project IAM bindings', reason: 'ERROR: (gcloud) PERMISSION_DENIED: fake' }]);
    assert.equal((last.checked_after as string[]).includes('project IAM bindings'), false);
    assert.equal((last.checked_after as string[]).length, 14);
    assert.deepEqual(last.remaining_after, []);
    // When it can be read, it is confirmed and named, and nothing is recorded as not inspected.
    const w2 = await deployed(t);
    const ok = await teardown(w2);
    assert.equal(ok.code, 0, ok.out);
    assert.match(ok.out, /in what was listed:\n(  .*\n)*  project IAM bindings\n/);
    assert.doesNotMatch(ok.out, /Not inspected/);
    const last2 = json(join(w2.stateDir, 'last-teardown.json'));
    assert.deepEqual(last2.not_checked_after, []);
    assert.deepEqual(last2.not_listed_before, []);
    assert.equal((last2.checked_after as string[]).at(-1), 'project IAM bindings');
  });

  test('repository and bucket grants that cannot be read are reported and recorded as not listed, not as empty; a missing repository or bucket has none', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_IAM_FAIL: 'artifacts-repositories,storage-buckets' });
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Not listed before removal \(removal goes ahead; the final confirmation still decides\):\n  grants on the repository: could not be listed: ERROR: \(gcloud\) PERMISSION_DENIED: fake policy read\n  grants on the build bucket: could not be listed: ERROR: \(gcloud\) PERMISSION_DENIED: fake policy read/);
    const last = json(join(w.stateDir, 'last-teardown.json'));
    assert.deepEqual(last.not_listed_before, [
      { kind: 'grants on the repository', reason: 'ERROR: (gcloud) PERMISSION_DENIED: fake policy read' },
      { kind: 'grants on the build bucket', reason: 'ERROR: (gcloud) PERMISSION_DENIED: fake policy read' },
    ]);
    // A repository and bucket that were never created (a partial deployment) have no grants: nothing to report.
    const w2 = await deployed(t);
    const gone = await teardown(w2, { FAKE_IAM_NOT_FOUND: 'artifacts-repositories,storage-buckets' });
    assert.equal(gone.code, 0, gone.out);
    assert.doesNotMatch(gone.out, /Not listed before removal/);
    assert.deepEqual(json(join(w2.stateDir, 'last-teardown.json')).not_listed_before, []);
  });

  test('a resource listing that fails before removal is recorded as not listed, not found', async (t) => {
    const w = await deployed(t);
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    w.cli.write('leftover-compute-addresses', `${name}-ip\n`);
    w.cli.write('owned-bootstrap', 'leftover-compute-addresses\n');
    const r = await teardown(w, { FAKE_IAM_FAIL: 'projects' });
    assert.equal(r.code, 0, r.out);
    const last = json(join(w.stateDir, 'last-teardown.json'));
    assert.deepEqual(last.found_before, [`addresses: ${name}-ip`]);
    assert.deepEqual(last.not_listed_before, [{ kind: 'project IAM bindings', reason: 'ERROR: (gcloud) PERMISSION_DENIED: fake policy read' }]);
    assert.deepEqual(last.not_checked_after, [{ kind: 'project IAM bindings', reason: 'ERROR: (gcloud) PERMISSION_DENIED: fake policy read' }]);
  });

  test('state that cannot be read stops the teardown before anything is removed', async (t) => {
    const w = await deployed(t);
    const r = await teardown(w, { FAKE_TF_FAIL_STATE_BOOTSTRAP: '1' });
    assert.equal(r.code, 1);
    assert.match(r.out, /the bootstrap stage's state can't be read/);
    assert.equal(terraform(w.cli.calls()).some((c) => c.args[0] === 'destroy'), false);
  });

  test('without STATE_DIR or GOOGLE_CLOUD_PROJECT it refuses; with only STATE_DIR it reads the project from the state', async (t) => {
    const w = await deployed(t);
    const env = { ...w.env };
    delete env['GOOGLE_CLOUD_PROJECT'];
    const r = await run(TEARDOWN, { ...env, STATE_DIR: '' });
    assert.equal(r.code, 2);
    assert.match(r.out, /GOOGLE_CLOUD_PROJECT is required/);
    const ok = await run(TEARDOWN, env);
    assert.equal(ok.code, 0, ok.out);
    assert.match(ok.out, /in project sandbox-project-1, region us-central1/);
  });

  test('an interrupted teardown keeps its state, releases its lock, and a rerun finishes', async (t) => {
    const w = await deployed(t);
    const name = json(join(w.stateDir, 'deployment.json')).name as string;
    const id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    w.cli.write(`builds/${id}`, JSON.stringify({ statuses: ['WORKING'], subs: {} }));
    w.cli.write('ongoing', `${id} ${name}\n`);
    const sticky = w.cli.read('bin/gcloud').replace("build.statuses = ['CANCELLED'];", '');
    writeFileSync(join(w.cli.bin, 'gcloud'), sticky, { mode: 0o755 });
    const interrupted = await run(TEARDOWN, w.env, { killWhen: () => w.cli.read('calls').includes('"cancel"') });
    assert.equal(interrupted.code, 143);
    assert.match(interrupted.out, /TEARDOWN NOT COMPLETE \(during: stopping image builds, exit 143\)/);
    assert.equal(existsSync(join(w.stateDir, '.lock')), false);
    assert.deepEqual(stateOf(w, 'service'), SERVICE_RESOURCES);
    w.cli.write(`builds/${id}`, JSON.stringify({ statuses: ['CANCELLED'], subs: {} }));
    const rerun = await teardown(w);
    assert.equal(rerun.code, 0, rerun.out);
  });
});
