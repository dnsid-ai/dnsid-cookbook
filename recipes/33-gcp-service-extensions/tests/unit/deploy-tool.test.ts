// The deployment helpers in scripts/lib/: TLS pinned to the deployment's certificate (the readiness probe), DEPLOY_OUT's
// assembly, checks and atomic write, the image build's digests, the build context's fingerprint, and the inventory checks
// behind the bypass cases. Local HTTPS servers with in-memory certificates; no cloud.

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';

import { parseDeployOut, readDeployOut, writeJsonAtomic, DeployOutError, type Inventory } from '../../scripts/lib/deploy-out.ts';
import { assembleDeployOut, buildImages, fingerprint, isOriginAnswer, outputValue, probeReady, probeReadyBurst, ToolError } from '../../scripts/lib/deploy-tool.ts';
import { checkCoverage, checkNoCdn, checkNoRewrite, inventoryFrom, resourceKey } from '../../scripts/lib/inventory.ts';
import { checkedPin, fingerprintOf, PinError } from '../../scripts/lib/pinned-tls.ts';
import { DIGEST_O, DIGEST_V, FAKE_SELF, REFS, deployOutInputs, deploymentListings } from '../support/deploy-fixtures.ts';
import { selfSignedCertificate, type LocalCertificate } from '../support/local-https.ts';

async function server(t: TestContext, certificate: LocalCertificate, answer: (path: string) => [number, Record<string, string>, string]): Promise<number> {
  const s: Server = createServer({ key: certificate.key, cert: certificate.cert }, (req, res) => {
    const [status, headers, body] = answer(req.url ?? '');
    res.writeHead(status, headers);
    res.end(body);
  });
  await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  });
  return (s.address() as AddressInfo).port;
}

const denial = (): [number, Record<string, string>, string] => [403, { 'cache-control': 'no-store' }, 'signature_missing'];

describe('the readiness probe: TLS pinned to the deployment certificate', () => {
  test("ready only on the verifier's own 403 signature_missing, over the pinned certificate", async (t) => {
    const cert = selfSignedCertificate('127.0.0.1');
    const port = await server(t, cert, denial);
    const result = await probeReady(`https://127.0.0.1:${port}`, cert.cert, fingerprintOf(cert.cert), '/accounts');
    assert.deepEqual(result, { ready: true, bypass: false, detail: 'HTTP 403 cache-control="no-store" body="signature_missing"' });
  });

  test('a load balancer error, another denial, a missing no-store or Demo Bank is not ready', async (t) => {
    const cert = selfSignedCertificate('127.0.0.1');
    const answers: [number, Record<string, string>, string][] = [
      [500, {}, '<html>Internal Server Error</html>'],
      [403, { 'cache-control': 'no-store' }, 'signature_invalid'],
      [403, {}, 'signature_missing'],
      [200, { 'cache-control': 'no-store' }, '{"bank":"Demo Bank","synthetic":true}'],
      [403, { 'cache-control': 'no-store' }, '{"error":"identity_context_required"}'],
      [404, {}, 'not found'],
    ];
    for (const answer of answers) {
      const port = await server(t, cert, () => answer);
      const result = await probeReady(`https://127.0.0.1:${port}`, cert.cert, fingerprintOf(cert.cert), '/accounts');
      assert.equal(result.ready, false, JSON.stringify(answer));
      // Only Demo Bank's own answers are a bypass of the authorization policy.
      assert.equal(result.bypass, answer[2].startsWith('{'), JSON.stringify(answer));
    }
  });

  test("Demo Bank's answer is its no-store JSON error or data; the verifier's denial, the load balancer's pages and other JSON are not", () => {
    assert.equal(isOriginAnswer('no-store', '{"error":"identity_context_required"}'), true);
    assert.equal(isOriginAnswer('no-store', '{"error":"identity_attestation_required"}'), true);
    assert.equal(isOriginAnswer('no-store', '{"bank":"Demo Bank","synthetic":true,"accounts":[]}'), true);
    for (const [cacheControl, body] of [
      ['no-store', 'signature_missing'],
      ['', '{"error":"identity_context_required"}'],
      ['no-store', '<html>Error</html>'],
      ['no-store', '{"other":1}'],
      ['no-store', 'null'],
      ['no-store', '"error"'],
    ] as const) {
      assert.equal(isOriginAnswer(cacheControl, body), false, body);
    }
  });

  test('a burst: every probe on its own connection, at once; ready only if all are denials, a bypass if any reached Demo Bank', async (t) => {
    const cert = selfSignedCertificate('127.0.0.1');
    let requests = 0;
    const sockets = new Set<unknown>();
    let answer = (n: number): [number, Record<string, string>, string] => (n === 3 ? [403, { 'cache-control': 'no-store' }, '{"error":"identity_context_required"}'] : denial());
    const s: Server = createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
      requests += 1;
      sockets.add(req.socket);
      const [status, headers, body] = answer(requests);
      res.writeHead(status, headers);
      res.end(body);
    });
    await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      s.closeAllConnections();
      await new Promise<void>((resolve) => s.close(() => resolve()));
    });
    const endpoint = `https://127.0.0.1:${(s.address() as AddressInfo).port}`;
    const bypassed = await probeReadyBurst(endpoint, cert.cert, fingerprintOf(cert.cert), '/accounts', 5_000, 8);
    assert.deepEqual(bypassed, {
      ready: false,
      bypass: true,
      detail: 'HTTP 403 cache-control="no-store" body="{\\"error\\":\\"identity_context_required\\"}" (7/8 verifier denials, 1 answered by Demo Bank)',
    });
    assert.equal(requests, 8);
    assert.equal(sockets.size, 8, 'each probe on its own connection');
    answer = (n) => (n === 10 ? [502, {}, '<html>Bad Gateway</html>'] : denial());
    const failed = await probeReadyBurst(endpoint, cert.cert, fingerprintOf(cert.cert), '/accounts', 5_000, 8);
    assert.deepEqual(failed, { ready: false, bypass: false, detail: 'HTTP 502 cache-control="" body="<html>Bad Gateway</html>" (7/8 verifier denials)' });
    answer = denial;
    assert.deepEqual(await probeReadyBurst(endpoint, cert.cert, fingerprintOf(cert.cert), '/accounts', 5_000, 8), {
      ready: true,
      bypass: false,
      detail: 'HTTP 403 cache-control="no-store" body="signature_missing" (8/8 verifier denials)',
    });
    for (const bad of [0, 65, 1.5, Number.NaN]) await assert.rejects(probeReadyBurst(endpoint, cert.cert, fingerprintOf(cert.cert), '/accounts', 5_000, bad), ToolError);
  });

  test('a different certificate for the same address fails: the trust anchor and the pin are the recorded certificate', async (t) => {
    const served = selfSignedCertificate('127.0.0.1');
    const recorded = selfSignedCertificate('127.0.0.1');
    const port = await server(t, served, denial);
    const result = await probeReady(`https://127.0.0.1:${port}`, recorded.cert, fingerprintOf(recorded.cert), '/accounts');
    assert.equal(result.ready, false);
    assert.match(result.detail, /^connection: /);
  });

  test('a certificate that does not name the endpoint address fails (hostname mismatch)', async (t) => {
    const cert = selfSignedCertificate('127.0.0.2');
    const port = await server(t, cert, denial);
    const result = await probeReady(`https://127.0.0.1:${port}`, cert.cert, fingerprintOf(cert.cert), '/accounts');
    assert.equal(result.ready, false);
    assert.match(result.detail, /ERR_TLS_CERT_ALTNAME_INVALID/);
  });

  test('a wrong pin fails before anything is sent, and a recorded pin that is not the certificate is refused', async (t) => {
    const cert = selfSignedCertificate('127.0.0.1');
    const other = selfSignedCertificate('127.0.0.1');
    let requests = 0;
    const port = await server(t, cert, () => {
      requests += 1;
      return denial();
    });
    const result = await probeReady(`https://127.0.0.1:${port}`, cert.cert, fingerprintOf(other.cert), '/accounts');
    assert.equal(result.ready, false);
    assert.match(result.detail, /recorded fingerprint does not match/);
    assert.equal(requests, 0);
    assert.throws(() => checkedPin({ certificatePem: cert.cert, fingerprint256: 'AA:BB' }), PinError);
    assert.throws(() => checkedPin({ certificatePem: 'not a certificate', fingerprint256: fingerprintOf(cert.cert) }), PinError);
  });

  test('no answer within the timeout is not ready', async (t) => {
    const cert = selfSignedCertificate('127.0.0.1');
    const s = createServer({ key: cert.key, cert: cert.cert }, () => {
      // never answers
    });
    await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      s.closeAllConnections();
      await new Promise<void>((resolve) => s.close(() => resolve()));
    });
    const result = await probeReady(`https://127.0.0.1:${(s.address() as AddressInfo).port}`, cert.cert, fingerprintOf(cert.cert), '/accounts', 300);
    assert.deepEqual(result, { ready: false, bypass: false, detail: 'no answer within 300 ms' });
  });
});

// ---------- DEPLOY_OUT ----------

describe('DEPLOY_OUT', () => {
  test('assembled from the stages: endpoint, protected path, the pinned certificate, digests, resources and bypass routes', () => {
    const cert = selfSignedCertificate('203.0.113.10');
    const out = assembleDeployOut(deployOutInputs(cert.cert), '2026-11-12T00:00:00Z');
    assert.equal(out.endpoint, 'https://203.0.113.10');
    assert.equal(out.protected_path, '/accounts');
    assert.equal(out.tls.fingerprint256, fingerprintOf(cert.cert));
    assert.equal(out.images.verifier.endsWith(`@${DIGEST_V}`), true);
    assert.deepEqual(out.bypass_routes.origin_run_app, ['https://dnsid-gse-0a1b2c3d-origin-123456789012.us-central1.run.app']);
    assert.deepEqual(out.bypass_routes.verifier_run_app, ['https://dnsid-gse-0a1b2c3d-verifier-123456789012.us-central1.run.app']);
    assert.equal(out.bypass_routes.http, 'http://203.0.113.10/accounts');
    assert.equal(out.bypass_routes.dotdot_path, '/dnsid-bypass/../accounts');
    assert.deepEqual(out.scaling, { verifier: { min: 1, max: 3 } });
    assert.equal(out.resources['authz_policy'], 'projects/sandbox-project-1/locations/global/authzPolicies/dnsid-gse-0a1b2c3d-authz-policy');
  });

  test('the run.app URLs Cloud Run reports are tried as well as the deterministic one', () => {
    const cert = selfSignedCertificate('203.0.113.10');
    const inputs = deployOutInputs(cert.cert);
    inputs.service.origin_urls = { value: ['https://dnsid-gse-0a1b2c3d-origin-abc123-uc.a.run.app/'], type: 'string', sensitive: false };
    const out = assembleDeployOut(inputs);
    assert.deepEqual(out.bypass_routes.origin_run_app, [
      'https://dnsid-gse-0a1b2c3d-origin-abc123-uc.a.run.app',
      'https://dnsid-gse-0a1b2c3d-origin-123456789012.us-central1.run.app',
    ]);
  });

  test('anything missing or inconsistent is refused, never defaulted', () => {
    const cert = selfSignedCertificate('203.0.113.10');
    const good = JSON.parse(JSON.stringify(assembleDeployOut(deployOutInputs(cert.cert))));
    const broken: [string, (o: Record<string, any>) => void][] = [
      ['plain http endpoint', (o) => (o.endpoint = 'http://203.0.113.10')],
      ['a name, not an address', (o) => (o.endpoint = 'https://example.com')],
      ['address mismatch', (o) => (o.address = '203.0.113.11')],
      ['another protected path', (o) => (o.protected_path = '/')],
      ['a pin for another certificate', (o) => (o.tls.fingerprint256 = fingerprintOf(selfSignedCertificate('203.0.113.10').cert))],
      ['no certificate', (o) => delete o.tls.certificate_pem],
      ['an image by tag', (o) => (o.images.verifier = 'us-central1-docker.pkg.dev/p/r/verifier:latest')],
      ['a missing resource', (o) => delete o.resources.authz_policy],
      ['no run.app routes', (o) => (o.bypass_routes.origin_run_app = [])],
      ['a non-run.app route', (o) => (o.bypass_routes.verifier_run_app = ['https://example.com'])],
      ['no .. segment', (o) => (o.bypass_routes.dotdot_path = '/accounts')],
      ['no inventory', (o) => delete o.inventory],
      ['another version', (o) => (o.version = 2)],
    ];
    for (const [what, change] of broken) {
      const copy = JSON.parse(JSON.stringify(good));
      change(copy);
      assert.throws(() => parseDeployOut(JSON.stringify(copy)), DeployOutError, what);
    }
    assert.throws(() => parseDeployOut('{'), DeployOutError);
    assert.throws(() => readDeployOut('/nonexistent/deploy-out.json'), /cannot read/);
  });

  test('written atomically and privately: a temporary file in the same directory, renamed, mode 600', (t) => {
    const dir = mkdtempSync(join(tmpdir(), 'deploy-out-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, 'deploy.json');
    writeFileSync(path, 'old');
    writeJsonAtomic(path, { a: 1 });
    assert.deepEqual(readdirSync(dir), ['deploy.json']);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    // A failed rename (the target is a directory) leaves no temporary file behind.
    const blocked = join(dir, 'blocked');
    mkdirSync(join(blocked, 'x'), { recursive: true });
    assert.throws(() => writeJsonAtomic(blocked, { a: 1 }));
    assert.deepEqual(readdirSync(dir).sort(), ['blocked', 'deploy.json']);
  });
});

describe('the image build', () => {
  const tagged = (name: string) => `us-central1-docker.pkg.dev/p/dnsid-gse-0a1b2c3d/${name}:0123456789ab-1`;
  const build = (images: unknown, status = 'SUCCESS') => ({ status, results: { images } });

  test('the digests of both published images, as immutable references', () => {
    const images = [
      { name: tagged('verifier'), digest: DIGEST_V },
      { name: tagged('origin'), digest: DIGEST_O },
    ];
    assert.deepEqual(buildImages(build(images), tagged('verifier'), tagged('origin')), {
      verifier: `us-central1-docker.pkg.dev/p/dnsid-gse-0a1b2c3d/verifier@${DIGEST_V}`,
      origin: `us-central1-docker.pkg.dev/p/dnsid-gse-0a1b2c3d/origin@${DIGEST_O}`,
    });
  });

  test('a build that did not succeed, a missing or repeated image, or a missing digest is refused', () => {
    const both = [
      { name: tagged('verifier'), digest: DIGEST_V },
      { name: tagged('origin'), digest: DIGEST_O },
    ];
    assert.throws(() => buildImages(build(both, 'FAILURE'), tagged('verifier'), tagged('origin')), /did not succeed \(FAILURE\)/);
    assert.throws(() => buildImages(build([both[0]]), tagged('verifier'), tagged('origin')), /did not publish .*origin/);
    assert.throws(() => buildImages(build([...both, both[0]]), tagged('verifier'), tagged('origin')), /exactly once/);
    assert.throws(() => buildImages(build([{ name: tagged('verifier'), digest: 'sha256:abc' }, both[1]]), tagged('verifier'), tagged('origin')), /no sha256 digest/);
    assert.throws(() => buildImages({ status: 'SUCCESS' }, tagged('verifier'), tagged('origin')), /no published images/);
    assert.throws(() => buildImages({}, tagged('verifier'), tagged('origin')), ToolError);
  });

  test('terraform outputs: a missing output is an error', () => {
    assert.equal(outputValue({ a: { value: 'x' } }, 'a'), 'x');
    assert.throws(() => outputValue({}, 'a'), /terraform output a is missing/);
  });

  test("the build context's fingerprint follows every path and byte, nothing else", (t) => {
    const dir = mkdtempSync(join(tmpdir(), 'context-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src/a.ts'), 'a');
    writeFileSync(join(dir, 'b'), 'b');
    const first = fingerprint(dir);
    assert.match(first, /^[0-9a-f]{64}$/);
    assert.equal(fingerprint(dir), first);
    writeFileSync(join(dir, 'b'), 'c');
    assert.notEqual(fingerprint(dir), first);
    writeFileSync(join(dir, 'b'), 'b');
    assert.equal(fingerprint(dir), first);
    writeFileSync(join(dir, 'src/a2.ts'), '');
    assert.notEqual(fingerprint(dir), first);
  });
});

// ---------- the inventory checks ----------

const inventory = (listings = deploymentListings()): Inventory => inventoryFrom(listings, 'test', '2026-11-12T00:00:00Z');

describe('the inventory checks behind the bypass cases', () => {
  test('references compare across self links, relative names, project IDs and numbers', () => {
    assert.equal(resourceKey(`${FAKE_SELF}/global/forwardingRules/x`), 'global/forwardingRules/x');
    assert.equal(resourceKey('projects/123/global/forwardingRules/x'), 'global/forwardingRules/x');
    assert.equal(resourceKey('https://compute.googleapis.com/compute/beta/projects/p/global/forwardingRules/x'), 'global/forwardingRules/x');
    assert.equal(resourceKey('projects/p/locations/global/authzExtensions/e'), 'locations/global/authzExtensions/e');
  });

  test("the deployment alone: covered, no rewrites, no CDN (an unrelated load balancer's CDN doesn't count)", () => {
    assert.equal(checkCoverage(inventory(), REFS).pass, true);
    assert.equal(checkNoRewrite(inventory(), REFS).pass, true);
    assert.equal(checkNoCdn(inventory(), REFS).pass, true);
  });

  test('another forwarding rule reaching Demo Bank, not targeted by the policy, fails coverage', () => {
    const l = deploymentListings();
    l.forwardingRules.push({ name: 'side-door', selfLink: `${FAKE_SELF}/global/forwardingRules/side-door`, target: `${FAKE_SELF}/global/targetHttpProxies/side-door`, IPAddress: '198.51.100.2', portRange: '80-80', loadBalancingScheme: 'EXTERNAL_MANAGED' });
    l.httpProxies.push({ selfLink: `${FAKE_SELF}/global/targetHttpProxies/side-door`, urlMap: `${FAKE_SELF}/global/urlMaps/side-door` });
    l.urlMaps.push({ selfLink: `${FAKE_SELF}/global/urlMaps/side-door`, defaultService: `${FAKE_SELF}/global/backendServices/side-door` });
    l.backendServices.push({ selfLink: `${FAKE_SELF}/global/backendServices/side-door`, enableCDN: true, protocol: 'HTTP', backends: [{ group: REFS.originNeg }] });
    const coverage = checkCoverage(inventory(l), REFS);
    assert.equal(coverage.pass, false);
    assert.match(coverage.detail, /1 not covered by the DNSid policy \(side-door:80-80\)/);
    // The side door's backend uses Demo Bank's NEG, so its CDN counts too.
    assert.equal(checkNoCdn(inventory(l), REFS).pass, false);
  });

  // A second load balancer whose backend uses another NEG: `group` is that backend's NEG, `neg` the NEG's listing.
  const sideDoor = (neg: Record<string, unknown> | undefined, cdn = false) => {
    const l = deploymentListings();
    const group = `${FAKE_SELF}/regions/us-central1/networkEndpointGroups/second-neg`;
    l.forwardingRules.push({ name: 'side-door', selfLink: `${FAKE_SELF}/global/forwardingRules/side-door`, target: `${FAKE_SELF}/global/targetHttpProxies/side-door`, IPAddress: '198.51.100.2', portRange: '80-80', loadBalancingScheme: 'EXTERNAL_MANAGED' });
    l.httpProxies.push({ selfLink: `${FAKE_SELF}/global/targetHttpProxies/side-door`, urlMap: `${FAKE_SELF}/global/urlMaps/side-door` });
    l.urlMaps.push({ selfLink: `${FAKE_SELF}/global/urlMaps/side-door`, defaultService: `${FAKE_SELF}/global/backendServices/side-door` });
    l.backendServices.push({ selfLink: `${FAKE_SELF}/global/backendServices/side-door`, enableCDN: cdn, protocol: 'HTTP', backends: [{ group }] });
    if (neg !== undefined) l.negs.push({ selfLink: group, networkEndpointType: 'SERVERLESS', region: `${FAKE_SELF}/regions/us-central1`, ...neg });
    return l;
  };

  test('another NEG naming the same Cloud Run origin is traced: its uncovered rule fails coverage, its CDN fails the cache check', () => {
    for (const destination of [
      { cloudRun: { service: REFS.originService } },
      { cloudRun: { service: REFS.originService, tag: 'blue' } },
      { cloudFunction: { function: REFS.originService } },
      { serverlessDeployment: { platform: 'run.googleapis.com', resource: REFS.originService } },
    ]) {
      const coverage = checkCoverage(inventory(sideDoor(destination)), REFS);
      assert.equal(coverage.pass, false, JSON.stringify(destination));
      assert.match(coverage.detail, /1 not covered by the DNSid policy \(side-door:80-80\)/);
      assert.match(coverage.detail, /reaching Demo Bank by destination: regions\/us-central1\/networkEndpointGroups\/second-neg/);
      const cdn = checkNoCdn(inventory(sideDoor(destination, true)), REFS);
      assert.equal(cdn.pass, false, JSON.stringify(destination));
      assert.match(cdn.detail, /2 backend service\(s\) in front of Demo Bank, Cloud CDN on 1 \(global\/backendServices\/side-door\)/);
    }
  });

  test('a NEG whose destination cannot be resolved counts as reaching Demo Bank: a URL mask, an unknown shape, a NEG not in the listing', () => {
    const unresolved: (Record<string, unknown> | undefined)[] = [
      { cloudRun: { urlMask: '<service>.example.com' } },
      { cloudFunction: { urlMask: '/<function>' } },
      { serverlessDeployment: { platform: 'run.googleapis.com', urlMask: '<service>.example.com' } },
      {},
      undefined,
    ];
    for (const destination of unresolved) {
      const coverage = checkCoverage(inventory(sideDoor(destination)), REFS);
      assert.equal(coverage.pass, false, JSON.stringify(destination));
      assert.match(coverage.detail, /couldn't be resolved, counted as reaching it: regions\/us-central1\/networkEndpointGroups\/second-neg/);
      assert.equal(checkNoCdn(inventory(sideDoor(destination, true)), REFS).pass, false, JSON.stringify(destination));
    }
    // An inventory recorded without a NEG listing: only the deployment's own NEG is known.
    const l = sideDoor(undefined, true) as Partial<ReturnType<typeof deploymentListings>>;
    delete l.negs;
    assert.equal(inventory(l as never).negs, undefined);
    assert.equal(checkCoverage(inventory(l as never), REFS).pass, false);
    assert.equal(checkNoCdn(inventory(l as never), REFS).pass, false);
  });

  test('genuinely unrelated services stay unrelated: another Cloud Run service, another region, App Engine, API Gateway, a non-serverless NEG', () => {
    const unrelated: Record<string, unknown>[] = [
      { cloudRun: { service: 'another-service' } },
      { cloudRun: { service: REFS.originService }, region: `${FAKE_SELF}/regions/europe-west4` },
      { cloudFunction: { function: 'another-function' } },
      { serverlessDeployment: { platform: 'run.googleapis.com', resource: 'another-service' } },
      { serverlessDeployment: { platform: 'apigateway.googleapis.com', resource: 'gw' } },
      { appEngine: { service: 'default' } },
      { networkEndpointType: 'INTERNET_FQDN_PORT' },
      { networkEndpointType: 'GCE_VM_IP_PORT', cloudRun: undefined },
    ];
    for (const destination of unrelated) {
      const coverage = checkCoverage(inventory(sideDoor(destination, true)), REFS);
      assert.equal(coverage.pass, true, `${JSON.stringify(destination)}: ${coverage.detail}`);
      assert.match(coverage.detail, /by destination: none; NEGs with a destination that couldn't be resolved, counted as reaching it: none/);
      assert.equal(checkNoCdn(inventory(sideDoor(destination, true)), REFS).pass, true, JSON.stringify(destination));
    }
  });

  test('a port-80 rule on the deployment address fails, even if it reaches nothing', () => {
    const l = deploymentListings();
    l.forwardingRules.push({ name: 'http', selfLink: `${FAKE_SELF}/global/forwardingRules/http`, target: `${FAKE_SELF}/global/targetHttpProxies/unrelated`, IPAddress: '203.0.113.10', portRange: '80-80', loadBalancingScheme: 'EXTERNAL_MANAGED' });
    assert.equal(checkCoverage(inventory(l), REFS).pass, false);
  });

  test('a policy that is not CUSTOM, or names another extension, does not cover', () => {
    for (const change of [(p: any) => (p.action = 'ALLOW'), (p: any) => (p.customProvider.authzExtension.resources = ['projects/p/locations/global/authzExtensions/other'])]) {
      const l = deploymentListings();
      change(l.policies[0]);
      assert.equal(checkCoverage(inventory(l), REFS).pass, false);
    }
  });

  test("a rewrite, a redirect, a route action or another backend in the deployment's URL map fails the rewrite check", () => {
    const changes: ((m: any) => void)[] = [
      (m) => (m.defaultRouteAction = { urlRewrite: { pathPrefixRewrite: '/' } }),
      (m) => (m.pathMatchers = [{ name: 'p', defaultService: REFS.originBackendService, pathRules: [{ paths: ['/a'], routeAction: { urlRewrite: { pathPrefixRewrite: '/b' } } }] }]),
      (m) => (m.defaultUrlRedirect = { httpsRedirect: true }),
      (m) => (m.pathMatchers = [{ name: 'p', defaultService: `${FAKE_SELF}/global/backendServices/other` }]),
    ];
    for (const change of changes) {
      const l = deploymentListings();
      change(l.urlMaps[0]);
      assert.equal(checkNoRewrite(inventory(l), REFS).pass, false);
    }
  });

  test("CDN on Demo Bank's backend fails; a missing URL map or backend is a failure, not a pass", () => {
    const l = deploymentListings();
    (l.backendServices[0] as any).enableCDN = true;
    assert.equal(checkNoCdn(inventory(l), REFS).pass, false);
    const empty = inventory({ forwardingRules: [], httpsProxies: [], httpProxies: [], urlMaps: [], backendServices: [], policies: [] } as any);
    assert.equal(checkCoverage(empty, REFS).pass, false);
    assert.equal(checkNoRewrite(empty, REFS).pass, false);
    assert.equal(checkNoCdn(empty, REFS).pass, false);
  });
});
