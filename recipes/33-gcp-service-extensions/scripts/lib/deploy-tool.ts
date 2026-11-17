// Helpers scripts/deploy.sh and scripts/teardown.sh call for what is awkward in shell: hashing the build context,
// reading the finished build's image digests, the readiness probe over pinned TLS, the inventory, and writing
// DEPLOY_OUT. No dependencies, so nothing has to be installed before a deployment.
//
//   node scripts/lib/deploy-tool.ts fingerprint <dir>
//   node scripts/lib/deploy-tool.ts build-status <build.json>
//   node scripts/lib/deploy-tool.ts build-images <build.json> <verifier-tagged> <origin-tagged>
//   node scripts/lib/deploy-tool.ts output <terraform-output.json> <name>
//   node scripts/lib/deploy-tool.ts cert-fingerprint <cert.pem>
//   node scripts/lib/deploy-tool.ts ready <endpoint> <cert.pem> <fingerprint256> <path> [timeout-ms] [count]
//   node scripts/lib/deploy-tool.ts inventory <listings-dir> <source>
//   node scripts/lib/deploy-tool.ts deploy-out <inputs.json> <path>
//
// Exit codes: 0 done (for `ready`: the verifier denied every one of `count` unsigned requests, sent at once, each on its
// own connection); 1 not done or invalid input, with one line on stderr saying why; 2 usage; 3 (`ready` only) Demo Bank
// answered an unsigned request: the load balancer forwarded it without the authorization policy.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { request } from 'node:https';
import { join, relative, sep } from 'node:path';

import { PROTECTED_PATH, writeJsonAtomic, parseDeployOut, type DeployOut, type Inventory } from './deploy-out.ts';
import { inventoryFrom } from './inventory.ts';
import { fingerprintOf, pinnedConnectionOptions } from './pinned-tls.ts';

export class ToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolError';
  }
}

const readJson = (path: string): unknown => {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new ToolError(`${path} is not readable JSON`);
  }
};

// ---------- the build context ----------

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) out.push(path);
      else throw new ToolError(`the build context holds something that is neither a file nor a directory: ${relative(dir, path)}`);
    }
  };
  walk(dir);
  return out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** SHA-256 over every file's relative path and contents, in a fixed order: equal inputs, equal fingerprint. */
export function fingerprint(dir: string): string {
  const hash = createHash('sha256');
  for (const path of filesUnder(dir)) {
    const name = relative(dir, path).split(sep).join('/');
    const content = readFileSync(path);
    hash.update(`${name}\0${content.length}\0`).update(content).update('\0');
  }
  return hash.digest('hex');
}

// ---------- the image build ----------

export const TERMINAL_BUILD_STATUSES = ['SUCCESS', 'FAILURE', 'INTERNAL_ERROR', 'TIMEOUT', 'CANCELLED', 'EXPIRED'] as const;

export function buildStatus(build: unknown): string {
  const status = (build as { status?: unknown } | null)?.status;
  if (typeof status !== 'string' || !/^[A-Z_]+$/.test(status)) throw new ToolError('the build description has no status');
  return status;
}

/**
 * The published images, by digest, from a finished build: both tagged names must be among `results.images`, each with
 * a sha256 digest. The service stage gets `<repository>/<name>@sha256:<digest>`, never a tag.
 */
export function buildImages(build: unknown, verifierTagged: string, originTagged: string): { verifier: string; origin: string } {
  if (buildStatus(build) !== 'SUCCESS') throw new ToolError(`the build did not succeed (${buildStatus(build)})`);
  const images = (build as { results?: { images?: unknown } }).results?.images;
  if (!Array.isArray(images)) throw new ToolError('the build reports no published images');
  const digestOf = (tagged: string): string => {
    const found = images.filter((image: { name?: unknown }) => image?.name === tagged);
    if (found.length !== 1) throw new ToolError(`the build did not publish ${tagged} exactly once`);
    const digest = (found[0] as { digest?: unknown }).digest;
    if (typeof digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(digest)) throw new ToolError(`the build reports no sha256 digest for ${tagged}`);
    const repository = tagged.replace(/:[^:/]+$/, '');
    return `${repository}@${digest}`;
  };
  return { verifier: digestOf(verifierTagged), origin: digestOf(originTagged) };
}

// ---------- terraform outputs ----------

/** One value from `terraform output -json`. */
export function outputValue(outputs: unknown, name: string): unknown {
  const entry = (outputs as Record<string, { value?: unknown }> | null)?.[name];
  if (entry === undefined || !('value' in entry)) throw new ToolError(`terraform output ${name} is missing`);
  return entry.value;
}

// ---------- readiness ----------

export interface ReadyResult {
  readonly ready: boolean;
  /** Demo Bank answered: the request reached it without the authorization policy being evaluated. */
  readonly bypass: boolean;
  readonly detail: string;
}

/**
 * Demo Bank's own answer: no-store JSON with its `error` or its data (`"bank":"Demo Bank"`). An unsigned request gets one
 * only when the load balancer forwarded it without asking the verifier, as one of Google's front ends did for some
 * minutes after the policy was created on the live deployment of 2026-11-14.
 */
export function isOriginAnswer(cacheControl: string, body: string): boolean {
  if (cacheControl !== 'no-store') return false;
  try {
    const value = JSON.parse(body) as { error?: unknown; bank?: unknown } | null;
    return typeof value === 'object' && value !== null && (typeof value.error === 'string' || value.bank === 'Demo Bank');
  } catch {
    return false;
  }
}

/**
 * One unsigned GET of `endpoint` + `path` over pinned TLS. Ready only when the verifier itself denies it: 403,
 * `Cache-Control: no-store`, body `signature_missing`. A load balancer error, a different denial, a TLS failure (a wrong
 * pin, a name mismatch, a certificate not yet served) or a timeout is not ready; Demo Bank's answer is not ready, and a
 * bypass of the authorization policy.
 */
export function probeReady(endpoint: string, certificatePem: string, fingerprint256: string, path: string, timeoutMs = 10_000): Promise<ReadyResult> {
  const url = new URL(endpoint);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: ReadyResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };
    let options;
    try {
      options = pinnedConnectionOptions(url.hostname, { certificatePem, fingerprint256 });
    } catch (error) {
      finish({ ready: false, bypass: false, detail: `pin: ${(error as Error).message}` });
      return;
    }
    const req = request({ ...options, port: url.port === '' ? 443 : Number(url.port), method: 'GET', path, agent: false, timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size <= 4096) chunks.push(chunk);
      });
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8').slice(0, 200);
        const cacheControl = String(res.headers['cache-control'] ?? '');
        const ready = res.statusCode === 403 && cacheControl === 'no-store' && body === 'signature_missing';
        const bypass = !ready && isOriginAnswer(cacheControl, body);
        finish({ ready, bypass, detail: `HTTP ${res.statusCode} cache-control=${JSON.stringify(cacheControl)} body=${JSON.stringify(body.slice(0, 80))}` });
      });
      res.on('error', () => finish({ ready: false, bypass: false, detail: 'the response failed' }));
    });
    req.on('timeout', () => {
      req.destroy();
      finish({ ready: false, bypass: false, detail: `no answer within ${timeoutMs} ms` });
    });
    req.on('error', (error: NodeJS.ErrnoException) => finish({ ready: false, bypass: false, detail: `connection: ${error.code ?? error.name}: ${error.message.slice(0, 160)}` }));
    req.end();
  });
}

/**
 * `count` probes sent at once, each on its own connection, so that they may reach different front ends. Ready only when
 * every one is the verifier's denial; a bypass when any reached Demo Bank. The detail is the first answer that wasn't a
 * denial (a bypass first), or the denial, with the tally.
 */
export async function probeReadyBurst(endpoint: string, certificatePem: string, fingerprint256: string, path: string, timeoutMs = 10_000, count = 1): Promise<ReadyResult> {
  if (!Number.isInteger(count) || count < 1 || count > 64) throw new ToolError('the probe count must be a whole number from 1 to 64');
  const results = await Promise.all(Array.from({ length: count }, () => probeReady(endpoint, certificatePem, fingerprint256, path, timeoutMs)));
  const denied = results.filter((r) => r.ready).length;
  const bypassed = results.filter((r) => r.bypass).length;
  const shown = results.find((r) => r.bypass) ?? results.find((r) => !r.ready) ?? (results[0] as ReadyResult);
  const tally = count === 1 ? '' : ` (${denied}/${count} verifier denials${bypassed > 0 ? `, ${bypassed} answered by Demo Bank` : ''})`;
  return { ready: denied === count, bypass: bypassed > 0, detail: `${shown.detail}${tally}` };
}

// ---------- the inventory ----------

const LISTING_FILES = {
  forwardingRules: 'forwarding-rules.json',
  httpsProxies: 'target-https-proxies.json',
  httpProxies: 'target-http-proxies.json',
  urlMaps: 'url-maps.json',
  backendServices: 'backend-services.json',
  negs: 'network-endpoint-groups.json',
  policies: 'authz-policies.json',
} as const;

export function inventoryFromDir(dir: string, source: string, takenAt = new Date().toISOString()): Inventory {
  const listings = Object.fromEntries(Object.entries(LISTING_FILES).map(([key, file]) => [key, readJson(join(dir, file))]));
  for (const [key, value] of Object.entries(listings)) {
    if (!Array.isArray(value)) throw new ToolError(`the ${key} listing is not a JSON array`);
  }
  return inventoryFrom(listings as never, source, takenAt);
}

// ---------- DEPLOY_OUT ----------

export interface DeployOutInputs {
  readonly bootstrap: unknown; // terraform output -json, bootstrap stage
  readonly service: unknown; // terraform output -json, service stage
  readonly images: { verifier: string; origin: string };
  readonly inventory: Inventory | { error: string; takenAt: string };
  readonly timing: Record<string, number | string>;
  readonly governance: string;
}

const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string' && v.length > 0) : []);

/** Assembles DEPLOY_OUT from the stages' outputs and checks it with the same parser test-live.sh uses. */
export function assembleDeployOut(inputs: DeployOutInputs, writtenAt = new Date().toISOString()): DeployOut {
  const b = (name: string) => outputValue(inputs.bootstrap, name);
  const s = (name: string) => outputValue(inputs.service, name);
  const address = String(s('address'));
  const project = String(b('project_id'));
  const region = String(b('region'));
  const number = String(b('project_number'));
  const certificatePem = String(s('certificate_pem'));
  // The default run.app URLs are disabled; the bypass cases try every form of them: what Cloud Run reports, and the
  // deterministic https://<service>-<project number>.<region>.run.app.
  const runApp = (service: string, uri: unknown, urls: unknown) =>
    [...new Set([...strings([uri]), ...strings(urls), `https://${service}-${number}.${region}.run.app`].map((u) => u.replace(/\/$/, '')))];
  const verifierService = String(s('verifier_service'));
  const originService = String(s('origin_service'));
  const scaling = s('verifier_scaling') as { min?: unknown; max?: unknown };
  const out = {
    version: 1,
    endpoint: String(s('endpoint')),
    protected_path: PROTECTED_PATH,
    address,
    tls: { certificate_pem: certificatePem, fingerprint256: fingerprintOf(certificatePem), not_after: String(s('certificate_not_after')) },
    project,
    region,
    deployment: String(b('deployment_name')),
    trusted_governance: inputs.governance,
    images: inputs.images,
    resources: {
      address: String(b('address_self_link')),
      artifact_repository: String(b('repository_url')),
      build_bucket: String(b('build_bucket')),
      build_service_account: String(b('build_service_account')),
      forwarding_rule: String(s('forwarding_rule')),
      target_https_proxy: String(s('target_https_proxy')),
      url_map: String(s('url_map')),
      ssl_certificate: String(s('ssl_certificate')),
      origin_backend_service: String(s('origin_backend_service')),
      callout_backend_service: String(s('callout_backend_service')),
      origin_neg: String(s('origin_neg')),
      verifier_neg: String(s('verifier_neg')),
      authz_extension: String(s('authz_extension')),
      authz_policy: String(s('authz_policy')),
      verifier_service: verifierService,
      origin_service: originService,
      verifier_service_account: String(s('verifier_service_account')),
      origin_service_account: String(s('origin_service_account')),
    },
    bypass_routes: {
      http: `http://${address}${PROTECTED_PATH}`,
      origin_run_app: runApp(originService, s('origin_uri'), s('origin_urls')),
      verifier_run_app: runApp(verifierService, s('verifier_uri'), s('verifier_urls')),
      dotdot_path: '/dnsid-bypass/..' + PROTECTED_PATH,
    },
    scaling: { verifier: { min: Number(scaling?.min), max: Number(scaling?.max) } },
    inventory: inputs.inventory,
    timing: inputs.timing,
    written_at: writtenAt,
  };
  return parseDeployOut(JSON.stringify(out));
}

// ---------- the command line ----------

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  const say = (line: string) => process.stdout.write(`${line}\n`);
  switch (command) {
    case 'fingerprint': {
      const [dir] = args;
      if (dir === undefined || !statSync(dir).isDirectory()) return usage();
      say(fingerprint(dir));
      return 0;
    }
    case 'build-status': {
      if (args.length !== 1) return usage();
      say(buildStatus(readJson(args[0] as string)));
      return 0;
    }
    case 'build-images': {
      if (args.length !== 3) return usage();
      say(JSON.stringify(buildImages(readJson(args[0] as string), args[1] as string, args[2] as string)));
      return 0;
    }
    case 'output': {
      if (args.length !== 2) return usage();
      const value = outputValue(readJson(args[0] as string), args[1] as string);
      say(typeof value === 'string' ? value : JSON.stringify(value));
      return 0;
    }
    case 'cert-fingerprint': {
      if (args.length !== 1) return usage();
      say(fingerprintOf(readFileSync(args[0] as string, 'utf8')));
      return 0;
    }
    case 'ready': {
      const [endpoint, certFile, pin, path, timeout, count] = args;
      if (endpoint === undefined || certFile === undefined || pin === undefined || path === undefined || args.length > 6) return usage();
      const result = await probeReadyBurst(endpoint, readFileSync(certFile, 'utf8'), pin, path, timeout === undefined ? 10_000 : Number(timeout), count === undefined ? 1 : Number(count));
      (result.ready ? process.stdout : process.stderr).write(`${result.detail}\n`);
      return result.ready ? 0 : result.bypass ? 3 : 1;
    }
    case 'inventory': {
      if (args.length !== 2) return usage();
      say(JSON.stringify(inventoryFromDir(args[0] as string, args[1] as string)));
      return 0;
    }
    case 'deploy-out': {
      if (args.length !== 2) return usage();
      const inputs = readJson(args[0] as string) as DeployOutInputs;
      writeJsonAtomic(args[1] as string, assembleDeployOut(inputs));
      return 0;
    }
    default:
      return usage();
  }
}

function usage(): number {
  process.stderr.write('usage: node scripts/lib/deploy-tool.ts fingerprint|build-status|build-images|output|cert-fingerprint|ready|inventory|deploy-out …\n');
  return 2;
}

if (import.meta.main) {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'failed'}\n`);
    process.exitCode = 1;
  }
}
