// DEPLOY_OUT: what scripts/deploy.sh writes once the endpoint answers, and what scripts/test-live.sh reads. JSON, one
// object, version 1. No dependencies.
//
// It is written only after a pinned-TLS unsigned request to `endpoint` + `protected_path` was denied by the verifier,
// and atomically (a temporary file in the same directory, then a rename), so a reader never sees a partial file.

import { chmodSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { checkedPin, type PinnedTls } from './pinned-tls.ts';

export const DEPLOY_OUT_VERSION = 1;
export const PROTECTED_PATH = '/accounts';

/** One forwarding rule as listed by the Compute API, reduced to what the coverage check needs. */
export interface ForwardingRuleRecord {
  readonly name: string;
  readonly selfLink: string;
  readonly target: string;
  readonly ipAddress: string;
  readonly portRange: string;
  readonly loadBalancingScheme: string;
}

export interface ProxyRecord {
  readonly selfLink: string;
  readonly urlMap: string;
}

export interface UrlMapRecord {
  readonly selfLink: string;
  readonly defaultService: string;
  /** Every backend service the map can route to: default, host and path rules, route actions. */
  readonly services: readonly string[];
  /** Whether any URL rewrite, route action or redirect appears anywhere in the map. */
  readonly rewrites: boolean;
}

export interface BackendServiceRecord {
  readonly selfLink: string;
  readonly enableCdn: boolean;
  readonly protocol: string;
  readonly groups: readonly string[];
}

/**
 * A network endpoint group, reduced to where it sends requests. Demo Bank's Cloud Run service takes traffic only from
 * Cloud Load Balancing (ingress) and has its default URL disabled, so only a serverless NEG in its region can reach it;
 * which one is decided by the destination, never by the NEG's name.
 */
export interface NegRecord {
  readonly selfLink: string;
  /** networkEndpointType, e.g. SERVERLESS, GCE_VM_IP_PORT, INTERNET_FQDN_PORT. */
  readonly type: string;
  /** The region's name (the last segment of its reference); empty for a zonal or global NEG. */
  readonly region: string;
  /** The serverless destination, as listed; every field empty when the NEG names none. */
  readonly cloudRun: { readonly service: string; readonly tag: string; readonly urlMask: string };
  readonly cloudFunction: { readonly function: string; readonly urlMask: string };
  readonly serverlessDeployment: { readonly platform: string; readonly resource: string; readonly urlMask: string };
  readonly appEngine: boolean;
}

export interface PolicyRecord {
  readonly name: string;
  readonly action: string;
  readonly targets: readonly string[];
  readonly extensions: readonly string[];
  /**
   * How many HTTP rules (match conditions) the policy has. A CUSTOM policy with none sends every request on its targets
   * to its extension; with any, only the requests that match them. Absent in an inventory read back from a file that
   * didn't record it: then the policy's reach is unknown, and it is not counted as covering anything.
   */
  readonly httpRules?: number;
}

/** The project's load-balancing configuration, observed through Google's APIs. */
export interface Inventory {
  readonly takenAt: string;
  /** Where it came from: `deploy.sh` (at deployment) or `test-live.sh` (at test time). */
  readonly source: string;
  readonly forwardingRules: readonly ForwardingRuleRecord[];
  readonly proxies: readonly ProxyRecord[];
  readonly urlMaps: readonly UrlMapRecord[];
  readonly backendServices: readonly BackendServiceRecord[];
  /**
   * Every network endpoint group in the project. Absent in an inventory recorded without it: then every NEG a backend
   * uses, other than the deployment's own, has an unknown destination and is counted as able to reach Demo Bank.
   */
  readonly negs?: readonly NegRecord[];
  readonly policies: readonly PolicyRecord[];
}

export interface DeployOut {
  readonly version: 1;
  readonly endpoint: string;
  readonly protected_path: string;
  readonly address: string;
  readonly tls: { readonly certificate_pem: string; readonly fingerprint256: string; readonly not_after: string };
  readonly project: string;
  readonly region: string;
  readonly deployment: string;
  readonly trusted_governance: string;
  readonly images: { readonly verifier: string; readonly origin: string };
  readonly resources: Readonly<Record<string, string>>;
  readonly bypass_routes: {
    /** Plain HTTP to the load balancer's address. */
    readonly http: string;
    /** Demo Bank's own run.app URLs (default URL disabled). */
    readonly origin_run_app: readonly string[];
    /** The verifier's own run.app URLs (default URL disabled). */
    readonly verifier_run_app: readonly string[];
    /** A path with a `..` segment, sent unnormalized. */
    readonly dotdot_path: string;
  };
  readonly scaling: { readonly verifier: { readonly min: number; readonly max: number } };
  readonly inventory: Inventory | { readonly error: string; readonly takenAt: string };
  readonly timing: Readonly<Record<string, number | string>>;
  readonly written_at: string;
}

export class DeployOutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeployOutError';
  }
}

const RESOURCE_KEYS = [
  'forwarding_rule',
  'target_https_proxy',
  'url_map',
  'ssl_certificate',
  'origin_backend_service',
  'callout_backend_service',
  'origin_neg',
  'verifier_neg',
  'authz_extension',
  'authz_policy',
  'verifier_service',
  'origin_service',
] as const;

function need(condition: unknown, what: string): asserts condition {
  if (!condition) throw new DeployOutError(`DEPLOY_OUT: ${what}`);
}

const isText = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

/** Parses and checks DEPLOY_OUT. Anything missing or malformed is an error, never a default. */
export function parseDeployOut(text: string): DeployOut {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new DeployOutError('DEPLOY_OUT: not JSON');
  }
  need(typeof value === 'object' && value !== null && !Array.isArray(value), 'not an object');
  const out = value as Record<string, unknown>;
  need(out['version'] === DEPLOY_OUT_VERSION, `version is not ${DEPLOY_OUT_VERSION}`);
  // A deployment's endpoint is https://<its IPv4 address>; a port appears only in local tests against a fixture.
  need(isText(out['endpoint']) && /^https:\/\/\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$/.test(out['endpoint']), 'endpoint is not https://<IPv4 address>');
  need(out['protected_path'] === PROTECTED_PATH, `protected_path is not ${PROTECTED_PATH}`);
  need(isText(out['address']) && new URL(out['endpoint']).hostname === out['address'], 'address does not match the endpoint');
  const tls = out['tls'] as Record<string, unknown> | undefined;
  need(typeof tls === 'object' && tls !== null, 'tls is missing');
  try {
    checkedPin({ certificatePem: tls['certificate_pem'] as string, fingerprint256: tls['fingerprint256'] as string });
  } catch (error) {
    throw new DeployOutError(`DEPLOY_OUT: tls: ${(error as Error).message}`);
  }
  for (const key of ['project', 'region', 'deployment', 'trusted_governance', 'written_at'] as const) need(isText(out[key]), `${key} is missing`);
  const images = out['images'] as Record<string, unknown> | undefined;
  need(typeof images === 'object' && images !== null, 'images are missing');
  for (const key of ['verifier', 'origin'] as const) need(isText(images[key]) && /@sha256:[0-9a-f]{64}$/.test(images[key]), `images.${key} is not a digest reference`);
  const resources = out['resources'] as Record<string, unknown> | undefined;
  need(typeof resources === 'object' && resources !== null, 'resources are missing');
  for (const key of RESOURCE_KEYS) need(isText(resources[key]), `resources.${key} is missing`);
  const routes = out['bypass_routes'] as Record<string, unknown> | undefined;
  need(typeof routes === 'object' && routes !== null, 'bypass_routes are missing');
  need(isText(routes['http']) && routes['http'] === `http://${out['address']}${PROTECTED_PATH}`, 'bypass_routes.http is not plain HTTP to the address');
  for (const key of ['origin_run_app', 'verifier_run_app'] as const) {
    const urls = routes[key];
    need(Array.isArray(urls) && urls.length > 0 && urls.every((u) => isText(u) && /^https:\/\/[a-z0-9.-]+\.run\.app\/?$/.test(u)), `bypass_routes.${key} are not run.app URLs`);
  }
  need(isText(routes['dotdot_path']) && routes['dotdot_path'].includes('/../'), 'bypass_routes.dotdot_path has no .. segment');
  const scaling = out['scaling'] as { verifier?: { min?: unknown; max?: unknown } } | undefined;
  need(Number.isInteger(scaling?.verifier?.min) && Number.isInteger(scaling?.verifier?.max), 'scaling.verifier is missing');
  need(typeof out['inventory'] === 'object' && out['inventory'] !== null, 'inventory is missing');
  need(typeof out['timing'] === 'object' && out['timing'] !== null, 'timing is missing');
  return out as unknown as DeployOut;
}

export function readDeployOut(path: string): DeployOut {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new DeployOutError(`DEPLOY_OUT: cannot read ${path}`);
  }
  return parseDeployOut(text);
}

export function pinOf(out: DeployOut): PinnedTls {
  return { certificatePem: out.tls.certificate_pem, fingerprint256: out.tls.fingerprint256 };
}

/** Writes `value` as JSON to `path` atomically: a private temporary file beside it, then a rename. */
export function writeJsonAtomic(path: string, value: unknown): void {
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  try {
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}
