// What the live tests need from Google Cloud's APIs, through gcloud: the project's load-balancing inventory, the
// reversible changes the governance, outage and timing cases make to the verifier and the forged-identity case makes to
// Demo Bank's own URL (and their restoration), each service's configuration that confirms a restoration, and the
// services' structured logs. Only used when a platform login is
// available; otherwise the cases that need it say so and fail.
//
// The login is the same as the deploy's (scripts/lib/common.sh): CLOUDSDK_AUTH_ACCESS_TOKEN_FILE, or
// GOOGLE_OAUTH_ACCESS_TOKEN (written to a private temporary file for gcloud), or Application Default Credentials (a
// token minted from them, likewise). A token never appears in arguments or output.
//
// Every gcloud command is bounded: it is killed (SIGTERM, then SIGKILL) when its time runs out or its signal aborts, and
// that is a failure, never a success.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DeployOut, Inventory } from '../lib/deploy-out.ts';
import { inventoryFrom } from '../lib/inventory.ts';

export interface Cloud {
  /** Where the login came from, for the report. */
  readonly login: string;
  inventory(): Promise<Inventory>;
  /** MANUAL scaling with zero instances (the verifier can't answer), or back to automatic scaling. */
  setVerifierScaling(mode: 'zero' | 'auto', signal?: AbortSignal): Promise<void>;
  /** Replaces the verifier's DNSID_TRUSTED_GOVERNANCE (a new revision). */
  setGovernance(value: string, signal?: AbortSignal): Promise<void>;
  /** Sets the verifier's DNSID_LOG_EVIDENCE to full-scan, or removes it (`default`): a new revision either way. */
  setLogEvidence(mode: 'full-scan' | 'default', signal?: AbortSignal): Promise<void>;
  /** The verifier's configuration as Cloud Run now records it: what a restoration is confirmed against. */
  verifierConfig(signal?: AbortSignal): Promise<VerifierConfig>;
  /**
   * Opens Demo Bank's own run.app URL to every caller (ingress all, the default URL enabled), or closes it again as
   * deployed (ingress internal and Cloud Load Balancing, the default URL disabled).
   */
  setOriginExposure(mode: 'open' | 'closed', signal?: AbortSignal): Promise<void>;
  /** Demo Bank's ingress and default URL as Cloud Run now records them. */
  originConfig(signal?: AbortSignal): Promise<OriginConfig>;
  /** Demo Bank's request records between two instants (ISO 8601), counted. */
  originRequests(since: string, until: string): Promise<number>;
  /** The verifier's records of requests from `domain` it let through between two instants (ISO 8601), oldest first. */
  verificationRecords(since: string, until: string, domain: string): Promise<VerificationRecord[]>;
  close(): void;
}

/** The settings the live tests change. `scaling` is 'other' for any manual scaling but zero instances. */
export interface VerifierConfig {
  readonly governance: string | undefined;
  readonly scaling: 'auto' | 'zero' | 'other';
  /** DNSID_LOG_EVIDENCE as set on the service; undefined when it isn't (the default). */
  readonly logEvidence: string | undefined;
}

/** Demo Bank's exposure: its ingress setting and whether its default run.app URL is disabled. */
export interface OriginConfig {
  /** run.googleapis.com/ingress: `all`, `internal` or `internal-and-cloud-load-balancing`; undefined when not recorded. */
  readonly ingress: string | undefined;
  readonly defaultUrlDisabled: boolean;
}

/** The ingress Demo Bank is deployed with (infra/service: INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER). */
export const ORIGIN_DEPLOYED_INGRESS = 'internal-and-cloud-load-balancing';

/**
 * Reads OriginConfig from `gcloud run services describe --format=json` (the Cloud Run Service resource): the service
 * annotations run.googleapis.com/ingress and run.googleapis.com/default-url-disabled ("true" when disabled). Anything
 * not shaped like a service is an error, never a default.
 */
export function originConfigFrom(service: unknown): OriginConfig {
  const s = service as { metadata?: { annotations?: Record<string, unknown> } } | null;
  if (typeof s !== 'object' || s === null || typeof s.metadata !== 'object' || s.metadata === null) throw new CloudError('the Demo Bank service description has no metadata');
  const annotations = s.metadata.annotations ?? {};
  const ingress = annotations['run.googleapis.com/ingress'];
  return {
    ingress: typeof ingress === 'string' ? ingress : undefined,
    defaultUrlDisabled: String(annotations['run.googleapis.com/default-url-disabled']).toLowerCase() === 'true',
  };
}

/**
 * One `continue_submitted` record of the verifier's (src/service.ts TerminalRecord), as Cloud Logging returns it. Each
 * field is kept only when it has the logged type; the cases decide whether a record is complete.
 */
export interface VerificationRecord {
  readonly timestamp: string;
  /** From acceptance of the stream to its decision, ms. */
  readonly elapsedMs?: number;
  readonly evidenceAgeMs?: number;
  readonly completenessMode?: string;
  readonly materialCache?: string;
}

/** Reads VerificationRecords from `gcloud logging read --format=json` entries, oldest first. */
export function verificationRecordsFrom(entries: readonly Record<string, unknown>[]): VerificationRecord[] {
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
  const text = (v: unknown) => (typeof v === 'string' ? v : undefined);
  return entries
    .map((entry) => {
      const payload = (entry['jsonPayload'] ?? {}) as { elapsedMs?: unknown; verified?: Record<string, unknown> };
      const verified = payload.verified ?? {};
      const fields = {
        elapsedMs: num(payload.elapsedMs),
        evidenceAgeMs: num(verified['evidenceAgeMs']),
        completenessMode: text(verified['completenessMode']),
        materialCache: text(verified['materialCache']),
      };
      return {
        timestamp: text(entry['timestamp']) ?? '',
        ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined)),
      } as VerificationRecord;
    })
    .sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
}

/**
 * Reads VerifierConfig from `gcloud run services describe --format=json` (the Cloud Run Service resource). Manual
 * scaling is the service annotations run.googleapis.com/scalingMode (manual) and run.googleapis.com/manualInstanceCount;
 * without them, or with automatic, scaling is automatic. The governance list is the container's
 * DNSID_TRUSTED_GOVERNANCE. Anything not shaped like a service is an error, never a default.
 */
export function verifierConfigFrom(service: unknown): VerifierConfig {
  const s = service as { metadata?: { annotations?: Record<string, unknown> }; spec?: { template?: { spec?: { containers?: unknown } } } } | null;
  const containers = s?.spec?.template?.spec?.containers;
  if (typeof s !== 'object' || s === null || !Array.isArray(containers) || containers.length === 0) throw new CloudError('the verifier service description has no containers');
  const annotations = s.metadata?.annotations ?? {};
  const mode = annotations['run.googleapis.com/scalingMode'];
  const count = annotations['run.googleapis.com/manualInstanceCount'];
  const scaling = mode === undefined || String(mode).toLowerCase() === 'automatic' ? 'auto' : String(mode).toLowerCase() === 'manual' && String(count) === '0' ? 'zero' : 'other';
  let governance: string | undefined;
  let logEvidence: string | undefined;
  for (const container of containers as { env?: unknown }[]) {
    for (const v of Array.isArray(container?.env) ? (container.env as { name?: unknown; value?: unknown }[]) : []) {
      if (v?.name === 'DNSID_TRUSTED_GOVERNANCE' && typeof v.value === 'string') governance = v.value;
      if (v?.name === 'DNSID_LOG_EVIDENCE' && typeof v.value === 'string') logEvidence = v.value;
    }
  }
  return { governance, scaling, logEvidence };
}

export class CloudError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CloudError';
  }
}

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export type Runner = (args: readonly string[], env: NodeJS.ProcessEnv, signal?: AbortSignal) => Promise<Run>;

/** The longest a gcloud command may run when its caller gives no signal of its own. */
export const DEFAULT_COMMAND_TIMEOUT_MS = 300_000;
/** How long a killed gcloud gets between SIGTERM and SIGKILL. */
export const KILL_GRACE_MS = 5_000;

/** Runs gcloud, killed when `signal` aborts or, without one, after DEFAULT_COMMAND_TIMEOUT_MS. */
export function commandRunner(program = 'gcloud', defaultTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS): Runner {
  return (args, env, signal = AbortSignal.timeout(defaultTimeoutMs)) =>
    new Promise((resolve) => {
      if (signal.aborted) {
        resolve({ code: null, stdout: '', stderr: 'not started: abandoned before it began' });
        return;
      }
      const child = spawn(program, ['--quiet', '--verbosity=error', ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let killed = false;
      let force: ReturnType<typeof setTimeout> | undefined;
      const kill = () => {
        killed = true;
        child.kill('SIGTERM');
        force = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS);
        force.unref();
      };
      signal.addEventListener('abort', kill, { once: true });
      child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
      child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
      child.on('error', () => {
        signal.removeEventListener('abort', kill);
        resolve({ code: 127, stdout, stderr: 'gcloud could not be run' });
      });
      child.on('close', (code) => {
        signal.removeEventListener('abort', kill);
        if (force !== undefined) clearTimeout(force);
        // A killed command failed, whatever it printed or returned on its way out.
        resolve(killed ? { code: null, stdout, stderr: 'stopped: it ran out of time or was interrupted' } : { code, stdout, stderr });
      });
    });
}

const gcloudRunner: Runner = commandRunner();

/**
 * The platform login for gcloud, or undefined when there is none. Never throws for a missing login: the cases that need
 * one report it.
 */
export async function connectCloud(out: DeployOut, env: NodeJS.ProcessEnv = process.env, run: Runner = gcloudRunner): Promise<Cloud | undefined> {
  const dir = mkdtempSync(join(tmpdir(), 'dnsid-live-auth-'));
  const childEnv: NodeJS.ProcessEnv = { ...env, CLOUDSDK_CORE_DISABLE_PROMPTS: '1' };
  let login: string;
  if (env['CLOUDSDK_AUTH_ACCESS_TOKEN_FILE']) {
    login = 'a short-lived access token (CLOUDSDK_AUTH_ACCESS_TOKEN_FILE)';
  } else if (env['GOOGLE_OAUTH_ACCESS_TOKEN']) {
    writeFileSync(join(dir, 'token'), env['GOOGLE_OAUTH_ACCESS_TOKEN'], { mode: 0o600 });
    childEnv['CLOUDSDK_AUTH_ACCESS_TOKEN_FILE'] = join(dir, 'token');
    login = 'a short-lived access token (GOOGLE_OAUTH_ACCESS_TOKEN)';
  } else {
    const minted = await run(['auth', 'application-default', 'print-access-token'], { ...childEnv, CLOUDSDK_AUTH_ACCESS_TOKEN_FILE: undefined });
    const token = minted.stdout.trim();
    if (minted.code !== 0 || token.length === 0) {
      rmSync(dir, { recursive: true, force: true });
      return undefined;
    }
    writeFileSync(join(dir, 'token'), token, { mode: 0o600 });
    childEnv['CLOUDSDK_AUTH_ACCESS_TOKEN_FILE'] = join(dir, 'token');
    login = 'Application Default Credentials';
  }
  const project = `--project=${out.project}`;
  const region = `--region=${out.region}`;
  const call = async (args: readonly string[], signal?: AbortSignal): Promise<string> => {
    const result = await run(args, childEnv, signal);
    if (result.code !== 0) throw new CloudError(`gcloud ${args.slice(0, 3).join(' ')} failed: ${result.stderr.trim().split('\n').slice(0, 2).join(' ').slice(0, 300)}`);
    return result.stdout;
  };
  const json = async (args: readonly string[]): Promise<unknown> => {
    const text = await call([...args, '--format=json']);
    try {
      return JSON.parse(text === '' ? '[]' : text);
    } catch {
      throw new CloudError(`gcloud ${args.slice(0, 3).join(' ')} did not return JSON`);
    }
  };
  const verifier = out.resources['verifier_service'] as string;
  const origin = out.resources['origin_service'] as string;
  const logs = async (filter: string): Promise<Record<string, unknown>[]> => {
    const entries = await json(['logging', 'read', filter, project, '--limit=1000', '--freshness=1d']);
    return Array.isArray(entries) ? (entries as Record<string, unknown>[]) : [];
  };
  return {
    login,
    async inventory() {
      const [forwardingRules, httpsProxies, httpProxies, urlMaps, backendServices, negs, policies] = await Promise.all([
        json(['compute', 'forwarding-rules', 'list', project]),
        json(['compute', 'target-https-proxies', 'list', project]),
        json(['compute', 'target-http-proxies', 'list', project]),
        json(['compute', 'url-maps', 'list', project]),
        json(['compute', 'backend-services', 'list', project]),
        json(['compute', 'network-endpoint-groups', 'list', project]),
        json(['network-security', 'authz-policies', 'list', project, '--location=global']),
      ]);
      return inventoryFrom({ forwardingRules, httpsProxies, httpProxies, urlMaps, backendServices, negs, policies }, 'test-live.sh', new Date().toISOString());
    },
    async setVerifierScaling(mode, signal) {
      await call(['run', 'services', 'update', verifier, project, region, `--scaling=${mode === 'zero' ? '0' : 'auto'}`], signal);
    },
    async setGovernance(value, signal) {
      // gcloud's alternate delimiter (^|^) keeps the commas in a governance list inside the one value.
      await call(['run', 'services', 'update', verifier, project, region, `--update-env-vars=^|^DNSID_TRUSTED_GOVERNANCE=${value}`], signal);
    },
    async setLogEvidence(mode, signal) {
      const change = mode === 'full-scan' ? '--update-env-vars=DNSID_LOG_EVIDENCE=full-scan' : '--remove-env-vars=DNSID_LOG_EVIDENCE';
      await call(['run', 'services', 'update', verifier, project, region, change], signal);
    },
    async verifierConfig(signal) {
      const text = await call(['run', 'services', 'describe', verifier, project, region, '--format=json'], signal);
      try {
        return verifierConfigFrom(JSON.parse(text));
      } catch (error) {
        throw error instanceof CloudError ? error : new CloudError('gcloud run services describe did not return JSON');
      }
    },
    async setOriginExposure(mode, signal) {
      const change = mode === 'open' ? ['--ingress=all', '--default-url'] : [`--ingress=${ORIGIN_DEPLOYED_INGRESS}`, '--no-default-url'];
      await call(['run', 'services', 'update', origin, project, region, ...change], signal);
    },
    async originConfig(signal) {
      const text = await call(['run', 'services', 'describe', origin, project, region, '--format=json'], signal);
      try {
        return originConfigFrom(JSON.parse(text));
      } catch (error) {
        throw error instanceof CloudError ? error : new CloudError('gcloud run services describe did not return JSON');
      }
    },
    async originRequests(since, until) {
      const entries = await logs(
        `resource.type="cloud_run_revision" AND resource.labels.service_name="${origin}" AND jsonPayload.event="origin_request" AND timestamp>="${since}" AND timestamp<="${until}"`,
      );
      return entries.length;
    },
    async verificationRecords(since, until, domain) {
      const entries = await logs(
        `resource.type="cloud_run_revision" AND resource.labels.service_name="${verifier}" AND jsonPayload.event="ext_proc_stream" AND jsonPayload.outcome="continue_submitted" AND jsonPayload.verified.domain="${domain}" AND timestamp>="${since}" AND timestamp<="${until}"`,
      );
      return verificationRecordsFrom(entries);
    },
    close() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
