// The live cases described in docs/live-tests.md, each a function from what the deployment answered to a verdict.
//
// How an answer is recognized:
//   - the verifier's denial: 403 with `Cache-Control: no-store` and a body that is one of the verifier's own reason
//     codes (src/response.ts). A HEAD denial has no body, so only status and Cache-Control are seen.
//   - Demo Bank: its JSON (`"bank":"Demo Bank"`, `"synthetic":true`) or its own JSON errors, always no-store.
//   - the load balancer's failure: a 5xx that is neither of those (D-05: a verifier that can't answer gives a 500).
// Each case states what it expects; anything else, a missing answer, missing evidence, or an exception is a FAIL with
// what was seen. A case passes only when its own check returns `pass: true`.
//
// The cases that change the deployment record each change durably before making it (Context.changes), bound every
// cloud command (Context.cloudTimeoutMs), stop waiting when the run is interrupted (Context.signal), and always attempt
// the restoration, which an interruption does not cancel. An abandoned command is waited for until it has stopped
// (Context.settleGraceMs), so it can't land after the restoration; one that doesn't stop leaves the outcome unknown.
// The record goes only once the restoration is confirmed three ways: the restoring update succeeded, Cloud Run's
// configuration of the changed service reads back as restored (before and after the edge is watched), and the edge
// behaves as before. Anything less keeps the record, reports the restoration failed, and no further change is made.

import { randomBytes } from 'node:crypto';

import { ATTESTATION_HEADER } from '../../src/attestation.ts';
import { PROCESS_METHOD } from '../../src/ext-proc.ts';
import { RESPONSE_REASONS } from '../../src/response.ts';
import type { DeployOut } from '../lib/deploy-out.ts';
import { checkCoverage, checkNoCdn, checkNoRewrite, type DeploymentRefs } from '../lib/inventory.ts';
import { ORIGIN_DEPLOYED_INGRESS, type Cloud, type OriginConfig, type VerificationRecord, type VerifierConfig } from './cloud.ts';
import type { Exchange, RequestSpec, Target } from './http.ts';
import type { Signer } from './signer.ts';
import type { LifecycleEvidence } from './status.ts';
import { accountsFor } from '../../origin/server.ts';

export type Mode = 'live' | 'allow' | 'revoked';

export interface Clients {
  h1(target: Target, spec: RequestSpec): Promise<Exchange>;
  h2(target: Target, spec: RequestSpec): Promise<Exchange>;
  plain(url: string, spec: Omit<RequestSpec, 'path'>): Promise<Exchange>;
  /** Opens a gRPC call to `path` at `url` (an HTTP/2 POST, application/grpc), as a gRPC client would. */
  grpc(url: string, path: string): Promise<Exchange>;
}

/** A change a case is about to make to the deployment, and how to undo it. */
export type PendingChange =
  | { readonly kind: 'governance'; readonly restore: string }
  | { readonly kind: 'scaling'; readonly restore: 'auto' }
  | { readonly kind: 'log-evidence'; readonly restore: 'default' }
  | { readonly kind: 'origin-exposure'; readonly restore: 'closed' };

/** Where changes in progress are recorded, so an interrupted or failed restoration can be finished later. */
export interface Changes {
  /** Records the change durably; called before the change is made. */
  begin(change: PendingChange): void;
  /** The restoration was confirmed: the record goes. */
  end(change: PendingChange): void;
}

export interface Context {
  readonly out: DeployOut;
  readonly target: Target;
  readonly signer: Signer;
  /** OTHER_AGENT_ID, when given. */
  readonly otherAgent: string | undefined;
  /** The governance IDs the deployment trusts, lowercased. */
  readonly trusted: readonly string[];
  /** Google Cloud access, when a platform login is available. */
  readonly cloud: Cloud | undefined;
  readonly http: Clients;
  readonly sleep: (ms: number) => Promise<void>;
  /** How long a reconfiguration may take to show at the edge, and how often to look. */
  readonly settle: { readonly timeoutMs: number; readonly intervalMs: number };
  /** How long to wait for Cloud Logging to show records that should be there (logging is delayed). */
  readonly logWaitMs: number;
  /** A real pause (quietGapMs) before a window of requests whose log records are counted. */
  readonly quietGap: () => Promise<void>;
  readonly log: (line: string) => void;
  /** Aborted when the run is interrupted (SIGINT, SIGTERM): waits stop, changes not yet made aren't made. */
  readonly signal: AbortSignal;
  /** A pause an interruption doesn't cut short: the waits that confirm a restoration use it. */
  readonly steadySleep: (ms: number) => Promise<void>;
  /** The longest any one cloud command may take, after which it is abandoned (and its process killed). */
  readonly cloudTimeoutMs: number;
  /** How long an abandoned command is given to stop (its process killed) before its outcome counts as unknown. */
  readonly settleGraceMs: number;
  readonly changes: Changes;
  /** The agent's lifecycle state from its DNSid status document and its authenticated log history, read independently of the edge. */
  readonly lifecycle: (domain: string) => Promise<LifecycleEvidence>;
}

export interface Verdict {
  readonly got: string;
  readonly pass: boolean;
  readonly detail: string;
  /** Set when a case changed the deployment and could not put it back. */
  readonly restorationFailed?: boolean;
}

export interface LiveCase {
  readonly id: string;
  readonly edge: string;
  readonly expect: string;
  readonly modes: readonly Mode[];
  /** Changes the deployment (and restores it): run after every case that doesn't. */
  readonly mutates?: boolean;
  run(ctx: Context): Promise<Verdict>;
}

// ---------- recognizing answers ----------

const REASONS = new Set<string>(RESPONSE_REASONS);
const BODY_REASONS = ['body_indicated', 'body_not_ruled_out'];

export function isVerifierDenial(e: Exchange, reasons?: readonly string[], head = false): boolean {
  if (e.status !== 403 || e.headers['cache-control'] !== 'no-store') return false;
  if (head) return e.body === '';
  return REASONS.has(e.body) && (reasons === undefined || reasons.includes(e.body));
}

interface Bank {
  readonly bank?: unknown;
  readonly synthetic?: unknown;
  readonly caller?: { readonly verifiedDomain?: unknown; readonly governanceId?: unknown };
  readonly error?: unknown;
}

function bankJson(e: Exchange): Bank | undefined {
  if (e.headers['cache-control'] !== 'no-store') return undefined;
  try {
    const value = JSON.parse(e.body) as unknown;
    return typeof value === 'object' && value !== null ? (value as Bank) : undefined;
  } catch {
    return undefined;
  }
}

/** Demo Bank served its data. */
export function isBankData(e: Exchange): boolean {
  const json = bankJson(e);
  return e.status === 200 && json?.bank === 'Demo Bank' && json.synthetic === true;
}

/** Any answer that came from Demo Bank: its data, or one of its own JSON errors. */
export function isBankAnswer(e: Exchange): boolean {
  if (isBankData(e)) return true;
  const json = bankJson(e);
  return e.status !== undefined && [403, 404, 405].includes(e.status) && typeof json?.error === 'string' && !REASONS.has(e.body);
}

/**
 * The load balancer's own refusal of a request that carries content: a 400 that isn't Demo Bank's (Demo Bank never
 * answers 400, and every answer of its own is `no-store` JSON). Google's front end answered every signed GET and HEAD
 * with content this way on the first live deployment to come up (2026-11-14), before the authorization extension ran.
 */
export function isEdgeContentRefusal(e: Exchange): boolean {
  return (
    e.status === 400 &&
    !isBankAnswer(e) &&
    e.headers['cache-control'] !== 'no-store' &&
    !(e.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')
  );
}

/** A GET or HEAD with content stopped before Demo Bank: the verifier's body denial, or the load balancer's own 400. */
function contentRefused(e: Exchange, head = false): boolean {
  return (head ? isVerifierDenial(e, undefined, true) : isVerifierDenial(e, BODY_REASONS)) || isEdgeContentRefusal(e);
}

export function isLbFailure(e: Exchange): boolean {
  return e.status !== undefined && e.status >= 500 && !isBankAnswer(e);
}

/** One line for the report: what the edge answered. */
export function describe(e: Exchange): string {
  if (e.error !== undefined) return `no HTTP answer (${e.error})`;
  const kind = isBankData(e)
    ? 'Demo Bank data'
    : isBankAnswer(e)
      ? `Demo Bank error ${JSON.stringify(e.body.slice(0, 60))}`
      : isVerifierDenial(e) || isVerifierDenial(e, undefined, true)
        ? `verifier denial ${e.body === '' ? '(HEAD, no body)' : e.body}`
        : isEdgeContentRefusal(e)
          ? `load balancer refusal${e.body === '' ? ' (no body)' : ''}`
          : e.status !== undefined && e.status >= 300 && e.status < 400
            ? `redirect to ${e.headers['location'] ?? '?'}`
            : `body ${JSON.stringify(e.body.slice(0, 60))}`;
  return `${e.status} ${kind}${e.protocol === undefined ? '' : ` over ${e.protocol}`} in ${e.ms} ms`;
}

const statuses = (list: readonly Exchange[]) => list.map((e) => (e.error === undefined ? String(e.status) : 'none')).join(',');
const details = (labelled: readonly [string, Exchange][]) => labelled.map(([label, e]) => `${label}: ${describe(e)}`).join('; ');

// ---------- requests ----------

function url(ctx: Context, path: string): string {
  return `${ctx.out.endpoint}${path}`;
}

async function signedGet(ctx: Context, path = ctx.out.protected_path, extra: [string, string][] = [], via: 'h1' | 'h2' = 'h1'): Promise<Exchange> {
  const headers = [...(await ctx.signer.sign('GET', url(ctx, path))), ...extra];
  return ctx.http[via](ctx.target, { method: 'GET', path, headers });
}

/** Demo Bank data received for the agent: the identity it saw is the verifier's, for this agent, under a trusted ID. */
function servedToAgent(ctx: Context, e: Exchange): boolean {
  const caller = bankJson(e)?.caller;
  return (
    isBankData(e) &&
    caller?.verifiedDomain === ctx.signer.domain &&
    typeof caller.governanceId === 'string' &&
    ctx.trusted.includes(caller.governanceId.toLowerCase())
  );
}

/** The verifier's reasons a revoked identity can be refused with: its status check, or its log reads. */
export const REVOCATION_REASONS: readonly string[] = ['identity_inactive', 'identity_invalid', 'lifecycle_not_established'];

/**
 * Whether a refusal is a revocation, for deny-revoked and the demo's revoked request. The verifier's reason alone is not
 * evidence: identity_inactive is the same for a retired identity, and the log reasons the same for a tampered or
 * unreachable log. So each reason needs the source behind it to identify revocation, read independently of the edge:
 * identity_inactive the status document (REVOKED), identity_invalid and lifecycle_not_established the authenticated log
 * history (ending in a REVOCATION). RETIRED in either source is never a revocation.
 */
export function judgeRevoked(e: Exchange, evidence: LifecycleEvidence | undefined, stillAllowed: boolean): { pass: boolean; got: string; detail: string } {
  if (!isVerifierDenial(e, REVOCATION_REASONS) || evidence === undefined) {
    let note = 'not a refusal with a revocation reason';
    if (stillAllowed) note = 'still allowed';
    else if (isLbFailure(e)) note = 'the load balancer failed (the verifier did not answer): not a revocation';
    else if (isVerifierDenial(e)) note = `refused for ${e.body}, which is not a revocation reason`;
    return { pass: false, got: statuses([e]), detail: note };
  }
  const { status, log } = evidence;
  const statusText =
    status.kind === 'state' ? `status document reports ${status.state} (read ${status.at})` : `status document not read: ${status.reason} (${status.at})`;
  const logText =
    log.kind === 'logged'
      ? `authenticated log history ends ${log.state}${log.reason ? ` (${log.reason})` : ''}${log.since ? ` since ${log.since}` : ''}, ${log.events} event(s) (read ${log.at})`
      : `log history not established: ${log.reason} (${log.at})`;
  const retired = (status.kind === 'state' && status.state === 'RETIRED') || (log.kind === 'logged' && log.state === 'RETIRED');
  const byStatus = status.kind === 'state' && status.state === 'REVOKED';
  const byLog = log.kind === 'logged' && log.state === 'REVOKED';
  const pass = !retired && (e.body === 'identity_inactive' ? byStatus : byLog);
  const source = e.body === 'identity_inactive' ? 'the status document' : 'the authenticated log history';
  const got = `${statuses([e])} ${e.body} status=${status.kind === 'state' ? status.state : 'unknown'} log=${log.kind === 'logged' ? log.state : 'unknown'}`;
  return { pass, got, detail: `${statusText}; ${logText}${pass ? `: revocation identified by ${source}` : `: not evidence of revocation (${e.body} needs ${source} to show REVOKED${retired ? ', and RETIRED is never a revocation' : ''})`}` };
}

function refs(out: DeployOut): DeploymentRefs {
  const r = out.resources;
  return {
    forwardingRule: r['forwarding_rule'] as string,
    urlMap: r['url_map'] as string,
    originBackendService: r['origin_backend_service'] as string,
    originNeg: r['origin_neg'] as string,
    originService: r['origin_service'] as string,
    originRegion: out.region,
    authzExtension: r['authz_extension'] as string,
    address: out.address,
  };
}

/** The inventory: taken now if a platform login is available, else the one deploy.sh recorded. */
async function inventoryOf(ctx: Context) {
  if (ctx.cloud !== undefined) return ctx.cloud.inventory();
  const recorded = ctx.out.inventory;
  if ('error' in recorded) throw new Error(`no inventory: deploy.sh recorded none (${recorded.error}) and there is no platform login to take one`);
  return recorded;
}

/** Repeats `probe` until `done` holds or the settle timeout passes; returns the last answer and how long it took. */
async function until(ctx: Context, probe: () => Promise<Exchange>, done: (e: Exchange) => boolean): Promise<{ last: Exchange; ok: boolean; ms: number; tries: number }> {
  const started = performance.now();
  let tries = 0;
  for (;;) {
    tries += 1;
    const last = await probe();
    if (done(last)) return { last, ok: true, ms: Math.round(performance.now() - started), tries };
    if (ctx.signal.aborted || performance.now() - started >= ctx.settle.timeoutMs) return { last, ok: false, ms: Math.round(performance.now() - started), tries };
    await ctx.sleep(ctx.settle.intervalMs);
  }
}

const UNTRUSTED_GOVERNANCE = 'untrusted-governance.invalid';

/** One cloud command's outcome. `settled` is false when it was abandoned and had not stopped within the grace period. */
interface Bounded<T> {
  readonly value?: T;
  /** A command's own failure as it gave it; when `abandoned`, what was abandoned and why. */
  readonly error?: string;
  readonly abandoned: boolean;
  readonly settled: boolean;
}

/**
 * Runs one cloud command, abandoning it after `timeoutMs`, and also when `interrupt` aborts. The command gets the signal
 * (gcloud's process is killed on it); a command that ignores it can't hold the run. An abandoned command is then waited
 * for, up to `graceMs`, so that it has stopped before anything else is done; if it hasn't, `settled` is false and its
 * effect, now or later, is unknown. An abandoned command is a failure, even if it then finishes.
 */
async function bounded<T>(what: string, timeoutMs: number, graceMs: number, interrupt: AbortSignal | undefined, command: (signal: AbortSignal) => Promise<T>): Promise<Bounded<T>> {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = interrupt === undefined ? timeout : AbortSignal.any([timeout, interrupt]);
  if (signal.aborted) return { error: `${what}: not started, the run was interrupted`, abandoned: true, settled: true };
  const running: Promise<{ value?: T; error?: string }> = command(signal).then(
    (value) => ({ value }),
    (error: unknown) => ({ error: error instanceof Error ? error.message : String(error) }),
  );
  let onAbort: (() => void) | undefined;
  const abandoned = new Promise<'abandoned'>((resolve) => {
    onAbort = () => resolve('abandoned');
    signal.addEventListener('abort', onAbort, { once: true });
  });
  const first = await Promise.race([running, abandoned]);
  if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
  if (first !== 'abandoned') return first.error === undefined ? { value: first.value as T, abandoned: false, settled: true } : { error: first.error, abandoned: false, settled: true };
  const why = timeout.aborted ? `${what}: no answer within ${timeoutMs} ms, abandoned` : `${what}: interrupted`;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stopped = await Promise.race([running.then(() => true), new Promise<false>((resolve) => (timer = setTimeout(() => resolve(false), graceMs)))]);
  clearTimeout(timer);
  return stopped ? { error: why, abandoned: true, settled: true } : { error: `${why}; it had not stopped ${graceMs} ms later, so whether it takes effect is unknown`, abandoned: true, settled: false };
}

/** The configuration a change is confirmed against: the verifier's, or Demo Bank's for its exposure. */
type ServiceConfig = VerifierConfig | OriginConfig;

const serviceOf = (change: PendingChange) => (change.kind === 'origin-exposure' ? "Demo Bank's" : "the verifier's");

function restored(change: PendingChange, config: ServiceConfig): boolean {
  if (change.kind === 'origin-exposure') {
    const origin = config as OriginConfig;
    return origin.ingress === ORIGIN_DEPLOYED_INGRESS && origin.defaultUrlDisabled === true;
  }
  const verifier = config as VerifierConfig;
  if (change.kind === 'governance') return verifier.governance === change.restore;
  if (change.kind === 'log-evidence') return verifier.logEvidence === undefined;
  return verifier.scaling === 'auto';
}

function configText(change: PendingChange, config: ServiceConfig): string {
  if (change.kind === 'origin-exposure') {
    const origin = config as OriginConfig;
    return `ingress ${origin.ingress ?? '(unrecorded)'}, default URL ${origin.defaultUrlDisabled ? 'disabled' : 'enabled'}`;
  }
  const verifier = config as VerifierConfig;
  if (change.kind === 'governance') return `DNSID_TRUSTED_GOVERNANCE=${verifier.governance ?? '(unset)'}`;
  if (change.kind === 'log-evidence') return `DNSID_LOG_EVIDENCE=${verifier.logEvidence ?? '(unset)'}`;
  return `scaling ${verifier.scaling}`;
}

function restoredText(change: PendingChange): string {
  if (change.kind === 'governance') return change.restore;
  if (change.kind === 'log-evidence') return 'DNSID_LOG_EVIDENCE unset';
  if (change.kind === 'origin-exposure') return `ingress ${ORIGIN_DEPLOYED_INGRESS}, default URL disabled`;
  return 'automatic scaling';
}

/** Reads the changed service's configuration back (bounded, uninterruptible). */
async function readBack(cloud: Cloud, change: PendingChange, timeoutMs: number, graceMs: number): Promise<{ readonly config?: ServiceConfig; readonly error?: string }> {
  const what = `reading ${serviceOf(change)} ${change.kind} back`;
  const read = await bounded<ServiceConfig>(what, timeoutMs, graceMs, undefined, (signal) =>
    change.kind === 'origin-exposure' ? cloud.originConfig(signal) : cloud.verifierConfig(signal),
  );
  if (read.value !== undefined) return { config: read.value };
  return { error: read.abandoned && read.error !== undefined ? read.error : `${what}: ${read.error ?? 'nothing returned'}` };
}

function mismatchText(change: PendingChange, config: ServiceConfig): string {
  return `${serviceOf(change)} configuration shows ${configText(change, config)}, not ${restoredText(change)}`;
}

/** Undefined when the changed service's configuration shows the change undone; else why not (a mismatch, or a failed read). */
export async function checkRestored(cloud: Cloud, change: PendingChange, timeoutMs: number, graceMs: number): Promise<string | undefined> {
  const read = await readBack(cloud, change, timeoutMs, graceMs);
  if (read.config === undefined) return read.error;
  return restored(change, read.config) ? undefined : mismatchText(change, read.config);
}

/**
 * Undoes a recorded change with a bounded, uninterruptible cloud command and confirms it in Cloud Run's configuration of
 * the changed service. A change that lands after the restoring update (an earlier command the platform finished late) shows in
 * that read: the update is applied once more and read again. Throws when the deployment isn't confirmed restored.
 */
export async function restoreChange(cloud: Cloud, change: PendingChange, timeoutMs: number, graceMs: number): Promise<void> {
  let mismatch = '';
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const applied = await bounded(`restoring ${change.kind}`, timeoutMs, graceMs, undefined, (signal) =>
      change.kind === 'governance'
        ? cloud.setGovernance(change.restore, signal)
        : change.kind === 'log-evidence'
          ? cloud.setLogEvidence(change.restore, signal)
          : change.kind === 'origin-exposure'
            ? cloud.setOriginExposure(change.restore, signal)
            : cloud.setVerifierScaling(change.restore, signal),
    );
    if (applied.error !== undefined) throw new Error(applied.error);
    const read = await readBack(cloud, change, timeoutMs, graceMs);
    if (read.config === undefined) throw new Error(`restoring ${change.kind}: the restoring update succeeded, but ${read.error}`);
    if (restored(change, read.config)) return;
    mismatch = mismatchText(change, read.config);
  }
  throw new Error(`restoring ${change.kind}: the restoring update succeeded twice, but ${mismatch}`);
}

interface MutationOutcome {
  readonly changed?: Awaited<ReturnType<typeof until>>;
  readonly changeError?: string;
  readonly restored?: Awaited<ReturnType<typeof until>>;
  readonly restoreError?: string;
  readonly restorationFailed: boolean;
  readonly interrupted: boolean;
}

/**
 * The shape both changing cases share: record the change, make it, watch for its effect, then always undo it and confirm
 * the deployment is back. Interrupted, it stops making and watching the change, but the restoration and every check of
 * it still run (bounded; a second signal ends the process, leaving the record). The record goes only when the change
 * command has stopped, the restoring update is confirmed in the verifier's configuration, the edge behaves as before,
 * and the configuration still reads as restored after that.
 */
async function withChange(
  ctx: Context,
  cloud: Cloud,
  change: PendingChange,
  make: (signal: AbortSignal) => Promise<void>,
  watch: () => Promise<Awaited<ReturnType<typeof until>>>,
  back: (steady: Context) => Promise<Awaited<ReturnType<typeof until>>>,
): Promise<MutationOutcome> {
  let changed: Awaited<ReturnType<typeof until>> | undefined;
  let changeError: string | undefined;
  let unsettled: string | undefined;
  ctx.changes.begin(change);
  const made = await bounded(`the ${change.kind} change`, ctx.cloudTimeoutMs, ctx.settleGraceMs, ctx.signal, make);
  if (made.error !== undefined) {
    changeError = made.error;
    if (!made.settled) unsettled = made.error;
  } else {
    try {
      changed = await watch();
    } catch (error) {
      changeError = (error as Error).message;
    }
  }
  let restoredAtEdge: Awaited<ReturnType<typeof until>> | undefined;
  let restoreError: string | undefined;
  try {
    await restoreChange(cloud, change, ctx.cloudTimeoutMs, ctx.settleGraceMs);
    // Confirming the restoration is not interrupted: its waits don't stop for the run's signal.
    restoredAtEdge = await back({ ...ctx, signal: new AbortController().signal, sleep: ctx.steadySleep });
    if (restoredAtEdge.ok) {
      const after = await checkRestored(cloud, change, ctx.cloudTimeoutMs, ctx.settleGraceMs);
      if (after !== undefined) restoreError = `restoring ${change.kind}: changed again after the restoration: ${after}`;
    }
  } catch (error) {
    restoreError = (error as Error).message;
  }
  if (restoreError === undefined && unsettled !== undefined) restoreError = `RECOVERY INCOMPLETE: ${unsettled}`;
  const restorationFailed = restoreError !== undefined || restoredAtEdge?.ok !== true;
  if (!restorationFailed) ctx.changes.end(change);
  return {
    ...(changed === undefined ? {} : { changed }),
    ...(changeError === undefined ? {} : { changeError }),
    ...(restoredAtEdge === undefined ? {} : { restored: restoredAtEdge }),
    ...(restoreError === undefined ? {} : { restoreError }),
    restorationFailed,
    interrupted: ctx.signal.aborted,
  };
}

function restorationText(m: MutationOutcome, what: string): string {
  if (m.restoreError !== undefined) return `RESTORATION FAILED: ${m.restoreError}`;
  const seen = m.restored ? `${describe(m.restored.last)} after ${m.restored.ms} ms` : 'not observed';
  if (m.restored?.ok !== true) return `RESTORATION NOT CONFIRMED at the edge: ${seen}`;
  return `${what}: ${seen}${m.interrupted ? ' (interrupted: the restoration was still confirmed before stopping)' : ''}`;
}
// ---------- the verifier's own records ----------

/** The verifier's per-request budget (src/callout.ts): a verification that can't finish within it is denied. */
export const VERIFICATION_BUDGET_MS = 2_500;
/** The evidence-age limits the verifier enforces (src/lifecycle.ts): at most 300 s old, at most 5 s ahead. */
const MAX_EVIDENCE_AGE_MS = 300_000;
const MAX_EVIDENCE_FUTURE_MS = 5_000;
const COMPLETENESS_MODES = ['trusted-index', 'full-scan'];
const CACHE_USES = ['hit', 'miss', 'partial'];

/** Why a record is not complete, valid evidence; undefined when it is. */
export function recordProblem(r: VerificationRecord): string | undefined {
  if (r.elapsedMs === undefined || r.elapsedMs < 0) return 'no elapsed time';
  if (r.elapsedMs > VERIFICATION_BUDGET_MS) return `elapsed ${r.elapsedMs} ms, over the ${VERIFICATION_BUDGET_MS} ms budget`;
  if (r.evidenceAgeMs === undefined) return 'no evidence age';
  if (r.evidenceAgeMs > MAX_EVIDENCE_AGE_MS || r.evidenceAgeMs < -MAX_EVIDENCE_FUTURE_MS) return `evidence age ${r.evidenceAgeMs} ms outside -${MAX_EVIDENCE_FUTURE_MS}..${MAX_EVIDENCE_AGE_MS} ms`;
  if (r.completenessMode === undefined || !COMPLETENESS_MODES.includes(r.completenessMode)) return `completeness mode ${r.completenessMode ?? 'missing'}`;
  if (r.materialCache === undefined || !CACHE_USES.includes(r.materialCache)) return `material cache use ${r.materialCache ?? 'missing'}`;
  return undefined;
}

const recordText = (r: VerificationRecord) =>
  `${r.elapsedMs ?? '?'} ms, ${r.completenessMode ?? '?'}, cache ${r.materialCache ?? '?'}, evidence ${r.evidenceAgeMs ?? '?'} ms old`;

/**
 * The verifier's records of the `expected` requests this agent sent between `since` and `until`, which were all served:
 * read until that many are there (logging is delayed) or the log wait passes. Nothing else is sent for this agent
 * meanwhile, so the records in the window are these requests' own, in order. Missing, extra or unreadable records are
 * a failure with the reason, never a pass.
 */
export async function collectRecords(
  ctx: Context,
  cloud: Cloud,
  since: string,
  until: string,
  expected: number,
): Promise<{ records?: VerificationRecord[]; problem?: string; text: string }> {
  const started = performance.now();
  let found: VerificationRecord[] = [];
  for (;;) {
    try {
      found = await cloud.verificationRecords(since, until, ctx.signer.domain);
    } catch (error) {
      return { problem: `the verifier's log records could not be read: ${(error as Error).message}`, text: '' };
    }
    if (found.length >= expected || ctx.signal.aborted || performance.now() - started >= ctx.logWaitMs) break;
    await ctx.sleep(ctx.settle.intervalMs);
  }
  const text = found.map((r, i) => `#${i + 1} ${recordText(r)}`).join('; ');
  if (found.length !== expected) {
    return { problem: `${found.length} verifier record(s) for ${expected} served request(s) after ${Math.round(performance.now() - started)} ms`, text };
  }
  const bad = found.map((r, i) => [i + 1, recordProblem(r)] as const).filter(([, p]) => p !== undefined);
  if (bad.length > 0) return { problem: bad.map(([i, p]) => `record #${i}: ${p}`).join('; '), records: found, text };
  return { records: found, text };
}

/**
 * The new revision's first verification, from the records of the requests sent after the change (`first`: those until
 * it served, `then`: the ones after): the first record read by full scan is the new revision's first, and it must be a
 * cold miss (nothing reused). A hit or partial there means it was warmed first and nothing cold was measured.
 */
export function coldFirstRecord(
  first: { records?: VerificationRecord[]; problem?: string; text: string },
  then: { records?: VerificationRecord[]; problem?: string },
): { problem?: string; text: string } {
  if (first.problem !== undefined) return { problem: first.problem, text: first.text };
  const records = [...(first.records ?? []), ...(then.records ?? [])];
  const r = records.find((x) => x.completenessMode === 'full-scan');
  if (r === undefined) return { problem: 'no record from the new revision (none read by full scan)', text: '' };
  const text = recordText(r);
  if (r.materialCache !== 'miss') return { problem: `not cold: cache ${r.materialCache ?? 'missing'}, so no cold verification was measured`, text };
  return { text };
}

/** Sends `n` signed GETs; the window they were sent in, and whether every one was served to the agent. */
async function servedRun(ctx: Context, n: number): Promise<{ since: string; until: string; exchanges: Exchange[]; served: boolean }> {
  // The verifier writes a request's record when its stream ends, which can be after the client has its answer: a pause
  // keeps an earlier request's record out of this window.
  await ctx.quietGap();
  const since = new Date().toISOString();
  const exchanges: Exchange[] = [];
  for (let i = 0; i < n; i += 1) exchanges.push(await signedGet(ctx));
  // Cloud Logging stamps a record when the verifier writes it, after the response: leave room past the last answer.
  const until = new Date(Date.now() + 5_000).toISOString();
  return { since, until, exchanges, served: exchanges.every((e) => servedToAgent(ctx, e)) };
}

// ---------- the cases ----------

export const CASES: readonly LiveCase[] = [
  {
    id: 'deny-unsigned',
    edge: 'EDGE-02',
    expect: '403 from the verifier (signature_missing, no-store) for an unsigned GET and HEAD',
    modes: ['live'],
    async run(ctx) {
      const get = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path });
      const head = await ctx.http.h1(ctx.target, { method: 'HEAD', path: ctx.out.protected_path });
      return {
        got: statuses([get, head]),
        pass: isVerifierDenial(get, ['signature_missing']) && isVerifierDenial(head, undefined, true),
        detail: details([['GET', get], ['HEAD', head]]),
      };
    },
  },
  {
    id: 'allow-trusted',
    edge: 'EDGE-01',
    expect: '200 from Demo Bank with the identity the verifier set for this agent (GET and HEAD); timed',
    modes: ['live', 'allow'],
    async run(ctx) {
      const first = await signedGet(ctx);
      const head = await ctx.http.h1(ctx.target, { method: 'HEAD', path: ctx.out.protected_path, headers: await ctx.signer.sign('HEAD', url(ctx, ctx.out.protected_path)) });
      const repeats: Exchange[] = [];
      for (let i = 0; i < 5; i += 1) repeats.push(await signedGet(ctx));
      const all = [first, ...repeats];
      const pass = all.every((e) => servedToAgent(ctx, e)) && head.status === 200 && head.headers['cache-control'] === 'no-store' && head.body === '';
      const sorted = repeats.map((e) => e.ms).sort((a, b) => a - b);
      // Client round trips only, for reference: the verifier's own timings, cache use and evidence ages are judged by
      // evidence-freshness (EDGE-06) and verification-timing (ADD-05) from its log records.
      return {
        got: statuses([first, head, ...repeats]),
        pass,
        detail: `first ${describe(first)}; HEAD ${describe(head)}; 5 more GETs ${statuses(repeats)} in ${sorted.join('/')} ms round trip (median ${sorted[2]} ms)`,
      };
    },
  },
  {
    id: 'evidence-freshness',
    edge: 'EDGE-06',
    expect:
      "the verifier's own log record for each of 3 served requests: evidence age within -5..300 s, a completeness mode, the material-cache use and the elapsed time within 2,500 ms; read until all are there (logging is delayed); a missing, extra or incomplete record fails",
    modes: ['live'],
    async run(ctx) {
      const cloud = ctx.cloud;
      if (cloud === undefined) return { got: 'not run', pass: false, detail: "needs the platform login to read the verifier's log records; none is available here" };
      const sent = await servedRun(ctx, 3);
      if (!sent.served) return { got: statuses(sent.exchanges), pass: false, detail: `not every request was served: ${details(sent.exchanges.map((e, i) => [`#${i + 1}`, e]))}` };
      const got = await collectRecords(ctx, cloud, sent.since, sent.until, 3);
      return {
        got: got.problem === undefined ? `${statuses(sent.exchanges)}; 3 complete records` : `${statuses(sent.exchanges)}; records incomplete`,
        pass: got.problem === undefined,
        detail: `verifier records: ${got.text || 'none'}${got.problem === undefined ? '' : `; ${got.problem}`}`,
      };
    },
  },
  {
    id: 'deny-malformed-signature',
    edge: 'EDGE-02',
    expect: '403 from the verifier (signature_malformed)',
    modes: ['live'],
    async run(ctx) {
      const e = await ctx.http.h1(ctx.target, {
        method: 'GET',
        path: ctx.out.protected_path,
        headers: [
          ['Signature-Input', 'sig1=!!!'],
          ['Signature', 'sig1=:AAAA:'],
        ],
      });
      return { got: statuses([e]), pass: isVerifierDenial(e, ['signature_malformed']), detail: describe(e) };
    },
  },
  {
    id: 'deny-tampered',
    edge: 'EDGE-02',
    expect: '403 from the verifier (signature_invalid) for a query and a method changed after signing',
    modes: ['live'],
    async run(ctx) {
      const query = await ctx.http.h1(ctx.target, { method: 'GET', path: `${ctx.out.protected_path}?a=2`, headers: await ctx.signer.sign('GET', url(ctx, `${ctx.out.protected_path}?a=1`)) });
      const method = await ctx.http.h1(ctx.target, { method: 'HEAD', path: ctx.out.protected_path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path)) });
      return {
        got: statuses([query, method]),
        pass: isVerifierDenial(query, ['signature_invalid']) && isVerifierDenial(method, undefined, true),
        detail: details([['query a=1 signed, a=2 sent', query], ['GET signed, HEAD sent', method]]),
      };
    },
  },
  {
    id: 'app-account-policy',
    edge: 'EDGE-01',
    expect:
      "(the architecture's application-authorization example, using the identity EDGE-01 delivers) Demo Bank's own account policy, behind the edge: the agent reads its own account (200), and another agent's account is refused by Demo Bank (403 account_not_permitted), not by the verifier",
    modes: ['live'],
    async run(ctx) {
      const [own] = accountsFor(ctx.signer.domain);
      const [theirs] = accountsFor(ctx.otherAgent ?? 'another-agent.invalid');
      const mine = await signedGet(ctx, `${ctx.out.protected_path}/${own?.id}`);
      const other = await signedGet(ctx, `${ctx.out.protected_path}/${theirs?.id}`);
      const read = servedToAgent(ctx, mine) && (bankJson(mine) as { account?: { id?: unknown } } | undefined)?.account?.id === own?.id;
      const refused = other.status === 403 && isBankAnswer(other) && !isVerifierDenial(other) && other.body === '{"error":"account_not_permitted"}';
      return { got: statuses([mine, other]), pass: read && refused, detail: details([['its own account', mine], ["another agent's account", other]]) };
    },
  },
  {
    id: 'deny-other-identity',
    edge: 'EDGE-03',
    expect: "403 from the verifier when the agent's key claims OTHER_AGENT_ID's identity, and when it claims a domain with no DNSid identity",
    modes: ['live'],
    async run(ctx) {
      const nowhere = `no-dnsid-${Date.now().toString(36)}.invalid`;
      const none = await ctx.http.h1(ctx.target, {
        method: 'GET',
        path: ctx.out.protected_path,
        headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path), { claimedDomain: nowhere }),
      });
      const noneOk = isVerifierDenial(none, ['signer_lookup_failed', 'identity_not_found']);
      if (ctx.otherAgent === undefined) {
        return { got: statuses([none]), pass: false, detail: `OTHER_AGENT_ID not given, so the other-identity claim was not tried; no identity: ${describe(none)}` };
      }
      const other = await ctx.http.h1(ctx.target, {
        method: 'GET',
        path: ctx.out.protected_path,
        headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path), { claimedDomain: ctx.otherAgent }),
      });
      return {
        got: statuses([other, none]),
        pass: isVerifierDenial(other, ['signature_key_unknown', 'signature_invalid']) && noneOk,
        detail: details([['claims OTHER_AGENT_ID', other], ['claims a domain with no identity', none]]),
      };
    },
  },
  {
    id: 'deny-expired-signature',
    edge: 'EDGE-08',
    expect: '403 from the verifier for a signature created an hour ago (signature_expired) and an hour ahead (signature_created_in_future)',
    modes: ['live'],
    async run(ctx) {
      const now = Math.floor(Date.now() / 1000);
      const old = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path), { created: now - 3600 }) });
      const ahead = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path), { created: now + 3600 }) });
      return {
        got: statuses([old, ahead]),
        pass: isVerifierDenial(old, ['signature_expired']) && isVerifierDenial(ahead, ['signature_created_in_future']),
        detail: details([['created -3600 s', old], ['created +3600 s', ahead]]),
      };
    },
  },
  {
    id: 'fidelity-http1',
    edge: 'ADD-02',
    expect: '200 from Demo Bank for a signed GET over HTTP/1.1, also with the signature fields named in mixed case',
    modes: ['live'],
    async run(ctx) {
      const plain = await signedGet(ctx, ctx.out.protected_path, [], 'h1');
      const fields = await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path));
      const mixed = await ctx.http.h1(ctx.target, {
        method: 'GET',
        path: ctx.out.protected_path,
        headers: fields.map(([name, value]) => [name === 'signature' ? 'SIGNATURE' : 'Signature-Input', value] as [string, string]),
      });
      return {
        got: statuses([plain, mixed]),
        pass: servedToAgent(ctx, plain) && plain.protocol === 'http/1.1' && servedToAgent(ctx, mixed),
        detail: details([['HTTP/1.1', plain], ['mixed-case names', mixed]]),
      };
    },
  },
  {
    id: 'fidelity-http2',
    edge: 'ADD-02',
    expect: '200 from Demo Bank for a signed GET over HTTP/2 with the same authority',
    modes: ['live'],
    async run(ctx) {
      const e = await signedGet(ctx, ctx.out.protected_path, [], 'h2');
      return { got: statuses([e]), pass: servedToAgent(ctx, e) && e.protocol === 'h2', detail: describe(e) };
    },
  },
  {
    id: 'fidelity-escaped-path',
    edge: 'ADD-02',
    expect:
      'a signed request with percent-escapes in the query, and one with an escaped space in the path, both pass verification and reach Demo Bank; an escaped unreserved character (/%61ccounts) reaches the verifier and Demo Bank as the same path: either both see it decoded (signed decoded: 200; signed escaped: 403 signature_invalid) or both see it escaped (signed escaped: Demo Bank; signed decoded: 403 signature_invalid)',
    modes: ['live'],
    async run(ctx) {
      const query = await signedGet(ctx, `${ctx.out.protected_path}?q=a%20b%2Fc%3D`);
      const kept = await signedGet(ctx, `${ctx.out.protected_path}%20x`);
      // RFC 3986 makes %61 and "a" equivalent; the load balancer may decode it before the extension. Whichever form the
      // verifier checks, Demo Bank must get the same one.
      const escaped = '/%61ccounts';
      const asSent = await signedGet(ctx, escaped);
      const decoded = await ctx.http.h1(ctx.target, { method: 'GET', path: escaped, headers: await ctx.signer.sign('GET', url(ctx, '/accounts')) });
      const lbDecodes = isVerifierDenial(asSent, ['signature_invalid']) && servedToAgent(ctx, decoded);
      const lbKeeps = isBankAnswer(asSent) && !isBankData(asSent) && isVerifierDenial(decoded, ['signature_invalid']);
      return {
        got: statuses([query, kept, asSent, decoded]),
        pass: servedToAgent(ctx, query) && isBankAnswer(kept) && (lbDecodes || lbKeeps),
        detail: `${details([
          ['escaped query', query],
          [`escaped space ${ctx.out.protected_path}%20x`, kept],
          [`${escaped} signed as sent`, asSent],
          [`${escaped} signed as /accounts`, decoded],
        ])}; ${
          lbDecodes
            ? 'the load balancer decoded %61 before the verifier and Demo Bank: a signer signs the normalized path'
            : lbKeeps
              ? 'the load balancer kept %61: the verifier and Demo Bank saw the path as sent'
              : 'the verifier and Demo Bank did not see the same path'
        }`,
      };
    },
  },
  {
    id: 'fidelity-query-order',
    edge: 'ADD-02',
    expect: 'a query in a non-sorted order verifies (200); a query reordered after signing is refused (403 signature_invalid)',
    modes: ['live'],
    async run(ctx) {
      const kept = await signedGet(ctx, `${ctx.out.protected_path}?b=2&a=1`);
      const reordered = await ctx.http.h1(ctx.target, {
        method: 'GET',
        path: `${ctx.out.protected_path}?b=2&a=1`,
        headers: await ctx.signer.sign('GET', url(ctx, `${ctx.out.protected_path}?a=1&b=2`)),
      });
      return {
        got: statuses([kept, reordered]),
        pass: servedToAgent(ctx, kept) && isVerifierDenial(reordered, ['signature_invalid']),
        detail: details([['?b=2&a=1 as signed', kept], ['signed ?a=1&b=2, sent ?b=2&a=1', reordered]]),
      };
    },
  },
  {
    id: 'fidelity-duplicate-headers',
    edge: 'ADD-02',
    expect: '403 from the verifier when the Signature and Signature-Input fields are each sent twice',
    modes: ['live'],
    async run(ctx) {
      const fields = await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path));
      const e = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers: [...fields, ...fields] });
      return { got: statuses([e]), pass: isVerifierDenial(e, ['signature_ambiguous', 'signature_malformed']), detail: describe(e) };
    },
  },
  {
    id: 'deny-body-on-get',
    edge: 'ADD-02',
    expect: "a signed GET with Content-Length and a body is refused before Demo Bank: the load balancer's own 400, or the verifier's 403 (body_indicated or body_not_ruled_out)",
    modes: ['live'],
    async run(ctx) {
      const e = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path)), body: Buffer.from('{"x":1}') });
      return { got: statuses([e]), pass: contentRefused(e), detail: describe(e) };
    },
  },
  {
    id: 'deny-body-on-get-chunked',
    edge: 'ADD-02',
    expect: "a signed HTTP/1.1 GET with a chunked body is refused before Demo Bank: the load balancer's own 400, or the verifier's 403 (body_indicated or body_not_ruled_out)",
    modes: ['live'],
    async run(ctx) {
      const e = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path)), body: Buffer.from('{"x":1}'), chunked: true });
      return { got: statuses([e]), pass: contentRefused(e), detail: describe(e) };
    },
  },
  {
    id: 'deny-body-on-get-h2',
    edge: 'ADD-02',
    expect: "signed HTTP/2 GET and HEAD requests carrying DATA with no length header are refused before Demo Bank: the load balancer's own 400, or the verifier's 403",
    modes: ['live'],
    async run(ctx) {
      const get = await ctx.http.h2(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path)), body: Buffer.from('{"x":1}') });
      const head = await ctx.http.h2(ctx.target, { method: 'HEAD', path: ctx.out.protected_path, headers: await ctx.signer.sign('HEAD', url(ctx, ctx.out.protected_path)), body: Buffer.from('{"x":1}') });
      return {
        got: statuses([get, head]),
        pass: contentRefused(get) && contentRefused(head, true) && get.protocol === 'h2',
        detail: details([['GET + DATA', get], ['HEAD + DATA', head]]),
      };
    },
  },
  {
    id: 'strip-spoofed-identity-headers',
    edge: 'ADD-04',
    expect: "200 from Demo Bank, which received only the verifier's identity, not the forged X-DNSid-* values",
    modes: ['live'],
    async run(ctx) {
      const forged = 'forged-identity.invalid';
      const e = await signedGet(ctx, ctx.out.protected_path, [
        ['X-DNSid-Verified-Domain', forged],
        ['x-dnsid-governance-id', forged],
        ['X-DNSID-Extra', 'forged'],
      ]);
      const caller = bankJson(e)?.caller;
      return {
        got: statuses([e]),
        pass: servedToAgent(ctx, e) && caller?.verifiedDomain !== forged && caller?.governanceId !== forged,
        detail: `${describe(e)}; Demo Bank saw ${JSON.stringify(caller ?? null)}`,
      };
    },
  },
  {
    id: 'replay-within-window',
    edge: 'ADD-07',
    expect: 'the same signed request sent twice within 300 s is allowed both times (the documented limitation, D-06)',
    modes: ['live'],
    async run(ctx) {
      const headers = await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path));
      const first = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers });
      const again = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path, headers });
      return {
        got: statuses([first, again]),
        pass: servedToAgent(ctx, first) && servedToAgent(ctx, again),
        detail: `${details([['first', first], ['replayed', again]])}; replay within the window is accepted, as documented`,
      };
    },
  },
  {
    id: 'deny-method',
    edge: 'ADD-08',
    expect: '403 from the verifier (method_not_allowed) for signed POST, PUT and DELETE',
    modes: ['live'],
    async run(ctx) {
      const results: [string, Exchange][] = [];
      for (const method of ['POST', 'PUT', 'DELETE']) {
        const body = method === 'DELETE' ? undefined : Buffer.from('{}');
        results.push([
          method,
          await ctx.http.h1(ctx.target, {
            method,
            path: ctx.out.protected_path,
            headers: await ctx.signer.sign(method, url(ctx, ctx.out.protected_path)),
            ...(body === undefined ? {} : { body }),
          }),
        ]);
      }
      return {
        got: statuses(results.map(([, e]) => e)),
        pass: results.every(([, e]) => isVerifierDenial(e, ['method_not_allowed'])),
        detail: details(results),
      };
    },
  },
  {
    id: 'deny-cache-reuse',
    edge: 'EDGE-09',
    expect: 'after an allowed request, three unsigned GETs of the same URL are each denied by the verifier (no cached copy), and Cloud CDN is off',
    modes: ['live'],
    async run(ctx) {
      const warm = await signedGet(ctx);
      const repeats: Exchange[] = [];
      for (let i = 0; i < 3; i += 1) repeats.push(await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path }));
      const config = checkNoCdn(await inventoryOf(ctx), refs(ctx.out));
      return {
        got: statuses([warm, ...repeats]),
        pass: servedToAgent(ctx, warm) && repeats.every((e) => isVerifierDenial(e, ['signature_missing']) && e.headers['age'] === undefined) && config.pass,
        detail: `signed ${describe(warm)}; unsigned ${repeats.map(describe).join(' | ')}; ${config.detail}`,
      };
    },
  },
  {
    id: 'deny-bypass-run-app',
    edge: 'EDGE-09',
    expect: "Demo Bank's run.app URLs serve nothing, even with forged identity headers",
    modes: ['live'],
    async run(ctx) {
      const results: [string, Exchange][] = [];
      for (const base of ctx.out.bypass_routes.origin_run_app) {
        results.push([
          base,
          await ctx.http.plain(`${base}${ctx.out.protected_path}`, {
            method: 'GET',
            headers: [
              ['x-dnsid-verified-domain', ctx.signer.domain],
              ['x-dnsid-governance-id', ctx.trusted[0] ?? 'dnsid-sandbox.io'],
            ],
          }),
        ]);
      }
      const closed = (e: Exchange) => e.error !== undefined || (!isBankAnswer(e) && e.status !== undefined && (e.status < 200 || e.status >= 300));
      return { got: statuses(results.map(([, e]) => e)), pass: results.length > 0 && results.every(([, e]) => closed(e)), detail: details(results) };
    },
  },
  {
    id: 'deny-bypass-http',
    edge: 'EDGE-09',
    expect: 'plain HTTP to the load balancer reaches nothing (no port-80 rule)',
    modes: ['live'],
    async run(ctx) {
      const e = await ctx.http.plain(ctx.out.bypass_routes.http, { method: 'GET', timeoutMs: 10_000 });
      return { got: statuses([e]), pass: e.error !== undefined || (!isBankAnswer(e) && (e.status ?? 0) >= 300), detail: describe(e) };
    },
  },
  {
    id: 'deny-bypass-uncovered-rule',
    edge: 'EDGE-09',
    expect: 'every forwarding rule that can reach Demo Bank is a target of the DNSid CUSTOM policy, and only the HTTPS rule uses the address',
    modes: ['live'],
    async run(ctx) {
      const finding = checkCoverage(await inventoryOf(ctx), refs(ctx.out));
      return { got: finding.pass ? 'covered' : 'not covered', pass: finding.pass, detail: finding.detail };
    },
  },
  {
    id: 'deny-bypass-dotdot',
    edge: 'EDGE-09',
    expect: 'a path with a /../ segment is redirected by the load balancer, never forwarded',
    modes: ['live'],
    async run(ctx) {
      const path = ctx.out.bypass_routes.dotdot_path;
      // Signed over the normalized URL, so the request would verify if the load balancer forwarded it normalized.
      const e = await ctx.http.h1(ctx.target, { method: 'GET', path, headers: await ctx.signer.sign('GET', url(ctx, ctx.out.protected_path)) });
      return { got: statuses([e]), pass: e.status !== undefined && e.status >= 300 && e.status < 400 && !isBankAnswer(e), detail: `${path}: ${describe(e)}` };
    },
  },
  {
    id: 'deny-bypass-verifier',
    edge: 'EDGE-09',
    expect:
      "the verifier's run.app URLs answer nothing usable: no 2xx to GET /, and a gRPC call to ExternalProcessor/Process gets no gRPC answer (no gRPC content type or status, and no message: a non-2xx, or an empty 200 as Google's front end gives a disabled URL, bare or as its application/grpc UNIMPLEMENTED (12))",
    modes: ['live'],
    async run(ctx) {
      const results: [string, Exchange][] = [];
      const calls: [string, Exchange][] = [];
      for (const base of ctx.out.bypass_routes.verifier_run_app) {
        results.push([`${base}/ GET`, await ctx.http.plain(`${base}/`, { method: 'GET' })]);
        calls.push([`${base}${PROCESS_METHOD.path} gRPC`, await ctx.http.grpc(base, PROCESS_METHOD.path)]);
      }
      const grpcAnswer = (e: Exchange) => (e.headers['content-type'] ?? '').startsWith('application/grpc') || e.headers['grpc-status'] !== undefined;
      const refused = (e: Exchange) => e.status !== undefined && (e.status < 200 || e.status >= 300);
      const closed = (e: Exchange) => e.error !== undefined || (refused(e) && !grpcAnswer(e));
      // The verifier would answer a gRPC call with gRPC framing and a status, and with a message (its 403) for the empty
      // request: an answer with none of them, even a 200, came from something else and carries nothing. Google's front
      // end may instead turn its 404 for a disabled URL into gRPC's UNIMPLEMENTED (12) with no message, typed
      // application/grpc. The verifier serves this method, and its grpc-js server types every answer
      // application/grpc+proto, so that answer can't be the verifier's either.
      const frontEndUnimplemented = (e: Exchange) =>
        e.status === 200 && e.headers['content-type'] === 'application/grpc' && e.headers['grpc-status'] === '12' && e.body === '';
      const noGrpcAnswer = (e: Exchange) => closed(e) || (e.error === undefined && e.body === '' && (!grpcAnswer(e) || frontEndUnimplemented(e)));
      const grpcDetail = (e: Exchange) =>
        e.error === undefined ? `; content-type ${JSON.stringify(e.headers['content-type'] ?? null)}, grpc-status ${JSON.stringify(e.headers['grpc-status'] ?? null)}` : '';
      return {
        got: statuses([...results, ...calls].map(([, e]) => e)),
        pass: calls.length > 0 && results.every(([, e]) => closed(e)) && calls.every(([, e]) => noGrpcAnswer(e)),
        detail: [details(results), ...calls.map(([label, e]) => `${label}: ${describe(e)}${grpcDetail(e)}`)].join('; '),
      };
    },
  },
  {
    id: 'deny-bypass-rewrite',
    edge: 'EDGE-09',
    expect: "the URL map rewrites nothing and routes only to Demo Bank's backend (a configuration check)",
    modes: ['live'],
    async run(ctx) {
      const finding = checkNoRewrite(await inventoryOf(ctx), refs(ctx.out));
      return { got: finding.pass ? 'no rewrites' : 'rewrites or other routes', pass: finding.pass, detail: finding.detail };
    },
  },
  {
    id: 'deny-untrusted-governance',
    edge: 'EDGE-04',
    expect: "with the agent's governance no longer trusted, a signed request gets 403 governance_not_trusted; once trusted again, 200 (no code change)",
    modes: ['live'],
    mutates: true,
    async run(ctx) {
      const cloud = ctx.cloud;
      if (cloud === undefined) return { got: 'not run', pass: false, detail: 'needs the platform login to change the trusted governance list; none is available here' };
      const original = ctx.out.trusted_governance;
      const m = await withChange(
        ctx,
        cloud,
        { kind: 'governance', restore: original },
        (signal) => cloud.setGovernance(UNTRUSTED_GOVERNANCE, signal),
        () => until(ctx, () => signedGet(ctx), (e) => isVerifierDenial(e, ['governance_not_trusted'])),
        (steady) => until(steady, () => signedGet(steady), (e) => servedToAgent(steady, e)),
      );
      const denied = m.changed;
      const detail = [
        m.changeError === undefined ? `trusting only ${UNTRUSTED_GOVERNANCE}: ${denied ? `${describe(denied.last)} after ${denied.ms} ms, ${denied.tries} request(s)` : 'not observed'}` : `the change failed: ${m.changeError}`,
        restorationText(m, `restored to ${original}`),
      ].join('; ');
      return {
        got: `${denied?.last.status ?? 'none'} then ${m.restored?.last.status ?? 'none'}`,
        pass: denied?.ok === true && !m.interrupted && !m.restorationFailed,
        detail,
        restorationFailed: m.restorationFailed,
      };
    },
  },
  {
    id: 'deny-verifier-down',
    edge: 'ADD-01',
    expect: "a denial is the verifier's 403; with the verifier unable to answer the load balancer blocks with 500 (signed or not, Demo Bank never answers); restored afterwards",
    modes: ['live'],
    mutates: true,
    async run(ctx) {
      const cloud = ctx.cloud;
      if (cloud === undefined) return { got: 'not run', pass: false, detail: 'needs the platform login to stop and restore the verifier; none is available here' };
      const before = await ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path });
      let signedWhileDown: Exchange | undefined;
      const unsigned = () => ctx.http.h1(ctx.target, { method: 'GET', path: ctx.out.protected_path });
      const m = await withChange(
        ctx,
        cloud,
        { kind: 'scaling', restore: 'auto' },
        (signal) => cloud.setVerifierScaling('zero', signal),
        async () => {
          const down = await until(ctx, unsigned, (e) => isLbFailure(e) && e.status === 500);
          if (down.ok && !ctx.signal.aborted) signedWhileDown = await signedGet(ctx);
          return down;
        },
        (steady) => until(steady, unsigned, (e) => isVerifierDenial(e, ['signature_missing'])),
      );
      const down = m.changed;
      const pass =
        isVerifierDenial(before, ['signature_missing']) &&
        down?.ok === true &&
        signedWhileDown !== undefined &&
        signedWhileDown.status === 500 &&
        !isBankAnswer(signedWhileDown) &&
        !m.interrupted &&
        !m.restorationFailed;
      const detail = [
        `before: ${describe(before)}`,
        m.changeError === undefined ? `verifier at zero instances: ${down ? `${describe(down.last)} after ${down.ms} ms` : 'not observed'}; signed while down: ${signedWhileDown ? describe(signedWhileDown) : 'not sent'}` : `the change failed: ${m.changeError}`,
        restorationText(m, 'restored'),
      ].join('; ');
      return { got: `${before.status ?? 'none'} then ${down?.last.status ?? 'none'} then ${m.restored?.last.status ?? 'none'}`, pass, detail, restorationFailed: m.restorationFailed };
    },
  },
  {
    id: 'verification-timing',
    edge: 'ADD-05',
    expect:
      "from the verifier's own records, each within the 2,500 ms budget: 5 requests in the deployed configuration (completeness mode and cache use recorded for each), then DNSID_LOG_EVIDENCE=full-scan (a new revision): the first request it serves must be a cold miss (nothing reused), measured, and 3 more must each say full-scan; then the setting removed and confirmed (changes the deployment for a moment)",
    modes: ['live'],
    mutates: true,
    async run(ctx) {
      const cloud = ctx.cloud;
      if (cloud === undefined) return { got: 'not run', pass: false, detail: "needs the platform login to read the verifier's log records and change its log mode; none is available here" };
      const deployed = await servedRun(ctx, 5);
      const before = deployed.served ? await collectRecords(ctx, cloud, deployed.since, deployed.until, 5) : { problem: 'not every request was served', text: '' };
      let scan: { problem?: string; text: string; records?: VerificationRecord[] } = { problem: 'not measured', text: '' };
      let cold: { problem?: string; text: string } = { problem: 'not measured', text: '' };
      let scanStatuses = 'none';
      const m = await withChange(
        ctx,
        cloud,
        { kind: 'log-evidence', restore: 'default' },
        (signal) => cloud.setLogEvidence('full-scan', signal),
        async () => {
          // The update returns once the new revision serves; requests are served throughout. Every request from here on
          // is in a window whose records are read, so the new revision's very first one is among them.
          await ctx.quietGap();
          const coldSince = new Date().toISOString();
          const probes: Exchange[] = [];
          const ready = await until(
            ctx,
            async () => {
              const e = await signedGet(ctx);
              probes.push(e);
              return e;
            },
            (e) => servedToAgent(ctx, e),
          );
          if (!ready.ok || ctx.signal.aborted) return ready;
          const sent = await servedRun(ctx, 3);
          scanStatuses = statuses(sent.exchanges);
          if (!sent.served) {
            scan = { problem: `not every request was served: ${details(sent.exchanges.map((e, i) => [`#${i + 1}`, e]))}`, text: '' };
            return ready;
          }
          const first = await collectRecords(ctx, cloud, coldSince, sent.since, probes.filter((e) => servedToAgent(ctx, e)).length);
          scan = await collectRecords(ctx, cloud, sent.since, sent.until, 3);
          cold = coldFirstRecord(first, scan);
          const notScanned = (scan.records ?? []).filter((r) => r.completenessMode !== 'full-scan').length;
          if (scan.problem === undefined && notScanned > 0) scan = { ...scan, problem: `${notScanned} record(s) not read by full scan: the setting had not taken effect` };
          return ready;
        },
        (steady) => until(steady, () => signedGet(steady), (e) => servedToAgent(steady, e)),
      );
      const pass = before.problem === undefined && cold.problem === undefined && scan.problem === undefined && m.changeError === undefined && !m.interrupted && !m.restorationFailed;
      const detail = [
        `deployed configuration: ${before.text || 'no records'}${before.problem === undefined ? '' : ` (${before.problem})`}`,
        m.changeError === undefined
          ? `new revision's first request: ${cold.text || 'no record'}${cold.problem === undefined ? '' : ` (${cold.problem})`}; full scan (${scanStatuses}): ${scan.text || 'no records'}${scan.problem === undefined ? '' : ` (${scan.problem})`}`
          : `the change failed: ${m.changeError}`,
        restorationText(m, 'DNSID_LOG_EVIDENCE removed'),
      ].join('; ');
      return { got: pass ? '5 + cold first + 3 records within budget' : 'evidence incomplete', pass, detail, restorationFailed: m.restorationFailed };
    },
  },
  {
    id: 'deny-forged-identity',
    edge: 'ADD-04',
    expect:
      "with Demo Bank reachable without the verifier (its own run.app URL opened for the case, as when a front end forwards a request without the authorization policy), forged identity headers are refused by Demo Bank itself: without an attestation 403 identity_attestation_required, with a forged one 403 identity_attestation_invalid; the URL closed again afterwards (changes the deployment for a moment)",
    modes: ['live'],
    mutates: true,
    async run(ctx) {
      const cloud = ctx.cloud;
      if (cloud === undefined) return { got: 'not run', pass: false, detail: "needs the platform login to open and close Demo Bank's own URL; none is available here" };
      const base = ctx.out.bypass_routes.origin_run_app[0];
      if (base === undefined) return { got: 'not run', pass: false, detail: "DEPLOY_OUT names no run.app URL for Demo Bank" };
      const forged: [string, string][] = [
        ['x-dnsid-verified-domain', ctx.signer.domain],
        ['x-dnsid-governance-id', ctx.trusted[0] ?? 'dnsid-sandbox.io'],
      ];
      // Well formed, current, and not made with the deployment's key: what a caller without the key can send.
      const forgedAttestation = `v1.${Math.floor(Date.now() / 1000)}.${randomBytes(32).toString('base64url')}`;
      const direct = (headers: [string, string][]) => ctx.http.plain(`${base}${ctx.out.protected_path}`, { method: 'GET', headers });
      const refusedAs = (e: Exchange, error: string) => e.status === 403 && isBankAnswer(e) && bankJson(e)?.error === error;
      const closed = (e: Exchange) => e.error !== undefined || (!isBankAnswer(e) && e.status !== undefined && (e.status < 200 || e.status >= 300));
      let missing: Exchange | undefined;
      let forgedOne: Exchange | undefined;
      const m = await withChange(
        ctx,
        cloud,
        { kind: 'origin-exposure', restore: 'closed' },
        (signal) => cloud.setOriginExposure('open', signal),
        async () => {
          // Open once Demo Bank itself answers there (its refusal of a request with no identity at all).
          const open = await until(ctx, () => direct([]), (e) => refusedAs(e, 'identity_context_required'));
          if (open.ok && !ctx.signal.aborted) {
            missing = await direct(forged);
            forgedOne = await direct([...forged, [ATTESTATION_HEADER, forgedAttestation]]);
          }
          return open;
        },
        (steady) => until(steady, () => direct(forged), closed),
      );
      const opened = m.changed;
      const pass =
        opened?.ok === true &&
        missing !== undefined &&
        refusedAs(missing, 'identity_attestation_required') &&
        forgedOne !== undefined &&
        refusedAs(forgedOne, 'identity_attestation_invalid') &&
        !m.interrupted &&
        !m.restorationFailed;
      const detail = [
        m.changeError === undefined
          ? `${base} ${opened?.ok === true ? 'opened' : 'never opened'}: ${opened ? `${describe(opened.last)} after ${opened.ms} ms` : 'not observed'}; forged identity, no attestation: ${missing ? describe(missing) : 'not sent'}; forged identity, forged attestation: ${forgedOne ? describe(forgedOne) : 'not sent'}`
          : `the change failed: ${m.changeError}`,
        restorationText(m, 'closed again'),
      ].join('; ');
      return {
        got: `${opened?.last.status ?? 'none'} then ${statuses([missing, forgedOne].filter((e): e is Exchange => e !== undefined)) || 'none'} then ${m.restored?.last.status ?? (m.restored?.last.error === undefined ? 'none' : 'no answer')}`,
        pass,
        detail,
        restorationFailed: m.restorationFailed,
      };
    },
  },
  {
    id: 'deny-revoked',
    edge: 'EDGE-05',
    expect:
      "403 from the verifier for a freshly signed request with a revocation reason, AND independently read lifecycle evidence identifying revocation: for identity_inactive (the status check) the agent's status document reports REVOKED; for identity_invalid or lifecycle_not_established (the log check) its authenticated log history ends in a REVOCATION; never RETIRED in either, a timeout, an outage or another denial",
    modes: ['revoked'],
    async run(ctx) {
      const e = await signedGet(ctx);
      const at = new Date().toISOString();
      let evidence: LifecycleEvidence | undefined;
      if (isVerifierDenial(e, REVOCATION_REASONS)) {
        try {
          evidence = await ctx.lifecycle(ctx.signer.domain);
        } catch (error) {
          const now = new Date().toISOString();
          evidence = { status: { kind: 'unknown', reason: (error as Error).message, at: now }, log: { kind: 'unknown', reason: (error as Error).message, at: now } };
        }
      }
      const judged = judgeRevoked(e, evidence, servedToAgent(ctx, e));
      return { got: judged.got, pass: judged.pass, detail: `${describe(e)} at ${at}; ${judged.detail}` };
    },
  },
];

export const CASE_IDS: ReadonlySet<string> = new Set(CASES.map((c) => c.id));

/** The cases a mode runs, in order: everything that doesn't change the deployment first. */
export function casesFor(mode: Mode): LiveCase[] {
  const selected = CASES.filter((c) => c.modes.includes(mode));
  return [...selected.filter((c) => !c.mutates), ...selected.filter((c) => c.mutates)];
}

/**
 * The cases whose whole window must leave nothing in Demo Bank's own request log: EDGE-02's denials, and the verifier
 * outage (ADD-01), where nothing, signed or not, may reach Demo Bank. The log is required evidence: without it they fail.
 */
export const ORIGIN_QUIET_CASES: ReadonlySet<string> = new Set(['deny-unsigned', 'deny-malformed-signature', 'deny-tampered', 'deny-verifier-down']);

/**
 * The control for the origin log check, sent after every other case: one signed GET Demo Bank must serve. Its record
 * showing up in Demo Bank's log, within its own window, means the log has caught up past every earlier window.
 */
export async function originControl(ctx: Context): Promise<{ readonly ok: boolean; readonly started_at: string; readonly finished_at: string; readonly detail: string }> {
  const started_at = new Date().toISOString();
  const e = await signedGet(ctx);
  const finished_at = new Date().toISOString();
  return { ok: servedToAgent(ctx, e), started_at, finished_at, detail: describe(e) };
}
