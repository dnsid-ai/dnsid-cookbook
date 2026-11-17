// The live tests against a deployment (scripts/test-live.sh runs this). Reads DEPLOY_OUT, signs as DNSID_AGENT_ID with
// the key in DNSID_AGENT_KEY_FILE, runs the cases MODE selects (cases.ts), and writes LIVE_OUT/report.json:
//   {"cases": [{"id", "edge", "expect", "got", "pass", "detail", "ms"}], …}
//
//   MODE=live     every live case but deny-revoked (OTHER_AGENT_ID: a second real identity, for deny-other-identity)
//   MODE=allow    allow-trusted only
//   MODE=revoked  deny-revoked only: DNSID_AGENT_ID is an identity already revoked; this never revokes anything
//
// Exit codes: 0 every case passed; 1 a case failed (the report says which and what was seen); 2 an input is missing or
// invalid (no report); 4 a case changed the deployment and could not restore it (the report says so; tear down or
// redeploy); 130 interrupted (SIGINT or SIGTERM), with any change in progress restored and confirmed. The key is never
// printed.
//
// Changes to the deployment: before a case changes the deployment it records the change in LIVE_OUT/pending-restore.json
// (atomically), and removes it only once the restoration is confirmed (cases.ts: the change command stopped, the
// verifier's configuration reads back as restored, the edge behaves as before). On SIGINT or SIGTERM the run stops
// making and watching changes, still restores and confirms a change in progress, writes the report with the cases it
// didn't get to marked as not run, and exits; a second signal exits at once, leaving the record. A record left by an
// earlier run is restored, and confirmed in the verifier's configuration, before anything else (it needs the platform
// login); if that can't be done the run stops with exit 4. After a restoration fails or can't be confirmed, no further
// change is made.

import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { readDeployOut, pinOf, writeJsonAtomic, type DeployOut } from '../lib/deploy-out.ts';
import { CASE_IDS, casesFor, ORIGIN_QUIET_CASES, originControl, restoreChange, type Changes, type Clients, type Context, type Mode, type PendingChange } from './cases.ts';
import { connectCloud, DEFAULT_COMMAND_TIMEOUT_MS, KILL_GRACE_MS, type Cloud } from './cloud.ts';
import { grpcCall, h1, h2, plain } from './http.ts';
import { checkAgentId, createSigner, loadKeyProvider, SignerError } from './signer.ts';
import { readLifecycleEvidence, type LifecycleEvidence } from './status.ts';

export interface CaseResult {
  readonly id: string;
  readonly edge: string;
  readonly expect: string;
  readonly got: string;
  readonly pass: boolean;
  readonly detail: string;
  readonly ms: number;
  readonly started_at: string;
  readonly finished_at: string;
}

export interface Report {
  readonly mode: Mode;
  readonly deployment: string;
  readonly endpoint: string;
  readonly agent: string;
  readonly cloud_login: string;
  readonly started_at: string;
  readonly finished_at: string;
  readonly restoration_failed: boolean;
  /** The run was interrupted: cases it didn't get to are in `cases`, failed, as not run. */
  readonly interrupted: boolean;
  /** The signed request sent last, whose record in Demo Bank's log shows the log has caught up (MODE=live). */
  readonly origin_log_control?: { readonly ok: boolean; readonly started_at: string; readonly finished_at: string; readonly detail: string };
  readonly cases: CaseResult[];
}

export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputError';
  }
}

export interface RunOptions {
  readonly mode: Mode;
  readonly out: DeployOut;
  readonly agent: string;
  readonly keyFile: string;
  readonly otherAgent: string | undefined;
  readonly cloud: Cloud | undefined;
  readonly http?: Clients;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly settle?: { timeoutMs: number; intervalMs: number };
  readonly log?: (line: string) => void;
  /**
   * How long to wait for Cloud Logging to show records that should be there: Demo Bank's log showing the control request
   * before the denial windows are judged, and the verifier's records of served requests (LIVE_LOG_WAIT_S; 120 s).
   */
  readonly logWaitMs?: number;
  /**
   * A pause before each case whose window is checked in Demo Bank's log, and before each window of requests whose
   * verifier records are counted, so a previous request's record can't fall in it.
   */
  readonly quietGapMs?: number;
  /** Aborted to interrupt the run (main() aborts it on SIGINT and SIGTERM). */
  readonly interrupt?: AbortSignal;
  /** The longest one cloud command may take. */
  readonly cloudTimeoutMs?: number;
  /** How long an abandoned cloud command is given to stop before its outcome counts as unknown. */
  readonly settleGraceMs?: number;
  /** Where a change in progress is recorded (LIVE_OUT/pending-restore.json); kept in memory only when absent. */
  readonly recoveryFile?: string;
  /** Reads the agent's status document and log history (deny-revoked); the SDK's production reads when absent. */
  readonly lifecycle?: (domain: string) => Promise<LifecycleEvidence>;
}

export const RECOVERY_FILE = 'pending-restore.json';
export const DEFAULT_LOG_WAIT_MS = 120_000;

/** LIVE_LOG_WAIT_S: whole seconds from 1 to 1800; absent means the default. */
export function logWaitFromSetting(value: string | undefined): number {
  if (value === undefined || value === '') return DEFAULT_LOG_WAIT_MS;
  if (!/^[0-9]{1,4}$/.test(value) || Number(value) < 1 || Number(value) > 1800) throw new InputError('LIVE_LOG_WAIT_S must be a whole number of seconds from 1 to 1800');
  return Number(value) * 1000;
}
/** An abandoned gcloud is killed (SIGTERM, then SIGKILL after KILL_GRACE_MS); this leaves room for it to be gone. */
export const DEFAULT_SETTLE_GRACE_MS = KILL_GRACE_MS + 5_000;

/** The changes in progress, kept in a file so a later run (or a person) can finish restoring them. */
export class ChangeRecord implements Changes {
  readonly #file: string | undefined;
  #pending: PendingChange[];

  constructor(file: string | undefined) {
    this.#file = file;
    this.#pending = file === undefined ? [] : readPending(file);
  }

  get pending(): readonly PendingChange[] {
    return this.#pending;
  }

  begin(change: PendingChange): void {
    this.#write([...this.#pending.filter((p) => p.kind !== change.kind), change]);
  }

  end(change: PendingChange): void {
    this.#write(this.#pending.filter((p) => p.kind !== change.kind));
  }

  #write(next: PendingChange[]): void {
    if (this.#file !== undefined) {
      if (next.length === 0) rmSync(this.#file, { force: true });
      else writeJsonAtomic(this.#file, { note: 'changes the live tests made and had not restored; scripts/test-live.sh restores them first', pending: next });
    }
    this.#pending = next;
  }
}

function readPending(file: string): PendingChange[] {
  if (!existsSync(file)) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw new InputError(`${file} is not readable JSON: restore the deployment by hand (or tear it down), then remove the file`);
  }
  const pending = (parsed as { pending?: unknown }).pending;
  const valid = (p: unknown): p is PendingChange => {
    const c = p as Record<string, unknown>;
    return (
      (c?.['kind'] === 'governance' && typeof c['restore'] === 'string' && c['restore'] !== '') ||
      (c?.['kind'] === 'scaling' && c['restore'] === 'auto') ||
      (c?.['kind'] === 'log-evidence' && c['restore'] === 'default') ||
      (c?.['kind'] === 'origin-exposure' && c['restore'] === 'closed')
    );
  };
  if (!Array.isArray(pending) || !pending.every(valid)) {
    throw new InputError(`${file} does not list changes to restore: restore the deployment by hand (or tear it down), then remove the file`);
  }
  return pending;
}

export class RecoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RecoveryError';
  }
}

/** Restores what an earlier, interrupted or failed run left changed. Throws RecoveryError, keeping the record, when it can't. */
export async function restoreEarlierChanges(record: ChangeRecord, cloud: Cloud | undefined, timeoutMs: number, graceMs: number, log: (line: string) => void): Promise<void> {
  if (record.pending.length === 0) return;
  const what = record.pending.map((p) => `${p.kind} (back to ${p.restore})`).join(', ');
  if (cloud === undefined) throw new RecoveryError(`an earlier run left the deployment changed: ${what}; restoring it needs the platform login, and none is available`);
  for (const change of [...record.pending]) {
    try {
      await restoreChange(cloud, change, timeoutMs, graceMs);
    } catch (error) {
      throw new RecoveryError(`an earlier run left the deployment changed: ${what}; restoring ${change.kind} failed: ${(error as Error).message}`);
    }
    record.end(change);
    log(`restored what an earlier run left changed: ${change.kind}, back to ${change.restore} (confirmed in ${change.kind === 'origin-exposure' ? "Demo Bank's" : "the verifier's"} configuration)`);
  }
}

export function parseMode(value: string | undefined): Mode {
  if (value === undefined || value === '') return 'live';
  if (value === 'live' || value === 'allow' || value === 'revoked') return value;
  throw new InputError('MODE must be live, allow or revoked');
}

/** Runs the selected cases and returns the report. Only a case's own check can make it pass. */
export async function runLive(options: RunOptions): Promise<Report> {
  const log = options.log ?? ((line: string) => process.stdout.write(`${line}\n`));
  const startedAt = new Date().toISOString();
  const keyProvider = await loadKeyProvider(options.keyFile);
  const signer = await createSigner(options.agent, keyProvider);
  const url = new URL(options.out.endpoint);
  const record = new ChangeRecord(options.recoveryFile);
  const cloudTimeoutMs = options.cloudTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
  const interrupt = options.interrupt ?? new AbortController().signal;
  // A real pause that an interruption cuts short. The quiet gaps always use it; the settle waits use options.sleep if given.
  const pause = (ms: number) => delay(ms, undefined, { signal: interrupt }).catch(() => {});
  const sleepFor = options.sleep ?? pause;
  const settleGraceMs = options.settleGraceMs ?? DEFAULT_SETTLE_GRACE_MS;
  await restoreEarlierChanges(record, options.cloud, cloudTimeoutMs, settleGraceMs, log);
  const ctx: Context = {
    out: options.out,
    target: { host: url.hostname, port: url.port === '' ? 443 : Number(url.port), pin: pinOf(options.out) },
    signer,
    otherAgent: options.otherAgent,
    trusted: options.out.trusted_governance.split(',').map((g) => g.trim().toLowerCase()).filter((g) => g.length > 0),
    cloud: options.cloud,
    http: options.http ?? { h1, h2, plain, grpc: grpcCall },
    sleep: sleepFor,
    settle: options.settle ?? { timeoutMs: 300_000, intervalMs: 10_000 },
    logWaitMs: options.logWaitMs ?? DEFAULT_LOG_WAIT_MS,
    quietGap: () => pause(options.quietGapMs ?? 2_000),
    log,
    signal: interrupt,
    steadySleep: options.sleep ?? ((ms: number) => delay(ms)),
    cloudTimeoutMs,
    settleGraceMs,
    changes: record,
    lifecycle: options.lifecycle ?? ((domain) => readLifecycleEvidence(domain, options.out.trusted_governance)),
  };
  const results: CaseResult[] = [];
  let restorationFailed = false;
  const notRun = (liveCase: { id: string; edge: string; expect: string }, why: string): CaseResult => {
    const now = new Date().toISOString();
    return { id: liveCase.id, edge: liveCase.edge, expect: liveCase.expect, got: 'not run', pass: false, detail: why, ms: 0, started_at: now, finished_at: now };
  };
  for (const liveCase of casesFor(options.mode)) {
    if (interrupt.aborted) {
      results.push(notRun(liveCase, 'not run: the run was interrupted'));
      continue;
    }
    if (liveCase.mutates === true && restorationFailed) {
      results.push(notRun(liveCase, 'not run: an earlier change to the deployment could not be restored, so no further change is made'));
      continue;
    }
    if (options.mode === 'live' && ORIGIN_QUIET_CASES.has(liveCase.id)) await pause(options.quietGapMs ?? 2_000);
    const started = performance.now();
    const caseStartedAt = new Date().toISOString();
    let got = 'error';
    let pass = false;
    let detail: string;
    try {
      const verdict = await liveCase.run(ctx);
      got = verdict.got;
      pass = verdict.pass === true;
      detail = verdict.detail;
      if (verdict.restorationFailed === true) restorationFailed = true;
    } catch (error) {
      detail = `the case could not complete: ${error instanceof Error ? error.message : 'failed'}`;
    }
    const result: CaseResult = {
      id: liveCase.id,
      edge: liveCase.edge,
      expect: liveCase.expect,
      got,
      pass,
      detail,
      ms: Math.round(performance.now() - started),
      started_at: caseStartedAt,
      finished_at: new Date().toISOString(),
    };
    results.push(result);
    log(`${pass ? 'PASS' : 'FAIL'}  ${liveCase.id.padEnd(32)} ${liveCase.edge.padEnd(8)} got ${got}`);
    if (!pass) log(`      ${detail}`);
  }
  let control: Report['origin_log_control'];
  if (options.mode === 'live') {
    if (!interrupt.aborted && ctx.cloud !== undefined) {
      await pause(options.quietGapMs ?? 2_000);
      control = await originControl(ctx);
    }
    await checkOriginQuiet(ctx, results, control, options.logWaitMs ?? DEFAULT_LOG_WAIT_MS, log);
  }
  // Nothing the cases module doesn't define can be in the report, and nothing in it passes without a check.
  for (const r of results) if (!CASE_IDS.has(r.id)) throw new Error(`unknown case in the report: ${r.id}`);
  return {
    mode: options.mode,
    deployment: options.out.deployment,
    endpoint: options.out.endpoint,
    agent: options.agent,
    cloud_login: options.cloud?.login ?? 'none',
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    restoration_failed: restorationFailed || record.pending.length > 0,
    interrupted: interrupt.aborted,
    ...(control === undefined ? {} : { origin_log_control: control }),
    cases: results,
  };
}

/**
 * EDGE-02 and ADD-01 say Demo Bank is not invoked. That is shown by Demo Bank's own request log, read with the platform
 * login: required evidence, so without it (or with it unreadable) those cases fail. Each case's window is judged only
 * once the log shows the control, a signed request sent after every case, inside the control's own window: an earlier
 * record (another case's allowed request) doesn't show the log has caught up past the last window. A log that is slow
 * is waited for, up to `waitMs`; past that the windows prove nothing and the cases fail.
 */
async function checkOriginQuiet(ctx: Context, results: CaseResult[], control: Report['origin_log_control'], waitMs: number, log: (line: string) => void): Promise<void> {
  const windows = results.filter((r) => ORIGIN_QUIET_CASES.has(r.id) && r.got !== 'not run');
  const amend = (r: CaseResult, pass: boolean, note: string) => {
    const at = results.indexOf(r);
    results[at] = { ...r, pass: r.pass && pass, detail: `${r.detail}; ${note}` };
    if (r.pass && !pass) log(`FAIL  ${r.id.padEnd(32)} ${note}`);
  };
  if (ctx.cloud === undefined) {
    for (const r of windows) amend(r, false, "Demo Bank's request log not read (no platform login): the evidence that Demo Bank was not invoked is missing");
    return;
  }
  if (control === undefined || !control.ok) {
    const why = control === undefined ? 'the run was interrupted before the control request' : `the control request was not served (${control.detail})`;
    for (const r of windows) amend(r, false, `Demo Bank's request log can't be judged: ${why}`);
    return;
  }
  let seen = 0;
  const started = performance.now();
  try {
    for (;;) {
      seen = await ctx.cloud.originRequests(control.started_at, control.finished_at);
      if (seen > 0 || ctx.signal.aborted || performance.now() - started >= waitMs) break;
      await ctx.sleep(ctx.settle.intervalMs);
    }
    if (seen === 0) {
      for (const r of windows) amend(r, false, `Demo Bank's request log did not show the control request (${control.started_at} to ${control.finished_at}) within ${waitMs} ms, so its silence proves nothing`);
      return;
    }
    for (const r of windows) {
      const count = await ctx.cloud.originRequests(r.started_at, r.finished_at);
      amend(r, count === 0, `Demo Bank's request log: ${count} request(s) during this case (control seen after ${Math.round(performance.now() - started)} ms)`);
    }
  } catch (error) {
    for (const r of windows) amend(r, false, `Demo Bank's request log could not be read: ${(error as Error).message}`);
  }
}

async function main(): Promise<number> {
  const env = process.env;
  let mode: Mode;
  let out: DeployOut;
  let agent: string;
  let otherAgent: string | undefined;
  let logWaitMs: number;
  const liveOut = env['LIVE_OUT'];
  const keyFile = env['DNSID_AGENT_KEY_FILE'];
  try {
    mode = parseMode(env['MODE']);
    logWaitMs = logWaitFromSetting(env['LIVE_LOG_WAIT_S']);
    if (!env['DEPLOY_OUT']) throw new InputError('DEPLOY_OUT is required: the file scripts/deploy.sh wrote');
    if (!liveOut) throw new InputError('LIVE_OUT is required: the directory report.json is written to');
    if (!keyFile) throw new InputError("DNSID_AGENT_KEY_FILE is required: the agent's private key, as the portal exports it");
    agent = checkAgentId('DNSID_AGENT_ID', env['DNSID_AGENT_ID']);
    otherAgent = env['OTHER_AGENT_ID'] ? checkAgentId('OTHER_AGENT_ID', env['OTHER_AGENT_ID']) : undefined;
    if (otherAgent === agent) throw new InputError('OTHER_AGENT_ID must be a different identity from DNSID_AGENT_ID');
    out = readDeployOut(env['DEPLOY_OUT']);
    mkdirSync(liveOut, { recursive: true });
  } catch (error) {
    process.stderr.write(`error: ${(error as Error).message}\n`);
    return 2;
  }
  process.stdout.write(`Live tests, MODE=${mode}, against ${out.endpoint} (deployment ${out.deployment}), signing as ${agent}\n`);
  const recoveryFile = join(liveOut as string, RECOVERY_FILE);
  // A change an earlier run left unrestored is restored first, in any mode: that needs the login.
  const cloud = mode === 'live' || existsSync(recoveryFile) ? await connectCloud(out, env) : undefined;
  if (mode === 'live') {
    process.stdout.write(
      cloud === undefined
        ? "No platform login: deny-untrusted-governance, deny-verifier-down and verification-timing cannot run, and the cases that need Cloud Logging as evidence fail; the inventory recorded by deploy.sh is used.\n"
        : `Platform login: ${cloud.login}\n`,
    );
  }
  // The first SIGINT or SIGTERM interrupts: waits stop, a change in progress is restored and confirmed, the report is
  // written. A second one exits at once; the record of an unrestored change stays in LIVE_OUT for the next run.
  const interrupt = new AbortController();
  const onSignal = (signal: NodeJS.Signals) => {
    if (interrupt.signal.aborted) {
      process.stderr.write(`${signal} again: stopping now. Anything not restored is listed in ${recoveryFile}; the next run restores it first.\n`);
      cloud?.close();
      process.exit(existsSync(recoveryFile) ? 4 : 130);
    }
    process.stderr.write(`${signal}: stopping; restoring and confirming any change in progress first (send it again to stop at once)\n`);
    interrupt.abort();
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  let report: Report;
  try {
    report = await runLive({ mode, out, agent, keyFile: keyFile as string, otherAgent, cloud, interrupt: interrupt.signal, recoveryFile, logWaitMs });
  } catch (error) {
    if (error instanceof RecoveryError) {
      process.stderr.write(`error: ${error.message}. Recorded in ${recoveryFile}. Restore it with the platform login (run again), or tear the deployment down (scripts/teardown.sh).\n`);
      return 4;
    }
    process.stderr.write(`error: ${error instanceof SignerError || error instanceof InputError ? error.message : `the live tests could not run: ${(error as Error).message}`}\n`);
    return 2;
  } finally {
    cloud?.close();
  }
  writeJsonAtomic(join(liveOut as string, 'report.json'), report);
  const failed = report.cases.filter((c) => !c.pass);
  process.stdout.write(`\n${report.cases.length - failed.length}/${report.cases.length} passed; report: ${join(liveOut as string, 'report.json')}\n`);
  if (report.restoration_failed) {
    process.stderr.write(
      `A case changed the deployment and could not restore it, or could not confirm the restoration${existsSync(recoveryFile) ? ` (recorded in ${recoveryFile}; the next run restores it first)` : ''}: ` +
        'restore it, tear it down (scripts/teardown.sh) or deploy again.\n',
    );
    return 4;
  }
  if (report.interrupted) return 130;
  return failed.length === 0 ? 0 : 1;
}

if (import.meta.main) process.exitCode = await main();
