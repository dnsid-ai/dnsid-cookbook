// LOCAL MODE ONLY. The local mode's lifecycle, behind `make bootstrap`, `make run`, `make verify` and `make clean`:
//
//   node local/recipe.ts bootstrap   DNSid Local up in this mode's own state directory; alice.test issued; bob.test
//                                    issued, then revoked. Safe to run again.
//   node local/recipe.ts run         the local request path (local/stack.ts) started in the background, once DNSid
//                                    Local's settings check out; a running one is reused.
//   node local/recipe.ts verify      signed and unsigned requests through that path, each outcome checked, and Demo
//                                    Bank's own records checked for what reached it. Exit 1 on any miss.
//   node local/recipe.ts clean       the local request path stopped and this mode's DNSid Local removed
//                                    (`dnsid local reset --hard` on its own state directory). Safe after a partial
//                                    start or an interruption, and to run again.
//
// Everything this mode creates is under one directory outside the repository, DNSID_GCP_LOCAL_HOME (default
// `${XDG_STATE_HOME:-~/.local/state}/dnsid-gcp-service-extensions/local`), marked as this mode's by `owner.json`:
//   registry/   DNSid Local's state (`--state`): its compose project, CA, keys, zone files. The CLI derives the Docker
//               Compose project name from this path, so its containers, network and volumes are this mode's alone.
//   cli/        the CLI's config directory (DNSID_CONFIG_DIR) for this mode's agents.
//   run/        the request path's process id, ready.json (ports, certificates), its log and output.
//   progress.json  which bootstrap steps are done.
// Clean removes only that directory, the containers and volumes of that compose project and the process recorded in
// run/ (checked by its command line before it is signalled). It never touches the default DNSid Local state, another
// state directory, another process, or a directory it didn't mark. Private keys stay where the CLI writes them, under
// registry/ and cli/; nothing here reads, copies or prints them (the client loads its own agent's key through the SDK).
//
// Only these environment variables reach the CLI from yours: every DNSID_* variable is dropped except DNSID_LOCAL_IMAGE,
// DNSID_LOCAL_REGISTRY_PORT and DNSID_LOCAL_DNS_PORT, so another DNSid setup in your shell can't redirect this one. The
// HTTPS proxy keeps DNSid Local's default port (443): agents' key and status URLs name no port. DNSID_CLI and DOCKER
// choose the executables (default `dnsid` and `docker`).

import { spawn, type ChildProcess } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { Resolver } from 'node:dns/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Observation } from './client.ts';
import { LocalConfigError, LOCAL_VARIABLES, localSettingsFromEnvironment, type LocalSettings } from './settings.ts';
import { LOG_FILE, READY_FILE, type Ready } from './stack.ts';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const OWNER = 'dnsid-gcp-service-extensions local mode';
export const ZONE = 'test';
/** Allowed: signs and is verified. */
export const ALICE = 'alice.test';
/** Revoked by bootstrap: signs, and is refused. */
export const BOB = 'bob.test';
/**
 * The agents' upstream. Nothing listens there and nothing needs to: these agents only send requests, and DNSid Local
 * serves their key and status documents itself.
 */
export const AGENT_UPSTREAM = 'http://127.0.0.1:9';
const KEPT_DNSID_VARIABLES = new Set(['DNSID_LOCAL_IMAGE', 'DNSID_LOCAL_REGISTRY_PORT', 'DNSID_LOCAL_DNS_PORT']);

export interface Timeouts {
  /** `dnsid local up`: the first one pulls the registry image. */
  readonly up: number;
  readonly command: number;
  readonly preflight: number;
  /** DNSid Local's DNS answering for the issued identities. */
  readonly dns: number;
  /** The request path writing ready.json. */
  readonly ready: number;
  /** A stopped request path exiting before it is killed. */
  readonly stop: number;
  readonly killGrace: number;
}

export const DEFAULT_TIMEOUTS: Timeouts = Object.freeze({
  up: 300_000,
  command: 120_000,
  preflight: 20_000,
  dns: 30_000,
  ready: 30_000,
  stop: 10_000,
  killGrace: 5_000,
});

export interface Paths {
  readonly home: string;
  readonly owner: string;
  readonly registry: string;
  readonly cli: string;
  readonly run: string;
  readonly progress: string;
  readonly pid: string;
  readonly ready: string;
  readonly log: string;
  readonly output: string;
}

export function pathsFor(home: string): Paths {
  const run = join(home, 'run');
  return Object.freeze({
    home,
    owner: join(home, 'owner.json'),
    registry: join(home, 'registry'),
    cli: join(home, 'cli'),
    run,
    progress: join(home, 'progress.json'),
    pid: join(run, 'stack.pid'),
    ready: join(run, READY_FILE),
    log: join(run, LOG_FILE),
    output: join(run, 'stack.out'),
  });
}

export class RecipeError extends Error {
  readonly exitCode: number;
  constructor(message: string, exitCode = 1) {
    super(message);
    this.name = 'RecipeError';
    this.exitCode = exitCode;
  }
}

export class Interrupted extends RecipeError {
  constructor() {
    super('interrupted', 130);
    this.name = 'Interrupted';
  }
}

/** The git work tree this directory is in (the nearest ancestor with a `.git`), if any. */
export function enclosingRepository(dir: string): string | undefined {
  for (let at = resolve(dir); ; at = dirname(at)) {
    if (existsSync(join(at, '.git'))) return at;
    if (dirname(at) === at) return undefined;
  }
}

/**
 * DNSID_GCP_LOCAL_HOME, or the default; refused when it is inside this directory or the git work tree around it (state
 * never belongs in the tree).
 */
export function homeFrom(env: Readonly<Record<string, string | undefined>>, root = ROOT): string {
  const configured = env['DNSID_GCP_LOCAL_HOME']?.trim();
  const base = env['XDG_STATE_HOME']?.trim() || join(env['HOME']?.trim() || homedir(), '.local', 'state');
  const home = resolve(configured || join(base, 'dnsid-gcp-service-extensions', 'local'));
  const repository = enclosingRepository(root);
  for (const tree of repository === undefined ? [root] : [root, repository]) {
    const inside = relative(tree, home);
    if (inside === '' || (!inside.startsWith('..') && !isAbsolute(inside))) {
      throw new RecipeError('DNSID_GCP_LOCAL_HOME must be outside the repository: private keys and state live there', 2);
    }
  }
  return home;
}

/** What the CLI and the request path see of your environment: nothing DNSid-related but the three kept settings. */
export function cliEnvironment(env: Readonly<Record<string, string | undefined>>, paths: Paths): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (!name.startsWith('DNSID_') || KEPT_DNSID_VARIABLES.has(name)) out[name] = value;
  }
  out['DNSID_CONFIG_DIR'] = paths.cli;
  return out;
}

// ---------- commands ----------

export interface CommandResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** Killed at its time bound. */
  readonly timedOut: boolean;
  /** Killed because the recipe was interrupted. */
  readonly interrupted: boolean;
}

/** Runs a command with captured output, killed (SIGTERM, then SIGKILL) at `timeoutMs` or when `signal` aborts. */
export function runCommand(
  program: string,
  args: readonly string[],
  options: { env: Record<string, string>; timeoutMs: number; signal?: AbortSignal; killGraceMs: number; cwd?: string },
): Promise<CommandResult> {
  return new Promise((done) => {
    if (options.signal?.aborted) {
      done({ code: null, stdout: '', stderr: '', timedOut: false, interrupted: true });
      return;
    }
    const child = spawn(program, [...args], { env: options.env, cwd: options.cwd ?? ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let interrupted = false;
    let force: ReturnType<typeof setTimeout> | undefined;
    const kill = () => {
      child.kill('SIGTERM');
      force = setTimeout(() => child.kill('SIGKILL'), options.killGraceMs);
      force.unref();
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, options.timeoutMs);
    const onAbort = () => {
      interrupted = true;
      kill();
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    const finish = (code: number | null) => {
      clearTimeout(timer);
      if (force !== undefined) clearTimeout(force);
      options.signal?.removeEventListener('abort', onAbort);
      done({ code: timedOut || interrupted ? null : code, stdout, stderr, timedOut, interrupted });
    };
    child.on('error', () => {
      stderr += `${program} could not be run\n`;
      finish(127);
    });
    child.on('close', (code) => finish(code));
  });
}

export interface Context {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly paths: Paths;
  readonly cli: string;
  readonly docker: string;
  readonly node: string;
  readonly timeouts: Timeouts;
  /** Aborted on SIGINT or SIGTERM. */
  readonly signal: AbortSignal;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
}

export function contextFrom(
  env: Readonly<Record<string, string | undefined>>,
  signal: AbortSignal,
  io: { out: (line: string) => void; err: (line: string) => void },
  timeouts: Timeouts = DEFAULT_TIMEOUTS,
): Context {
  return {
    env,
    paths: pathsFor(homeFrom(env)),
    cli: env['DNSID_CLI']?.trim() || 'dnsid',
    docker: env['DOCKER']?.trim() || 'docker',
    node: process.execPath,
    timeouts,
    signal,
    ...io,
  };
}

/**
 * Lines of command output fit to show: at most `lines` of the end, without any line that could carry a credential or
 * key material. Diagnostics only; nothing is judged from them.
 */
export function safeTail(text: string, lines = 20): string[] {
  const unsafe = /(api[_-]?key|token|secret|password|private|BEGIN [A-Z ]*KEY|"d"\s*:|authorization)/i;
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => (unsafe.test(line) ? '[line withheld: it may carry a credential]' : line.slice(0, 300)))
    .slice(-lines);
}

async function cli(ctx: Context, label: string, args: readonly string[], timeoutMs = ctx.timeouts.command, signal: AbortSignal | undefined = ctx.signal): Promise<CommandResult> {
  const result = await runCommand(ctx.cli, args, { env: cliEnvironment(ctx.env, ctx.paths), timeoutMs, signal, killGraceMs: ctx.timeouts.killGrace });
  if (result.interrupted) throw new Interrupted();
  if (result.code !== 0) {
    const why = result.timedOut ? `timed out after ${Math.round(timeoutMs / 1000)} s` : result.code === 127 ? `\`${ctx.cli}\` could not be run` : `exit ${result.code}`;
    ctx.err(`${label} failed (${why}). Its output (credential-like lines withheld):`);
    for (const line of safeTail(`${result.stdout}\n${result.stderr}`)) ctx.err(`  ${line}`);
    await registryDiagnostics(ctx);
    throw new RecipeError(`${label} failed`);
  }
  return result;
}

/** This mode's DNSid Local containers and their recent logs (credential-like lines withheld), for a failure report. */
export async function registryDiagnostics(ctx: Context): Promise<void> {
  const env = cliEnvironment(ctx.env, ctx.paths);
  const filter = `label=com.docker.compose.project.working_dir=${ctx.paths.registry}`;
  const bound = { env, timeoutMs: ctx.timeouts.preflight, killGraceMs: ctx.timeouts.killGrace };
  const ps = await runCommand(ctx.docker, ['ps', '-a', '--filter', filter, '--format', '{{.ID}} {{.Names}} {{.Status}}'], bound);
  if (ps.code !== 0) {
    ctx.err('--- DNSid Local containers: `docker ps` failed (is Docker running?)');
    return;
  }
  const rows = ps.stdout.split('\n').filter((row) => row.trim() !== '');
  ctx.err(`--- DNSid Local containers of this mode (${rows.length}):`);
  for (const row of rows) {
    ctx.err(`  ${row}`);
    const id = row.split(' ')[0] as string;
    const logs = await runCommand(ctx.docker, ['logs', '--tail', '30', id], bound);
    for (const line of safeTail(`${logs.stdout}\n${logs.stderr}`, 30)) ctx.err(`    ${line}`);
  }
}

// ---------- the mode's directory ----------

/** Creates the home (private) with its owner mark, or checks an existing one is this mode's. */
export function claimHome(paths: Paths): void {
  if (existsSync(paths.home)) {
    if (!isOwned(paths)) {
      if (readdirSync(paths.home).length > 0) {
        throw new RecipeError(`${paths.home} exists and was not created by this local mode; choose another DNSID_GCP_LOCAL_HOME`, 2);
      }
    } else return;
  }
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  writeFileSync(paths.owner, `${JSON.stringify({ owner: OWNER, createdAt: new Date().toISOString() })}\n`, { mode: 0o600 });
}

export function isOwned(paths: Paths): boolean {
  try {
    return (JSON.parse(readFileSync(paths.owner, 'utf8')) as { owner?: unknown }).owner === OWNER;
  } catch {
    return false;
  }
}

export interface Progress {
  issued?: string[];
  revoked?: string[];
}

export function readProgress(paths: Paths): Progress {
  try {
    return JSON.parse(readFileSync(paths.progress, 'utf8')) as Progress;
  } catch {
    return {};
  }
}

function writeProgress(paths: Paths, progress: Progress): void {
  writeFileSync(`${paths.progress}.tmp`, `${JSON.stringify(progress)}\n`, { mode: 0o600 });
  renameSync(`${paths.progress}.tmp`, paths.progress);
}

function checkInterrupted(ctx: Context): void {
  if (ctx.signal.aborted) throw new Interrupted();
}

// ---------- DNSid Local's settings ----------

/** `dnsid local env --format json` for this mode's state: only the five settings the verifier reads, validated. */
export async function localEnvironment(ctx: Context): Promise<{ variables: Record<string, string>; settings: LocalSettings }> {
  const result = await cli(ctx, 'Reading DNSid Local settings (dnsid local env)', ['local', 'env', '--state', ctx.paths.registry, '--format', 'json']);
  let all: unknown;
  try {
    all = JSON.parse(result.stdout);
  } catch {
    throw new RecipeError('dnsid local env did not print a JSON object');
  }
  if (typeof all !== 'object' || all === null || Array.isArray(all)) throw new RecipeError('dnsid local env did not print a JSON object');
  const variables: Record<string, string> = {};
  for (const name of LOCAL_VARIABLES) {
    const value = (all as Record<string, unknown>)[name];
    if (typeof value === 'string') variables[name] = value;
  }
  try {
    return { variables, settings: localSettingsFromEnvironment(variables) };
  } catch (error) {
    throw new RecipeError(`DNSid Local's settings are not usable: ${error instanceof LocalConfigError ? error.message : 'invalid'}`);
  }
}

/** Waits until DNSid Local's DNS answers `_dnsid.<fqdn>` with a TXT record, for each identity. */
export async function waitForRecords(ctx: Context, dnsServer: string, domains: readonly string[]): Promise<void> {
  const resolver = new Resolver({ timeout: 1_000, tries: 1 });
  resolver.setServers([dnsServer]);
  const deadline = performance.now() + ctx.timeouts.dns;
  for (const domain of domains) {
    for (;;) {
      checkInterrupted(ctx);
      try {
        if ((await resolver.resolveTxt(`_dnsid.${domain}`)).length > 0) break;
      } catch {
        // Not published yet: DNSid Local's DNS reloads its zone files a moment after issuance.
      }
      if (performance.now() >= deadline) {
        await registryDiagnostics(ctx);
        throw new RecipeError(`DNSid Local's DNS did not publish _dnsid.${domain} within ${Math.round(ctx.timeouts.dns / 1000)} s`);
      }
      await new Promise((r) => setTimeout(r, 250));
    }
  }
}

// ---------- bootstrap ----------

async function preflight(ctx: Context): Promise<void> {
  const env = cliEnvironment(ctx.env, ctx.paths);
  const bound = { env, timeoutMs: ctx.timeouts.preflight, signal: ctx.signal, killGraceMs: ctx.timeouts.killGrace };
  const version = await runCommand(ctx.cli, ['--version'], bound);
  if (version.interrupted) throw new Interrupted();
  if (version.code !== 0) {
    throw new RecipeError(`the dnsid CLI (\`${ctx.cli}\`) could not be run: install it (brew install dnsid-ai/tap/dnsid, or https://docs.dnsid.ai/cli-installation) or set DNSID_CLI`);
  }
  ctx.out(`dnsid CLI: ${version.stdout.trim().split('\n')[0] ?? ''}`);
  const docker = await runCommand(ctx.docker, ['info', '--format', '{{.ServerVersion}}'], bound);
  if (docker.interrupted) throw new Interrupted();
  if (docker.code !== 0) throw new RecipeError('Docker is not running or not reachable (`docker info` failed): DNSid Local runs in Docker');
}

export async function bootstrap(ctx: Context): Promise<void> {
  claimHome(ctx.paths);
  await preflight(ctx);
  mkdirSync(ctx.paths.cli, { recursive: true, mode: 0o700 });
  // DNSid Local's containers read this directory as another user (CoreDNS must traverse it); its parent stays private.
  mkdirSync(ctx.paths.registry, { recursive: true, mode: 0o755 });
  ctx.out(`==> DNSid Local up (state ${ctx.paths.registry})`);
  await cli(ctx, 'Starting DNSid Local (dnsid local up)', ['local', 'up', '--zone', ZONE, '--state', ctx.paths.registry], ctx.timeouts.up);
  const progress = readProgress(ctx.paths);
  const revoked = new Set(progress.revoked ?? []);
  const issued = new Set(progress.issued ?? []);
  for (const domain of [ALICE, BOB]) {
    checkInterrupted(ctx);
    if (revoked.has(domain)) {
      ctx.out(`==> ${domain}: already issued and revoked`);
      continue;
    }
    ctx.out(`==> ${domain}: registered and issued (dnsid local agent ensure … -- dnsid log issue)`);
    await cli(ctx, `Issuing ${domain}`, [
      'local', 'agent', 'ensure', '--state', ctx.paths.registry, '--upstream', AGENT_UPSTREAM, domain,
      '--', ctx.cli, 'log', 'issue', '--domain', domain,
    ]);
    issued.add(domain);
    writeProgress(ctx.paths, { issued: [...issued], revoked: [...revoked] });
  }
  const { settings } = await localEnvironment(ctx);
  await waitForRecords(ctx, settings.dnsServer, [ALICE, BOB].filter((domain) => !revoked.has(domain)));
  if (!revoked.has(BOB)) {
    checkInterrupted(ctx);
    ctx.out(`==> ${BOB}: revoked (dnsid revoke --reason owner_request)`);
    await cli(ctx, `Revoking ${BOB}`, [
      'local', 'agent', 'ensure', '--state', ctx.paths.registry, '--upstream', AGENT_UPSTREAM, BOB,
      '--', ctx.cli, 'revoke', '--domain', BOB, '--reason', 'owner_request', '--yes',
    ]);
    revoked.add(BOB);
    writeProgress(ctx.paths, { issued: [...issued], revoked: [...revoked] });
  }
  ctx.out(`bootstrap: done. ${ALICE} is ACTIVE, ${BOB} is REVOKED, governance ${settings.governance.entries[0]?.governanceId ?? ''}.`);
}

export function bootstrapped(paths: Paths): boolean {
  const progress = readProgress(paths);
  return isOwned(paths) && (progress.issued ?? []).includes(ALICE) && (progress.revoked ?? []).includes(BOB);
}

// ---------- run ----------

interface PidRecord {
  readonly pid: number;
  readonly startedAt: string;
}

function readPid(paths: Paths): PidRecord | undefined {
  try {
    const record = JSON.parse(readFileSync(paths.pid, 'utf8')) as PidRecord;
    return Number.isInteger(record.pid) && record.pid > 1 ? record : undefined;
  } catch {
    return undefined;
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * Whether `pid` is this mode's request path: alive, and its command line is `node …local/stack.ts <this run dir>`. A
 * recorded process id that now belongs to anything else is never signalled.
 */
export async function isOurStack(ctx: Context, pid: number): Promise<boolean> {
  if (!alive(pid)) return false;
  let args: string;
  try {
    args = readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').join(' ');
  } catch {
    const ps = await runCommand('ps', ['-o', 'args=', '-p', String(pid)], { env: { PATH: process.env['PATH'] ?? '' }, timeoutMs: 5_000, killGraceMs: 1_000 });
    if (ps.code !== 0) return false;
    args = ps.stdout.trim();
  }
  return args.includes(join(ROOT, 'local', 'stack.ts')) && args.includes(ctx.paths.run);
}

export function readReadyFile(paths: Paths): Ready | undefined {
  try {
    return JSON.parse(readFileSync(paths.ready, 'utf8')) as Ready;
  } catch {
    return undefined;
  }
}

/** The running request path's ready state, when the recorded process is ours and has written ready.json. */
export async function runningStack(ctx: Context): Promise<Ready | undefined> {
  const record = readPid(ctx.paths);
  if (record === undefined || !(await isOurStack(ctx, record.pid))) return undefined;
  const ready = readReadyFile(ctx.paths);
  return ready?.pid === record.pid ? ready : undefined;
}

/** Stops the recorded request path if it is ours (SIGTERM, then SIGKILL past the bound) and clears its run files. */
export async function stopStack(ctx: Context): Promise<'stopped' | 'not running' | 'not ours'> {
  const record = readPid(ctx.paths);
  let outcome: 'stopped' | 'not running' | 'not ours' = 'not running';
  if (record !== undefined && alive(record.pid)) {
    if (!(await isOurStack(ctx, record.pid))) {
      outcome = 'not ours';
    } else {
      process.kill(record.pid, 'SIGTERM');
      const deadline = performance.now() + ctx.timeouts.stop;
      while (alive(record.pid) && performance.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      if (alive(record.pid)) {
        process.kill(record.pid, 'SIGKILL');
        const killDeadline = performance.now() + ctx.timeouts.killGrace;
        while (alive(record.pid) && performance.now() < killDeadline) await new Promise((r) => setTimeout(r, 50));
      }
      if (alive(record.pid)) throw new RecipeError(`the local request path (process ${record.pid}) did not stop`);
      outcome = 'stopped';
    }
  }
  rmSync(ctx.paths.pid, { force: true });
  rmSync(ctx.paths.ready, { force: true });
  rmSync(`${ctx.paths.ready}.tmp`, { force: true });
  return outcome;
}

function startStackProcess(ctx: Context, variables: Record<string, string>): ChildProcess {
  const env = cliEnvironment(ctx.env, ctx.paths);
  delete env['DNSID_CONFIG_DIR'];
  const output = openSync(ctx.paths.output, 'a', 0o600);
  try {
    const child = spawn(ctx.node, [join(ROOT, 'local', 'stack.ts'), ctx.paths.run], {
      env: { ...env, ...variables },
      cwd: ROOT,
      detached: true,
      stdio: ['ignore', output, output],
    });
    child.unref();
    return child;
  } finally {
    closeSync(output);
  }
}

function printEndpoints(ctx: Context, ready: Ready): void {
  ctx.out(`local request path: running (process ${ready.pid})`);
  ctx.out(`  edge (trusts ${ready.governanceId}):   https://${ready.host}:${ready.edges.trusted.port}/accounts`);
  ctx.out(`  edge (trusts only a governance no identity uses): https://${ready.host}:${ready.edges.untrusted.port}/accounts`);
  ctx.out(`  Demo Bank (behind the edges, loopback): http://${ready.host}:${ready.originPort}/accounts`);
  ctx.out(`  records: ${ctx.paths.log}`);
  ctx.out(`try: make verify    (or an unsigned request: node local/client.ts ${ctx.paths.run} unsigned)`);
}

export async function run(ctx: Context): Promise<Ready> {
  if (!bootstrapped(ctx.paths)) throw new RecipeError('the local mode is not bootstrapped: run `make bootstrap` first');
  const running = await runningStack(ctx);
  if (running !== undefined) {
    printEndpoints(ctx, running);
    return running;
  }
  // Whatever an earlier run left (a dead or replaced process, a stale ready.json) goes first.
  if ((await stopStack(ctx)) === 'not ours') ctx.err('note: the recorded process id now belongs to another process; it was left alone');
  mkdirSync(ctx.paths.run, { recursive: true, mode: 0o700 });
  const { variables } = await localEnvironment(ctx);
  checkInterrupted(ctx);
  const child = startStackProcess(ctx, variables);
  if (child.pid === undefined) throw new RecipeError('the local request path could not be started');
  writeFileSync(ctx.paths.pid, `${JSON.stringify({ pid: child.pid, startedAt: new Date().toISOString() })}\n`, { mode: 0o600 });
  let exited: number | null | undefined;
  child.on('exit', (code) => (exited = code ?? -1));
  const deadline = performance.now() + ctx.timeouts.ready;
  try {
    for (;;) {
      checkInterrupted(ctx);
      const ready = readReadyFile(ctx.paths);
      if (ready?.pid === child.pid) {
        printEndpoints(ctx, ready);
        return ready;
      }
      if (exited !== undefined) throw new RecipeError(`the local request path exited during startup (exit ${exited})`);
      if (performance.now() >= deadline) throw new RecipeError(`the local request path was not ready within ${Math.round(ctx.timeouts.ready / 1000)} s`);
      await new Promise((r) => setTimeout(r, 100));
    }
  } catch (error) {
    ctx.err('local request path output:');
    try {
      for (const line of safeTail(readFileSync(ctx.paths.output, 'utf8'))) ctx.err(`  ${line}`);
    } catch {
      ctx.err('  (none)');
    }
    await stopStack(ctx);
    throw error;
  }
}

// ---------- verify ----------

export interface Check {
  readonly name: string;
  readonly pass: boolean;
  readonly detail: string;
}

interface OriginRecord {
  readonly component: string;
  readonly event?: string;
  readonly outcome?: string;
  readonly verifiedDomain?: string;
  readonly governanceId?: string;
}

function originRecords(paths: Paths): OriginRecord[] {
  let text = '';
  try {
    text = readFileSync(paths.log, 'utf8');
  } catch {
    return [];
  }
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => {
      try {
        return JSON.parse(line) as OriginRecord;
      } catch {
        return { component: 'unreadable' };
      }
    })
    .filter((record) => record.component === 'origin');
}

/** Runs local/client.ts, as an agent through the CLI or directly for `unsigned`, and parses its observations. */
async function observe(ctx: Context, domain: string | undefined, cases: readonly string[]): Promise<Observation[]> {
  const client = [ctx.node, join(ROOT, 'local', 'client.ts'), ctx.paths.run, ...cases];
  const label = domain === undefined ? 'The unsigned request' : `Requests signed as ${domain}`;
  const result =
    domain === undefined
      ? await runCommand(client[0] as string, client.slice(1), {
          env: cliEnvironment(ctx.env, ctx.paths),
          timeoutMs: ctx.timeouts.command,
          signal: ctx.signal,
          killGraceMs: ctx.timeouts.killGrace,
        })
      : await cli(ctx, label, ['local', 'agent', 'ensure', '--state', ctx.paths.registry, '--upstream', AGENT_UPSTREAM, domain, '--', ...client]);
  if (result.interrupted) throw new Interrupted();
  if (result.code !== 0) {
    for (const line of safeTail(result.stderr)) ctx.err(`  ${line}`);
    throw new RecipeError(`${label} could not be sent`);
  }
  return result.stdout
    .split('\n')
    .filter((line) => line.trim().startsWith('{'))
    .map((line) => JSON.parse(line) as Observation);
}

function bank(observation: Observation | undefined): { bank?: unknown; synthetic?: unknown; caller?: { verifiedDomain?: unknown; governanceId?: unknown } } | undefined {
  if (observation?.status !== 200 || observation.cacheControl !== 'no-store') return undefined;
  try {
    return JSON.parse(observation.body) as ReturnType<typeof bank>;
  } catch {
    return undefined;
  }
}

function denial(observation: Observation | undefined, reasons: readonly string[]): boolean {
  return observation?.status === 403 && observation.cacheControl === 'no-store' && reasons.includes(observation.body);
}

function shown(observation: Observation | undefined): string {
  if (observation === undefined) return 'no observation';
  if (observation.error !== null) return `no HTTP answer (${observation.error})`;
  return `HTTP ${observation.status}${observation.body === '' ? '' : `: ${observation.body.slice(0, 120)}`}`;
}

/** The judgments, from the observations and Demo Bank's records before and after each identity's requests. */
export function judge(
  governanceId: string,
  observations: { unsigned: Observation[]; alice: Observation[]; bob: Observation[] },
  reached: { unsigned: OriginRecord[]; alice: OriginRecord[]; bob: OriginRecord[] },
): Check[] {
  const find = (list: Observation[], name: string) => list.find((o) => o.case === name);
  const unsigned = find(observations.unsigned, 'unsigned');
  const get = find(observations.alice, 'signed-get');
  const head = find(observations.alice, 'signed-head');
  const tampered = find(observations.alice, 'tampered');
  const forged = find(observations.alice, 'forged-headers');
  const untrusted = find(observations.alice, 'untrusted-governance');
  const revoked = find(observations.bob, 'signed-get');
  const getBank = bank(get);
  const forgedBank = bank(forged);
  const served = reached.alice.filter((r) => r.outcome === 'served');
  return [
    { name: 'unsigned request refused (signature_missing)', pass: denial(unsigned, ['signature_missing']), detail: shown(unsigned) },
    {
      name: `${ALICE} signed GET allowed: Demo Bank's synthetic data, for ${ALICE} under ${governanceId}`,
      pass: getBank?.bank === 'Demo Bank' && getBank.synthetic === true && getBank.caller?.verifiedDomain === ALICE && getBank.caller.governanceId === governanceId,
      detail: shown(get),
    },
    { name: `${ALICE} signed HEAD allowed`, pass: head?.status === 200 && head.body === '', detail: shown(head) },
    { name: 'tampered request refused (signature_invalid)', pass: denial(tampered, ['signature_invalid']), detail: shown(tampered) },
    {
      name: 'forged x-dnsid-* headers replaced: Demo Bank saw the verified identity',
      pass: forgedBank?.caller?.verifiedDomain === ALICE && forgedBank.caller.governanceId === governanceId,
      detail: shown(forged),
    },
    { name: 'untrusted governance refused (governance_not_trusted)', pass: denial(untrusted, ['governance_not_trusted']), detail: shown(untrusted) },
    {
      // DNSid Local's `revoke` changes both the status document and the log. Whichever the verifier reads first refuses
      // it: the identity stage's own log read (SDK 0.37.0 treats a REVOKED history as invalid evidence:
      // identity_invalid), the status document (identity_inactive), or the lifecycle stage (lifecycle_not_established).
      // bob.test is issued exactly as alice.test, which must be allowed, so none of these is a malformed record.
      name: `revoked ${BOB} refused (identity_inactive, identity_invalid or lifecycle_not_established)`,
      pass: denial(revoked, ['identity_inactive', 'identity_invalid', 'lifecycle_not_established']),
      detail: shown(revoked),
    },
    {
      name: 'Demo Bank served exactly the three allowed requests, each for the verified identity',
      pass:
        reached.alice.length === 3 &&
        served.length === 3 &&
        served.every((r) => r.verifiedDomain === ALICE && r.governanceId === governanceId),
      detail: `${reached.alice.length} record(s) during ${ALICE}'s requests: ${reached.alice.map((r) => `${r.outcome ?? '?'}/${r.verifiedDomain ?? '-'}`).join(', ') || 'none'}`,
    },
    {
      name: 'nothing refused reached Demo Bank',
      pass: reached.unsigned.length === 0 && reached.bob.length === 0,
      detail: `${reached.unsigned.length} record(s) during the unsigned request, ${reached.bob.length} during ${BOB}'s`,
    },
  ];
}

export async function verify(ctx: Context): Promise<Check[]> {
  const ready = await runningStack(ctx);
  if (ready === undefined) throw new RecipeError('the local request path is not running: run `make run` first');
  const { settings } = await localEnvironment(ctx);
  const governanceId = settings.governance.entries[0]?.governanceId ?? '';
  const window = async (domain: string | undefined, cases: readonly string[]) => {
    const before = originRecords(ctx.paths).length;
    const observed = await observe(ctx, domain, cases);
    // Demo Bank writes its record before its response completes, so every record of these requests is in by now.
    return { observed, reached: originRecords(ctx.paths).slice(before) };
  };
  ctx.out(`==> unsigned request`);
  const unsigned = await window(undefined, ['unsigned']);
  ctx.out(`==> as ${ALICE}`);
  const alice = await window(ALICE, ['signed-get', 'signed-head', 'tampered', 'forged-headers', 'untrusted-governance']);
  ctx.out(`==> as ${BOB} (revoked)`);
  const bob = await window(BOB, ['signed-get']);
  const checks = judge(
    governanceId,
    { unsigned: unsigned.observed, alice: alice.observed, bob: bob.observed },
    { unsigned: unsigned.reached, alice: alice.reached, bob: bob.reached },
  );
  for (const check of checks) ctx.out(`${check.pass ? '✓' : '✗'} ${check.name}${check.pass ? '' : `\n    got: ${check.detail}`}`);
  if (checks.every((check) => check.pass)) {
    ctx.out('✓ verify passed (DNSid Local and a local forwarding harness; this says nothing about Google\'s load balancer)');
  } else {
    ctx.err(`local request path records: ${ctx.paths.log}`);
    await registryDiagnostics(ctx);
    throw new RecipeError('verify failed');
  }
  return checks;
}

// ---------- clean ----------

export async function clean(ctx: Context): Promise<void> {
  const { paths } = ctx;
  if (!existsSync(paths.home)) {
    ctx.out(`clean: nothing to remove (${paths.home} does not exist)`);
    return;
  }
  if (!isOwned(paths)) throw new RecipeError(`clean: ${paths.home} was not created by this local mode; nothing removed`, 2);
  // Interruptions don't cut a clean short: each step is bounded on its own.
  const stopped = await stopStack(ctx);
  ctx.out(`clean: local request path ${stopped === 'not ours' ? 'not stopped (the recorded process id belongs to another process)' : stopped}`);
  if (existsSync(join(paths.registry, 'compose.yml'))) {
    await cli(ctx, 'Removing DNSid Local (dnsid local reset --hard)', ['local', 'reset', '--hard', '--state', paths.registry], ctx.timeouts.command, undefined);
    ctx.out(`clean: DNSid Local removed (containers, network and volumes of ${paths.registry})`);
  } else {
    ctx.out('clean: DNSid Local was never started here');
  }
  rmSync(paths.home, { recursive: true, force: true });
  ctx.out(`clean: removed ${paths.home}`);
}

// ---------- the executable ----------

export async function main(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): Promise<number> {
  const controller = new AbortController();
  let signals = 0;
  const onSignal = () => {
    signals += 1;
    if (signals > 1) process.exit(130);
    controller.abort();
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  const io = { out: (line: string) => void process.stdout.write(`${line}\n`), err: (line: string) => void process.stderr.write(`${line}\n`) };
  try {
    const ctx = contextFrom(env, controller.signal, io);
    switch (argv[0]) {
      case 'bootstrap':
        await bootstrap(ctx);
        break;
      case 'run':
        await run(ctx);
        break;
      case 'verify':
        await verify(ctx);
        break;
      case 'clean':
        await clean(ctx);
        break;
      default:
        throw new RecipeError('usage: node local/recipe.ts bootstrap|run|verify|clean', 2);
    }
    return 0;
  } catch (error) {
    if (error instanceof Interrupted) {
      io.err(`interrupted: run the same target again to resume, or \`make clean\` to remove everything this mode made`);
      return 130;
    }
    io.err(`${argv[0] ?? 'recipe'}: ${error instanceof RecipeError ? error.message : 'failed unexpectedly'}`);
    return error instanceof RecipeError ? error.exitCode : 1;
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2), process.env);
