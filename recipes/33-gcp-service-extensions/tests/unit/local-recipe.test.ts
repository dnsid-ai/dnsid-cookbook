// The local mode's lifecycle (local/recipe.ts: `make bootstrap`, `run`, `verify`, `clean`) against SIMULATED `dnsid`
// and `docker` commands (tests/support/fake-dnsid.ts) and a DNSID LOCAL LOOK-ALIKE (tests/support/dnsid-local-lookalike.ts:
// real DNS and HTTPS on loopback serving offline test identities, NOT DNSid Local). The request path it starts is the
// real one (local/stack.ts as its own process, the production verifier with the DNSid Local backend over the SDK's real
// Node transport), so `verify` judges real answers. What this cannot show: the real CLI's issuance and revocation,
// DNSid Local's containers, and anything about Google's load balancer.
//
// Also here: startup failures and their diagnostics, interruption, repeated cleanup, that nothing this mode doesn't own
// is touched, and that local trust can't reach the production entry point or image.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { describe, test, type TestContext } from 'node:test';

import {
  ALICE,
  BOB,
  bootstrap,
  clean,
  cliEnvironment,
  contextFrom,
  enclosingRepository,
  homeFrom,
  Interrupted,
  pathsFor,
  readProgress,
  RecipeError,
  ROOT,
  run,
  safeTail,
  verify,
  type Context,
  type Timeouts,
} from '../../local/recipe.ts';
import { dnsidLocalLookalike, type Lookalike } from '../support/dnsid-local-lookalike.ts';
import { fakeDnsid, hangingPid, type FakeDnsid } from '../support/fake-dnsid.ts';

const FAST: Timeouts = Object.freeze({ up: 5_000, command: 20_000, preflight: 5_000, dns: 5_000, ready: 20_000, stop: 5_000, killGrace: 1_000 });

interface Harness {
  readonly fake: FakeDnsid;
  readonly home: string;
  readonly out: string[];
  readonly err: string[];
  readonly controller: AbortController;
  ctx(extra?: Record<string, string>, timeouts?: Timeouts): Context;
}

function harness(t: TestContext, agentDir?: string): Harness {
  const fake = fakeDnsid(t, agentDir);
  const parent = mkdtempSync(join(tmpdir(), 'local-mode-'));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const home = join(parent, 'home');
  const out: string[] = [];
  const err: string[] = [];
  const controller = new AbortController();
  return {
    fake,
    home,
    out,
    err,
    controller,
    ctx(extra = {}, timeouts = FAST) {
      const env = { PATH: process.env['PATH'] ?? '', HOME: parent, DNSID_GCP_LOCAL_HOME: home, ...fake.env, ...extra };
      return contextFrom(env, controller.signal, { out: (l) => void out.push(l), err: (l) => void err.push(l) }, timeouts);
    },
  };
}

/** The recipe's own `dnsid` calls; the commands the simulated `local agent ensure` runs as an agent (with its DNSID_DOMAIN) are left out. */
const dnsidCalls = (fake: FakeDnsid) => fake.calls().filter((c) => c.tool === 'dnsid' && c.env?.['DNSID_DOMAIN'] === undefined);
const agentCommands = (fake: FakeDnsid) => fake.calls().filter((c) => c.tool === 'dnsid' && c.env?.['DNSID_DOMAIN'] !== undefined);
const verbs = (fake: FakeDnsid) => dnsidCalls(fake).map((c) => (c.args[0] === 'local' ? `local ${c.args[1]}` : c.args[0]));

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function until(what: () => boolean, ms = 5_000): Promise<void> {
  const deadline = performance.now() + ms;
  while (!what()) {
    if (performance.now() > deadline) throw new Error('condition not reached in time');
    await new Promise((r) => setTimeout(r, 20));
  }
}

async function rejectsWith(promise: Promise<unknown>, pattern: RegExp, code = 1): Promise<RecipeError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof RecipeError, String(error));
    assert.match(error.message, pattern);
    assert.equal(error.exitCode, code);
    return error;
  }
  assert.fail('expected a RecipeError');
}

describe('the local mode\'s directory and environment', () => {
  test('state lives outside the repository: the default is under XDG_STATE_HOME or ~/.local/state, and a home in the tree is refused', () => {
    assert.equal(homeFrom({ HOME: '/h' }), '/h/.local/state/dnsid-gcp-service-extensions/local');
    assert.equal(homeFrom({ HOME: '/h', XDG_STATE_HOME: '/x' }), '/x/dnsid-gcp-service-extensions/local');
    assert.equal(homeFrom({ DNSID_GCP_LOCAL_HOME: '/elsewhere/l' }), '/elsewhere/l');
    for (const inside of [ROOT, join(ROOT, 'local', 'state')]) {
      assert.throws(() => homeFrom({ DNSID_GCP_LOCAL_HOME: inside }), (e: RecipeError) => e.exitCode === 2 && /outside the repository/.test(e.message));
    }
  });

  test('inside a git work tree, the whole tree is refused too; outside one, only this directory', () => {
    const parent = mkdtempSync(join(tmpdir(), 'local-mode-tree-'));
    try {
      const recipe = join(parent, 'recipes', 'recipe');
      mkdirSync(recipe, { recursive: true });
      // No .git anywhere above (a temporary directory): only the recipe directory itself is refused.
      assert.equal(enclosingRepository(recipe), undefined);
      assert.equal(homeFrom({ DNSID_GCP_LOCAL_HOME: join(parent, 'state') }, recipe), join(parent, 'state'));
      assert.throws(() => homeFrom({ DNSID_GCP_LOCAL_HOME: join(recipe, 'state') }, recipe), RecipeError);
      // A .git at the top makes the whole tree the repository.
      mkdirSync(join(parent, '.git'));
      assert.equal(enclosingRepository(recipe), parent);
      assert.throws(() => homeFrom({ DNSID_GCP_LOCAL_HOME: join(parent, 'state') }, recipe), (e: RecipeError) => e.exitCode === 2);
      assert.equal(homeFrom({ DNSID_GCP_LOCAL_HOME: join(tmpdir(), 'elsewhere') }, recipe), join(tmpdir(), 'elsewhere'));
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  test('the CLI sees none of your DNSid settings but the three kept ones, and its own config directory', () => {
    const env = cliEnvironment(
      { PATH: '/bin', DNSID_API_KEY: 'k', DNSID_SERVER: 's', DNSID_LOG_POLICY_URL: 'p', DNSID_CONFIG_DIR: '/mine', DNSID_LOCAL_IMAGE: 'i', DNSID_LOCAL_REGISTRY_PORT: '1', DNSID_LOCAL_DNS_PORT: '2' },
      pathsFor('/m'),
    );
    assert.deepEqual(env, { PATH: '/bin', DNSID_LOCAL_IMAGE: 'i', DNSID_LOCAL_REGISTRY_PORT: '1', DNSID_LOCAL_DNS_PORT: '2', DNSID_CONFIG_DIR: '/m/cli' });
  });

  test('diagnostic output withholds credential-like lines and keeps the end', () => {
    // A PEM armour line, assembled so this file carries no private-key marker of its own.
    const armour = ['-----BEGIN', 'EC', 'PRIVATE', 'KEY-----'].join(' ');
    const output = `a\nDNSID_API_KEY=x\n${armour}\n{"d": "x"}\nAuthorization: Bearer y\nb\n`;
    const lines = safeTail(output.concat('z\n'.repeat(30)));
    assert.equal(lines.length, 20);
    const all = safeTail(output, 50);
    assert.deepEqual(all, ['a', ...Array(4).fill('[line withheld: it may carry a credential]'), 'b']);
  });
});

describe('the whole lifecycle: bootstrap, run, verify, clean (simulated CLI, DNSid Local look-alike, real request path)', () => {
  test('every check passes, a second run and bootstrap reuse what is there, and clean removes it all, twice safely', { timeout: 120_000 }, async (t) => {
    const lookalike: Lookalike = await dnsidLocalLookalike();
    t.after(() => lookalike.close());
    const h = harness(t, lookalike.configDir);
    h.fake.setLocalEnv(lookalike.env);
    // Settings from your own shell that must not reach the CLI or the request path.
    const ctx = h.ctx({ DNSID_API_KEY: 'from-your-shell', DNSID_LOG_POLICY_URL: 'https://elsewhere.example/policy' });

    await bootstrap(ctx);
    assert.deepEqual(verbs(h.fake), ['--version', 'local up', 'local agent', 'local agent', 'local env', 'local agent']);
    const calls = dnsidCalls(h.fake);
    const registry = join(h.home, 'registry');
    assert.deepEqual(calls[1]?.args, ['local', 'up', '--zone', 'test', '--state', registry]);
    assert.deepEqual(calls[2]?.args.slice(-6), [ALICE, '--', h.fake.dnsid, 'log', 'issue', '--domain', ALICE].slice(-6));
    assert.deepEqual(calls[5]?.args.slice(-7), [BOB, '--', h.fake.dnsid, 'revoke', '--domain', BOB, '--reason', 'owner_request', '--yes'].slice(-7));
    for (const call of calls) {
      assert.equal(call.env?.['DNSID_API_KEY'], undefined, 'your DNSID_API_KEY reached the CLI');
      assert.equal(call.env?.['DNSID_LOG_POLICY_URL'], undefined);
      assert.equal(call.env?.['DNSID_CONFIG_DIR'], join(h.home, 'cli'));
    }
    // Each ran as its agent: the CLI's agent directory and domain, not this mode's.
    assert.deepEqual(agentCommands(h.fake).map((c) => [c.env?.['DNSID_DOMAIN'], ...c.args]), [
      [ALICE, 'log', 'issue', '--domain', ALICE],
      [BOB, 'log', 'issue', '--domain', BOB],
      [BOB, 'revoke', '--domain', BOB, '--reason', 'owner_request', '--yes'],
    ]);
    assert.deepEqual(readProgress(pathsFor(h.home)), { issued: [ALICE, BOB], revoked: [BOB] });
    assert.ok(lookalike.dnsQueries.includes(`_dnsid.${ALICE}/16`) && lookalike.dnsQueries.includes(`_dnsid.${BOB}/16`));
    // The simulated `dnsid revoke` changes nothing; the look-alike is told instead, in the status and in the log.
    lookalike.setStatus(BOB, 'REVOKED');
    await lookalike.revokeInLog(BOB);

    // A second bootstrap skips what is done (bob is not issued again).
    const before = dnsidCalls(h.fake).length;
    await bootstrap(ctx);
    assert.deepEqual(verbs(h.fake).slice(before), ['--version', 'local up', 'local agent', 'local env']);

    const ready = await run(ctx);
    t.after(async () => {
      if (alive(ready.pid)) process.kill(ready.pid, 'SIGKILL');
    });
    assert.ok(alive(ready.pid));
    // The request path got exactly the five settings, from DNSid Local, not yours.
    const stackEnv = readFileSync(`/proc/${ready.pid}/environ`, 'utf8').split('\0').filter((v) => v.startsWith('DNSID_')).sort();
    assert.deepEqual(stackEnv, Object.entries(lookalike.env).filter(([k]) => ['DNSID_LOG_POLICY_URL', 'DNSID_DNS_SERVER', 'DNSID_CA_BUNDLE', 'DNSID_PRIVATE_HOSTS', 'DNSID_GOVERNANCE_ID'].includes(k)).map(([k, v]) => `${k}=${v}`).sort());
    assert.equal((await run(ctx)).pid, ready.pid, 'a running request path is reused');

    const checks = await verify(ctx);
    assert.equal(checks.length, 9);
    for (const check of checks) assert.ok(check.pass, `${check.name}: ${check.detail}`);
    // Through the look-alike, revoked in its log and its status document, bob.test is refused by the log read first.
    assert.ok(h.out.some((l) => /^✓ revoked bob\.test refused/.test(l)));
    assert.ok(h.out.some((l) => /verify passed .*says nothing about Google's load balancer/.test(l)));
    // The verifier really fetched through the look-alike: the identities' records and documents, the log's policy.
    assert.ok(lookalike.httpsRequests.some((r) => r.startsWith('log.test /policy')));
    assert.ok(lookalike.httpsRequests.some((r) => r.startsWith(`${ALICE} /.well-known/dnsid/ku.json`)));
    // No key material reached the output.
    const printed = [...h.out, ...h.err].join('\n');
    assert.doesNotMatch(printed, /PRIVATE KEY|"d"\s*:/);
    assert.doesNotMatch(printed, /from-your-shell/);

    await clean(ctx);
    assert.equal(alive(ready.pid), false);
    assert.equal(existsSync(h.home), false);
    const resets = dnsidCalls(h.fake).filter((c) => c.args[1] === 'reset');
    assert.deepEqual(resets.map((c) => c.args), [['local', 'reset', '--hard', '--state', registry]]);
    await clean(ctx);
    assert.match(h.out.at(-1) as string, /nothing to remove/);
  });
});

describe('startup failures say what failed, without credentials', () => {
  test('no dnsid CLI: the install hint, nothing started', async (t) => {
    const h = harness(t);
    await rejectsWith(bootstrap(h.ctx({ DNSID_CLI: join(h.fake.dir, 'missing') })), /dnsid CLI .* could not be run: install it/);
    assert.equal(h.fake.calls().length, 0);
  });

  test('Docker not running: refused before DNSid Local is started', async (t) => {
    const h = harness(t);
    await rejectsWith(bootstrap(h.ctx({ FAKE_DOCKER_DOWN: '1' })), /Docker is not running/);
    assert.deepEqual(verbs(h.fake), ['--version']);
  });

  test('`dnsid local up` fails: its output and this mode\'s containers\' logs are shown with credential lines withheld', async (t) => {
    const h = harness(t);
    await rejectsWith(bootstrap(h.ctx({ FAKE_DNSID_FAIL: 'local up' })), /Starting DNSid Local \(dnsid local up\) failed/);
    const shown = h.err.join('\n');
    assert.match(shown, /exit 1/);
    assert.match(shown, /fake dnsid: local up failed/);
    assert.match(shown, /dnsid-registry-0a1b2c-registry-1 Exited/);
    assert.match(shown, /registry: listening on :7755/);
    assert.doesNotMatch(shown, /testnet/);
    // Diagnostics ask only about this mode's own compose project.
    const ps = h.fake.calls().find((c) => c.tool === 'docker' && c.args[0] === 'ps');
    assert.ok(ps?.args.includes(`label=com.docker.compose.project.working_dir=${join(h.home, 'registry')}`));
  });

  test('a command past its bound is killed and reported as timed out', async (t) => {
    const h = harness(t);
    await rejectsWith(bootstrap(h.ctx({ FAKE_DNSID_HANG: 'local up' }, { ...FAST, up: 500 })), /dnsid local up\) failed/);
    assert.match(h.err.join('\n'), /timed out after 1 s|timed out after 0 s/);
    await until(() => {
      const pid = hangingPid(h.fake, 'local up');
      return pid !== undefined && !alive(pid);
    });
  });

  test('DNSid Local hands out settings the verifier refuses: the request path is never started', async (t) => {
    const lookalike = await dnsidLocalLookalike([]);
    t.after(() => lookalike.close());
    const h = harness(t);
    const ctx = h.ctx();
    writeFileSync(join(h.fake.dir, 'never'), '');
    for (const [name, value, why] of [
      ['DNSID_PRIVATE_HOSTS', 'example.com', /may name only the .test zone/],
      ['DNSID_DNS_SERVER', '10.0.0.1:53', /not a loopback host:port/],
      ['DNSID_LOG_POLICY_URL', 'http://log.test/policy', /not an https URL/],
      ['DNSID_CA_BUNDLE', join(h.fake.dir, 'nope.pem'), /not a readable file/],
    ] as const) {
      h.fake.setLocalEnv({ ...lookalike.env, [name]: value });
      mkdirSync(join(h.home, 'registry'), { recursive: true });
      writeFileSync(join(h.home, 'registry', 'compose.yml'), '');
      writeFileSync(join(h.home, 'owner.json'), JSON.stringify({ owner: 'dnsid-gcp-service-extensions local mode' }));
      writeFileSync(join(h.home, 'progress.json'), JSON.stringify({ issued: [ALICE, BOB], revoked: [BOB] }));
      const error = await rejectsWith(run(ctx), /settings are not usable/);
      assert.match(error.message, why);
      assert.doesNotMatch(error.message, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.equal(existsSync(join(h.home, 'run', 'stack.pid')), false);
    }
  });

  test('the request path exits during startup: its output is shown and its records are cleared', async (t) => {
    const lookalike = await dnsidLocalLookalike();
    t.after(() => lookalike.close());
    const h = harness(t);
    h.fake.setLocalEnv(lookalike.env);
    await bootstrap(h.ctx());
    const ctx = { ...h.ctx(), node: join(h.fake.dir, 'failing-node') };
    writeFileSync(ctx.node, '#!/bin/sh\necho "listener failed: DNSID_API_KEY=testnet"\necho "port in use" >&2\nexit 3\n', { mode: 0o755 });
    await rejectsWith(run(ctx), /exited during startup \(exit 3\)/);
    assert.match(h.err.join('\n'), /port in use/);
    assert.doesNotMatch(h.err.join('\n'), /testnet/);
    assert.equal(existsSync(join(h.home, 'run', 'stack.pid')), false);
    assert.equal(existsSync(join(h.home, 'run', 'ready.json')), false);
  });

  test('run and verify before bootstrap, and verify before run, say which target comes first', async (t) => {
    const h = harness(t);
    await rejectsWith(run(h.ctx()), /not bootstrapped: run `make bootstrap` first/);
    await rejectsWith(verify(h.ctx()), /not running: run `make run` first/);
  });
});

describe('interruption and recovery', () => {
  test('interrupted during `dnsid local up`: the command is stopped, and clean afterwards removes the partial start', async (t) => {
    const h = harness(t);
    const ctx = h.ctx({ FAKE_DNSID_HANG: 'local up' }, { ...FAST, up: 60_000 });
    const started = bootstrap(ctx);
    await until(() => hangingPid(h.fake, 'local up') !== undefined);
    h.controller.abort();
    await assert.rejects(started, (e) => e instanceof Interrupted && e.exitCode === 130);
    const pid = hangingPid(h.fake, 'local up') as number;
    await until(() => !alive(pid));

    const after = harness(t);
    const cleanCtx = { ...after.ctx(), paths: pathsFor(h.home), cli: h.fake.dnsid, env: { ...after.ctx().env, ...h.fake.env } };
    await clean(cleanCtx);
    assert.equal(existsSync(h.home), false);
    assert.ok(after.out.some((l) => /DNSid Local was never started here/.test(l)));
  });

  test('interrupted between issuing the agents: the next bootstrap carries on from the record', async (t) => {
    const lookalike = await dnsidLocalLookalike();
    t.after(() => lookalike.close());
    const h = harness(t, lookalike.configDir);
    h.fake.setLocalEnv(lookalike.env);
    await assert.rejects(bootstrap(h.ctx({ FAKE_DNSID_FAIL: 'revoke' })), RecipeError);
    assert.deepEqual(readProgress(pathsFor(h.home)), { issued: [ALICE, BOB], revoked: [] });
    const before = dnsidCalls(h.fake).length;
    await bootstrap(h.ctx());
    const rest = dnsidCalls(h.fake).slice(before);
    assert.equal(rest.filter((c) => c.args.includes('revoke')).length, 1);
    assert.deepEqual(readProgress(pathsFor(h.home)), { issued: [ALICE, BOB], revoked: [BOB] });
  });

  test('SIGTERM to `node local/recipe.ts bootstrap`: exit 130 with how to resume, and the hung command is gone', { timeout: 30_000 }, async (t) => {
    const h = harness(t);
    const child = spawn(process.execPath, [join(ROOT, 'local', 'recipe.ts'), 'bootstrap'], {
      env: { ...h.ctx().env, FAKE_DNSID_HANG: 'local up' } as Record<string, string>,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (c: Buffer) => (stderr += c.toString()));
    await until(() => hangingPid(h.fake, 'local up') !== undefined, 15_000);
    child.kill('SIGTERM');
    const code = await new Promise<number | null>((r) => child.on('close', r));
    assert.equal(code, 130);
    assert.match(stderr, /interrupted: run the same target again to resume, or `make clean`/);
    const pid = hangingPid(h.fake, 'local up') as number;
    await until(() => !alive(pid));
  });

  test('a request path that died is replaced by the next run; a stale ready.json is never trusted', { timeout: 60_000 }, async (t) => {
    const lookalike = await dnsidLocalLookalike();
    t.after(() => lookalike.close());
    const h = harness(t, lookalike.configDir);
    h.fake.setLocalEnv(lookalike.env);
    const ctx = h.ctx();
    await bootstrap(ctx);
    const first = await run(ctx);
    process.kill(first.pid, 'SIGKILL');
    await until(() => !alive(first.pid));
    assert.ok(existsSync(join(h.home, 'run', 'ready.json')), 'the killed process left its ready.json');
    await rejectsWith(verify(ctx), /not running/);
    const second = await run(ctx);
    t.after(() => (alive(second.pid) ? process.kill(second.pid, 'SIGKILL') : undefined));
    assert.notEqual(second.pid, first.pid);
    await clean(ctx);
    assert.equal(alive(second.pid), false);
  });
});

describe('nothing this mode does not own is touched', () => {
  test('a home it did not create is refused by bootstrap and by clean, and left as it was', async (t) => {
    const h = harness(t);
    mkdirSync(h.home, { recursive: true });
    writeFileSync(join(h.home, 'yours.txt'), 'keep');
    await rejectsWith(bootstrap(h.ctx()), /was not created by this local mode/, 2);
    await rejectsWith(clean(h.ctx()), /was not created by this local mode; nothing removed/, 2);
    assert.deepEqual(readdirSync(h.home), ['yours.txt']);
    assert.equal(h.fake.calls().length, 0);
  });

  test('a recorded process id that now belongs to another process is never signalled', { timeout: 30_000 }, async (t) => {
    const h = harness(t);
    const other = spawn('sleep', ['30'], { stdio: 'ignore' });
    t.after(() => other.kill('SIGKILL'));
    const ctx = h.ctx();
    mkdirSync(join(h.home, 'run'), { recursive: true });
    writeFileSync(join(h.home, 'owner.json'), JSON.stringify({ owner: 'dnsid-gcp-service-extensions local mode' }));
    writeFileSync(join(h.home, 'run', 'stack.pid'), JSON.stringify({ pid: other.pid, startedAt: 'x' }));
    // A ready.json that claims the other process.
    writeFileSync(join(h.home, 'run', 'ready.json'), JSON.stringify({ pid: other.pid }));
    await rejectsWith(verify(ctx), /not running/);
    await clean(ctx);
    assert.ok(h.out.some((l) => /not stopped \(the recorded process id belongs to another process\)/.test(l)));
    assert.ok(alive(other.pid as number));
  });

  test('clean resets only this mode\'s DNSid Local state; another state directory and the default are left alone', async (t) => {
    const h = harness(t);
    const ctx = h.ctx();
    await bootstrap({ ...ctx, timeouts: FAST }).catch(() => {});
    // bootstrap stopped at `local env` (no settings): DNSid Local is up in this mode's registry.
    assert.ok(existsSync(join(h.home, 'registry', 'compose.yml')));
    const elsewhere = mkdtempSync(join(tmpdir(), 'other-dnsid-local-'));
    t.after(() => rmSync(elsewhere, { recursive: true, force: true }));
    writeFileSync(join(elsewhere, 'compose.yml'), '');
    await clean(ctx);
    assert.ok(existsSync(join(elsewhere, 'compose.yml')));
    for (const call of dnsidCalls(h.fake)) {
      if (call.args[0] !== 'local' || call.args[1] === undefined) continue;
      if (['up', 'env', 'reset', 'agent'].includes(call.args[1])) assert.equal(call.args[call.args.indexOf('--state') + 1], join(h.home, 'registry'), call.args.join(' '));
    }
  });
});

describe('the executable', () => {
  test('an unknown target, or a home inside the repository, exits 2 with a reason', () => {
    const env = { PATH: process.env['PATH'] ?? '', HOME: tmpdir() };
    const bad = spawnSync(process.execPath, [join(ROOT, 'local', 'recipe.ts'), 'deploy'], { env, encoding: 'utf8' });
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /usage: node local\/recipe.ts bootstrap\|run\|verify\|clean/);
    const inside = spawnSync(process.execPath, [join(ROOT, 'local', 'recipe.ts'), 'clean'], { env: { ...env, DNSID_GCP_LOCAL_HOME: join(ROOT, 'state') }, encoding: 'utf8' });
    assert.equal(inside.status, 2);
    assert.match(inside.stderr, /must be outside the repository/);
  });

  test('the Makefile has the cookbook\'s four targets, each through local/recipe.ts', () => {
    const makefile = readFileSync(join(ROOT, 'Makefile'), 'utf8');
    for (const target of ['bootstrap', 'run', 'verify', 'clean']) {
      assert.match(makefile, new RegExp(`^${target}:.*\\n\\t\\$\\(NODE\\) local/recipe\\.ts ${target}$`, 'm'), target);
    }
    assert.match(makefile, /^\.PHONY: bootstrap run verify clean$/m);
  });
});

describe('local trust stays in the local mode', () => {
  const sources = (dir: string): string[] =>
    readdirSync(join(ROOT, dir), { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile() && e.name.endsWith('.ts'))
      .map((e) => relative(ROOT, join(e.parentPath, e.name)));

  test('nothing the production verifier or Demo Bank runs imports local/ or reads DNSid Local\'s settings', () => {
    const production = [...sources('src'), ...sources('origin')];
    assert.ok(production.includes('src/main.ts'));
    for (const file of production) {
      const text = readFileSync(join(ROOT, file), 'utf8');
      assert.doesNotMatch(text, /from ['"][^'"]*\/local\//, file);
      for (const name of ['DNSID_LOG_POLICY_URL', 'DNSID_DNS_SERVER', 'DNSID_CA_BUNDLE', 'DNSID_PRIVATE_HOSTS', 'DNSID_GOVERNANCE_ID', 'privateAddressHosts', 'caBundlePath', 'policyUrl']) {
        assert.equal(text.includes(name), false, `${file} mentions ${name}`);
      }
    }
  });

  test('the image copies only src/ and proto/ besides the manifests, so local/ cannot be in it', () => {
    const dockerfile = readFileSync(join(ROOT, 'Dockerfile'), 'utf8');
    const copies = dockerfile.split('\n').filter((l) => l.startsWith('COPY ')).map((l) => l.replace(/\s+/g, ' '));
    assert.deepEqual(copies, ['COPY package.json package-lock.json .npmrc ./', 'COPY --from=install /app/node_modules ./node_modules', 'COPY package.json LICENSE ./', 'COPY proto ./proto', 'COPY src ./src']);
    assert.match(dockerfile, /^ENTRYPOINT \["node", "src\/main\.ts"\]$/m);
  });

  test('the production runtime is built on the managed backend only, whatever the environment holds', async () => {
    const { createProductionVerificationRuntime, PRODUCTION_BACKEND } = await import('../../src/identity.ts');
    const runtime = createProductionVerificationRuntime('gov.test');
    assert.equal(runtime.backend, PRODUCTION_BACKEND);
    assert.equal(PRODUCTION_BACKEND.name, 'production');
    assert.match(PRODUCTION_BACKEND.transportContext, /no extra CA, no private-address exceptions/);
  });

});
