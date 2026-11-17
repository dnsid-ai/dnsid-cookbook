// TEST ONLY. Fake `dnsid` and `docker` commands for local/recipe.ts: SIMULATIONS, not the DNSid CLI, DNSid Local or
// Docker. They do what local/recipe.ts relies on the real ones doing, as observed from DNSid CLI 2026.10.29-537b773
// (`--help`, and `local up`/`down`/`reset --hard`/`env` run against a logging stand-in for docker): `local up --state S`
// writes S/compose.yml; `local env` fails until then and prints a flat JSON object; `local reset --hard --state S`
// removes S; `local agent ensure … <fqdn> -- <cmd>` runs <cmd> with the agent's DNSID_DOMAIN and DNSID_CONFIG_DIR and
// returns its exit code. Every call is recorded with the DNSID_* variables it saw. FAKE_* variables make a command fail
// (printing a credential-like line first) or hang.

import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';

const DNSID = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const dir = process.env.FAKE_DNSID_STATE;
const args = process.argv.slice(2);
const seen = Object.fromEntries(Object.entries(process.env).filter(([k]) => k.startsWith('DNSID_')));
fs.appendFileSync(path.join(dir, 'calls'), JSON.stringify({ tool: 'dnsid', args, env: seen, pid: process.pid }) + '\\n');
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const verb = args[0] === 'local' ? 'local ' + args[1] + (args[1] === 'agent' ? ' ' + args[2] : '') : args[0] + (args[0] === 'log' ? ' ' + args[1] : '');
const hangs = (process.env.FAKE_DNSID_HANG || '').split(',');
if (hangs.includes(verb)) {
  fs.writeFileSync(path.join(dir, 'hanging-' + verb.replace(/ /g, '-')), String(process.pid));
  setInterval(() => {}, 1000);
  return;
}
const fails = (process.env.FAKE_DNSID_FAIL || '').split(',');
if (fails.includes(verb)) {
  console.log('DNSID_API_KEY=testnet');
  console.error('fake dnsid: ' + verb + ' failed');
  process.exit(1);
}
if (args[0] === '--version') { console.log('dnsid fake-1 (commit 0)'); process.exit(0); }
const state = flag('--state');
if (verb === 'local up') {
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(path.join(state, 'compose.yml'), 'services: {}\\n');
  process.exit(0);
}
if (verb === 'local env') {
  if (!fs.existsSync(path.join(state, 'compose.yml'))) { console.error('compose.yml is missing; run dnsid local up first'); process.exit(1); }
  process.stdout.write(fs.readFileSync(process.env.FAKE_DNSID_ENV_JSON, 'utf8'));
  process.exit(0);
}
if (verb === 'local reset') {
  if (!args.includes('--hard')) process.exit(2);
  fs.rmSync(state, { recursive: true, force: true });
  process.exit(0);
}
if (verb === 'local agent ensure') {
  if (!fs.existsSync(path.join(state, 'compose.yml'))) { console.error('run dnsid local up first'); process.exit(1); }
  const dash = args.indexOf('--');
  const fqdn = args[dash - 1];
  const command = args.slice(dash + 1);
  const result = spawnSync(command[0], command.slice(1), { stdio: 'inherit', env: { ...process.env, DNSID_DOMAIN: fqdn, DNSID_CONFIG_DIR: process.env.FAKE_DNSID_AGENT_DIR || '/nonexistent', DNSID_API_KEY: 'testnet' } });
  process.exit(result.status === null ? 1 : result.status);
}
if (verb === 'log issue' || verb === 'revoke') process.exit(0);
console.error('fake dnsid: unexpected ' + args.join(' '));
process.exit(2);
`;

const DOCKER = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.env.FAKE_DNSID_STATE, 'calls'), JSON.stringify({ tool: 'docker', args }) + '\\n');
if (process.env.FAKE_DOCKER_DOWN === '1') { console.error('Cannot connect to the Docker daemon'); process.exit(1); }
if (args[0] === 'info') { console.log('27.5.1'); process.exit(0); }
if (args[0] === 'ps') { console.log('abc123 dnsid-registry-0a1b2c-registry-1 Exited (1)'); process.exit(0); }
if (args[0] === 'logs') { console.log('registry: listening on :7755'); console.log('registry: api_key=testnet'); process.exit(0); }
process.exit(0);
`;

export interface DnsidCall {
  readonly tool: 'dnsid' | 'docker';
  readonly args: string[];
  readonly env?: Record<string, string>;
  readonly pid?: number;
}

export interface FakeDnsid {
  readonly dir: string;
  readonly dnsid: string;
  readonly docker: string;
  /** The environment the recipe needs to use these fakes (pass it as part of its env). */
  readonly env: Record<string, string>;
  calls(): DnsidCall[];
  /** Sets what `dnsid local env --format json` prints. */
  setLocalEnv(value: unknown): void;
}

export function fakeDnsid(t: TestContext, agentDir?: string): FakeDnsid {
  const dir = mkdtempSync(join(tmpdir(), 'fake-dnsid-'));
  const dnsid = join(dir, 'dnsid');
  const docker = join(dir, 'docker');
  writeFileSync(dnsid, DNSID);
  writeFileSync(docker, DOCKER);
  chmodSync(dnsid, 0o755);
  chmodSync(docker, 0o755);
  writeFileSync(join(dir, 'calls'), '');
  const envJson = join(dir, 'local-env.json');
  writeFileSync(envJson, '{}');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return {
    dir,
    dnsid,
    docker,
    env: {
      DNSID_CLI: dnsid,
      DOCKER: docker,
      FAKE_DNSID_STATE: dir,
      FAKE_DNSID_ENV_JSON: envJson,
      ...(agentDir === undefined ? {} : { FAKE_DNSID_AGENT_DIR: agentDir }),
    },
    calls: () =>
      readFileSync(join(dir, 'calls'), 'utf8')
        .split('\n')
        .filter((line) => line !== '')
        .map((line) => JSON.parse(line) as DnsidCall),
    setLocalEnv(value) {
      writeFileSync(envJson, typeof value === 'string' ? value : JSON.stringify(value));
    },
  };
}

/** The pid a hanging fake command recorded, once it has started. */
export function hangingPid(fake: FakeDnsid, verb: string): number | undefined {
  const file = join(fake.dir, `hanging-${verb.replace(/ /g, '-')}`);
  return existsSync(file) ? Number(readFileSync(file, 'utf8')) : undefined;
}
