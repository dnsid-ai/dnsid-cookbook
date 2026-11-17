// TEST ONLY. Fake `terraform`, `gcloud`, `sleep` and `date` commands for running scripts/deploy.sh and
// scripts/teardown.sh with no cloud and no Terraform providers: SIMULATIONS, not Google Cloud or Terraform. They keep
// their state in files under one directory, record every call (arguments, and which credentials each one saw), and fail
// the operations a test asks them to. The clock is simulated too: `sleep` advances it instantly and `date +%s` reads it,
// so the scripts' bounded waits run out in milliseconds.

import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';

// `terraform -chdir=<infra/stage> <command> …`. The stage's "state" is the backend path given at init, one resource
// address per line. FAKE_TF_FAIL_<COMMAND>_<STAGE>=n makes the next n such commands fail; FAKE_TF_PARTIAL_<STAGE> is
// the state a failed apply leaves (addresses separated by commas); FAKE_TF_FAIL_LOG_<STAGE> names a file whose content a
// failed apply prints in place of the generic error.
const TERRAFORM = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const dir = process.env.FAKE_CLI_STATE;
let args = process.argv.slice(2);
let stage = '';
if (args[0] && args[0].startsWith('-chdir=')) { stage = path.basename(args[0].slice(7)); args = args.slice(1); }
const command = args[0];
const data = process.env.TF_DATA_DIR;
fs.appendFileSync(path.join(dir, 'calls'), JSON.stringify({ tool: 'terraform', stage, args, env: {
  GOOGLE_OAUTH_ACCESS_TOKEN: process.env.GOOGLE_OAUTH_ACCESS_TOKEN ?? null, TF_DATA_DIR: data ?? null } }) + '\\n');
const failing = (name) => {
  const key = 'FAKE_TF_FAIL_' + name.toUpperCase() + '_' + stage.toUpperCase();
  const counter = path.join(dir, key);
  const budget = Number(process.env[key] ?? 0);
  const used = fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) : 0;
  if (used < budget) { fs.writeFileSync(counter, String(used + 1)); return true; }
  return false;
};
const backend = () => fs.readFileSync(path.join(data, 'backend'), 'utf8');
const write = (lines) => fs.writeFileSync(backend(), lines.length ? lines.join('\\n') + '\\n' : '');
if (command === 'init') {
  fs.mkdirSync(data, { recursive: true });
  const config = args.find((a) => a.startsWith('-backend-config=path='));
  if (!args.includes('-lockfile=readonly')) { console.error('fake terraform: init without -lockfile=readonly'); process.exit(1); }
  if (!config) { console.error('fake terraform: init without a backend path'); process.exit(1); }
  fs.writeFileSync(path.join(data, 'backend'), config.slice('-backend-config=path='.length));
  if (failing('init')) { console.error('fake terraform: init failed'); process.exit(1); }
  process.exit(0);
}
if (command === 'apply') {
  if (failing('apply')) {
    const partial = process.env['FAKE_TF_PARTIAL_' + stage.toUpperCase()];
    if (partial) write(partial.split(','));
    const log = process.env['FAKE_TF_FAIL_LOG_' + stage.toUpperCase()];
    console.log(log ? fs.readFileSync(log, 'utf8') : 'Error: fake apply failure in ' + stage);
    process.exit(1);
  }
  write(fs.readFileSync(path.join(dir, 'resources-' + stage), 'utf8').trim().split('\\n'));
  console.log('Apply complete! Resources: fake.');
  process.exit(0);
}
if (command === 'output') { process.stdout.write(fs.readFileSync(path.join(dir, 'outputs-' + stage + '.json'), 'utf8')); process.exit(0); }
if (command === 'state' && args[1] === 'list') {
  if (failing('state')) { console.error('fake terraform: state unreadable'); process.exit(1); }
  const file = backend();
  if (fs.existsSync(file)) process.stdout.write(fs.readFileSync(file, 'utf8'));
  process.exit(0);
}
if (command === 'destroy') {
  if (failing('destroy')) { console.log('Error: fake destroy failure in ' + stage); process.exit(1); }
  if (process.env['FAKE_TF_DESTROY_KEEPS_' + stage.toUpperCase()]) process.exit(0);
  write([]);
  // owned-<stage>: the listing files (leftover-*, iam-*) of what this stage created, gone once it is destroyed.
  const owned = path.join(dir, 'owned-' + stage);
  if (fs.existsSync(owned)) for (const f of fs.readFileSync(owned, 'utf8').split('\\n').filter(Boolean)) fs.rmSync(path.join(dir, f), { force: true });
  console.log('Destroy complete!');
  process.exit(0);
}
console.error('fake terraform: unexpected ' + args.join(' '));
process.exit(99);
`;

// `gcloud …`. Builds live in files: builds/<id> holds the remaining status sequence (FAKE_BUILD_STATUSES, comma
// separated, consumed one per describe, the last one sticky) and the tagged image names from the submission.
const GCLOUD = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dir = process.env.FAKE_CLI_STATE;
const args = process.argv.slice(2).filter((a) => a !== '--quiet' && a !== '--verbosity=error');
const tokenFile = process.env.CLOUDSDK_AUTH_ACCESS_TOKEN_FILE ?? null;
let token = null, tokenMode = null;
if (tokenFile) { try { token = fs.readFileSync(tokenFile, 'utf8'); tokenMode = (fs.statSync(tokenFile).mode & 0o777).toString(8); } catch { token = 'UNREADABLE'; } }
fs.appendFileSync(path.join(dir, 'calls'), JSON.stringify({ tool: 'gcloud', args, tokenFile, token, tokenMode }) + '\\n');
const joined = args.join(' ');
const flag = (name) => (args.find((a) => a.startsWith('--' + name + '=')) ?? '').slice(name.length + 3);
const out = (text) => process.stdout.write(text);
const fail = (message, code = 1) => { process.stderr.write(message + '\\n'); process.exit(code); };
const builds = path.join(dir, 'builds');
fs.mkdirSync(builds, { recursive: true });
if (joined === 'auth application-default print-access-token') {
  if (tokenFile) fail('fake gcloud: minting an ADC token must not see a token file');
  if (!process.env.FAKE_ADC_TOKEN) fail('ERROR: (gcloud.auth.application-default.print-access-token) Could not automatically determine credentials.');
  out(process.env.FAKE_ADC_TOKEN + '\\n');
  process.exit(0);
}
if (args[0] === 'builds' && args[1] === 'submit') {
  if (process.env.FAKE_SUBMIT_FAIL) fail('ERROR: fake submit failure');
  const id = crypto.randomUUID();
  const subs = Object.fromEntries(flag('substitutions').split(',').map((kv) => kv.split('=')));
  const statuses = (process.env.FAKE_BUILD_STATUSES ?? 'QUEUED,WORKING,SUCCESS').split(',');
  fs.writeFileSync(path.join(builds, id), JSON.stringify({ statuses, subs, context: args[2] }));
  fs.appendFileSync(path.join(dir, 'submitted'), id + '\\n');
  // Cloud Build lists a build by its tags; cloudbuild.yaml tags each one with the deployment's name.
  fs.appendFileSync(path.join(dir, 'ongoing'), id + ' ' + subs._DEPLOYMENT + '\\n');
  out(id + '\\n');
  process.exit(0);
}
if (args[0] === 'builds' && (args[1] === 'describe' || args[1] === 'cancel')) {
  const file = path.join(builds, args[2]);
  if (!fs.existsSync(file)) fail('ERROR: NOT_FOUND');
  const build = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (args[1] === 'cancel') { build.statuses = ['CANCELLED']; fs.writeFileSync(file, JSON.stringify(build)); process.exit(0); }
  const status = build.statuses.length > 1 ? build.statuses.shift() : build.statuses[0];
  fs.writeFileSync(file, JSON.stringify(build));
  if (flag('format') === 'value(status)') { out(status + '\\n'); process.exit(0); }
  const digest = (name) => 'sha256:' + crypto.createHash('sha256').update(name).digest('hex');
  const images = status === 'SUCCESS' ? [build.subs._VERIFIER_IMAGE, build.subs._ORIGIN_IMAGE].map((name) => ({ name, digest: digest(name) })) : [];
  out(JSON.stringify({ id: args[2], status, results: { images } }));
  process.exit(0);
}
if (args[0] === 'builds' && args[1] === 'list') {
  if (process.env.FAKE_BUILDS_LIST_FAIL) fail('ERROR: fake list failure');
  const tag = flag('filter').replace(/^tags=/, '');
  const ongoing = fs.existsSync(path.join(dir, 'ongoing')) ? fs.readFileSync(path.join(dir, 'ongoing'), 'utf8').trim().split('\\n').filter(Boolean) : [];
  let listed = 0;
  for (const line of ongoing) { const [id, t] = line.split(' '); if (t === tag) { const b = JSON.parse(fs.readFileSync(path.join(builds, id), 'utf8')); if (!['SUCCESS','FAILURE','CANCELLED','TIMEOUT','INTERNAL_ERROR','EXPIRED'].includes(b.statuses[0])) { out(id + '\\n'); listed += 1; } } }
  if (listed === 0) process.stderr.write('Listed 0 items.\\n');
  process.exit(0);
}
if (args[0] === 'storage' && args[1] === 'cat') { out('fake build log: step validate failed\\n'); process.exit(0); }
if (args.includes('--format=json') && args.includes('list')) {
  const kind = args.slice(0, args.indexOf('list')).join('-');
  const file = path.join(dir, 'listing-' + kind + '.json');
  if (process.env.FAKE_LISTING_FAIL) fail('ERROR: fake listing failure');
  out(fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '[]');
  process.exit(0);
}
if (args.includes('get-iam-policy')) {
  // IAM bindings, one "role member" line each, from iam-<kind> (no file: no bindings).
  const kind = args.slice(0, args.indexOf('get-iam-policy')).join('-');
  if (process.env.FAKE_INVENTORY_FAIL === kind) fail('ERROR: (gcloud) PERMISSION_DENIED: fake');
  // FAKE_IAM_FAIL / FAKE_IAM_NOT_FOUND: comma-separated kinds whose policy read alone is refused / finds no resource.
  if ((process.env.FAKE_IAM_FAIL || '').split(',').includes(kind)) fail('ERROR: (gcloud) PERMISSION_DENIED: fake policy read');
  if ((process.env.FAKE_IAM_NOT_FOUND || '').split(',').includes(kind)) fail('ERROR: (gcloud) NOT_FOUND: fake resource');
  const file = path.join(dir, 'iam-' + kind);
  if (fs.existsSync(file)) out(fs.readFileSync(file, 'utf8'));
  process.exit(0);
}
if (args.includes('list')) {
  const kind = args.slice(0, args.indexOf('list')).join('-');
  if (process.env.FAKE_INVENTORY_FAIL === kind) fail('ERROR: (gcloud) PERMISSION_DENIED: fake');
  if (process.env.FAKE_INVENTORY_DISABLED === kind) fail('ERROR: API [x.googleapis.com] has not been used in project 1 before or it is disabled.');
  const file = path.join(dir, 'leftover-' + kind);
  // Like gcloud, a note about an empty listing goes to stderr; only stdout lists resources.
  if (fs.existsSync(file)) out(fs.readFileSync(file, 'utf8'));
  else process.stderr.write('Listed 0 items.\\n');
  process.exit(0);
}
fail('fake gcloud: unexpected ' + joined, 99);
`;

const SLEEP = `#!/usr/bin/env bash
clock="$FAKE_CLI_STATE/clock"
now="$(cat "$clock")"
echo $(( now + \${1%.*} )) > "$clock"
`;

const DATE = `#!/usr/bin/env bash
if [[ "$*" == "+%s" ]]; then cat "$FAKE_CLI_STATE/clock"; exit 0; fi
exec /bin/date "$@"
`;

export interface Call {
  readonly tool: 'terraform' | 'gcloud';
  readonly stage?: string;
  readonly args: string[];
  readonly env?: { GOOGLE_OAUTH_ACCESS_TOKEN: string | null; TF_DATA_DIR: string | null };
  readonly tokenFile?: string | null;
  readonly token?: string | null;
  readonly tokenMode?: string | null;
}

export interface FakeCli {
  readonly dir: string;
  readonly bin: string;
  calls(): Call[];
  write(name: string, content: string): void;
  read(name: string): string;
  exists(name: string): boolean;
}

export function fakeCli(t: TestContext): FakeCli {
  const dir = mkdtempSync(join(tmpdir(), 'fake-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  for (const [name, content] of [
    ['terraform', TERRAFORM],
    ['gcloud', GCLOUD],
    ['sleep', SLEEP],
    ['date', DATE],
  ] as const) {
    writeFileSync(join(bin, name), content);
    chmodSync(join(bin, name), 0o755);
  }
  writeFileSync(join(dir, 'calls'), '');
  writeFileSync(join(dir, 'clock'), String(Math.floor(Date.now() / 1000)));
  return {
    dir,
    bin,
    calls: () =>
      readFileSync(join(dir, 'calls'), 'utf8')
        .split('\n')
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line) as Call),
    write: (name, content) => writeFileSync(join(dir, name), content),
    read: (name) => readFileSync(join(dir, name), 'utf8'),
    exists: (name) => existsSync(join(dir, name)),
  };
}
