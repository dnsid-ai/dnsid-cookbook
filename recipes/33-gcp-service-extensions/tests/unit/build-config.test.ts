// Static checks of what the deployment builds and uploads, with no container engine and no cloud: the Cloud Build
// configuration (cloudbuild.yaml), the two Dockerfiles and their build-context allowlists, the upload allowlist
// (scripts/lib/build-context.sh, run for real into a temporary directory), the container smoke script's build mode
// (SMOKE_IMAGES, SMOKE_NETWORK) against a fake `docker`, and the Terraform files' shape and provider locks. Terraform's
// own validation and its mock-provider tests run in scripts/test-local.sh.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';
import { parseDocument } from 'yaml';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const read = (path: string) => readFileSync(join(ROOT, path), 'utf8');
const code = (text: string) =>
  text
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');

function filesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else out.push(relative(dir, path));
    }
  };
  walk(dir);
  return out.sort();
}

describe('cloudbuild.yaml', () => {
  const yaml = read('cloudbuild.yaml');
  const body = code(yaml);
  const BUILDER = 'gcr.io/cloud-builders/docker:24.0.9@sha256:8c01add5afa1da06e187d07064555cce9d27c59e732f0460a9977936da0d8cdd';
  // Parsed as YAML, as gcloud parses it before submitting: a file that is not valid YAML is refused before any build.
  const parse = (text: string) => {
    const doc = parseDocument(text, { strict: true, uniqueKeys: true });
    return { errors: doc.errors.map((e) => `${e.code} at line ${e.linePos?.[0]?.line}`), config: doc.toJS() as Record<string, unknown> };
  };
  const { errors, config } = parse(yaml);

  test('is valid YAML, with no warnings, and has only the fields Cloud Build reads', () => {
    assert.deepEqual(errors, []);
    assert.deepEqual(parseDocument(yaml).warnings, []);
    assert.deepEqual(Object.keys(config), ['steps', 'images', 'tags', 'timeout', 'options']);
  });

  test('a substitution in a flow list (the first deployment’s refused file) is caught by this parse', () => {
    // The two build steps as they were written when gcloud refused the file ("expected ',' or ']', but got '{'").
    const refused = yaml.replace(
      /    args:\n      - build\n      - --platform=linux\/amd64\n      - --pull\n      - --tag=\$\{(_[A-Z_]+)\}\n      - (\S+)\n/g,
      '    args: [build, --platform=linux/amd64, --pull, --tag=${$1}, $2]\n',
    );
    assert.notEqual(refused, yaml);
    assert.deepEqual(parse(refused).errors, ['MISSING_CHAR at line 24', 'MISSING_CHAR at line 28']);
  });

  test('every step runs the docker builder pinned by digest', () => {
    const steps = config['steps'] as Record<string, unknown>[];
    assert.deepEqual(steps.map((s) => s['id']), ['build-verifier', 'build-origin', 'validate']);
    for (const step of steps) assert.equal(step['name'], BUILDER);
  });

  test('both images are built for linux/amd64 from their own contexts, pulling the pinned base', () => {
    const [verifier, origin] = config['steps'] as Record<string, unknown>[];
    assert.deepEqual(verifier, { id: 'build-verifier', name: BUILDER, args: ['build', '--platform=linux/amd64', '--pull', '--tag=${_VERIFIER_IMAGE}', '.'] });
    assert.deepEqual(origin, { id: 'build-origin', name: BUILDER, args: ['build', '--platform=linux/amd64', '--pull', '--tag=${_ORIGIN_IMAGE}', 'origin'] });
  });

  test('the images are checked by the container smoke script, on the build network, before anything is published', () => {
    const validate = (config['steps'] as Record<string, unknown>[])[2];
    assert.deepEqual(validate, {
      id: 'validate',
      name: BUILDER,
      entrypoint: 'bash',
      args: ['scripts/container-smoke.sh'],
      env: ['SMOKE_IMAGES=${_VERIFIER_IMAGE} ${_ORIGIN_IMAGE}', 'SMOKE_NETWORK=cloudbuild'],
    });
    // `images` are pushed only after every step succeeded; nothing pushes earlier.
    assert.deepEqual(config['images'], ['${_VERIFIER_IMAGE}', '${_ORIGIN_IMAGE}']);
    assert.doesNotMatch(body, /\bpush\b/);
  });

  test('logs go to the build identity’s own bucket, every substitution is required, and the build is tagged with the deployment', () => {
    assert.deepEqual(config['options'], { logging: 'GCS_ONLY', substitutionOption: 'MUST_MATCH' });
    assert.deepEqual(config['tags'], ['dnsid-gse', '${_DEPLOYMENT}']);
    assert.equal(config['timeout'], '1800s');
  });

  test('no secrets, credentials or other inputs reach the build', () => {
    assert.doesNotMatch(body, /secretEnv|availableSecrets|secretManager|kmsKeyName|serviceAccount:|logsBucket:/);
    const substitutions = new Set([...JSON.stringify(config).matchAll(/\$\{(_[A-Z_]+)\}/g)].map((m) => m[1]));
    assert.deepEqual([...substitutions].sort(), ['_DEPLOYMENT', '_ORIGIN_IMAGE', '_VERIFIER_IMAGE']);
    assert.deepEqual([...body.matchAll(/\$\{?([A-Za-z_]+)/g)].map((m) => m[1]).filter((n) => !n?.startsWith('_')), []);
  });
});

describe('the Dockerfiles and their build contexts', () => {
  const BASE = 'node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54';
  for (const [dockerfile, ignore, entrypoint, allowed] of [
    ['Dockerfile', '.dockerignore', '["node", "src/main.ts"]', ['package.json', 'package-lock.json', '.npmrc', 'LICENSE', 'src/', 'proto/']],
    ['origin/Dockerfile', 'origin/.dockerignore', '["node", "server.ts"]', ['package.json', 'server.ts', 'LICENSE']],
  ] as const) {
    test(`${dockerfile}: the pinned base, a non-root user, an exec-form entry point, no CMD; ${ignore} admits only ${allowed.join(' ')}`, () => {
      const text = code(read(dockerfile));
      assert.match(text, new RegExp(`^ARG NODE_IMAGE=${BASE.replace(/[.@:]/g, '\\$&')}$`, 'm'));
      for (const from of text.match(/^FROM .*$/gm) ?? []) assert.match(from, /^FROM \$\{NODE_IMAGE\}( AS install)?$/);
      assert.match(text, /^USER 1000:1000$/m);
      assert.equal(text.match(/^ENTRYPOINT .*$/gm)?.join(), `ENTRYPOINT ${entrypoint}`);
      assert.doesNotMatch(text, /^CMD /m);
      assert.doesNotMatch(text, /^(ADD|ARG (?!NODE_IMAGE))/m);
      const rules = code(read(ignore)).split('\n').filter((line) => line.trim().length > 0);
      assert.equal(rules[0], '*');
      assert.deepEqual(rules.filter((r) => r.startsWith('!')).map((r) => r.slice(1)).sort(), [...allowed].sort());
    });
  }
});

// umask: the shell's umask while assembling (scripts/deploy.sh runs under 077).
function assemble(t: TestContext, root = ROOT, umask = '022'): { dest: string; result: ReturnType<typeof spawnSync> } {
  const dir = mkdtempSync(join(tmpdir(), 'build-context-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const dest = join(dir, 'context');
  mkdirSync(dest);
  const result = spawnSync('bash', ['-c', 'set -euo pipefail; umask "$4"; source "$1"; assemble_build_context "$2" "$3"', 'x', join(ROOT, 'scripts/lib/build-context.sh'), root, dest, umask], {
    encoding: 'utf8',
  });
  return { dest, result };
}

describe('the upload to Cloud Build (scripts/lib/build-context.sh)', () => {
  test('exactly the allowlist: the build configuration, both images’ inputs, the smoke script and its probes', (t) => {
    const { dest, result } = assemble(t);
    assert.equal(result.status, 0, String(result.stderr));
    const expected = [
      '.dockerignore',
      '.gcloudignore',
      '.npmrc',
      '.nvmrc',
      'Dockerfile',
      'LICENSE',
      'cloudbuild.yaml',
      'origin/.dockerignore',
      'origin/Dockerfile',
      'origin/LICENSE',
      'origin/package.json',
      'origin/server.ts',
      'package-lock.json',
      'package.json',
      'scripts/container-smoke.sh',
      'scripts/lib/container-cleanup.sh',
      'tests/container/probe.ts',
      'tests/support/grpc-client.ts',
      'tests/support/http-client.ts',
      'tests/support/response-wire.ts',
      'tests/support/signing.ts',
      ...filesUnder(join(ROOT, 'src')).map((f) => `src/${f}`),
      ...filesUnder(join(ROOT, 'proto')).map((f) => `proto/${f}`),
    ].sort();
    assert.deepEqual(filesUnder(dest), expected);
    for (const file of expected) {
      if (file === '.gcloudignore') continue;
      assert.equal(readFileSync(join(dest, file), 'utf8'), readFileSync(join(ROOT, file), 'utf8'), file);
    }
    // Nothing of the deployment's own machinery, state, plan records or other tests is uploaded.
    for (const absent of ['local', 'Makefile', 'infra', 'docs', 'README.md', 'quickstart.json', 'scripts/deploy.sh', 'scripts/teardown.sh', 'scripts/live', 'tests/unit', 'tsconfig.json', 'node_modules']) {
      assert.equal(expected.some((f) => f === absent || f.startsWith(`${absent}/`)), false, absent);
    }
    assert.match(readFileSync(join(dest, '.gcloudignore'), 'utf8'), /^# Everything here was copied from an allowlist/);
  });

  test('the smoke script and the probe are executable in the build as uploaded', (t) => {
    const { dest } = assemble(t);
    assert.ok((statSync(join(dest, 'scripts/container-smoke.sh')).mode & 0o111) !== 0);
  });

  // The second deployment's image build failed here: under deploy.sh's umask 077 the copied directories were 0700,
  // Docker kept that mode for proto/'s subdirectories, and the image's uid 1000 could not read the schemas.
  test('every directory and file is readable by any user, whatever the umask and the checkout’s modes', (t) => {
    const modes = (dest: string) => {
      const out: Record<string, string> = {};
      const walk = (dir: string) => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const path = join(dir, entry.name);
          out[relative(dest, path)] = (statSync(path).mode & 0o7777).toString(8);
          if (entry.isDirectory()) walk(path);
        }
      };
      out['.'] = (statSync(dest).mode & 0o7777).toString(8);
      walk(dest);
      return out;
    };
    const expect = (dest: string) => {
      const found = modes(dest);
      const expected = Object.fromEntries(
        Object.keys(found).map((p) => [p, statSync(join(dest, p)).isDirectory() || p === 'scripts/container-smoke.sh' ? '755' : '644']),
      );
      assert.deepEqual(found, expected);
      assert.ok(Object.keys(found).includes('proto/envoy/service/ext_proc/v3'));
    };

    // This checkout, assembled under deploy.sh's umask.
    let assembled = assemble(t, ROOT, '077');
    assert.equal(assembled.result.status, 0, String(assembled.result.stderr));
    expect(assembled.dest);

    // A checkout made under umask 077: directories 0700, files 0600, the smoke script 0700.
    const copy = mkdtempSync(join(tmpdir(), 'build-context-root-'));
    t.after(() => rmSync(copy, { recursive: true, force: true }));
    const cp = (args: string[]) => assert.equal(spawnSync('cp', args).status, 0);
    cp(['-R', join(ROOT, 'src'), join(ROOT, 'proto'), join(ROOT, 'origin'), join(ROOT, 'scripts'), copy]);
    mkdirSync(join(copy, 'tests/container'), { recursive: true });
    mkdirSync(join(copy, 'tests/support'), { recursive: true });
    for (const f of ['cloudbuild.yaml', 'Dockerfile', '.dockerignore', 'package.json', 'package-lock.json', '.npmrc', '.nvmrc', 'LICENSE', 'tests/container/probe.ts', 'tests/support/grpc-client.ts', 'tests/support/http-client.ts', 'tests/support/response-wire.ts', 'tests/support/signing.ts']) {
      cp([join(ROOT, f), join(copy, f)]);
    }
    assert.equal(spawnSync('find', [copy, '-mindepth', '1', '-type', 'd', '-exec', 'chmod', '700', '{}', '+']).status, 0);
    assert.equal(spawnSync('find', [copy, '-type', 'f', '-exec', 'chmod', '600', '{}', '+']).status, 0);
    assert.equal(spawnSync('chmod', ['700', join(copy, 'scripts/container-smoke.sh')]).status, 0);
    assembled = assemble(t, copy, '077');
    assert.equal(assembled.result.status, 0, String(assembled.result.stderr));
    expect(assembled.dest);
  });

  test('a missing entry, a symbolic link, a key or state file, or a non-empty destination is refused', (t) => {
    const copy = mkdtempSync(join(tmpdir(), 'build-context-root-'));
    t.after(() => rmSync(copy, { recursive: true, force: true }));
    const cp = (args: string[]) => assert.equal(spawnSync('cp', args).status, 0);
    cp(['-R', join(ROOT, 'src'), join(ROOT, 'proto'), join(ROOT, 'origin'), join(ROOT, 'scripts'), copy]);
    mkdirSync(join(copy, 'tests/container'), { recursive: true });
    mkdirSync(join(copy, 'tests/support'), { recursive: true });
    for (const f of ['cloudbuild.yaml', 'Dockerfile', '.dockerignore', 'package.json', 'package-lock.json', '.npmrc', '.nvmrc', 'LICENSE', 'tests/container/probe.ts', 'tests/support/grpc-client.ts', 'tests/support/http-client.ts', 'tests/support/response-wire.ts', 'tests/support/signing.ts']) {
      cp([join(ROOT, f), join(copy, f)]);
    }
    assert.equal(assemble(t, copy).result.status, 0);

    writeFileSync(join(copy, 'src/agent-key.pem'), 'x');
    let r = assemble(t, copy).result;
    assert.notEqual(r.status, 0);
    assert.match(String(r.stderr), /refusing to upload: \.\/src\/agent-key\.pem/);
    rmSync(join(copy, 'src/agent-key.pem'));

    writeFileSync(join(copy, 'proto/terraform.tfstate'), '{}');
    assert.match(String(assemble(t, copy).result.stderr), /refusing to upload: \.\/proto\/terraform\.tfstate/);
    rmSync(join(copy, 'proto/terraform.tfstate'));

    symlinkSync('/etc/hostname', join(copy, 'src/link'));
    assert.notEqual(assemble(t, copy).result.status, 0);
    rmSync(join(copy, 'src/link'));

    rmSync(join(copy, 'cloudbuild.yaml'));
    r = assemble(t, copy).result;
    assert.match(String(r.stderr), /cloudbuild\.yaml is missing/);
    cp([join(ROOT, 'cloudbuild.yaml'), join(copy, 'cloudbuild.yaml')]);

    const dir = mkdtempSync(join(tmpdir(), 'build-context-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    writeFileSync(join(dir, 'leftover'), 'x');
    r = spawnSync('bash', ['-c', 'source "$1"; assemble_build_context "$2" "$3"', 'x', join(ROOT, 'scripts/lib/build-context.sh'), copy, dir], { encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(String(r.stderr), /is not an empty directory/);
  });
});

describe('the container smoke script in the image build (SMOKE_IMAGES, SMOKE_NETWORK), against a fake docker', () => {
  // TEST ONLY: not Docker. It records calls and answers `info`, and `image inspect` succeeds only for listed images.
  const FAKE = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_STATE/calls"
case "$1 $2" in
  "info "*) exit 0 ;;
  "version "*) echo fake; exit 0 ;;
  "image inspect") shift 2; for i in "$@"; do grep -qx -- "$i" "$FAKE_STATE/images" || exit 1; done; exit 0 ;;
  "ps -aq") exit 0 ;;
  "image ls") exit 0 ;;
esac
exit 99
`;
  function fake(t: TestContext, images: string[]) {
    const dir = mkdtempSync(join(tmpdir(), 'smoke-build-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    mkdirSync(join(dir, 'bin'));
    writeFileSync(join(dir, 'bin/docker'), FAKE, { mode: 0o755 });
    writeFileSync(join(dir, 'images'), images.map((i) => `${i}\n`).join(''));
    writeFileSync(join(dir, 'calls'), '');
    return { dir, calls: () => readFileSync(join(dir, 'calls'), 'utf8') };
  }
  const run = (dir: string, env: Record<string, string>) =>
    spawnSync('bash', [join(ROOT, 'scripts/container-smoke.sh')], {
      cwd: tmpdir(),
      env: { ...process.env, PATH: `${join(dir, 'bin')}:${process.env['PATH'] ?? ''}`, FAKE_STATE: dir, ...env },
      encoding: 'utf8',
      timeout: 30_000,
    });

  test('SMOKE_IMAGES must name exactly two images, and SMOKE_NETWORK must be a network name: else NOT RUN, nothing done', (t) => {
    for (const env of [{ SMOKE_IMAGES: 'only-one' }, { SMOKE_IMAGES: 'a b c' }, { SMOKE_NETWORK: 'bad name;rm' }]) {
      const f = fake(t, []);
      const r = run(f.dir, env);
      assert.equal(r.status, 2, JSON.stringify(env));
      assert.match(r.stderr, /CONTAINER SMOKE NOT RUN/);
      assert.equal(f.calls(), '');
    }
  });

  test('given images that do not exist: a failure, and nothing is built or removed', (t) => {
    const f = fake(t, []);
    const r = run(f.dir, { SMOKE_IMAGES: 'reg/verifier:t reg/origin:t', SMOKE_NETWORK: 'cloudbuild' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /an image named in SMOKE_IMAGES does not exist/);
    assert.doesNotMatch(f.calls(), /^build /m);
    assert.doesNotMatch(f.calls(), /image rm/);
    assert.match(r.stdout, /cleanup: confirmed: no containers or images with label dnsid-gcp-smoke=[0-9a-f]{8}, images {2}absent/);
  });

  test('on the build network, Node.js and installed dependencies are not required on the host', (t) => {
    const f = fake(t, []);
    // PATH without node: the script still gets past its prerequisites to the image check.
    const r = spawnSync('/bin/bash', [join(ROOT, 'scripts/container-smoke.sh')], {
      cwd: tmpdir(),
      env: { PATH: `${join(f.dir, 'bin')}:/usr/bin:/bin`, FAKE_STATE: f.dir, SMOKE_IMAGES: 'reg/v:t reg/o:t', SMOKE_NETWORK: 'cloudbuild' },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.doesNotMatch(r.stderr, /NOT RUN/);
    assert.match(r.stderr, /an image named in SMOKE_IMAGES does not exist/);
  });
});

describe('the container smoke script in the image build: a complete run against a simulated engine', () => {
  // TEST ONLY: a simulated Docker engine, not Docker. Like a real engine it refuses a second container with a name that
  // is still in use (exit 125, "Conflict"), until that container is removed. The images answer the smoke script's
  // inspections with what the real ones are built to have; started containers log their listening and stopped events.
  // Each container is a line "id name image port state" in $FAKE_STATE/containers; every call goes to $FAKE_STATE/calls.
  const ENGINE = `#!/usr/bin/env bash
state="$FAKE_STATE"
echo "$*" >> "$state/calls"
touch "$state/containers"
row() { awk -v c="$1" '$1 == c || $2 == c' "$state/containers"; }
set_state() { awk -v c="$1" -v s="$2" '{ if ($1 == c) $5 = s; print }' "$state/containers" > "$state/c.next"; mv "$state/c.next" "$state/containers"; }
drop() { awk -v c="$1" '$1 != c && $2 != c' "$state/containers" > "$state/c.next"; mv "$state/c.next" "$state/containers"; }
case "$1" in
  info) exit 0 ;;
  version) echo "simulated engine"; exit 0 ;;
  image)
    [[ "$2" == inspect ]] || exit 0
    if [[ "$3" != -f ]]; then exit 0; fi
    fmt="$4" image="$5"
    case "$fmt" in
      *'{{json .Config.Entrypoint}}'*'{{json .Config.Cmd}}'*) echo "id sha256:x platform linux/amd64" ;;
      '{{.Os}}/{{.Architecture}}') echo linux/amd64 ;;
      '{{json .Config.Entrypoint}}') if [[ "$image" == *verifier* ]]; then echo '["node","src/main.ts"]'; else echo '["node","server.ts"]'; fi ;;
      '{{json .Config.Cmd}}') echo null ;;
      '{{.Config.User}}') echo 1000:1000 ;;
    esac
    exit 0 ;;
  run|create)
    command="$1"; shift
    detach="" name="" port="" entry="" image="" key=""
    while (($#)); do
      case "$1" in
        --rm) ;;
        -d) detach=1 ;;
        --platform|--label|--network|-p) shift ;;
        --name) name="$2"; shift ;;
        --entrypoint) entry="$2"; shift ;;
        -e) [[ "$2" == PORT=* ]] && port="\${2#PORT=}"; [[ "$2" == DNSID_TRUSTED_GOVERNANCE= ]] && entry=empty-governance
            # The attestation key, passed by name from the script's environment: a service without it doesn't start.
            [[ "$2" == DNSID_ATTESTATION_KEY && "$DNSID_ATTESTATION_KEY" =~ ^[0-9a-f]{64}$ ]] && key=1; shift ;;
        *) image="$1"; shift; break ;;
      esac
      shift
    done
    if [[ "$command" == create ]]; then
      id="prober-$RANDOM$RANDOM"; echo "$id x $image 0 created" >> "$state/containers"; echo "$id"; exit 0
    fi
    if [[ -n "$detach" ]]; then
      if [[ -n "$name" && -n "$(row "$name")" ]]; then
        echo "docker: Error response from daemon: Conflict. The container name \\"/$name\\" is already in use." >&2
        exit 125
      fi
      id="c-$RANDOM$RANDOM"
      [[ -n "$name" ]] || name="$id"
      echo "$id $name $image \${port:-8080} $([[ -n "$key" ]] && echo running || echo exited)" >> "$state/containers"
      echo "$id"; exit 0
    fi
    case "$entry $*" in
      "node --version") echo v24.22.3 ;;
      "id -u") echo 1000 ;;
      "sh -c "*"npm ls"*) echo done ;;
      "sh -c "*) echo "LICENSE package.json server.ts " ;;
      "empty-governance"*) echo '{"severity":"ERROR","event":"ext_proc_startup_failed","reason":"invalid configuration: DNSID_TRUSTED_GOVERNANCE is set but empty"}'; exit 1 ;;
      " ")
        if [[ -z "$key" ]]; then
          reason='DNSID_ATTESTATION_KEY must be set to 32 to 256 characters from A-Z, a-z, 0-9, \\"-\\" and \\"_\\"'
          if [[ "$image" == *verifier* ]]; then echo "{\\"severity\\":\\"ERROR\\",\\"event\\":\\"ext_proc_startup_failed\\",\\"reason\\":\\"invalid configuration: $reason\\"}"
          else echo "{\\"severity\\":\\"ERROR\\",\\"event\\":\\"origin_startup_failed\\",\\"reason\\":\\"$reason\\"}"; fi
          exit 1
        fi ;;
    esac
    exit 0 ;;
  logs)
    read -r _ _ image port st <<< "$(row "$2")"
    kind=origin; [[ "$image" == *verifier* ]] && kind=ext_proc
    [[ "$st" == exited ]] && { echo "{\\"event\\":\\"\${kind}_startup_failed\\"}"; exit 0; }
    echo "{\\"event\\":\\"\${kind}_listening\\",\\"port\\":$port}"
    [[ "$st" == stopped ]] && echo "{\\"event\\":\\"\${kind}_stopped\\"}"
    exit 0 ;;
  inspect)
    read -r _ name _ _ st <<< "$(row "$4")"
    case "$3" in
      '{{.State.Running}}') [[ "$st" == running ]] && echo true || echo false ;;
      '{{.Name}}') echo "/$name" ;;
      *ExitCode*) echo "0 oom=false" ;;
    esac
    exit 0 ;;
  cp) exit 0 ;;
  start) exit 0 ;;
  stop) set_state "$4" stopped; exit 0 ;;
  rm) [[ "$2" == -f ]] && shift; for c in "\${@:2}"; do drop "$c"; done; exit 0 ;;
  ps) awk '{ print $1 }' "$state/containers"; exit 0 ;;
esac
echo "simulated engine: unexpected: $*" >&2
exit 99
`;

  function engine(t: TestContext) {
    const dir = mkdtempSync(join(tmpdir(), 'smoke-engine-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    mkdirSync(join(dir, 'bin'));
    writeFileSync(join(dir, 'bin/docker'), ENGINE, { mode: 0o755 });
    writeFileSync(join(dir, 'calls'), '');
    return dir;
  }
  const smoke = (dir: string) =>
    spawnSync('bash', [join(ROOT, 'scripts/container-smoke.sh')], {
      cwd: tmpdir(),
      env: { ...process.env, PATH: `${join(dir, 'bin')}:${process.env['PATH'] ?? ''}`, FAKE_STATE: dir, SMOKE_IMAGES: 'reg/verifier:t reg/origin:t', SMOKE_NETWORK: 'cloudbuild' },
      encoding: 'utf8',
      timeout: 60_000,
    });

  test('all four started containers get distinct names, each is removed after its checks, and the run passes', (t) => {
    const dir = engine(t);
    const r = smoke(dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /== container smoke passed/);
    const calls = readFileSync(join(dir, 'calls'), 'utf8').split('\n');
    const names = calls.filter((c) => c.startsWith('run -d ')).map((c) => /--name (\S+)/.exec(c)?.[1]);
    assert.equal(names.length, 4);
    assert.ok(names.every((n) => n !== undefined && /^dnsid-gcp-smoke-[0-9a-f]{8}-/.test(n)), JSON.stringify(names));
    assert.equal(new Set(names).size, 4, `names repeat: ${JSON.stringify(names)}`);
    // Every started container is removed right after its graceful stop, before the next one starts (rm -f is the probes'
    // throwaway containers).
    const order = calls.filter((c) => /^(run -d|stop|rm) /.test(c) && !c.startsWith('rm -f ')).map((c) => c.split(' ')[0]);
    assert.deepEqual(order, ['run', 'stop', 'rm', 'run', 'stop', 'rm', 'run', 'stop', 'rm', 'run', 'stop', 'rm']);
    assert.match(r.stdout, /cleanup: confirmed/);
  });
});

describe('the Terraform configuration', () => {
  const stage = (name: string) =>
    readdirSync(join(ROOT, 'infra', name))
      .filter((f) => f.endsWith('.tf'))
      .map((f) => code(read(`infra/${name}/${f}`)))
      .join('\n');

  test('state is a local backend (its path given at init), and no credentials setting appears anywhere', () => {
    for (const name of ['bootstrap', 'service']) {
      const text = stage(name);
      assert.match(text, /backend "local" \{\}/);
      assert.doesNotMatch(text, /^\s*(credentials|access_token)\s*=/m);
      assert.doesNotMatch(text, /google-beta/);
      assert.match(text, /required_version = ">= 1\.17\.2, < 2\.0\.0"/);
      assert.match(text, /source {2}= "hashicorp\/google"\n\s+version = "~> 8\.11"/);
    }
  });

  test('the service stage has one forwarding rule, HTTPS, and nothing that would open another route', () => {
    const text = stage('service');
    assert.equal(text.match(/resource "google_compute_(global_)?forwarding_rule"/g)?.length, 1);
    assert.match(text, /port_range\s+= "443"/);
    assert.doesNotMatch(text, /google_compute_target_http_proxy|url_rewrite|url_redirect|route_action|path_matcher|host_rule/);
    assert.doesNotMatch(text, /enable_cdn\s+= true|cdn_policy/);
    assert.match(text, /fail_open\s+= false/);
    assert.match(text, /timeout\s+= "3s"/);
    assert.doesNotMatch(text, /forward_headers/);
    assert.match(text, /action\s+= "CUSTOM"/);
    assert.equal(text.match(/ingress\s+= "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"/g)?.length, 2);
    assert.equal(text.match(/default_uri_disabled = true/g)?.length, 2);
    assert.equal(text.match(/deletion_protection\s+= false/g)?.length, 2);
    assert.doesNotMatch(text, /allUsers|google_cloud_run_v2_service_iam/);
  });

  test('the bootstrap stage grants only on its own repository and bucket, and leaves APIs enabled on destroy', () => {
    const text = stage('bootstrap');
    assert.doesNotMatch(text, /google_project_iam|google_organization_iam|roles\/(owner|editor)/);
    assert.equal(text.match(/resource "google_[a-z_]+_iam_member"/g)?.length, 3);
    assert.match(text, /disable_on_destroy = false/);
    assert.match(text, /force_destroy\s+= true/);
  });

  test('the provider locks pin exact versions with checksums for Linux and macOS on amd64 and arm64', () => {
    const locks: [string, string, string[]][] = [
      ['bootstrap', 'google', ['8.11.0']],
      ['service', 'google', ['8.11.0']],
      ['service', 'tls', ['4.4.2']],
    ];
    for (const [name, provider, [version]] of locks) {
      const lock = read(`infra/${name}/.terraform.lock.hcl`);
      const block = lock.slice(lock.indexOf(`provider "registry.terraform.io/hashicorp/${provider}"`));
      assert.match(block, new RegExp(`^\\s+version\\s+= "${version?.replace(/\./g, '\\.')}"`, 'm'), `${name} ${provider}`);
      const h1 = block.slice(0, block.indexOf('}')).match(/"h1:/g)?.length ?? 0;
      const zh = block.slice(0, block.indexOf('}')).match(/"zh:/g)?.length ?? 0;
      assert.ok(h1 >= 4, `${name} ${provider}: ${h1} h1 hashes`);
      assert.ok(zh >= 4, `${name} ${provider}: ${zh} zh hashes`);
    }
    assert.doesNotMatch(read('infra/bootstrap/.terraform.lock.hcl'), /hashicorp\/tls/);
  });
});
