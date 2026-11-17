// The container smoke check's cleanup (scripts/lib/container-cleanup.sh), against a fake `docker` on PATH: a shell script
// that keeps containers and images as lines in files and fails the operations a test asks it to. No container engine is
// used. The cleanup must report only what its final inventory confirms, and exit non-zero whenever it can't confirm it.
// The last cases run scripts/container-smoke.sh itself, to check its exit trap carries the cleanup result.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const LIBRARY = join(ROOT, 'scripts/lib/container-cleanup.sh');
const SMOKE = join(ROOT, 'scripts/container-smoke.sh');
const LABEL = 'dnsid-gcp-smoke=feedface';
const VERIFIER = 'dnsid-gcp-smoke-verifier:feedface';
const ORIGIN = 'dnsid-gcp-smoke-origin:feedface';

// TEST ONLY: not Docker. State: `containers` holds one id per line; `images` holds "reference label" per line. Every
// call is appended to `calls`. FAKE_* variables make one kind of operation fail, or report success without removing.
const FAKE_DOCKER = `#!/usr/bin/env bash
state="$FAKE_DOCKER_STATE"
echo "$*" >> "$state/calls"
case "$1 $2" in
  "info "*) exit "\${FAKE_INFO_RC:-0}" ;;
  "version "*) echo "fake docker"; exit 0 ;;
  "build "*) [[ -n "\${FAKE_BUILD_FAIL:-}" ]] && exit 1
    label="" ref=""
    while (($#)); do case "$1" in --label) label="$2"; shift ;; -t) ref="$2"; shift ;; esac; shift; done
    echo "$ref $label" >> "$state/images"; exit 0 ;;
  "ps -aq") [[ -n "\${FAKE_PS_FAIL:-}" ]] && exit 1; cat "$state/containers"; exit 0 ;;
  "rm -f") [[ -n "\${FAKE_RM_FAIL:-}" ]] && exit 1
    [[ -n "\${FAKE_RM_STICKY:-}" ]] && exit 0
    : > "$state/containers"; exit 0 ;;
  "image ls") [[ -n "\${FAKE_IMAGE_LS_FAIL:-}" ]] && exit 1
    if [[ "$4" == --filter ]]; then
      awk -v l="\${5#label=}" '$2 == l { print "sha-" NR }' "$state/images"
    else
      awk -v r="$4" '$1 == r { print "sha-" NR }' "$state/images"
    fi
    exit 0 ;;
  "image rm") [[ -n "\${FAKE_IMAGE_RM_FAIL:-}" ]] && exit 1
    shift 3
    for target in "$@"; do
      awk -v t="$target" '$1 != t && ("sha-" NR) != t' "$state/images" > "$state/images.next"
      mv "$state/images.next" "$state/images"
    done
    exit 0 ;;
esac
echo "fake docker: unexpected: $*" >&2
exit 99
`;

interface Fake {
  readonly dir: string;
  readonly work: string;
  readonly env: Record<string, string>;
  containers(): string[];
  images(): string[];
}

function fake(t: TestContext, options: { containers?: string[]; images?: string[]; fail?: Record<string, string> } = {}): Fake {
  const dir = mkdtempSync(join(tmpdir(), 'cleanup-test-'));
  t.after(() => {
    // A test may have made the scratch directory unremovable.
    if (existsSync(join(dir, 'work'))) chmodSync(join(dir, 'work'), 0o700);
    rmSync(dir, { recursive: true, force: true });
  });
  mkdirSync(join(dir, 'bin'));
  writeFileSync(join(dir, 'bin/docker'), FAKE_DOCKER, { mode: 0o755 });
  mkdirSync(join(dir, 'state'));
  writeFileSync(join(dir, 'state/containers'), (options.containers ?? []).map((id) => `${id}\n`).join(''));
  writeFileSync(join(dir, 'state/images'), (options.images ?? []).map((line) => `${line}\n`).join(''));
  writeFileSync(join(dir, 'state/calls'), '');
  const work = join(dir, 'work');
  mkdirSync(work);
  writeFileSync(join(work, 'scratch'), 'x');
  const read = (name: string) => readFileSync(join(dir, 'state', name), 'utf8').split('\n').filter((line) => line.length > 0);
  return {
    dir,
    work,
    env: { ...cleanEnv(), PATH: `${join(dir, 'bin')}:${process.env['PATH'] ?? ''}`, FAKE_DOCKER_STATE: join(dir, 'state'), ...options.fail },
    containers: () => read('containers'),
    images: () => read('images'),
  };
}

function cleanEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) if (value !== undefined && !key.startsWith('FAKE_')) env[key] = value;
  return env;
}

function cleanup(f: Fake, status: number): { code: number | null; stdout: string; stderr: string } {
  const result = spawnSync(
    'bash',
    ['-c', 'set -euo pipefail; source "$1"; shift; smoke_cleanup "$@"', 'cleanup', LIBRARY, String(status), LABEL, f.work, VERIFIER, ORIGIN],
    { env: f.env, encoding: 'utf8', timeout: 20_000 },
  );
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

const LEFTOVERS = { containers: ['c1', 'c2'], images: [`${VERIFIER} ${LABEL}`, `${ORIGIN} ${LABEL}`, `unrelated:1 other=1`] };

describe('container smoke: cleanup is confirmed by a final inventory', () => {
  test('everything removed: the run status is kept, and the report says what the inventory confirmed', (t) => {
    for (const status of [0, 1, 2]) {
      const f = fake(t, LEFTOVERS);
      const result = cleanup(f, status);
      assert.equal(result.code, status);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /^cleanup: confirmed: no containers or images with label dnsid-gcp-smoke=feedface/);
      assert.deepEqual(f.containers(), []);
      assert.deepEqual(f.images(), ['unrelated:1 other=1']);
      assert.equal(existsSync(f.work), false);
    }
  });

  test('nothing to remove: still confirmed, exit 0', (t) => {
    const f = fake(t);
    const result = cleanup(f, 0);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /^cleanup: confirmed/);
  });

  const failures: [string, Record<string, string>, RegExp][] = [
    ['a container removal fails', { FAKE_RM_FAIL: '1' }, /removing containers failed[\s\S]*containers left: c1 c2/],
    ['a container removal reports success but the containers remain', { FAKE_RM_STICKY: '1' }, /containers left: c1 c2/],
    ['an image removal fails', { FAKE_IMAGE_RM_FAIL: '1' }, /removing image dnsid-gcp-smoke-verifier:feedface failed[\s\S]*image left: dnsid-gcp-smoke-origin:feedface/],
    ['the container inventory cannot be taken', { FAKE_PS_FAIL: '1' }, /listing containers failed[\s\S]*the final container inventory could not be taken/],
    ['the image inventory cannot be taken', { FAKE_IMAGE_LS_FAIL: '1' }, /the final image inventory could not be taken/],
  ];
  for (const [name, fail, reason] of failures) {
    test(`${name}: not confirmed, a passing run exits 1, a failed run keeps its status`, (t) => {
      for (const [status, expected] of [[0, 1], [1, 1], [2, 2]] as const) {
        const f = fake(t, { ...LEFTOVERS, fail });
        const result = cleanup(f, status);
        assert.equal(result.code, expected, `status ${status}`);
        assert.match(result.stderr, /^CLEANUP NOT CONFIRMED: /m);
        assert.match(result.stderr, reason);
        assert.equal(result.stdout.includes('confirmed'), false, result.stdout);
      }
    });
  }

  test('the temporary directory cannot be removed: not confirmed, exit 1', (t) => {
    const f = fake(t, LEFTOVERS);
    chmodSync(f.work, 0o500);
    const result = cleanup(f, 0);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /removing the temporary directory failed[\s\S]*temporary directory left: /);
    assert.equal(existsSync(f.work), true);
    // The removals that could happen still happened.
    assert.deepEqual(f.containers(), []);
  });
});

describe('container smoke: the script carries the cleanup result into its exit code', () => {
  function smoke(f: Fake): { code: number | null; stdout: string; stderr: string } {
    const result = spawnSync('bash', [SMOKE], { cwd: tmpdir(), env: f.env, encoding: 'utf8', timeout: 60_000 });
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  }

  test('no engine: exit 2, NOT RUN, and nothing is built or cleaned', (t) => {
    const f = fake(t, { fail: { FAKE_INFO_RC: '1' } });
    const result = smoke(f);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /CONTAINER SMOKE NOT RUN/);
    assert.equal(result.stdout.includes('PASS'), false);
    assert.equal(readFileSync(join(f.dir, 'state/calls'), 'utf8').includes('build'), false);
  });

  test('a failed build with confirmed cleanup: exit 1, the images it built are gone', (t) => {
    // The first build succeeds and the second fails, so one labeled image exists when the cleanup runs.
    const f = fake(t);
    const bin = join(f.dir, 'bin/docker');
    writeFileSync(bin, FAKE_DOCKER.replace('"build "*) [[ -n "${FAKE_BUILD_FAIL:-}" ]] && exit 1', '"build "*) [[ -f "$state/built" ]] && exit 1; touch "$state/built"'), { mode: 0o755 });
    const result = smoke(f);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /CONTAINER SMOKE FAILED: the Demo Bank image did not build/);
    assert.match(result.stdout, /cleanup: confirmed/);
    assert.deepEqual(f.images(), []);
  });

  test('a failed build whose cleanup cannot be confirmed: exit 1 and CLEANUP NOT CONFIRMED, never "confirmed"', (t) => {
    const f = fake(t, { containers: ['c1'], fail: { FAKE_BUILD_FAIL: '1', FAKE_RM_STICKY: '1' } });
    const result = smoke(f);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /CLEANUP NOT CONFIRMED: containers left: c1/);
    assert.equal(result.stdout.includes('cleanup: confirmed'), false);
  });
});
