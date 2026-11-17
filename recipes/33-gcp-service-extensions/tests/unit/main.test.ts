// The verifier's executable, run as a child process exactly as Cloud Run would run it (`node src/main.ts`, with `PORT`),
// with the production runtime and its default governance. Only requests the verifier refuses before any identity
// lookup are sent, so nothing leaves this machine. Every child is stopped and every port released by the end.

import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { createServer, type Server } from 'node:net';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';

import { ATTESTATION_KEY_SETTING } from '../../src/attestation.ts';
import { portFromSetting, DEFAULT_PORT, StartupError } from '../../src/main.ts';
import { byteClient, exchange, status } from '../support/grpc-client.ts';
import { decodeDenial } from '../support/response-wire.ts';
import { serialize } from '../support/signing.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
/** The attestation key every child gets unless a test sets DNSID_ATTESTATION_KEY itself (to a value, or undefined: none). */
const KEY = 'test-attestation-key-0123456789abcdefghijklmnop';

async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, '0.0.0.0');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  server.close();
  await once(server, 'close');
  return port;
}

interface Child {
  readonly process: ChildProcess;
  stdout: string;
  stderr: string;
  readonly exited: Promise<number | null>;
}

function run(t: TestContext, env: Record<string, string | undefined>): Child {
  const childEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && key !== 'PORT' && key !== 'DNSID_TRUSTED_GOVERNANCE' && key !== ATTESTATION_KEY_SETTING) childEnv[key] = value;
  }
  for (const [key, value] of Object.entries(ATTESTATION_KEY_SETTING in env ? env : { [ATTESTATION_KEY_SETTING]: KEY, ...env })) if (value !== undefined) childEnv[key] = value;
  const child = spawn(process.execPath, ['src/main.ts'], { cwd: ROOT, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  const result: Child = {
    process: child,
    stdout: '',
    stderr: '',
    exited: new Promise((resolve) => child.on('exit', (code) => resolve(code))),
  };
  child.stdout.on('data', (chunk: Buffer) => (result.stdout += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (result.stderr += chunk.toString()));
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await result.exited;
    }
  });
  return result;
}

async function untilOutput(child: Child, text: string, timeoutMs = 10_000): Promise<void> {
  const end = performance.now() + timeoutMs;
  while (!child.stdout.includes(text)) {
    if (performance.now() > end || child.process.exitCode !== null) throw new Error(`no "${text}" from the child: ${child.stderr}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function lines(text: string): Record<string, unknown>[] {
  return text
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function portIsFree(port: number): Promise<boolean> {
  const server: Server = createServer();
  server.listen(port, '0.0.0.0');
  const [event] = await Promise.race([once(server, 'listening').then(() => ['listening']), once(server, 'error').then(() => ['error'])]);
  if (event === 'listening') {
    server.close();
    await once(server, 'close');
  }
  return event === 'listening';
}

describe('main: PORT', () => {
  test('absent is 8080; a whole number from 1 to 65535 is used; anything else is refused without echoing it', () => {
    assert.equal(DEFAULT_PORT, 8080);
    assert.equal(portFromSetting(undefined), 8080);
    assert.equal(portFromSetting('9090'), 9090);
    assert.equal(portFromSetting('65535'), 65_535);
    for (const bad of ['', '0', '65536', '-1', '80.5', ' 80', '0x50', '8080abc', '100000']) {
      assert.throws(() => portFromSetting(bad), (error: unknown) => error instanceof StartupError && !error.message.includes(bad || '\u0000'), bad);
    }
  });
});

describe('main: the executable', () => {
  test('binds 0.0.0.0 at PORT, answers over plaintext HTTP/2, logs one record per stream, and exits 0 on SIGTERM', async (t) => {
    const port = await freePort();
    const child = run(t, { PORT: String(port) });
    await untilOutput(child, 'ext_proc_listening');
    const client = byteClient(port);
    t.after(() => client.close());
    // A request with no signature: refused by the production verifier before any identity lookup.
    const { stream, status: final } = await exchange(client, serialize([[':method', 'GET'], [':authority', 'api-example.test'], [':path', '/'], [':scheme', 'https']]));
    assert.equal(final.code, status.OK);
    assert.equal(stream.responses.length, 1);
    assert.equal(decodeDenial(stream.responses[0] as Buffer).body.toString(), 'signature_missing');
    client.close();
    child.process.kill('SIGTERM');
    assert.equal(await child.exited, 0);
    const records = lines(child.stdout);
    assert.deepEqual(records.map((r) => r['event']), ['ext_proc_listening', 'ext_proc_stream', 'ext_proc_stopped']);
    assert.deepEqual(records[0], { severity: 'INFO', event: 'ext_proc_listening', port });
    assert.equal(records[1]?.['outcome'], 'deny_submitted');
    assert.equal(records[1]?.['reason'], 'signature_missing');
    assert.equal(child.stderr, '');
    assert.equal(await portIsFree(port), true, 'the port is released');
  });

  test('an unknown DNSID_LOG_EVIDENCE: a fixed diagnostic, exit 1, nothing listening', async (t) => {
    const port = await freePort();
    const child = run(t, { PORT: String(port), DNSID_LOG_EVIDENCE: 'SECRET-VALUE' });
    assert.equal(await child.exited, 1);
    assert.deepEqual(lines(child.stderr), [{ severity: 'ERROR', event: 'ext_proc_startup_failed', reason: 'invalid configuration: DNSID_LOG_EVIDENCE must be bundle or full-scan' }]);
    assert.equal(child.stderr.includes('SECRET'), false);
    assert.equal(child.stdout, '');
    assert.equal(await portIsFree(port), true);
  });

  test('no DNSID_ATTESTATION_KEY, or one not of the required form: a fixed diagnostic that never repeats it, exit 1, nothing listening', async (t) => {
    for (const value of [undefined, '', 'SECRET-but-too-short', `SECRET${'a'.repeat(40)}=`, `SECRET${'b'.repeat(251)}`]) {
      const port = await freePort();
      const child = run(t, { PORT: String(port), [ATTESTATION_KEY_SETTING]: value });
      assert.equal(await child.exited, 1, String(value));
      assert.deepEqual(lines(child.stderr), [
        { severity: 'ERROR', event: 'ext_proc_startup_failed', reason: 'invalid configuration: DNSID_ATTESTATION_KEY must be set to 32 to 256 characters from A-Z, a-z, 0-9, "-" and "_"' },
      ]);
      assert.equal(child.stderr.includes('SECRET'), false);
      assert.equal(child.stdout, '');
      assert.equal(await portIsFree(port), true);
    }
  });

  test('invalid governance configuration: a fixed diagnostic, exit 1, nothing listening', async (t) => {
    const port = await freePort();
    const child = run(t, { PORT: String(port), DNSID_TRUSTED_GOVERNANCE: 'SECRET-VALUE.example,' });
    // The second entry is empty; the first is never echoed.
    assert.equal(await child.exited, 1);
    assert.deepEqual(lines(child.stderr), [{ severity: 'ERROR', event: 'ext_proc_startup_failed', reason: 'invalid configuration: trusted governance entry 2 is empty or padded' }]);
    assert.equal(child.stderr.includes('SECRET'), false);
    assert.equal(child.stdout, '');
    assert.equal(await portIsFree(port), true);
  });

  test('an explicitly empty governance setting or an invalid PORT: exit 1, nothing listening', async (t) => {
    const empty = run(t, { PORT: String(await freePort()), DNSID_TRUSTED_GOVERNANCE: '' });
    assert.equal(await empty.exited, 1);
    assert.match(empty.stderr, /DNSID_TRUSTED_GOVERNANCE is set but empty/);
    const badPort = run(t, { PORT: 'not-a-port' });
    assert.equal(await badPort.exited, 1);
    assert.deepEqual(lines(badPort.stderr), [{ severity: 'ERROR', event: 'ext_proc_startup_failed', reason: 'PORT is not a port number' }]);
  });

  test('a port already in use: a fixed diagnostic without system error text, exit 1', async (t) => {
    const blocker = createServer();
    blocker.listen(0, '0.0.0.0');
    await once(blocker, 'listening');
    t.after(() => blocker.close());
    const { port } = blocker.address() as { port: number };
    const child = run(t, { PORT: String(port) });
    assert.equal(await child.exited, 1);
    // grpc-js's own bind error is reduced to a fixed record by the executable's logger.
    assert.deepEqual(lines(child.stderr), [
      { severity: 'ERROR', event: 'grpc_library_error' },
      { severity: 'ERROR', event: 'ext_proc_startup_failed', reason: `could not listen on port ${port}` },
    ]);
    assert.equal(/EADDRINUSE|errno|Error/.test(child.stderr), false);
  });

  test('importing the modules starts no listener', async (t) => {
    const child = spawn(
      process.execPath,
      ['--input-type=module', '-e', "await import('./src/main.ts'); await import('./src/service.ts'); console.log(JSON.stringify(process.getActiveResourcesInfo()));"],
      { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    t.after(() => child.kill('SIGKILL'));
    let out = '';
    child.stdout.on('data', (chunk: Buffer) => (out += chunk.toString()));
    const [code] = await once(child, 'exit');
    assert.equal(code, 0);
    assert.equal((JSON.parse(out) as string[]).includes('TCPServerWrap'), false);
  });
});
