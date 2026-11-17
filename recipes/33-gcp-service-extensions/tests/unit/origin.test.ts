// Demo Bank, the protected origin, over real local HTTP/1.1 connections: the handler in process on loopback, and the
// executable as a child process (`node origin/server.ts`, with `PORT`) exactly as its container runs it. Every listener
// and child is closed by the end.

import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { connect, createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { describe, test, type TestContext } from 'node:test';

import { ATTESTATION_HEADER as VERIFIER_ATTESTATION_HEADER, attest } from '../../src/attestation.ts';
import {
  ATTESTATION_HEADER,
  ATTESTATION_KEY_SETTING,
  ATTESTATION_MAX_AGE_S,
  ATTESTATION_MAX_FUTURE_S,
  BANK,
  DEFAULT_PORT,
  GOVERNANCE_ID_HEADER,
  SHUTDOWN_GRACE_MS,
  StartupError,
  VERIFIED_DOMAIN_HEADER,
  accountsFor,
  attestationKeyFromSetting,
  checkAttestation,
  identityContext,
  listen,
  portFromSetting,
  type Origin,
  type OriginRecord,
} from '../../origin/server.ts';
import { call } from '../support/http-client.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DOMAIN = 'agent-gov-fixture.test';
const GOVERNANCE = 'gov-fixture.test';
/** This test deployment's attestation key, as Terraform would generate it, and the clock the in-process origin runs on. */
const KEY = randomBytes(36).toString('base64url');
const KEY_BYTES = Buffer.from(KEY, 'ascii');
const NOW = Date.now();

/** The identity headers as the verifier sets them: both values and its attestation of them, made at `at`. */
function attested(domain: string, governance: string, at = NOW, key: Uint8Array = KEY_BYTES): [string, string][] {
  return [
    [VERIFIED_DOMAIN_HEADER, domain],
    [GOVERNANCE_ID_HEADER, governance],
    [ATTESTATION_HEADER, attest(key, domain, governance, at)],
  ];
}

const IDENTITY = attested(DOMAIN, GOVERNANCE);
const RECORD_KEYS = ['event', 'id', 'method', 'outcome', 'route', 'severity', 'status'];
/** Header names that an object lookup would find on Object.prototype. */
const HOSTILE_NAMES = ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty', '__defineGetter__', 'isPrototypeOf'];

async function origin(t: TestContext, shutdownGraceMs = 200): Promise<{ origin: Origin; records: OriginRecord[] }> {
  const records: OriginRecord[] = [];
  const started = await listen('127.0.0.1', 0, { attestationKey: KEY_BYTES, now: () => NOW, log: (record) => void records.push(record), shutdownGraceMs });
  t.after(() => started.stop());
  return { origin: started, records };
}

function assertNoLeak(text: string): void {
  for (const leak of ['secret', 'signature', 'sig1', 'authorization', 'Bearer', 'view=', '?', '/accounts', 'evil', 'Error', 'stack']) {
    assert.equal(text.includes(leak), false, `"${leak}" in a log record`);
  }
}

describe('origin: the identity context', () => {
  test('exactly one of each header, each a domain name of at most 253 characters', () => {
    assert.deepEqual(identityContext([VERIFIED_DOMAIN_HEADER, DOMAIN, GOVERNANCE_ID_HEADER, GOVERNANCE]), { verifiedDomain: DOMAIN, governanceId: GOVERNANCE });
    // Header names are matched case-insensitively, as HTTP defines them.
    assert.deepEqual(identityContext(['X-DNSid-Verified-Domain', DOMAIN, 'X-DNSID-GOVERNANCE-ID', GOVERNANCE]), { verifiedDomain: DOMAIN, governanceId: GOVERNANCE });
    const long = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(58)}.io`;
    assert.equal(long.length, 253);
    assert.deepEqual(identityContext([VERIFIED_DOMAIN_HEADER, long, GOVERNANCE_ID_HEADER, GOVERNANCE]), { verifiedDomain: long, governanceId: GOVERNANCE });
  });

  test('missing either header is identity_missing', () => {
    assert.equal(identityContext([]), 'identity_missing');
    assert.equal(identityContext([VERIFIED_DOMAIN_HEADER, DOMAIN]), 'identity_missing');
    assert.equal(identityContext([GOVERNANCE_ID_HEADER, GOVERNANCE]), 'identity_missing');
  });

  test('repeated, empty, overlong or not a domain name is identity_malformed', () => {
    const cases: [string, string][] = [
      ['', GOVERNANCE],
      [DOMAIN, ''],
      [`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(59)}.io`, GOVERNANCE],
      ['Agent-Gov-Fixture.Test', GOVERNANCE],
      ['localhost', GOVERNANCE],
      ['10.0.0.1', GOVERNANCE],
      [`${DOMAIN}.`, GOVERNANCE],
      [` ${DOMAIN}`, GOVERNANCE],
      [`${DOMAIN}, evil.example`, GOVERNANCE],
      ['agent_x-gov-fixture.test', GOVERNANCE],
      ['-agent-gov-fixture.test', GOVERNANCE],
      [DOMAIN, 'gov..fixture.test'],
      [DOMAIN, 'gov-fixture.test\u0000'],
    ];
    for (const [domain, governance] of cases) {
      assert.equal(identityContext([VERIFIED_DOMAIN_HEADER, domain, GOVERNANCE_ID_HEADER, governance]), 'identity_malformed', JSON.stringify([domain, governance]));
    }
    assert.equal(identityContext([VERIFIED_DOMAIN_HEADER, DOMAIN, VERIFIED_DOMAIN_HEADER, DOMAIN, GOVERNANCE_ID_HEADER, GOVERNANCE]), 'identity_malformed');
    assert.equal(identityContext([VERIFIED_DOMAIN_HEADER, DOMAIN, GOVERNANCE_ID_HEADER, GOVERNANCE, 'x-dnsid-governance-id', GOVERNANCE]), 'identity_malformed');
  });

  test('header names that are Object.prototype properties are ordinary headers, with or without the identity context', () => {
    for (const name of HOSTILE_NAMES) {
      for (const casing of [name, name.toUpperCase()]) {
        assert.deepEqual(identityContext([casing, 'x', VERIFIED_DOMAIN_HEADER, DOMAIN, GOVERNANCE_ID_HEADER, GOVERNANCE]), { verifiedDomain: DOMAIN, governanceId: GOVERNANCE }, casing);
        assert.deepEqual(identityContext([VERIFIED_DOMAIN_HEADER, DOMAIN, GOVERNANCE_ID_HEADER, GOVERNANCE, casing, 'x']), { verifiedDomain: DOMAIN, governanceId: GOVERNANCE }, casing);
        assert.equal(identityContext([casing, 'x']), 'identity_missing', casing);
        assert.equal(identityContext([casing, DOMAIN, VERIFIED_DOMAIN_HEADER, DOMAIN]), 'identity_missing', casing);
      }
    }
  });
});

describe("origin: the verifier's attestation of the identity context", () => {
  const ID = { verifiedDomain: DOMAIN, governanceId: GOVERNANCE };
  const raw = (headers: [string, string][]) => headers.flat();
  const value = (at = NOW, key: Uint8Array = KEY_BYTES, domain = DOMAIN, governance = GOVERNANCE) => attest(key, domain, governance, at);

  test("the verifier's own attestation (src/attestation.ts) is accepted: the same header, key form, input and window", () => {
    assert.equal(VERIFIER_ATTESTATION_HEADER, ATTESTATION_HEADER);
    assert.equal(ATTESTATION_MAX_AGE_S, 30);
    assert.equal(ATTESTATION_MAX_FUTURE_S, 5);
    assert.match(value(), /^v1\.[0-9]+\.[A-Za-z0-9_-]{43}$/);
    assert.equal(checkAttestation(raw(IDENTITY), ID, KEY_BYTES, NOW), 'attested');
    // Header names in any letter case, as HTTP defines them.
    assert.equal(checkAttestation(['X-DNSid-Attestation', value()], ID, KEY_BYTES, NOW), 'attested');
    assert.deepEqual(attestationKeyFromSetting(KEY), KEY_BYTES);
  });

  test('missing is attestation_missing; repeated, malformed, forged, under another key or for another identity is attestation_invalid', () => {
    assert.equal(checkAttestation(raw([[VERIFIED_DOMAIN_HEADER, DOMAIN], [GOVERNANCE_ID_HEADER, GOVERNANCE]]), ID, KEY_BYTES, NOW), 'attestation_missing');
    const good = value();
    const [, seconds, mac] = good.split('.') as [string, string, string];
    const flipped = `${mac.slice(0, 10)}${mac[10] === 'A' ? 'B' : 'A'}${mac.slice(11)}`;
    const invalid: [string, string[]][] = [
      ['repeated', [ATTESTATION_HEADER, good, ATTESTATION_HEADER, good]],
      ['empty', [ATTESTATION_HEADER, '']],
      ['another version', [ATTESTATION_HEADER, `v2.${seconds}.${mac}`]],
      ['no time', [ATTESTATION_HEADER, `v1..${mac}`]],
      ['a short MAC', [ATTESTATION_HEADER, `v1.${seconds}.${mac.slice(1)}`]],
      ['standard base64', [ATTESTATION_HEADER, `v1.${seconds}.${mac.slice(0, 42)}+`]],
      ['surrounding space', [ATTESTATION_HEADER, ` ${good}`]],
      ['a MAC with one character changed', [ATTESTATION_HEADER, `v1.${seconds}.${flipped}`]],
      ['a MAC of zeros', [ATTESTATION_HEADER, `v1.${seconds}.${'A'.repeat(43)}`]],
      ['the time changed', [ATTESTATION_HEADER, `v1.${Number(seconds) - 1}.${mac}`]],
      ['another key', [ATTESTATION_HEADER, value(NOW, randomBytes(32))]],
      ["another domain's", [ATTESTATION_HEADER, value(NOW, KEY_BYTES, 'other-gov2-fixture.test')]],
      ["another governance ID's", [ATTESTATION_HEADER, value(NOW, KEY_BYTES, DOMAIN, 'gov2-fixture.test')]],
      // A forgery claiming an old time is still a forgery, not merely stale.
      ['another key, long ago', [ATTESTATION_HEADER, value(NOW - 3_600_000, randomBytes(32))]],
    ];
    for (const [label, headers] of invalid) assert.equal(checkAttestation(headers, ID, KEY_BYTES, NOW), 'attestation_invalid', label);
  });

  test('older than 30 s or more than 5 s ahead of the clock is attestation_stale; within that window it is accepted', () => {
    const at = (offsetS: number) => [ATTESTATION_HEADER, value(NOW + offsetS * 1000)];
    for (const offset of [0, -ATTESTATION_MAX_AGE_S, ATTESTATION_MAX_FUTURE_S]) assert.equal(checkAttestation(at(offset), ID, KEY_BYTES, NOW), 'attested', String(offset));
    for (const offset of [-ATTESTATION_MAX_AGE_S - 1, -3600, ATTESTATION_MAX_FUTURE_S + 1]) assert.equal(checkAttestation(at(offset), ID, KEY_BYTES, NOW), 'attestation_stale', String(offset));
  });

  test("forged identity headers reach Demo Bank (as when the load balancer skips the authorization policy): refused, nothing served, the claimed identity and the attestation never logged", async (t) => {
    const { origin: o, records } = await origin(t);
    const forged: [string, string][] = [
      [VERIFIED_DOMAIN_HEADER, DOMAIN],
      [GOVERNANCE_ID_HEADER, GOVERNANCE],
    ];
    const forgedValue = `v1.${Math.floor(NOW / 1000)}.${'A'.repeat(43)}`;
    const cases: [string, [string, string][], string][] = [
      ['GET', forged, 'identity_attestation_required'],
      ['HEAD', forged, 'identity_attestation_required'],
      ['GET', [...forged, [ATTESTATION_HEADER, forgedValue]], 'identity_attestation_invalid'],
      ['GET', [...forged, [ATTESTATION_HEADER, value(NOW, randomBytes(32))]], 'identity_attestation_invalid'],
      ['GET', attested(DOMAIN, GOVERNANCE, NOW - 60_000), 'identity_attestation_stale'],
      ['GET', [...IDENTITY, [ATTESTATION_HEADER, value()]], 'identity_attestation_invalid'],
    ];
    for (const [method, headers, error] of cases) {
      for (const path of ['/accounts', `/accounts/${accountsFor(DOMAIN)[0]?.id}`]) {
        const reply = await call(o.port, method, path, headers);
        assert.equal(reply.status, 403, `${method} ${path} ${error}`);
        assert.equal(reply.headers['cache-control'], 'no-store');
        assert.equal(reply.body, method === 'HEAD' ? '' : JSON.stringify({ error }));
        assert.equal(reply.body.includes('demo-'), false);
      }
    }
    assert.deepEqual(
      records.map((r) => r.outcome),
      ['attestation_missing', 'attestation_missing', 'attestation_missing', 'attestation_missing', 'attestation_invalid', 'attestation_invalid', 'attestation_invalid', 'attestation_invalid', 'attestation_stale', 'attestation_stale', 'attestation_invalid', 'attestation_invalid'],
    );
    for (const record of records) assert.deepEqual(Object.keys(record).sort(), RECORD_KEYS);
    const text = JSON.stringify(records);
    assert.equal(text.includes(DOMAIN), false);
    assert.equal(text.includes(KEY), false);
    assert.equal(text.includes('v1.'), false);
    // The verifier's attestation, by contrast, is served.
    assert.equal((await call(o.port, 'GET', '/accounts', IDENTITY)).status, 200);
    assert.equal(JSON.stringify(records).includes(KEY), false);
  });

  test('Demo Bank never starts without a key of at least 32 bytes', async () => {
    await assert.rejects(listen('127.0.0.1', 0, {} as never), StartupError);
    await assert.rejects(listen('127.0.0.1', 0, { attestationKey: randomBytes(31) }), StartupError);
    for (const bad of [undefined, '', 'x'.repeat(31), `${'x'.repeat(31)}=`, 'y'.repeat(257)]) {
      assert.throws(() => attestationKeyFromSetting(bad), (error: unknown) => error instanceof StartupError && !error.message.includes(String(bad || 'none-given')), String(bad));
    }
  });
});

describe("origin: Demo Bank's account policy (the application's authorization, not the edge's)", () => {
  const OTHER_DOMAIN = 'other-gov2-fixture.test';
  const OTHER_IDENTITY = attested(OTHER_DOMAIN, 'gov2-fixture.test');

  test('each verified domain maps to its own two synthetic accounts: stable, distinct between domains', () => {
    const mine = accountsFor(DOMAIN);
    assert.deepEqual(accountsFor(DOMAIN), mine);
    assert.deepEqual(mine.map((a) => a.type), ['checking', 'savings']);
    for (const a of mine) {
      assert.match(a.id, /^demo-(checking|savings)-[0-9a-f]{10}$/);
      assert.match(a.balance, /^[0-9]+\.[0-9]{2}$/);
      assert.equal(a.currency, 'USD');
    }
    const theirs = new Set(accountsFor(OTHER_DOMAIN).map((a) => a.id));
    for (const a of mine) assert.equal(theirs.has(a.id), false);
  });

  test("a trusted, verified agent reads its own account and is refused another agent's, whatever governance vouched for it", async (t) => {
    const { origin: o, records } = await origin(t);
    const [own] = accountsFor(DOMAIN);
    const [theirs] = accountsFor(OTHER_DOMAIN);
    const served = await call(o.port, 'GET', `/accounts/${own?.id}`, IDENTITY);
    assert.equal(served.status, 200);
    assert.deepEqual(JSON.parse(served.body), { ...BANK, account: own, caller: { verifiedDomain: DOMAIN, governanceId: GOVERNANCE } });
    // The other agent's account: refused by Demo Bank, with the identity context intact.
    const refused = await call(o.port, 'GET', `/accounts/${theirs?.id}`, IDENTITY);
    assert.equal(refused.status, 403);
    assert.equal(refused.headers['cache-control'], 'no-store');
    assert.equal(refused.body, '{"error":"account_not_permitted"}');
    // The other agent reads it; an account that exists for nobody gets the same refusal as someone else's.
    assert.equal((await call(o.port, 'GET', `/accounts/${theirs?.id}`, OTHER_IDENTITY)).status, 200);
    const nobody = await call(o.port, 'GET', '/accounts/demo-checking-0000000000', IDENTITY);
    assert.equal(nobody.status, 403);
    assert.equal(nobody.body, refused.body);
    // HEAD: the same status, no body. Without the identity context: the identity refusal comes first.
    const head = await call(o.port, 'HEAD', `/accounts/${theirs?.id}`, IDENTITY);
    assert.equal(head.status, 403);
    assert.equal(head.body, '');
    assert.equal((await call(o.port, 'GET', `/accounts/${own?.id}`, [])).body, '{"error":"identity_context_required"}');
    // The list for each caller is its own.
    assert.deepEqual(JSON.parse((await call(o.port, 'GET', '/accounts', OTHER_IDENTITY)).body).accounts, accountsFor(OTHER_DOMAIN));
    assert.deepEqual(records.map((r) => `${r.method} ${r.route} ${r.status} ${r.outcome} ${r.verifiedDomain ?? '-'}`), [
      `GET account 200 served ${DOMAIN}`,
      `GET account 403 account_not_permitted ${DOMAIN}`,
      `GET account 200 served ${OTHER_DOMAIN}`,
      `GET account 403 account_not_permitted ${DOMAIN}`,
      `HEAD account 403 account_not_permitted ${DOMAIN}`,
      'GET account 403 identity_missing -',
      `GET accounts 200 served ${OTHER_DOMAIN}`,
    ]);
    assertNoLeak(JSON.stringify(records));
  });
});

describe('origin: routes and methods over a real local connection', () => {
  test("GET /accounts with the identity context: 200, the caller's own synthetic accounts and the caller, no-store, one record", async (t) => {
    const { origin: o, records } = await origin(t);
    const reply = await call(o.port, 'GET', '/accounts?view=summary', IDENTITY);
    assert.equal(reply.status, 200);
    assert.equal(reply.headers['cache-control'], 'no-store');
    assert.equal(reply.headers['content-type'], 'application/json; charset=utf-8');
    assert.equal(reply.headers['content-length'], String(Buffer.byteLength(reply.body)));
    assert.deepEqual(JSON.parse(reply.body), { ...BANK, accounts: accountsFor(DOMAIN), caller: { verifiedDomain: DOMAIN, governanceId: GOVERNANCE } });
    assert.equal(BANK.synthetic, true);
    assert.equal(records.length, 1);
    const record = records[0] as OriginRecord;
    assert.deepEqual(Object.keys(record).sort(), [...RECORD_KEYS, 'governanceId', 'verifiedDomain'].sort());
    assert.deepEqual({ ...record, id: '' }, {
      severity: 'INFO',
      event: 'origin_request',
      id: '',
      method: 'GET',
      route: 'accounts',
      status: 200,
      outcome: 'served',
      verifiedDomain: DOMAIN,
      governanceId: GOVERNANCE,
    });
    assert.match(record.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  test('HEAD /accounts: the same status and headers as GET, and no body', async (t) => {
    const { origin: o, records } = await origin(t);
    const get = await call(o.port, 'GET', '/accounts', IDENTITY);
    const head = await call(o.port, 'HEAD', '/accounts', IDENTITY);
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    for (const name of ['cache-control', 'content-type', 'content-length', 'x-content-type-options']) assert.equal(head.headers[name], get.headers[name], name);
    assert.deepEqual(records.map((r) => [r.method, r.status, r.outcome]), [
      ['GET', 200, 'served'],
      ['HEAD', 200, 'served'],
    ]);
  });

  test('no identity context, or a malformed one: 403, fixed body, no data, no identity value logged', async (t) => {
    const { origin: o, records } = await origin(t);
    const cases: [string, [string, string][], string][] = [
      ['GET', [], 'identity_context_required'],
      ['HEAD', [], 'identity_context_required'],
      ['GET', [[VERIFIED_DOMAIN_HEADER, DOMAIN]], 'identity_context_required'],
      ['GET', [[GOVERNANCE_ID_HEADER, GOVERNANCE]], 'identity_context_required'],
      ['GET', [...IDENTITY, [VERIFIED_DOMAIN_HEADER, 'evil.example']], 'identity_context_invalid'],
      ['GET', [[VERIFIED_DOMAIN_HEADER, 'evil example'], [GOVERNANCE_ID_HEADER, GOVERNANCE]], 'identity_context_invalid'],
      ['GET', [[VERIFIED_DOMAIN_HEADER, 'x'.repeat(300)], [GOVERNANCE_ID_HEADER, GOVERNANCE]], 'identity_context_invalid'],
    ];
    for (const [method, headers, error] of cases) {
      const reply = await call(o.port, method, '/accounts', [...headers, ['authorization', 'Bearer secret'], ['signature', 'sig1=:c2lnbmF0dXJl:']]);
      assert.equal(reply.status, 403, error);
      assert.equal(reply.headers['cache-control'], 'no-store');
      assert.equal(reply.body, method === 'HEAD' ? '' : JSON.stringify({ error }));
      assert.equal(reply.body.includes('demo-'), false);
    }
    assert.deepEqual(records.map((r) => r.outcome), ['identity_missing', 'identity_missing', 'identity_missing', 'identity_missing', 'identity_malformed', 'identity_malformed', 'identity_malformed']);
    for (const record of records) assert.deepEqual(Object.keys(record).sort(), RECORD_KEYS);
    assertNoLeak(JSON.stringify(records));
    assert.equal(JSON.stringify(records).includes(DOMAIN), false);
  });

  test('other methods on /accounts: 405 with Allow, recorded as "other"; other paths: 404; all no-store', async (t) => {
    const { origin: o, records } = await origin(t);
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const reply = await call(o.port, method, '/accounts', IDENTITY);
      assert.equal(reply.status, 405, method);
      assert.equal(reply.headers['allow'], 'GET, HEAD');
      assert.equal(reply.headers['cache-control'], 'no-store');
      assert.equal(reply.body, '{"error":"method_not_allowed"}');
    }
    for (const path of ['/', '/accounts/', '/accounts/Demo-Checking', '/accounts/a/b', '/Accounts', '/accounts%2F', '//accounts', '/accounts/..', 'http://127.0.0.1/accounts']) {
      for (const method of ['GET', 'POST']) {
        const reply = await call(o.port, method, path, IDENTITY);
        assert.equal(reply.status, 404, `${method} ${path}`);
        assert.equal(reply.headers['cache-control'], 'no-store');
        assert.equal(reply.body, '{"error":"not_found"}');
      }
    }
    assert.deepEqual(new Set(records.map((r) => `${r.method} ${r.route} ${r.status} ${r.outcome}`)), new Set([
      'other accounts 405 method_not_allowed',
      'GET other 404 not_found',
      'other other 404 not_found',
    ]));
    for (const record of records) assert.deepEqual(Object.keys(record).sort(), RECORD_KEYS);
    assertNoLeak(JSON.stringify(records));
  });

  test('requests with header names that are Object.prototype properties are answered, and the origin keeps serving', async (t) => {
    const { origin: o, records } = await origin(t);
    for (const name of HOSTILE_NAMES) {
      const served = await call(o.port, 'GET', '/accounts', [[name, 'x'], ...IDENTITY]);
      assert.equal(served.status, 200, name);
      assert.deepEqual(JSON.parse(served.body).caller, { verifiedDomain: DOMAIN, governanceId: GOVERNANCE });
      const refused = await call(o.port, 'GET', '/accounts', [[name, 'x']]);
      assert.equal(refused.status, 403, name);
      assert.equal(refused.body, '{"error":"identity_context_required"}');
    }
    assert.equal((await call(o.port, 'GET', '/accounts', IDENTITY)).status, 200);
    assert.deepEqual(records.map((r) => r.outcome), [...HOSTILE_NAMES.flatMap(() => ['served', 'identity_missing']), 'served']);
  });

  test('records are bounded: a huge query, path and header set leave every record under 300 bytes', async (t) => {
    const { origin: o, records } = await origin(t);
    const noise: [string, string][] = Array.from({ length: 40 }, (_, i) => [`x-noise-${i}`, 'n'.repeat(200)]);
    await call(o.port, 'GET', `/accounts?${'q'.repeat(4000)}`, [...IDENTITY, ...noise]);
    await call(o.port, 'GET', `/${'p'.repeat(4000)}`, noise);
    await call(o.port, 'GET', '/accounts', noise);
    assert.equal(records.length, 3);
    for (const record of records) assert.ok(JSON.stringify(record).length < 300, JSON.stringify(record));
    assert.equal(JSON.stringify(records).includes('noise'), false);
    assert.equal(JSON.stringify(records).includes('qqq'), false);
  });

  test('stop: stops accepting, and closes a connection still sending its request once the grace period ends', async (t) => {
    const { origin: o } = await origin(t, 300);
    // A request whose headers never finish keeps its connection active, so only the grace period ends it.
    const socket = connect(o.port, '127.0.0.1');
    await once(socket, 'connect');
    socket.write('GET /accounts HTTP/1.1\r\nHost: x\r\n');
    const closed = once(socket, 'close');
    const started = performance.now();
    let elapsed: number;
    try {
      // Bounded here, so a stop that never forces the connection closed fails this test instead of hanging the run.
      const stopped = await Promise.race([o.stop().then(() => true), new Promise((resolve) => setTimeout(resolve, 3000, false))]);
      elapsed = performance.now() - started;
      assert.equal(stopped, true, 'stopped within 3 s');
    } finally {
      socket.destroy();
    }
    await closed;
    assert.ok(elapsed >= 250 && elapsed < 2000, `stopped after ${elapsed} ms`);
    await assert.rejects(call(o.port, 'GET', '/accounts', IDENTITY), { code: 'ECONNREFUSED' });
    assert.equal(o.stop(), o.stop(), 'stop is idempotent');
  });

  test('stop with only idle keep-alive connections finishes at once, well inside the grace period', async (t) => {
    const { origin: o } = await origin(t, 5000);
    const socket = connect(o.port, '127.0.0.1');
    await once(socket, 'connect');
    socket.write(`GET /accounts HTTP/1.1\r\nHost: x\r\n${VERIFIED_DOMAIN_HEADER}: ${DOMAIN}\r\n${GOVERNANCE_ID_HEADER}: ${GOVERNANCE}\r\n\r\n`);
    await once(socket, 'data');
    const started = performance.now();
    await o.stop();
    assert.ok(performance.now() - started < 1000);
    socket.destroy();
  });
});

describe('origin: settings', () => {
  test('PORT: absent is 8080; 1 to 65535 is used; anything else is refused without echoing it', () => {
    assert.equal(DEFAULT_PORT, 8080);
    assert.equal(SHUTDOWN_GRACE_MS, 3000);
    assert.equal(portFromSetting(undefined), 8080);
    assert.equal(portFromSetting('9090'), 9090);
    assert.equal(portFromSetting('1'), 1);
    assert.equal(portFromSetting('65535'), 65_535);
    for (const bad of ['', '0', '65536', '-1', '80.5', ' 80', '0x50', '8080abc', '100000']) {
      assert.throws(() => portFromSetting(bad), (error: unknown) => error instanceof StartupError && error.message === 'PORT is not a port number', bad);
    }
  });
});

// ---------- the executable ----------

interface Child {
  readonly process: ChildProcess;
  stdout: string;
  stderr: string;
  readonly exited: Promise<number | null>;
}

function run(t: TestContext, env: Record<string, string | undefined>): Child {
  const childEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) if (value !== undefined && key !== 'PORT' && key !== ATTESTATION_KEY_SETTING) childEnv[key] = value;
  for (const [key, value] of Object.entries(env)) if (value !== undefined) childEnv[key] = value;
  const child = spawn(process.execPath, ['origin/server.ts'], { cwd: ROOT, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  const result: Child = { process: child, stdout: '', stderr: '', exited: new Promise((resolve) => child.on('exit', (code) => resolve(code))) };
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

async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, '0.0.0.0');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  server.close();
  await once(server, 'close');
  return port;
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

describe('origin: the executable', () => {
  test('binds 0.0.0.0 at PORT, serves, logs one line per request, and exits 0 soon after SIGTERM', async (t) => {
    const port = await freePort();
    const child = run(t, { PORT: String(port), [ATTESTATION_KEY_SETTING]: KEY });
    await untilOutput(child, 'origin_listening');
    assert.equal((await call(port, 'GET', '/accounts', attested(DOMAIN, GOVERNANCE, Date.now()))).status, 200);
    assert.equal((await call(port, 'GET', '/accounts')).status, 403);
    const started = performance.now();
    child.process.kill('SIGTERM');
    assert.equal(await child.exited, 0);
    assert.ok(performance.now() - started < SHUTDOWN_GRACE_MS + 1000);
    const records = lines(child.stdout);
    assert.deepEqual(records.map((r) => r['event']), ['origin_listening', 'origin_request', 'origin_request', 'origin_stopped']);
    assert.deepEqual(records[0], { severity: 'INFO', event: 'origin_listening', port });
    assert.deepEqual(records.slice(1, 3).map((r) => r['outcome']), ['served', 'identity_missing']);
    assert.equal(child.stderr, '');
  });

  test('a request with a __proto__ or constructor header does not stop the executable', async (t) => {
    const port = await freePort();
    const child = run(t, { PORT: String(port), [ATTESTATION_KEY_SETTING]: KEY });
    await untilOutput(child, 'origin_listening');
    assert.equal((await call(port, 'GET', '/accounts', [['__proto__', 'x'], ['constructor', 'x']])).status, 403);
    assert.equal((await call(port, 'GET', '/accounts', [['constructor', 'x'], ['__proto__', 'x'], ...attested(DOMAIN, GOVERNANCE, Date.now())])).status, 200);
    assert.equal((await call(port, 'GET', '/accounts', attested(DOMAIN, GOVERNANCE, Date.now()))).status, 200);
    assert.equal(child.process.exitCode, null);
    child.process.kill('SIGTERM');
    assert.equal(await child.exited, 0);
    assert.deepEqual(lines(child.stdout).map((r) => r['outcome'] ?? r['event']), ['origin_listening', 'identity_missing', 'served', 'served', 'origin_stopped']);
    assert.equal(child.stderr, '');
  });

  test('an invalid PORT or a port already in use: a fixed diagnostic, exit 1, nothing else printed', async (t) => {
    const bad = run(t, { PORT: 'not-a-port' });
    assert.equal(await bad.exited, 1);
    assert.deepEqual(lines(bad.stderr), [{ severity: 'ERROR', event: 'origin_startup_failed', reason: 'PORT is not a port number' }]);
    assert.equal(bad.stdout, '');
    const blocker = createServer();
    blocker.listen(0, '0.0.0.0');
    await once(blocker, 'listening');
    t.after(() => blocker.close());
    const { port } = blocker.address() as { port: number };
    const busy = run(t, { PORT: String(port), [ATTESTATION_KEY_SETTING]: KEY });
    assert.equal(await busy.exited, 1);
    assert.deepEqual(lines(busy.stderr), [{ severity: 'ERROR', event: 'origin_startup_failed', reason: `could not listen on port ${port}` }]);
    assert.equal(/EADDRINUSE|errno|Error/.test(busy.stderr), false);
  });

  test('no DNSID_ATTESTATION_KEY, or one not of the required form: a fixed diagnostic that never repeats it, exit 1, nothing served', async (t) => {
    const reason = 'DNSID_ATTESTATION_KEY must be set to 32 to 256 characters from A-Z, a-z, 0-9, "-" and "_"';
    for (const value of [undefined, '', 'short-secret-value', `${'a'.repeat(40)}!`, 'b'.repeat(257)]) {
      const child = run(t, { PORT: String(await freePort()), [ATTESTATION_KEY_SETTING]: value });
      assert.equal(await child.exited, 1, String(value));
      assert.deepEqual(lines(child.stderr), [{ severity: 'ERROR', event: 'origin_startup_failed', reason }]);
      assert.equal(child.stdout, '');
      if (value !== undefined && value !== '') assert.equal(child.stderr.includes(value), false);
    }
  });

  test('importing the module starts no listener', async (t) => {
    const child = spawn(
      process.execPath,
      ['--input-type=module', '-e', "await import('./origin/server.ts'); console.log(JSON.stringify(process.getActiveResourcesInfo()));"],
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
