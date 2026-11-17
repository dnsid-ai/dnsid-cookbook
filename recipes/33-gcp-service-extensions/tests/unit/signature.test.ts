// Local tests of the signature stage: requests signed with real ephemeral Ed25519 keys by the SDK, verified by the SDK's
// verifySignedHttpRequest. The keys come from a test-only fixture resolver (tests/support/signing.ts), so these tests
// show the RFC 9421 handling only. They are not DNSid identity verification (no DNS, records, governance, status or log
// evidence), and they say nothing about how Google's load balancer forwards requests.

import assert from 'node:assert/strict';
import { describe, it, type TestContext } from 'node:test';

import { createHttpSignaturesProfile } from '@dnsid-ai/sdk';

import {
  checkSerializedRequestSignature,
  REQUIRED_COMPONENTS,
  SIGNATURE_PROFILE_CONFIG,
  verifyRequestSignature,
  type SignatureStageContext,
} from '../../src/signature.ts';
import {
  context,
  eligible,
  fieldsOf,
  fixtureResolver,
  hangingResolver,
  newSigner,
  replaced,
  serialize,
  without,
  type Field,
} from '../support/signing.ts';

const AGENT = 'agent.example';
const API = 'https://api.example';
const T = 1_794_000_000; // signing time, Unix seconds

const alice = await newSigner(AGENT);
const mallory = await newSigner(AGENT); // same domain, a different key
const keys = { [AGENT]: [alice.publicKey] };

/** Freezes Date at T (the SDK's freshness checks read Date.now), optionally moved by `offset` seconds. */
const frozen = new WeakSet<TestContext>();
function at(t: TestContext, offset = 0): void {
  if (frozen.has(t)) {
    t.mock.timers.setTime((T + offset) * 1000);
    return;
  }
  t.mock.timers.enable({ apis: ['Date'], now: (T + offset) * 1000 });
  frozen.add(t);
}
const later = (t: TestContext, offset: number) => t.mock.timers.setTime((T + offset) * 1000);

async function signed(t: TestContext, path = '/accounts/123?view=summary', method = 'GET') {
  at(t);
  return alice.sign(new Request(`${API}${path}`, { method }));
}

async function verify(fields: Field[], resolver = fixtureResolver(keys), ctx?: SignatureStageContext) {
  const result = await verifyRequestSignature(eligible(fields), ctx ?? context(resolver.resolver));
  return { result, resolver };
}

const denied = (reason: string) => ({ outcome: 'deny', status: 403, reason });

describe('valid signed requests', () => {
  it('passes a signed GET and keeps the SDK result, with nothing else in the result', async (t) => {
    const request = await signed(t);
    const { result, resolver } = await verify(fieldsOf(request));
    assert.equal(result.outcome, 'signature_stage_passed');
    assert.deepEqual(Object.keys(result).sort(), ['keyId', 'outcome', 'sdkResult']);
    assert.ok(result.outcome === 'signature_stage_passed');
    assert.equal(result.keyId, `${AGENT}#${alice.publicKey.kid}`);
    assert.equal(result.sdkResult.domain, AGENT);
    assert.deepEqual(resolver.calls, [AGENT]);
    assert.ok(resolver.signals[0] instanceof AbortSignal);
  });

  it('passes a signed HEAD', async (t) => {
    const request = await signed(t, '/accounts/123', 'HEAD');
    const { result } = await verify(fieldsOf(request));
    assert.equal(result.outcome, 'signature_stage_passed');
  });

  it('accepts a replay of the same request within the window (approved limitation)', async (t) => {
    const fields = fieldsOf(await signed(t));
    later(t, 120);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
  });

  it('passes with unrelated and repeated uncovered fields', async (t) => {
    const fields = fieldsOf(await signed(t), {}, [
      ['accept', 'application/json'],
      ['x-cloud-trace-context', 'a'],
      ['x-cloud-trace-context', 'b'],
      ['user-agent', 'agent/1.0'],
    ]);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
  });

  it('passes an escaped path and query exactly as signed', async (t) => {
    const request = await signed(t, '/files/a%2Fb/c%20d?name=%41%42&x=1&x=2');
    assert.equal(new URL(request.url).pathname, '/files/a%2Fb/c%20d');
    assert.equal((await verify(fieldsOf(request))).result.outcome, 'signature_stage_passed');
  });

  it('builds the target from :authority, never from forwarding headers', async (t) => {
    const request = await signed(t);
    const forwarded: Field[] = [
      ['x-forwarded-host', 'evil.example'],
      ['x-forwarded-proto', 'http'],
      ['forwarded', 'host=evil.example;proto=http'],
    ];
    assert.equal((await verify(fieldsOf(request, {}, forwarded))).result.outcome, 'signature_stage_passed');

    // Signed for the forwarded host but received for the real one: refused.
    at(t);
    const forOther = await alice.sign(new Request('https://evil.example/accounts/123?view=summary'));
    const fields = fieldsOf(forOther, { authority: 'api.example' }, forwarded);
    assert.deepEqual((await verify(fields)).result, denied('signature_invalid'));
  });

  it('passes a Host field equal to :authority', async (t) => {
    const fields = fieldsOf(await signed(t), {}, [['host', 'api.example']]);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
  });
});

describe('missing and malformed signatures', () => {
  it('denies a request with neither field, or only one, without a lookup', async (t) => {
    const fields = fieldsOf(await signed(t));
    for (const variant of [
      without(without(fields, 'signature'), 'signature-input'),
      without(fields, 'signature'),
      without(fields, 'signature-input'),
    ]) {
      const { result, resolver } = await verify(variant);
      assert.deepEqual(result, denied('signature_missing'));
      assert.equal(resolver.calls.length, 0);
    }
  });

  it('denies malformed Signature and Signature-Input fields', async (t) => {
    const fields = fieldsOf(await signed(t));
    const input = fields.find(([name]) => name === 'signature-input')?.[1] as string;
    for (const variant of [
      replaced(fields, 'signature', 'sig1=notbytes'),
      replaced(fields, 'signature', 'sig1=:not base64:'),
      replaced(fields, 'signature', '(('),
      replaced(fields, 'signature', ''),
      replaced(fields, 'signature-input', ''),
      replaced(fields, 'signature-input', 'sig1="@method"'),
      replaced(fields, 'signature-input', input.replace(/created=\d+/, 'created="soon"')),
      replaced(fields, 'signature-input', 'sig1=(@method)'),
    ]) {
      const { result, resolver } = await verify(variant);
      assert.deepEqual(result, denied('signature_malformed'), JSON.stringify(variant));
      assert.equal(resolver.calls.length, 0);
    }
  });

  it('denies mismatched labels', async (t) => {
    const fields = fieldsOf(await signed(t));
    const signature = fields.find(([name]) => name === 'signature')?.[1] as string;
    const { result } = await verify(replaced(fields, 'signature', signature.replace(/^sig1=/, 'sig2=')));
    assert.deepEqual(result, denied('signature_label_mismatch'));
  });
});

describe('exactly one signature', () => {
  it('denies a repeated Signature or Signature-Input field, even with identical values', async (t) => {
    const fields = fieldsOf(await signed(t));
    for (const name of ['signature', 'signature-input']) {
      const value = fields.find(([key]) => key === name)?.[1] as string;
      const { result, resolver } = await verify([...fields, [name, value]]);
      assert.deepEqual(result, denied('signature_ambiguous'));
      assert.equal(resolver.calls.length, 0);
    }
  });

  it('denies a repeated field whose name differs only in case', async (t) => {
    const fields = fieldsOf(await signed(t));
    const value = fields.find(([key]) => key === 'signature')?.[1] as string;
    assert.deepEqual((await verify([...fields, ['Signature', value]])).result, denied('signature_ambiguous'));
  });

  it('denies two valid signatures coalesced in one field each', async (t) => {
    at(t);
    const once = await alice.sign(new Request(`${API}/accounts/123`), { label: 'sig1' });
    const twice = await alice.sign(once, { label: 'sig2' });
    assert.match(twice.headers.get('signature') ?? '', /^sig1=.*, sig2=/);
    const { result, resolver } = await verify(fieldsOf(twice));
    assert.deepEqual(result, denied('signature_ambiguous'));
    assert.equal(resolver.calls.length, 0);
  });

  it('denies one valid plus one invalid signature, which the SDK alone accepts', async (t) => {
    at(t);
    const valid = await alice.sign(new Request(`${API}/accounts/123`), { label: 'sig1' });
    const both = await mallory.sign(valid, { label: 'sig2' }); // mallory's key isn't in the fixture
    const fields = fieldsOf(both);
    assert.deepEqual((await verify(fields)).result, denied('signature_ambiguous'));

    // The reason for the check: the SDK on its own picks the one candidate that verifies.
    const sdkOnly = createHttpSignaturesProfile({
      domain: 'verifier.invalid',
      identityResolver: fixtureResolver(keys).resolver,
      httpMessageSignatures: { ...SIGNATURE_PROFILE_CONFIG },
    });
    const accepted = await sdkOnly.verifySignedHttpRequest(both);
    assert.equal(accepted.domain, AGENT);
  });

  it('denies a member repeated under the same label', async (t) => {
    const fields = fieldsOf(await signed(t));
    const signature = fields.find(([name]) => name === 'signature')?.[1] as string;
    const { result } = await verify(replaced(fields, 'signature', `${signature}, ${signature}`));
    assert.deepEqual(result, denied('signature_malformed'));
  });

  it('denies an extra member in only one of the two fields', async (t) => {
    const fields = fieldsOf(await signed(t));
    const signature = fields.find(([name]) => name === 'signature')?.[1] as string;
    const input = fields.find(([name]) => name === 'signature-input')?.[1] as string;
    const extraSignature = replaced(fields, 'signature', `${signature}, sig2=:AAAA:`);
    const extraInput = replaced(fields, 'signature-input', `${input}, sig2=("@method");created=${T};keyid="x#y"`);
    assert.deepEqual((await verify(extraSignature)).result, denied('signature_ambiguous'));
    assert.deepEqual((await verify(extraInput)).result, denied('signature_ambiguous'));
  });
});

describe('covered components', () => {
  const keyId = `${AGENT}#${alice.publicKey.kid}`;
  for (const components of [
    ['@method', '@authority'],
    ['@method', '@target-uri'],
    ['@authority', '@target-uri'],
    ['@method', '@authority', '@path', '@query'],
    ['@method', '@authority', { name: '@target-uri', params: { req: true } }],
  ]) {
    it(`denies coverage ${JSON.stringify(components)} without a lookup`, async (t) => {
      at(t);
      const request = await alice.signWith(new Request(`${API}/accounts/123?view=summary`), {
        label: 'sig1',
        components: components.filter((c) => typeof c === 'string'),
        keyId,
        alg: 'ed25519',
        created: T,
      });
      const fields = fieldsOf(request);
      if (components.some((c) => typeof c !== 'string')) {
        // Rewrite the coverage to carry a parameter the profile won't sign; the check runs before the signature.
        const input = fields.find(([name]) => name === 'signature-input')?.[1] as string;
        fields.splice(0, fields.length, ...replaced(fields, 'signature-input', input.replace(')', ' "@target-uri";req)')));
      }
      const { result, resolver } = await verify(fields);
      assert.deepEqual(result, denied('signature_coverage_insufficient'));
      assert.equal(resolver.calls.length, 0);
    });
  }

  it('the required coverage is exactly @method, @authority and @target-uri', () => {
    assert.deepEqual([...REQUIRED_COMPONENTS], ['@method', '@authority', '@target-uri']);
  });

  it('passes extra covered components and denies when a covered field is changed', async (t) => {
    at(t);
    const request = await alice.sign(new Request(`${API}/accounts/123`, { headers: { accept: 'application/json' } }), {
      additionalComponents: ['accept'],
    });
    assert.equal((await verify(fieldsOf(request))).result.outcome, 'signature_stage_passed');
    const fields = replaced(fieldsOf(request), 'accept', 'text/html');
    assert.deepEqual((await verify(fields)).result, denied('signature_invalid'));
  });

  it('denies missing keyid without a lookup', async (t) => {
    at(t);
    const request = await alice.signWith(new Request(`${API}/accounts/123`), {
      label: 'sig1',
      components: ['@method', '@authority', '@target-uri'],
      alg: 'ed25519',
      created: T,
    });
    const { result, resolver } = await verify(fieldsOf(request));
    assert.deepEqual(result, denied('signature_keyid_missing'));
    assert.equal(resolver.calls.length, 0);
  });
});

describe('tampering after signing', () => {
  const cases: [string, { method?: string; authority?: string; path?: string }][] = [
    ['method GET -> HEAD', { method: 'HEAD' }],
    ['authority', { authority: 'other.example' }],
    ['authority port', { authority: 'api.example:8443' }],
    ['path', { path: '/accounts/124?view=summary' }],
    ['query value', { path: '/accounts/123?view=full' }],
    ['query removed', { path: '/accounts/123' }],
    ['query added', { path: '/accounts/123?view=summary&x=1' }],
  ];
  for (const [name, overrides] of cases) {
    it(`denies a changed ${name}`, async (t) => {
      const { result } = await verify(fieldsOf(await signed(t), overrides));
      assert.deepEqual(result, denied('signature_invalid'));
    });
  }

  it('denies reordered query parameters', async (t) => {
    const request = await signed(t, '/accounts?a=1&b=2');
    const { result } = await verify(fieldsOf(request, { path: '/accounts?b=2&a=1' }));
    assert.deepEqual(result, denied('signature_invalid'));
  });

  it('denies an escaped path received unescaped, and the reverse', async (t) => {
    const escaped = await signed(t, '/files/a%2Fb');
    assert.deepEqual((await verify(fieldsOf(escaped, { path: '/files/a/b' }))).result, denied('signature_invalid'));
    const plain = await signed(t, '/files/a/b');
    assert.deepEqual((await verify(fieldsOf(plain, { path: '/files/a%2Fb' }))).result, denied('signature_invalid'));
  });

  it('denies a percent-escape whose hex case changed (no normalization)', async (t) => {
    const request = await signed(t, '/files/a%2Fb?q=%7E');
    for (const path of ['/files/a%2fb?q=%7E', '/files/a%2Fb?q=%7e', '/files/a%2Fb?q=~']) {
      assert.deepEqual((await verify(fieldsOf(request, { path }))).result, denied('signature_invalid'), path);
    }
  });

  it('denies a changed signature value', async (t) => {
    const fields = fieldsOf(await signed(t));
    const signature = fields.find(([name]) => name === 'signature')?.[1] as string;
    const flipped = signature.replace(/:(.)/, (_, c: string) => `:${c === 'A' ? 'B' : 'A'}`);
    assert.deepEqual((await verify(replaced(fields, 'signature', flipped))).result, denied('signature_invalid'));
  });
});

describe('keys and the claimed domain', () => {
  it('denies a signature from a different key published under the same kid', async (t) => {
    const impostor = { ...mallory.publicKey, kid: alice.publicKey.kid };
    const { result } = await verify(fieldsOf(await signed(t)), fixtureResolver({ [AGENT]: [impostor] }));
    assert.deepEqual(result, denied('signature_invalid'));
  });

  it('denies a keyid whose kid the signer does not publish', async (t) => {
    const { result } = await verify(fieldsOf(await signed(t)), fixtureResolver({ [AGENT]: [mallory.publicKey] }));
    assert.deepEqual(result, denied('signature_key_unknown'));
  });

  it('denies when the claimed domain cannot be looked up', async (t) => {
    const { result, resolver } = await verify(fieldsOf(await signed(t)), fixtureResolver({ 'other.example': [alice.publicKey] }));
    assert.deepEqual(result, denied('signer_lookup_failed'));
    assert.deepEqual(resolver.calls, [AGENT]);
  });

  it('denies when the resolver throws something other than an SDK error, without echoing it', async (t) => {
    const secret = 'secret-detail-from-resolver';
    const throwing = { resolver: { verifyDomain: async () => { throw new Error(secret); } }, calls: [], signals: [] };
    const { result } = await verify(fieldsOf(await signed(t)), throwing);
    assert.deepEqual(result, denied('signer_lookup_failed'));
    assert.ok(!JSON.stringify(result).includes(secret));
  });

  it('a denial carries only its fixed code', async (t) => {
    const fields = fieldsOf(await signed(t), { path: '/accounts/999' });
    const { result } = await verify(fields);
    assert.deepEqual(Object.keys(result).sort(), ['outcome', 'reason', 'status']);
  });
});

describe('signature age (deterministic clock)', () => {
  it(`accepts created exactly ${SIGNATURE_PROFILE_CONFIG.maxAge} s ago and denies one second more`, async (t) => {
    const fields = fieldsOf(await signed(t));
    later(t, 300);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
    later(t, 301);
    const { result, resolver } = await verify(fields);
    assert.deepEqual(result, denied('signature_expired'));
    assert.equal(resolver.calls.length, 0);
  });

  it(`accepts created ${SIGNATURE_PROFILE_CONFIG.clockSkew} s ahead and denies one second more`, async (t) => {
    const fields = fieldsOf(await signed(t));
    later(t, -30);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
    later(t, -31);
    assert.deepEqual((await verify(fields)).result, denied('signature_created_in_future'));
  });

  it('denies created an hour old and an hour in the future (EDGE-08)', async (t) => {
    const fields = fieldsOf(await signed(t));
    later(t, 3600);
    assert.deepEqual((await verify(fields)).result, denied('signature_expired'));
    later(t, -3600);
    assert.deepEqual((await verify(fields)).result, denied('signature_created_in_future'));
  });

  it('denies a signature without created, without a lookup', async (t) => {
    at(t);
    const request = await alice.signWith(new Request(`${API}/accounts/123`), {
      label: 'sig1',
      components: ['@method', '@authority', '@target-uri'],
      keyId: `${AGENT}#${alice.publicKey.kid}`,
      alg: 'ed25519',
    });
    const { result, resolver } = await verify(fieldsOf(request));
    assert.deepEqual(result, denied('signature_created_missing'));
    assert.equal(resolver.calls.length, 0);
  });

  it('honors expires with the 30 s skew: accepted at expires + 30, denied at expires + 31', async (t) => {
    at(t);
    const request = await alice.sign(new Request(`${API}/accounts/123`), { expiresInSeconds: 60 });
    const fields = fieldsOf(request);
    later(t, 90);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
    later(t, 91);
    assert.deepEqual((await verify(fields)).result, denied('signature_expired'));
  });

  it('denies a lifetime longer than 300 s or an expires before created', async (t) => {
    at(t);
    // The SDK's signer refuses to make either, so both are signed with explicit parameters.
    const params = {
      label: 'sig1',
      components: ['@method', '@authority', '@target-uri'],
      keyId: `${AGENT}#${alice.publicKey.kid}`,
      alg: 'ed25519',
      created: T,
    };
    const long = await alice.signWith(new Request(`${API}/accounts/123`), { ...params, expires: T + 301 });
    assert.deepEqual((await verify(fieldsOf(long))).result, denied('signature_lifetime_invalid'));
    const atLimit = await alice.signWith(new Request(`${API}/accounts/123`), { ...params, expires: T + 300 });
    assert.equal((await verify(fieldsOf(atLimit))).result.outcome, 'signature_stage_passed');
    const backwards = await alice.signWith(new Request(`${API}/accounts/123`), {
      label: 'sig1',
      components: ['@method', '@authority', '@target-uri'],
      keyId: `${AGENT}#${alice.publicKey.kid}`,
      alg: 'ed25519',
      created: T,
      expires: T - 1,
    });
    assert.deepEqual((await verify(fieldsOf(backwards))).result, denied('signature_lifetime_invalid'));
  });

  it('the SDK itself enforces the configured 300 s and 30 s, and its 5 s default would not', async (t) => {
    const request = await signed(t);
    const sdk = (config?: typeof SIGNATURE_PROFILE_CONFIG) =>
      createHttpSignaturesProfile({
        domain: 'verifier.invalid',
        identityResolver: fixtureResolver(keys).resolver,
        ...(config === undefined ? {} : { httpMessageSignatures: { ...config } }),
      });
    const outcome = (config?: typeof SIGNATURE_PROFILE_CONFIG) =>
      sdk(config).verifySignedHttpRequest(request).then(() => 'accepted', () => 'refused');
    later(t, 300);
    assert.equal(await outcome(SIGNATURE_PROFILE_CONFIG), 'accepted');
    later(t, 301);
    assert.equal(await outcome(SIGNATURE_PROFILE_CONFIG), 'refused');
    later(t, -30);
    assert.equal(await outcome(SIGNATURE_PROFILE_CONFIG), 'accepted');
    assert.equal(await outcome(), 'refused');
    later(t, -31);
    assert.equal(await outcome(SIGNATURE_PROFILE_CONFIG), 'refused');
  });
});

describe('cancellation and the verification budget', () => {
  it('denies an already-cancelled request without a lookup', async (t) => {
    const controller = new AbortController();
    controller.abort();
    const resolver = fixtureResolver(keys);
    const { result } = await verify(fieldsOf(await signed(t)), resolver, context(resolver.resolver, { signal: controller.signal }));
    assert.deepEqual(result, denied('verification_cancelled'));
    assert.equal(resolver.calls.length, 0);
  });

  it('cancels a lookup in progress when the caller aborts, through the signal the resolver received', async (t) => {
    const fields = fieldsOf(await signed(t));
    const controller = new AbortController();
    const resolver = hangingResolver();
    const pending = verify(fields, resolver, context(resolver.resolver, { signal: controller.signal }));
    while (resolver.calls.length === 0) await new Promise((resolve) => setImmediate(resolve));
    const aborted = performance.now();
    controller.abort();
    const { result } = await pending;
    const elapsed = performance.now() - aborted;
    assert.deepEqual(result, denied('verification_cancelled'));
    assert.ok(elapsed < 1000, `took ${elapsed} ms after the abort`);
    assert.equal(resolver.signals[0]?.aborted, true);
  });

  it('denies without a lookup when the budget is already spent', async (t) => {
    const resolver = fixtureResolver(keys);
    const { result } = await verify(fieldsOf(await signed(t)), resolver, context(resolver.resolver, { budgetMs: -1 }));
    assert.deepEqual(result, denied('verification_budget_exhausted'));
    assert.equal(resolver.calls.length, 0);
  });

  it('gives the SDK only what is left of the budget, not its 30 s default', async (t) => {
    const fields = fieldsOf(await signed(t));
    const resolver = hangingResolver();
    const started = performance.now();
    const { result } = await verify(fields, resolver, context(resolver.resolver, { budgetMs: 150 }));
    const elapsed = performance.now() - started;
    assert.deepEqual(result, denied('verification_budget_exhausted'));
    assert.ok(elapsed < 2000, `took ${elapsed} ms`);
    assert.equal(resolver.signals[0]?.aborted, true);
  });

  it('requires a resolver, a signal and a deadline: there is no default resolver', async (t) => {
    const ok = eligible(fieldsOf(await signed(t)));
    const signal = new AbortController().signal;
    const deadline = performance.now() + 2500;
    const bad = [
      { signal, deadline },
      { identityResolver: undefined, signal, deadline },
      { identityResolver: {}, signal, deadline },
      { identityResolver: fixtureResolver(keys).resolver, deadline },
      { identityResolver: fixtureResolver(keys).resolver, signal, deadline: Number.NaN },
    ];
    for (const ctx of bad) {
      await assert.rejects(verifyRequestSignature(ok, ctx as unknown as SignatureStageContext), TypeError);
      await assert.rejects(checkSerializedRequestSignature(serialize(fieldsOf(await signed(t))), ctx as unknown as SignatureStageContext), TypeError);
    }
  });
});

describe('rebuilding the signed target', () => {
  it('requires exactly one :authority and :path, and a Host that agrees', async (t) => {
    const fields = fieldsOf(await signed(t));
    const cases: [Field[], string][] = [
      [without(fields, ':authority'), 'authority_missing'],
      [[...fields, [':authority', 'api.example']], 'authority_ambiguous'],
      [[...fields, ['host', 'other.example']], 'authority_ambiguous'],
      [[...fields, ['host', 'api.example'], ['host', 'api.example']], 'authority_ambiguous'],
      [[...fields, ['Host', 'API.example']], 'authority_ambiguous'],
      [without(fields, ':path'), 'path_missing'],
      [[...fields, [':path', '/accounts/123?view=summary']], 'path_ambiguous'],
    ];
    for (const [variant, reason] of cases) {
      const { result, resolver } = await verify(variant);
      assert.deepEqual(result, denied(reason), reason);
      assert.equal(resolver.calls.length, 0);
    }
  });

  // Each would be silently rewritten by URL parsing, so the SDK would verify a target the agent didn't send.
  const lossy: [string, { authority?: string; path?: string }][] = [
    ['dot segment', { path: '/accounts/../admin' }],
    ['single dot segment', { path: '/accounts/./123' }],
    ['encoded dot segment', { path: '/accounts/%2e%2e/admin' }],
    ['backslash', { path: '/accounts\\123' }],
    ['space in the path', { path: '/accounts/1 23' }],
    ['double quote in the path', { path: '/accounts/"123"' }],
    ['brace in the path', { path: '/accounts/{id}' }],
    ['apostrophe in the query', { path: "/accounts?name='x'" }],
    ['empty query', { path: '/accounts?' }],
    ['fragment', { path: '/accounts#top' }],
    ['no leading slash', { path: 'accounts' }],
    ['asterisk form', { path: '*' }],
    ['absolute form', { path: 'https://api.example/accounts' }],
    ['upper-case authority', { authority: 'API.example' }],
    ['default port', { authority: 'api.example:443' }],
    ['userinfo', { authority: 'user@api.example' }],
    ['path in the authority', { authority: 'api.example/x' }],
    ['empty authority', { authority: '' }],
    ['bad port', { authority: 'api.example:99999' }],
    ['percent in the host', { authority: 'api%2Eexample' }],
  ];
  for (const [name, overrides] of lossy) {
    it(`refuses a target that would be rewritten: ${name}`, async (t) => {
      const { result, resolver } = await verify(fieldsOf(await signed(t), overrides));
      assert.deepEqual(result, denied('target_not_representable'));
      assert.equal(resolver.calls.length, 0);
    });
  }

  it('refuses header bytes the SDK request would alter', async (t) => {
    const fields = fieldsOf(await signed(t));
    const variants: Field[][] = [
      [...fields, ['x-name', Uint8Array.from([0x63, 0x61, 0x66, 0xe9])]], // Latin-1 é
      [...fields, ['x-name', Buffer.from('café')]], // UTF-8 é
      [...fields, ['x-name', ' leading']],
      [...fields, ['x-name', 'trailing\t']],
      [...fields, ['x-name', 'a\rb']],
      [...fields, ['x-name', 'a\nb']],
      [...fields, ['x-name', 'a\0b']],
      [...fields, ['x-name', 'a\x7fb']],
      [...fields, ['bad name', 'x']],
      [...fields, ['x-name(', 'x']],
      replaced(fields, ':path', '/accounts/\xe9'),
    ];
    for (const variant of variants) {
      const { result, resolver } = await verify(variant);
      assert.deepEqual(result, denied('header_not_representable'));
      assert.equal(resolver.calls.length, 0);
    }
  });

  it('keeps an empty field value and inner spaces as they are', async (t) => {
    const fields = fieldsOf(await signed(t), {}, [['x-empty', ''], ['x-inner', 'a  b\tc']]);
    assert.equal((await verify(fields)).result.outcome, 'signature_stage_passed');
  });
});

describe('serialized ext_proc request to the signature stage', () => {
  const run = (bytes: Uint8Array, resolver = fixtureResolver(keys)) =>
    checkSerializedRequestSignature(bytes, context(resolver.resolver)).then((result) => ({ result, resolver }));

  it('passes a serialized signed GET and HEAD', async (t) => {
    for (const method of ['GET', 'HEAD']) {
      const { result, resolver } = await run(serialize(fieldsOf(await signed(t, '/accounts/123?view=summary', method))));
      assert.equal(result.outcome, 'signature_stage_passed', method);
      assert.deepEqual(resolver.calls, [AGENT]);
    }
  });

  it('passes an escaped path carried in raw_value bytes', async (t) => {
    const { result } = await run(serialize(fieldsOf(await signed(t, '/files/a%2Fb?q=%7E&a=1'))));
    assert.equal(result.outcome, 'signature_stage_passed');
  });

  it('never calls the resolver for a message refused before the signature stage', async (t) => {
    at(t);
    const post = await alice.sign(new Request(`${API}/accounts`, { method: 'POST' }));
    const get = fieldsOf(await signed(t));
    const cases: [Uint8Array, unknown][] = [
      [serialize(fieldsOf(post, { method: 'POST' })), denied('method_not_allowed')],
      [serialize(get, null), denied('body_not_ruled_out')],
      [serialize(get, false), denied('body_not_ruled_out')],
      [serialize([...get, ['content-length', '5']]), denied('body_indicated')],
      [serialize(without(get, ':method')), denied('method_missing')],
      [Buffer.from([0x12, 0x05, 0x0a]), { outcome: 'reject', reason: 'malformed_message' }],
      [Buffer.alloc(0), { outcome: 'reject', reason: 'empty_message' }],
    ];
    for (const [bytes, expected] of cases) {
      const { result, resolver } = await run(bytes);
      assert.deepEqual(result, expected);
      assert.equal(resolver.calls.length, 0);
    }
  });

  it('denies serialized tampering, duplicates and lossy targets', async (t) => {
    const fields = fieldsOf(await signed(t));
    const signature = fields.find(([name]) => name === 'signature')?.[1] as string;
    const cases: [Field[], string][] = [
      [replaced(fields, ':path', '/accounts/124?view=summary'), 'signature_invalid'],
      [replaced(fields, ':path', '/accounts/123?view=summary&view=full'), 'signature_invalid'],
      [[...fields, ['signature', signature]], 'signature_ambiguous'],
      [replaced(fields, ':path', '/x/../accounts/123?view=summary'), 'target_not_representable'],
      [replaced(fields, ':authority', 'API.EXAMPLE'), 'target_not_representable'],
    ];
    for (const [variant, reason] of cases) {
      assert.deepEqual((await run(serialize(variant))).result, denied(reason), reason);
    }
  });
});
