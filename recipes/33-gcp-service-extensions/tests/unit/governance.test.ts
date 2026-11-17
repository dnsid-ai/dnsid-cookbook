// Governance configuration and production construction, offline. Production construction is inspected, not run against
// the network: what it trusts, what it refuses, and that it carries no test trust or transport exception.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, test } from 'node:test';

import { InMemoryIdentityCache, LogRegistry, NoopLogReader, VerificationError } from '@dnsid-ai/sdk';
import { C2spTlogError, C2spTlogReader, InMemoryTrustedC2spCheckpointStore } from '@dnsid-ai/log-c2sp-tlog';

import {
  DEFAULT_TRUSTED_GOVERNANCE,
  GovernanceConfigError,
  PRODUCTION_BACKEND,
  RequestBoundCheckpointStore,
  StrictLogRegistry,
  SUPPORTED_LOG_METHODS,
  createProductionVerificationRuntime,
  createVerificationRuntime,
  FULL_SCAN_BACKEND,
  fullScanFetcher,
  LogEvidenceConfigError,
  logEvidenceFromSetting,
  governanceFromSetting,
  governancePolicy,
  sdkVerificationConfig,
} from '../../src/identity.ts';

const PIN = 'us-OdAPVLC_kogmmQhjwkqKyISO8JHgtBoyMozPsDqE';

describe('DNSID_TRUSTED_GOVERNANCE', () => {
  test('absent: the quick start default', () => {
    assert.deepEqual(governanceFromSetting(undefined).entries, [{ governanceId: DEFAULT_TRUSTED_GOVERNANCE }]);
    assert.equal(DEFAULT_TRUSTED_GOVERNANCE, 'dnsid-sandbox.io');
  });

  test('a list, trimmed and normalized', () => {
    assert.deepEqual(governanceFromSetting('dnsid-sandbox.io, Example.COM ,gov.example.org.').entries, [
      { governanceId: 'dnsid-sandbox.io' },
      { governanceId: 'example.com' },
      { governanceId: 'gov.example.org' },
    ]);
  });

  for (const [name, value] of [
    ['explicitly empty', ''],
    ['only whitespace', '   '],
    ['an empty item', 'a.example,,b.example'],
    ['a trailing comma', 'a.example,'],
    ['a leading comma', ',a.example'],
    ['a URL', 'https://a.example'],
    ['a path', 'a.example/x'],
    ['a port', 'a.example:443'],
    ['a single label', 'localhost'],
    ['an IPv4 address', '192.0.2.1'],
    ['a wildcard', '*.example.com'],
    ['inner whitespace', 'a example.com'],
    ['an underscore label', '_dnsid.example.com'],
    ['a duplicate', 'a.example, A.example'],
    ['a label over 63 octets', `${'a'.repeat(64)}.example`],
  ] as const) {
    test(`refuses ${name}`, () => {
      assert.throws(() => governanceFromSetting(value), GovernanceConfigError);
    });
  }

  test('the refusal does not echo the configured value', () => {
    assert.throws(
      () => governanceFromSetting('secret-looking-value.example/x'),
      (error: unknown) => error instanceof GovernanceConfigError && !error.message.includes('secret-looking'),
    );
  });
});

describe('typed governance policy with optional key pins', () => {
  test('accepts pins and freezes the policy', () => {
    const policy = governancePolicy([{ governanceId: 'gov.example', entityKeyThumbprints: [PIN] }, { governanceId: 'other.example' }]);
    assert.deepEqual(policy.entries, [
      { governanceId: 'gov.example', entityKeyThumbprints: [PIN] },
      { governanceId: 'other.example' },
    ]);
    assert.ok(Object.isFrozen(policy) && Object.isFrozen(policy.entries) && Object.isFrozen(policy.entries[0]));
    assert.ok(Object.isFrozen(policy.entries[0]?.entityKeyThumbprints));
  });

  test('refuses an empty list', () => {
    assert.throws(() => governancePolicy([]), GovernanceConfigError);
  });

  for (const [name, pins] of [
    ['an empty pin list', []],
    ['a malformed pin', ['not-a-thumbprint']],
    ['a non-canonical pin', [`${PIN.slice(0, 42)}F`]],
    ['duplicate pins', [PIN, PIN]],
  ] as const) {
    test(`refuses ${name}`, () => {
      assert.throws(() => governancePolicy([{ governanceId: 'gov.example', entityKeyThumbprints: [...pins] }]), GovernanceConfigError);
    });
  }

  test('a runtime cannot be built without a policy', () => {
    assert.throws(
      () => createVerificationRuntime({ governance: { entries: [] }, backend: PRODUCTION_BACKEND }),
      GovernanceConfigError,
    );
  });
});

describe('the SDK configuration each request gets', () => {
  test('trusted entities (never empty), DNSSEC auto, status interval zero, and no transport section', () => {
    const config = sdkVerificationConfig(
      governancePolicy([{ governanceId: 'gov.example', entityKeyThumbprints: [PIN] }, { governanceId: 'dnsid-sandbox.io' }]),
    );
    assert.deepEqual(config, {
      verification: {
        trustedEntities: [{ governanceId: 'gov.example', entityKeyThumbprints: [PIN] }, { governanceId: 'dnsid-sandbox.io' }],
        dnssecMode: 'auto',
        statusCheckInterval: 0,
      },
    });
    assert.equal('transport' in config, false);
    assert.equal('identity' in config, false);
  });
});

describe('production construction', () => {
  test('the runtime: default governance, the production backend, a per-process checkpoint store', () => {
    const runtime = createProductionVerificationRuntime(undefined);
    assert.deepEqual(runtime.governance.entries, [{ governanceId: 'dnsid-sandbox.io' }]);
    assert.equal(runtime.backend, PRODUCTION_BACKEND);
    assert.ok(runtime.checkpointStore instanceof InMemoryTrustedC2spCheckpointStore);
    assert.notEqual(createProductionVerificationRuntime(undefined).checkpointStore, runtime.checkpointStore);
    assert.ok(Object.isFrozen(PRODUCTION_BACKEND) && Object.isFrozen(runtime));
  });

  test('refuses an empty or malformed setting before any request', () => {
    assert.throws(() => createProductionVerificationRuntime(''), GovernanceConfigError);
    assert.throws(() => createProductionVerificationRuntime('a.example,'), GovernanceConfigError);
  });

  test('DNSID_LOG_EVIDENCE: unset or bundle is the production backend; full-scan the full-scan backend; anything else refused', () => {
    assert.equal(logEvidenceFromSetting(undefined), 'bundle');
    assert.equal(logEvidenceFromSetting('bundle'), 'bundle');
    assert.equal(logEvidenceFromSetting('full-scan'), 'full-scan');
    for (const bad of ['', 'FULL-SCAN', 'scan', ' full-scan']) assert.throws(() => logEvidenceFromSetting(bad), LogEvidenceConfigError, JSON.stringify(bad));
    assert.equal(createProductionVerificationRuntime(undefined, undefined).backend, PRODUCTION_BACKEND);
    assert.equal(createProductionVerificationRuntime(undefined, 'bundle').backend, PRODUCTION_BACKEND);
    const scan = createProductionVerificationRuntime(undefined, 'full-scan');
    assert.equal(scan.backend, FULL_SCAN_BACKEND);
    // Only the log registry differs: the same identity transport, trust and governance.
    assert.equal(FULL_SCAN_BACKEND.createIdentityVerifier, PRODUCTION_BACKEND.createIdentityVerifier);
    assert.equal(FULL_SCAN_BACKEND.transportContext, PRODUCTION_BACKEND.transportContext);
    assert.deepEqual(scan.governance.entries, [{ governanceId: 'dnsid-sandbox.io' }]);
    assert.throws(() => createProductionVerificationRuntime(undefined, 'x'), LogEvidenceConfigError);
  });

  test("the full-scan fetcher answers a stream-bundle request as the log's 404, without fetching it; everything else goes through", async () => {
    const fetched: string[] = [];
    const guarantees = { marker: true };
    const base = {
      securityGuarantees: () => guarantees,
      fetchBounded: async (url: string) => {
        fetched.push(url);
        return new Uint8Array([1]);
      },
    } as never;
    const fetcher = fullScanFetcher(base);
    assert.equal(fetcher.securityGuarantees(), guarantees as never);
    const bundle = 'https://log.example/streams/agent.example.org?format=bundle';
    await assert.rejects(fetcher.fetchBounded(bundle, 1024, { timeoutMs: 1000 }), (error: unknown) => {
      assert.ok(error instanceof C2spTlogError);
      assert.equal(error.status, 404);
      return true;
    });
    for (const url of ['https://log.example/checkpoint', 'https://log.example/tile/entries/000.p/1', 'https://log.example/streams/agent.example.org']) {
      assert.deepEqual(await fetcher.fetchBounded(url, 1024, { timeoutMs: 1000 }), new Uint8Array([1]));
    }
    assert.deepEqual(fetched, ['https://log.example/checkpoint', 'https://log.example/tile/entries/000.p/1', 'https://log.example/streams/agent.example.org']);
  });

  test('the identity verifier: the SDK defaults for DNS and HTTPS, no CA bundle, no DNS server, no private-address exception', async () => {
    const policy = governanceFromSetting(undefined);
    const verifier = await PRODUCTION_BACKEND.createIdentityVerifier(sdkVerificationConfig(policy), {
      logRegistry: new StrictLogRegistry(),
      cache: new InMemoryIdentityCache(),
      transport: (base) => base,
    });
    assert.deepEqual(verifier.config.transport, {});
    assert.equal(verifier.config.identity, undefined);
    assert.deepEqual(verifier.config.verification, {
      trustedEntities: [{ governanceId: 'dnsid-sandbox.io' }],
      dnssecMode: 'auto',
      statusCheckInterval: 0,
    });
  });

  test('the log registry trusts only the SDK-bundled DNSid-managed logs; test trust and unknown logs are refused', async () => {
    const controller = new AbortController();
    const managed = await PRODUCTION_BACKEND.createLogRegistry({
      signal: controller.signal,
      trustedCheckpointStore: new RequestBoundCheckpointStore(new InMemoryTrustedC2spCheckpointStore(), controller.signal),
    });
    const registry = StrictLogRegistry.of(managed, SUPPORTED_LOG_METHODS);
    // The four managed logs (production, partners, staging, development), as the pinned SDK bundles them: read from its
    // own distribution, so the hosts are the SDK's, not copied here.
    const bundled = readFileSync(fileURLToPath(import.meta.resolve('@dnsid-ai/log-c2sp-tlog')), 'utf8');
    const prefixes = [...bundled.matchAll(/\{ scope: "public", logPrefix: "(https:\/\/[^"]+)"/g)].map((m) => m[1] as string);
    assert.equal(prefixes.length, 4, prefixes.join(' '));
    for (const prefix of prefixes) {
      assert.match(prefix, /^https:\/\/log\.(?:(?:partners|stg|dev)\.)?dnsid\.ai$/);
      assert.ok(registry.newReader(`c2sp-tlog:public:${prefix}#stream`) instanceof C2spTlogReader, prefix);
    }
    const partners = prefixes.find((prefix) => prefix.includes('//log.partners.')) as string;
    assert.ok(partners);
    for (const lr of [
      'c2sp-tlog:public:https://log-fixture.test#stream', // the tests' log
      `c2sp-tlog:testnet:${partners}#stream`, // a managed log under another scope
      `c2sp-tlog:public:${partners}.evil-example.test#stream`, // a host under a managed log's name
    ]) {
      assert.throws(() => registry.newReader(lr), VerificationError, lr);
    }
    controller.abort();
  });
});

describe('strict log registry', () => {
  test('refuses a method nobody registered, where the SDK registry hands back a NoopLogReader', () => {
    const plain = new LogRegistry();
    assert.ok(plain.newReader('example-log:x') instanceof NoopLogReader);
    const strict = StrictLogRegistry.of(plain, SUPPORTED_LOG_METHODS);
    assert.throws(() => strict.newReader('example-log:x'), VerificationError);
    assert.throws(() => strict.newReader('no-colon'), VerificationError);
  });

  test('keeps the refusal through snapshot(), which the identity verifier uses', () => {
    const strict = StrictLogRegistry.of(new LogRegistry(), SUPPORTED_LOG_METHODS);
    const copy = strict.snapshot();
    assert.ok(copy instanceof StrictLogRegistry);
    assert.throws(() => copy.newReader('example-log:x'), VerificationError);
  });
});
