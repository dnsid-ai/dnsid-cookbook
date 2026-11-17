// The transports production verification uses, exercised directly: the SDK's HTTPS JSON fetcher (what
// `createNodeIdentityVerifier` uses for key sets and status documents) and the SDK's default bounded C2SP resource
// fetcher (what `createDnsidManagedVerificationRegistry` uses for log reads). Prohibited destinations are refused before
// any connection; redirects keep their restrictions. The local origin and its private-address exception exist only in
// these tests, to prove the checks still apply to a reachable server.

import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { describe, test } from 'node:test';

import { VerificationCode, VerificationError } from '@dnsid-ai/sdk';
import { createDefaultC2spBoundedResourceFetcher } from '@dnsid-ai/log-c2sp-tlog';
import { fetchJson } from '@dnsid-ai/transport';

import { localOrigin, selfSignedCertificate, type Route } from '../support/local-https.ts';

const PROHIBITED = [
  'https://127.0.0.1/doc.json', // loopback
  'https://10.1.2.3/doc.json', // private
  'https://192.168.1.1/doc.json',
  'https://169.254.169.254/computeMetadata/v1/', // link-local: the metadata server
  'https://[::1]/doc.json',
  'https://[fe80::1]/doc.json',
  'https://[::ffff:127.0.0.1]/doc.json', // IPv4-mapped loopback
  'https://100.64.0.1/doc.json', // carrier-grade NAT
];

const json: Route = (_request, response) => {
  response.setHeader('content-type', 'application/json');
  response.end('{"ok":true}');
};
const redirect =
  (location: (origin: { origin: string; port: number }) => string): Route =>
  (_request, response, origin) => {
    response.statusCode = 302;
    response.setHeader('location', location(origin));
    response.end();
  };

const isTlsError = (error: unknown) => error instanceof VerificationError && error.code === VerificationCode.TLSError;
// The C2SP fetcher wraps transport refusals in its own VerificationError subclass.
const isRefusal = (error: unknown) => error instanceof VerificationError;
/** The messages along an error's cause chain (the C2SP fetcher wraps fetch's TypeError, which wraps the refusal). */
function causes(error: unknown): string {
  const messages: string[] = [];
  for (let current = error; current instanceof Error; current = current.cause) messages.push(current.message);
  return messages.join(' <- ');
}

describe('identity documents: the SDK HTTPS fetcher with production settings', () => {
  for (const url of PROHIBITED) {
    test(`refuses ${url} before connecting`, async () => {
      await assert.rejects(fetchJson(url, { timeoutMs: 1000 }), isTlsError);
    });
  }

  test('refuses plain HTTP', async () => {
    await assert.rejects(fetchJson('http://example.test/doc.json', { timeoutMs: 1000 }), isTlsError);
  });

  test('refuses a name that resolves to loopback (localhost)', async () => {
    await assert.rejects(fetchJson('https://localhost/doc.json', { timeoutMs: 1000 }), isTlsError);
  });

  test('refuses a reachable server whose name resolves to a private address, and sends it nothing', async () => {
    const origin = await localOrigin('private-fixture.test', { '/doc.json': json });
    try {
      // The production fetcher with only the test DNS server and the test CA: no private-address exception.
      await assert.rejects(
        fetchJson(`${origin.origin}/doc.json`, { dnsServer: origin.dnsServer, caBundlePath: origin.caBundlePath }),
        (error: unknown) => isTlsError(error) && /unsafe resolved IP address/.test((error as Error).message),
      );
      assert.deepEqual(origin.requests, []);
    } finally {
      await origin.close();
    }
  });
});

describe('identity documents: redirects and certificates (local origin, test-only private-address exception)', () => {
  const routes: Record<string, Route> = {
    '/doc.json': json,
    '/to-http': redirect(() => 'http://origin-fixture.test/doc.json'),
    '/to-loopback-ip': redirect(({ port }) => `https://127.0.0.1:${port}/doc.json`),
    '/to-metadata': redirect(() => 'https://169.254.169.254/computeMetadata/v1/'),
    '/to-other-host': redirect(() => 'https://elsewhere.example/doc.json'),
    '/circular': redirect(({ origin }) => `${origin}/circular`),
    '/same-host': redirect(({ origin }) => `${origin}/doc.json`),
    '/large': (_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.end(`{"pad":"${'x'.repeat(4096)}"}`);
    },
  };

  async function withOrigin(run: (base: string, options: Parameters<typeof fetchJson>[1]) => Promise<void>) {
    const origin = await localOrigin('origin-fixture.test', routes);
    try {
      await run(origin.origin, {
        dnsServer: origin.dnsServer,
        caBundlePath: origin.caBundlePath,
        privateAddressHosts: ['origin-fixture.test'],
        timeoutMs: 2000,
      });
    } finally {
      await origin.close();
    }
  }

  test('control: the exception and test CA reach the origin (so the refusals below are the checks, not the setup)', () =>
    withOrigin(async (base, options) => {
      assert.deepEqual((await fetchJson(`${base}/doc.json`, options)).data, { ok: true });
      assert.deepEqual((await fetchJson(`${base}/same-host`, options)).data, { ok: true });
    }));

  test('refuses a redirect to plain HTTP', () =>
    withOrigin(async (base, options) => {
      await assert.rejects(fetchJson(`${base}/to-http`, options), /redirect to non-HTTPS URL/);
    }));

  test('refuses a redirect to an IP literal (never exempted)', () =>
    withOrigin(async (base, options) => {
      await assert.rejects(fetchJson(`${base}/to-loopback-ip`, options), isTlsError);
      await assert.rejects(fetchJson(`${base}/to-metadata`, options), isTlsError);
    }));

  test('refuses a redirect off the pinned host', () =>
    withOrigin(async (base, options) => {
      await assert.rejects(
        fetchJson(`${base}/to-other-host`, { ...options, allowedHost: 'origin-fixture.test' }),
        /redirect changes host/,
      );
    }));

  test('refuses an endless redirect chain', () =>
    withOrigin(async (base, options) => {
      await assert.rejects(fetchJson(`${base}/circular`, options), /too many redirects/);
    }));

  test('refuses a body over the bound', () =>
    withOrigin(async (base, options) => {
      await assert.rejects(fetchJson(`${base}/large`, { ...options, maxResponseBytes: 1024 }), /exceeds 1024 byte limit/);
    }));

  test('refuses a certificate it cannot verify (no test CA)', async () => {
    const origin = await localOrigin('origin-fixture.test', routes);
    try {
      await assert.rejects(
        fetchJson(`${origin.origin}/doc.json`, {
          dnsServer: origin.dnsServer,
          privateAddressHosts: ['origin-fixture.test'],
          timeoutMs: 2000,
        }),
        (error: unknown) => isTlsError(error) && /self-signed certificate/.test((error as Error).message),
      );
    } finally {
      await origin.close();
    }
  });
});

describe('log reads: the SDK default bounded C2SP fetcher', () => {
  const options = { timeoutMs: 1000 };

  for (const url of PROHIBITED) {
    test(`production settings refuse ${url}`, async () => {
      await assert.rejects(createDefaultC2spBoundedResourceFetcher().fetchBounded(url, 1024, options), isRefusal);
    });
  }

  test('production settings declare every guarantee the SDK requires', () => {
    assert.deepEqual(createDefaultC2spBoundedResourceFetcher().securityGuarantees(), {
      httpsOnly: true,
      rejectsRedirects: true,
      validatesAllResolvedAddresses: true,
      connectsToValidatedAddress: true,
      boundsResponseDuringRead: true,
    });
  });

  test('production settings refuse a reachable server on a private address, sending it nothing', async () => {
    const origin = await localOrigin('log-fixture.test', { '/checkpoint': json });
    try {
      const fetcher = createDefaultC2spBoundedResourceFetcher({ dnsServer: origin.dnsServer, caBundlePath: origin.caBundlePath });
      await assert.rejects(fetcher.fetchBounded(`${origin.origin}/checkpoint`, 1024, options), (error: unknown) =>
        isRefusal(error) && /unsafe resolved IP address/.test(causes(error)),
      );
      assert.deepEqual(origin.requests, []);
    } finally {
      await origin.close();
    }
  });

  test('refuses any redirect, even to the same host, and a body over the bound', async () => {
    const origin = await localOrigin('log-fixture.test', {
      '/checkpoint': json,
      '/moved': redirect(({ origin: base }) => `${base}/checkpoint`),
      '/large': routes4096,
    });
    try {
      const fetcher = createDefaultC2spBoundedResourceFetcher({
        dnsServer: origin.dnsServer,
        caBundlePath: origin.caBundlePath,
        privateAddressHosts: ['log-fixture.test'],
      });
      // Control: reachable.
      assert.equal(new TextDecoder().decode(await fetcher.fetchBounded(`${origin.origin}/checkpoint`, 1024, options)), '{"ok":true}');
      await assert.rejects(fetcher.fetchBounded(`${origin.origin}/moved`, 1024, options), /redirects are not allowed/);
      await assert.rejects(fetcher.fetchBounded(`${origin.origin}/large`, 1024, options), /exceeds configured byte maximum 1024/);
    } finally {
      await origin.close();
    }
  });
});

const routes4096: Route = (_request, response) => {
  response.end('x'.repeat(4096));
};

describe('the local origin used above', () => {
  // A random serial number once came out with a leading zero byte (non-minimal DER), which OpenSSL refuses; with 300
  // certificates that encoding fault shows up nine times in ten.
  test('its in-memory certificates always parse, for the name given only', () => {
    for (let i = 0; i < 300; i++) {
      const certificate = new X509Certificate(selfSignedCertificate('origin-fixture.test').cert);
      assert.equal(certificate.subjectAltName, 'DNS:origin-fixture.test');
      assert.equal(certificate.checkHost('origin-fixture.test'), 'origin-fixture.test');
      assert.equal(certificate.checkHost('other-fixture.test'), undefined);
    }
  });
});
