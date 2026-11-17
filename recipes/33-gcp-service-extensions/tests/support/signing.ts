// TEST ONLY. Real ephemeral Ed25519 keys and the SDK's real RFC 9421 signing, plus a deterministic IdentityResolver
// that returns local public-key fixtures. The fixture resolver is NOT DNSid identity verification: it does no DNS, no
// record or key-binding checks, no governance, no status and no log evidence. It only lets the signature stage run its
// real cryptographic check against a known key. It never makes a signature verify; only the key it returns can.

import assert from 'node:assert/strict';

import {
  createHttpSignaturesProfile,
  DNSSECState,
  DnsIdTxtRecord,
  httpSignatures,
  JWKS,
  jwkThumbprint,
  NoopLogReader,
  VerificationCode,
  VerificationError,
  VerifiedDomain,
  type DnsIdJWK,
  type IdentityResolver,
  type KeyProvider,
} from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

import { checkRequestPreconditions, type EligibleForVerification, type HeaderValue } from '../../src/preconditions.ts';
import type { SignatureStageContext } from '../../src/signature.ts';

export interface TestSigner {
  readonly domain: string;
  readonly keyProvider: KeyProvider;
  readonly publicKey: DnsIdJWK;
  /** Signs with the SDK's profile defaults (@method, @authority, @target-uri, created = now, a nonce). */
  sign(request: Request, options?: httpSignatures.HttpSigningOptions): Promise<Request>;
  /** Signs with explicit parameters, for signatures the profile wouldn't produce (no created, no keyid, less coverage). */
  signWith(request: Request, params: httpSignatures.SignatureParams): Promise<Request>;
}

const signingOnly: IdentityResolver = {
  verifyDomain() {
    throw new Error('a test signer never verifies');
  },
};

export async function newSigner(domain: string): Promise<TestSigner> {
  const keyProvider = await LocalKeyProvider.generate('EdDSA');
  const publicKey = await keyProvider.signingKey();
  const profile = createHttpSignaturesProfile({ domain, keyProvider, identityResolver: signingOnly });
  return {
    domain,
    keyProvider,
    publicKey,
    sign: (request, options) => profile.createSignedHttpRequest(request, options),
    signWith: (request, params) => httpSignatures.signHttpMessage(request, params, keyProvider),
  };
}

export interface FixtureResolver {
  readonly resolver: IdentityResolver;
  /** The domains asked for, in order. */
  readonly calls: string[];
  /** The signal each call received. */
  readonly signals: (AbortSignal | undefined)[];
}

/**
 * Returns the given public keys for each domain, or a RecordNotFound lookup failure for any other domain. Every field
 * of the result except `jwks` (and `domain`) is a placeholder: the signature stage reads only the keys.
 */
export function fixtureResolver(keysByDomain: Readonly<Record<string, readonly DnsIdJWK[]>>): FixtureResolver {
  const calls: string[] = [];
  const signals: (AbortSignal | undefined)[] = [];
  const resolver: IdentityResolver = {
    async verifyDomain(domain, _peerCert, options) {
      calls.push(domain);
      signals.push(options?.signal);
      const keys = keysByDomain[domain];
      if (keys === undefined) {
        throw new VerificationError('fixture: no such domain', { code: VerificationCode.RecordNotFound });
      }
      const first = keys[0] as DnsIdJWK;
      const placeholderTime = new Date(0);
      return new VerifiedDomain({
        domain,
        record: new DnsIdTxtRecord(),
        jwks: new JWKS([...keys]),
        signingKey: first,
        signingKeyThumbprint: await jwkThumbprint(first),
        tlsCert: { notAfter: placeholderTime, san: [] },
        registryStatus: { state: 'PENDING', lastTransitionAt: placeholderTime },
        verifiedAt: placeholderTime,
        dnsTTL: 0,
        keyBoundAt: placeholderTime,
        lastStatusCheckAt: placeholderTime,
        dnssecState: DNSSECState.UNKNOWN,
        logReader: new NoopLogReader('fixture'),
      });
    },
  };
  return { resolver, calls, signals };
}

/** A resolver whose lookup never settles until its signal aborts, to exercise cancellation and the budget. */
export function hangingResolver(): FixtureResolver {
  const calls: string[] = [];
  const signals: (AbortSignal | undefined)[] = [];
  const resolver: IdentityResolver = {
    verifyDomain(domain, _peerCert, options) {
      calls.push(domain);
      signals.push(options?.signal);
      return new Promise((_, reject) => {
        options?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    },
  };
  return { resolver, calls, signals };
}

export function context(
  resolver: IdentityResolver,
  options: { signal?: AbortSignal; budgetMs?: number } = {},
): SignatureStageContext {
  return {
    identityResolver: resolver,
    signal: options.signal ?? new AbortController().signal,
    deadline: performance.now() + (options.budgetMs ?? 2500),
  };
}

export type Field = [name: string, value: string | Uint8Array];

/**
 * The header fields Envoy would send for a signed request: the pseudo-headers from its method and URL (each
 * overridable), then its fields in order. `extra` fields are appended as given.
 */
export function fieldsOf(
  signed: Request,
  overrides: { method?: string; authority?: string; path?: string } = {},
  extra: Field[] = [],
): Field[] {
  const url = new URL(signed.url);
  const fields: Field[] = [
    [':method', overrides.method ?? signed.method],
    [':authority', overrides.authority ?? url.host],
    [':path', overrides.path ?? `${url.pathname}${url.search}`],
    [':scheme', 'https'],
  ];
  for (const [name, value] of signed.headers) fields.push([name, value]);
  return [...fields, ...extra];
}

export function without(fields: Field[], name: string): Field[] {
  return fields.filter(([key]) => key !== name);
}

export function replaced(fields: Field[], name: string, value: string | Uint8Array): Field[] {
  return fields.map(([key, old]) => [key, key === name ? value : old]);
}

/** Runs the fields through the real preconditions (as raw_value bytes, end of stream) and returns the eligible request. */
export function eligible(fields: Field[]): EligibleForVerification {
  const headers: HeaderValue[] = fields.map(([key, value]) => ({
    key,
    raw_value: typeof value === 'string' ? Buffer.from(value, 'latin1') : Buffer.from(value),
  }));
  const result = checkRequestPreconditions({ request_headers: { headers: { headers }, end_of_stream: true } });
  assert.equal(result.outcome, 'eligible_for_verification');
  return result as EligibleForVerification;
}

// A minimal protobuf writer for ProcessingRequest { request_headers = 2: HttpHeaders { headers = 1: HeaderMap
// { headers = 1: HeaderValue { key = 1, raw_value = 3 } }, end_of_stream = 3 } }, from the encoding spec
// (https://protobuf.dev/programming-guides/encoding/) and the pinned Envoy schema.
function varint(n: number): Buffer {
  const out: number[] = [];
  do {
    const low = n & 0x7f;
    n = Math.floor(n / 128);
    out.push(n > 0 ? low | 0x80 : low);
  } while (n > 0);
  return Buffer.from(out);
}
const len = (field: number, ...payload: Buffer[]) => {
  const body = Buffer.concat(payload);
  return Buffer.concat([varint((field << 3) | 2), varint(body.length), body]);
};

/** Serializes the fields as an ext_proc request-headers message; `eos` null leaves end_of_stream out. */
export function serialize(fields: Field[], eos: boolean | null = true): Buffer {
  const entries = fields.map(([key, value]) =>
    len(1, len(1, Buffer.from(key)), len(3, typeof value === 'string' ? Buffer.from(value, 'latin1') : Buffer.from(value))),
  );
  const endOfStream = eos === null ? Buffer.alloc(0) : Buffer.from([0x18, eos ? 1 : 0]);
  return len(2, len(1, ...entries), endOfStream);
}
