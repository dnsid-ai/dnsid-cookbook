// TEST ONLY. A deterministic, offline DNSid identity world for the real SDK identity verifier: ephemeral keys, a `_dnsid`
// TXT record signed by the SDK, accountable-entity and operational JWK Sets, a status document, and a C2SP lifecycle log
// whose checkpoint is signed by a test log key and cosigned by a test witness. The SDK verifies all of it exactly as it
// would live; only the DNS answers, the HTTPS documents and the log's trust policy are supplied here.
//
// This is NOT DNSid Local (`dnsid local`) and NOT the DNSid-managed service: no registry, no managed log, no real DNS and
// no network. Its trust (the log key and witness) exists only in this process and is never accepted by production
// construction, which uses the SDK's bundled managed trust roots.

import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import {
  DNSSECState,
  IdentityManager,
  jwkThumbprint,
  VerificationCode,
  VerificationError,
  type C2spIssuanceEvent,
  type DNSResolver,
  type DnsIdJWK,
  type JsonFetcher,
  type JsonFetchOptions,
  LogRegistry,
  type DnsidConfig,
  type IdentityCache,
  type KeyProvider,
  type TXTRecord,
} from '@dnsid-ai/sdk';
import { createNodeIdentityVerifier, LocalKeyProvider } from '@dnsid-ai/sdk/node';
import {
  c2spEventId,
  c2spTlogEntryBytes,
  checkpointOrigin,
  createC2spTlogVerificationRegistry,
  encodeEntryBundle,
  entryBundlePath,
  checkpointPath,
  merkleRootFromEntries,
  parseC2spTlogLr,
  prepareC2spTlogEventForSigning,
  requiredC2spResourceFetchGuarantees,
  signPreparedC2spTlogEvent,
  signedC2spEntryBytes,
  stateHash,
  type C2spBoundedResourceFetcher,
  type C2spResourceFetchOptions,
} from '@dnsid-ai/log-c2sp-tlog';

import type { RegistryRequest, VerificationBackend } from '../../src/identity.ts';

export const FIXTURE_LOG_PREFIX = 'https://log-fixture.test';
export const FIXTURE_GOVERNANCE = 'gov-fixture.test';
const WITNESS_NAME = 'witness-fixture.test/w1';
const DNS_TTL_SECONDS = 300;
/** The SDK managed registry's `checkpointMaxAge` (TEN_MINUTES_MS in @dnsid-ai/log-c2sp-tlog 0.37.0). */
export const MANAGED_CHECKPOINT_MAX_AGE_MS = 600_000;

// ---------- signed notes (c2sp.org/signed-note, tlog-checkpoint, tlog-cosignature) ----------

interface NoteSigner {
  readonly name: string;
  readonly vkey: string;
  signLine(message: string, timestamp?: number): string;
}

function noteSigner(name: string, type: 0x01 | 0x04): NoteSigner {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const typed = Buffer.concat([Buffer.from([type]), raw]);
  const keyId = createHash('sha256').update(Buffer.concat([Buffer.from(`${name}\n`), typed])).digest().subarray(0, 4);
  return {
    name,
    vkey: `${name}+${keyId.toString('hex')}+${typed.toString('base64')}`,
    signLine(message, timestamp) {
      let body: Buffer;
      if (type === 0x01) {
        body = cryptoSign(null, Buffer.from(message), privateKey);
      } else {
        const time = Buffer.alloc(8);
        time.writeBigUInt64BE(BigInt(timestamp ?? 0));
        const signed = cryptoSign(null, Buffer.from(`cosignature/v1\ntime ${timestamp}\n${message}`), privateKey);
        body = Buffer.concat([time, signed]);
      }
      return `— ${name} ${Buffer.concat([keyId, body]).toString('base64')}`;
    },
  };
}

// ---------- the test log ----------

export interface FixtureLog {
  readonly prefix: string;
  readonly origin: string;
  readonly policyDocument: Uint8Array;
  readonly entries: Uint8Array[];
  /** Reads served, by URL. */
  readonly reads: string[];
  /** Appends an entry and re-signs the checkpoint (cosigned `witnessAgeSeconds` ago). */
  append(entry: Uint8Array): void;
  resign(options?: { witnessAgeSeconds?: number }): void;
  /** Replaces what the log serves for a URL (status 0 = network failure). */
  override(url: string, response: { status: number; body?: Uint8Array } | undefined): void;
  readonly fetcher: C2spBoundedResourceFetcher;
  /** Called before every log read with the read's signal; may delay, or ignore the signal. */
  gate?: (url: string, signal: AbortSignal | undefined) => Promise<void>;
}

export function fixtureLog(prefix = FIXTURE_LOG_PREFIX): FixtureLog {
  const origin = checkpointOrigin(prefix);
  const logKey = noteSigner(origin, 0x01);
  const witness = noteSigner(WITNESS_NAME, 0x04);
  const policyDocument = new TextEncoder().encode(`log ${logKey.vkey}\nwitness w1 ${witness.vkey}\nquorum w1\n`);
  const entries: Uint8Array[] = [];
  const reads: string[] = [];
  const served = new Map<string, Uint8Array>();
  const overrides = new Map<string, { status: number; body?: Uint8Array }>();

  function resign(options: { witnessAgeSeconds?: number } = {}) {
    served.clear();
    const root = merkleRootFromEntries(entries);
    const note = `${origin}\n${entries.length}\n${Buffer.from(root).toString('base64')}\n`;
    const witnessed = Math.floor(Date.now() / 1000) - (options.witnessAgeSeconds ?? 1);
    const text = `${note}\n${logKey.signLine(note)}\n${witness.signLine(note, witnessed)}\n`;
    served.set(checkpointPath(prefix), new TextEncoder().encode(text));
    for (let bundle = 0; bundle * 256 < entries.length; bundle++) {
      const slice = entries.slice(bundle * 256, bundle * 256 + 256);
      served.set(entryBundlePath(prefix, bundle, slice.length === 256 ? undefined : slice.length), encodeEntryBundle(slice));
    }
  }

  const fetcher: C2spBoundedResourceFetcher = {
    // Test transport: in-memory, so it is declared with the guarantees the SDK requires of a real one.
    securityGuarantees: () => requiredC2spResourceFetchGuarantees(),
    async fetchBounded(url: string, maxBytes: number, options: C2spResourceFetchOptions) {
      options.signal?.throwIfAborted();
      reads.push(url);
      await log.gate?.(url, options.signal);
      const override = overrides.get(url);
      if (override !== undefined) {
        if (override.status === 0) throw new Error('fixture: log unreachable');
        if (override.status !== 200) {
          throw new VerificationError(`fixture: log status ${override.status}`, {
            code: VerificationCode.LogError,
            transient: override.status >= 500,
          });
        }
        return override.body ?? new Uint8Array();
      }
      const body = served.get(url);
      if (body === undefined) {
        throw new VerificationError('fixture: log resource not found', { code: VerificationCode.LogError });
      }
      if (body.length > maxBytes) throw new VerificationError('fixture: too large', { code: VerificationCode.LogError });
      return new Uint8Array(body);
    },
  };

  const log: FixtureLog = {
    prefix,
    origin,
    policyDocument,
    entries,
    reads,
    append(entry) {
      entries.push(entry);
      resign();
    },
    resign,
    override(url, response) {
      if (response === undefined) overrides.delete(url);
      else overrides.set(url, response);
    },
    fetcher,
  };
  return log;
}

// ---------- identities ----------

export interface FixtureIdentity {
  readonly domain: string;
  readonly governanceId: string;
  readonly entity: KeyProvider;
  readonly operational: LocalKeyProvider;
  readonly entityKey: DnsIdJWK;
  readonly operationalKey: DnsIdJWK;
  readonly entityThumbprint: string;
  readonly lr: string;
  readonly txt: string;
  readonly ekUrl: string;
  readonly kuUrl: string;
  readonly statusUrl: string;
  /** This identity's own lifecycle stream: its entries so far, in order (chained by seq and previous event). */
  readonly stream: Uint8Array[];
}

let streamCounter = 0;

/** An identity issued in `log`: the ISSUANCE entry is appended and the checkpoint re-signed. */
export async function issueIdentity(
  log: FixtureLog,
  domain: string,
  options: {
    governanceId?: string;
    policyFlags?: string;
    lr?: string;
    issue?: boolean;
    /** Another identity's accountable-entity key, shared (as under one governance's single `ek` document). */
    entity?: KeyProvider;
    /** The operational (signing) key, for example one loaded from a key file; a new one when absent. */
    operational?: LocalKeyProvider;
    /** The key and status URLs, for identities served over real HTTPS on a test port; the defaults when absent. */
    urls?: { readonly ekUrl?: string; readonly kuUrl?: string; readonly statusUrl?: string };
  } = {},
): Promise<FixtureIdentity> {
  const governanceId = options.governanceId ?? FIXTURE_GOVERNANCE;
  const entity = options.entity ?? (await LocalKeyProvider.generate('EdDSA'));
  const operational = options.operational ?? (await LocalKeyProvider.generate('EdDSA'));
  const entityKey = await entity.signingKey();
  const operationalKey = await operational.signingKey();
  const lr = options.lr ?? `c2sp-tlog:public:${log.prefix}#stream${++streamCounter}`;
  const ekUrl = options.urls?.ekUrl ?? `https://${governanceId}/.well-known/dnsid/ek.json`;
  const kuUrl = options.urls?.kuUrl ?? `https://${domain}/.well-known/dnsid/ku.json`;
  const statusUrl = options.urls?.statusUrl ?? `https://${governanceId}/status/${domain}`;

  const identity = {
    domain,
    governanceId,
    logRef: lr,
    statusUrl,
    ekUrl,
    kuUrl,
    ...(options.policyFlags === undefined ? {} : { policyFlags: options.policyFlags }),
  };
  const publisher = new IdentityManager({ identity }, { keyProvider: operational, entityKeyProvider: entity });
  const txt = await publisher.createTxtRecord();

  const stream: Uint8Array[] = [];
  if (options.issue !== false) {
    const event: C2spIssuanceEvent = {
      type: 'ISSUANCE',
      domain,
      governanceId,
      timestamp: new Date((Math.floor(Date.now() / 1000) - 60) * 1000),
      initialEntityKid: entityKey.kid,
      initialEntityAlg: entityKey.alg as string,
      initialEntityPublicKey: entityKey,
      initialEntityThumbprint: await jwkThumbprint(entityKey),
      initialOperationalKid: operationalKey.kid,
      initialOperationalAlg: operationalKey.alg as string,
      initialOperationalPublicKey: operationalKey,
      initialOperationalThumbprint: await jwkThumbprint(operationalKey),
    };
    const context = { expectedFqdn: domain, expectedGovernanceId: governanceId, entityKey, operationalKey };
    let prepared = prepareC2spTlogEventForSigning(event, lr);
    prepared = await signPreparedC2spTlogEvent(prepared, 'Entity', entity, context);
    prepared = await signPreparedC2spTlogEvent(prepared, 'OperationalCountersignature', operational, context);
    const entry = await c2spTlogEntryBytes(prepared, context);
    stream.push(entry);
    log.append(entry);
  }

  return {
    domain,
    governanceId,
    entity,
    operational,
    entityKey,
    operationalKey,
    entityThumbprint: await jwkThumbprint(entityKey),
    lr,
    txt,
    ekUrl,
    kuUrl,
    statusUrl,
    stream,
  };
}

/**
 * The next lifecycle event of `identity`'s stream, REVOCATION or RETIREMENT, signed by its accountable-entity key with the
 * SDK's prepared-event writer and chained to the stream's last entry (seq, previous event ID and previous state hash).
 * Returns the entry bytes and records them in the identity's stream; appending them to the log is the caller's step, so a
 * test can choose the moment the log changes.
 */
export async function lifecycleEntry(
  identity: FixtureIdentity,
  type: 'REVOCATION' | 'RETIREMENT',
  options: { secondsAgo?: number } = {},
): Promise<Uint8Array> {
  const previous = identity.stream.at(-1);
  if (previous === undefined) throw new Error('fixture: the identity has no ISSUANCE to follow');
  const timestamp = new Date((Math.floor(Date.now() / 1000) - (options.secondsAgo ?? 30)) * 1000);
  const event =
    type === 'REVOCATION'
      ? { type, domain: identity.domain, timestamp, reason: 'keyCompromise' as const }
      : { type, domain: identity.domain, timestamp };
  // The state after the last entry: ISSUANCE (or a terminal event) never changes the keys in these fixtures.
  const status = identity.stream.length === 1 ? 'ACTIVE' : undefined;
  if (status === undefined) throw new Error('fixture: only one lifecycle event after ISSUANCE is supported');
  const state = {
    fqdn: identity.domain,
    status,
    entity_thumb: identity.entityThumbprint,
    operational_thumb: await jwkThumbprint(identity.operationalKey),
  };
  const chain = {
    sequence: identity.stream.length,
    previousEventId: c2spEventId(signedC2spEntryBytes(previous)),
    previousStateHash: stateHash(state),
  };
  const context = { expectedFqdn: identity.domain, expectedGovernanceId: identity.governanceId, entityKey: identity.entityKey };
  let prepared = prepareC2spTlogEventForSigning(event, identity.lr, chain);
  prepared = await signPreparedC2spTlogEvent(prepared, 'Entity', identity.entity, context);
  const entry = await c2spTlogEntryBytes(prepared, context);
  identity.stream.push(entry);
  return entry;
}

// ---------- DNS and HTTPS ----------

type DnsAnswer = { records: TXTRecord[]; state: DNSSECState } | { error: Error } | { hang: true };
type HttpAnswer = { data: unknown } | { error: VerificationError } | { hang: true };

export interface FixtureNetwork {
  readonly dnsResolver: DNSResolver;
  readonly fetchJson: JsonFetcher;
  /** Every DNS name and URL requested, in order. */
  readonly requests: string[];
  publish(identity: FixtureIdentity, status?: 'ACTIVE' | 'REVOKED' | 'RETIRED'): void;
  setDns(name: string, answer: DnsAnswer | undefined): void;
  setHttp(url: string, answer: HttpAnswer | undefined): void;
  /** Called before every DNS or HTTPS answer, with the request's signal; may delay. */
  gate?: (what: string, signal: AbortSignal | undefined) => Promise<void>;
  /** Called after a DNS or HTTPS answer is read and before it is returned, with the request's signal; may delay. */
  delivered?: (what: string, signal: AbortSignal | undefined) => Promise<void>;
  /** The served certificate's notAfter for a URL; one day after the fetch when absent or undefined. */
  certificateNotAfter?: (url: string) => Date | undefined;
}

/** Waits for ever, ignoring cancellation: a dependency that doesn't honour its signal. */
const never = () => new Promise<never>(() => {});

export function fixtureNetwork(): FixtureNetwork {
  const dns = new Map<string, DnsAnswer>();
  const http = new Map<string, HttpAnswer>();
  const requests: string[] = [];

  const network: FixtureNetwork = {
    requests,
    dnsResolver: {
      async fetchTXT(name, options) {
        requests.push(`dns:${name}`);
        await network.gate?.(`dns:${name}`, options?.signal);
        const answer = dns.get(name);
        if (answer === undefined) return [[], DNSSECState.UNKNOWN];
        if ('hang' in answer) return never();
        if ('error' in answer) throw answer.error;
        const result: [TXTRecord[], DNSSECState] = [
          answer.records.map((record) => ({ ...record, strings: [...record.strings] })),
          answer.state,
        ];
        await network.delivered?.(`dns:${name}`, options?.signal);
        return result;
      },
    },
    async fetchJson(url: string, options?: JsonFetchOptions) {
      requests.push(url);
      await network.gate?.(url, options?.signal);
      options?.signal?.throwIfAborted();
      const host = new URL(url).hostname;
      // The SDK's host restriction, as the real transport applies it.
      if (options?.allowedHost !== undefined) {
        const allowed =
          host === options.allowedHost || (options.domainBoundary === true && host.endsWith(`.${options.allowedHost}`));
        if (!allowed) throw new VerificationError('fixture: host not permitted', { code: VerificationCode.TLSError });
      }
      const answer = http.get(url);
      if (answer === undefined) {
        throw new VerificationError('fixture: HTTP 404', { code: VerificationCode.HTTPError, transient: false });
      }
      if ('hang' in answer) return never();
      if ('error' in answer) throw answer.error;
      const notAfter = network.certificateNotAfter?.(url) ?? new Date(Date.now() + 86_400_000);
      const result = { data: structuredClone(answer.data), tlsCert: { notAfter, san: [host] } };
      await network.delivered?.(url, options?.signal);
      return result;
    },
    publish(identity, status = 'ACTIVE') {
      dns.set(`_dnsid.${identity.domain}`, {
        records: [{ strings: [identity.txt], ttl: DNS_TTL_SECONDS }],
        state: DNSSECState.UNKNOWN,
      });
      http.set(identity.ekUrl, { data: { keys: [identity.entityKey] } });
      http.set(identity.kuUrl, { data: { keys: [identity.operationalKey] } });
      const document: Record<string, string> = {
        state: status,
        lastTransitionAt: new Date(Date.now() - 60_000).toISOString(),
      };
      if (status === 'REVOKED') document.revocationReason = 'keyCompromise';
      http.set(identity.statusUrl, { data: document });
    },
    setDns(name, answer) {
      if (answer === undefined) dns.delete(name);
      else dns.set(name, answer);
    },
    setHttp(url, answer) {
      if (answer === undefined) http.delete(url);
      else http.set(url, answer);
    },
  };
  return network;
}

// ---------- the test backend ----------

export interface FixtureBackendCounters {
  registries: number;
  verifiers: number;
  /** The registry request each construction received. */
  readonly registryRequests: RegistryRequest[];
  /** The identity cache each verifier was given. */
  readonly caches: IdentityCache[];
}

export interface FixtureBackendOptions {
  /** Logs that are served but NOT trusted (their keys are not in the policy). */
  readonly untrustedLogs?: readonly FixtureLog[];
  /** Served at the trusted log's prefix in its place: same prefix, its own (untrusted) keys. */
  readonly impostor?: FixtureLog;
  /** Runs before the registry is built, with the request's registry options; may delay or throw. */
  readonly beforeRegistry?: (request: RegistryRequest) => Promise<void>;
  /** Runs before the verifier is built; may delay or throw. */
  readonly beforeVerifier?: () => Promise<void>;
  /** Builds the verifier with this configuration instead of the one the stage passes (to test the explicit checks). */
  readonly overrideConfig?: (config: DnsidConfig) => DnsidConfig;
}

/**
 * The verification backend for tests: the real SDK identity verifier (`createNodeIdentityVerifier`) and the real
 * generic C2SP verification registry (`createC2spTlogVerificationRegistry`), with this file's DNS, HTTPS and log
 * transports and the test log's trust policy injected explicitly. As the managed registry does for its catalog, it
 * refuses a log reference outside the trusted log before reading anything. Production never uses it.
 */
let backendCounter = 0;

export function fixtureBackend(
  network: FixtureNetwork,
  trusted: FixtureLog,
  options: FixtureBackendOptions = {},
): VerificationBackend & { readonly counters: FixtureBackendCounters } {
  const counters: FixtureBackendCounters = { registries: 0, verifiers: 0, registryRequests: [], caches: [] };
  const served = [options.impostor ?? trusted, ...(options.untrustedLogs ?? [])];
  const fetcher: C2spBoundedResourceFetcher = {
    securityGuarantees: () => requiredC2spResourceFetchGuarantees(),
    fetchBounded(url, maxBytes, fetchOptions) {
      const log = served.find((each) => url.startsWith(`${each.prefix}/`));
      if (log === undefined) throw new VerificationError('fixture: no such log', { code: VerificationCode.LogError });
      return log.fetcher.fetchBounded(url, maxBytes, fetchOptions);
    },
  };
  return {
    name: 'test-fixture',
    // Its own context per backend: test transport and trust never share cached material with production or each other.
    transportContext: `test-fixture #${++backendCounter}: in-memory DNS and HTTPS, test log trust`,
    counters,
    async createLogRegistry(request): Promise<LogRegistry> {
      counters.registries++;
      counters.registryRequests.push(request);
      await options.beforeRegistry?.(request);
      const generic = await createC2spTlogVerificationRegistry({
        policyDocument: trusted.policyDocument,
        resourceFetcher: fetcher,
        trustedCheckpointStore: request.trustedCheckpointStore,
        signal: request.signal,
        // The managed registry's own time policy (createDnsidManagedVerificationRegistry, SDK 0.37.0): checkpoints for
        // non-revocation at most ten minutes old, and no clock skew, so a witness timestamp in the future is refused.
        checkpointMaxAge: MANAGED_CHECKPOINT_MAX_AGE_MS,
        allowedClockSkew: 0,
      });
      const registry = new LogRegistry();
      registry.register('c2sp-tlog', (lr, invocation) => {
        if (parseC2spTlogLr(lr).logPrefix !== trusted.prefix) throw new Error('fixture: log not trusted');
        return generic.newReader(lr, invocation);
      });
      return registry;
    },
    async createIdentityVerifier(config, dependencies) {
      counters.verifiers++;
      counters.caches.push(dependencies.cache);
      await options.beforeVerifier?.();
      const { dnsResolver, fetchJson } = dependencies.transport({
        dnsResolver: network.dnsResolver,
        fetchJson: network.fetchJson,
      });
      return createNodeIdentityVerifier(options.overrideConfig?.(config) ?? config, {
        logRegistry: dependencies.logRegistry,
        cache: dependencies.cache,
        dnsResolver,
        fetchJson,
      });
    },
  };
}
