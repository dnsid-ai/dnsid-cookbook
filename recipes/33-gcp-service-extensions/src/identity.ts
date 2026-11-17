// The identity stage: the signer's DNSid identity, verified per request by the DNSid SDK's identity verifier
// (`createNodeIdentityVerifier`, @dnsid-ai/sdk 0.37.0) with the DNSid-managed C2SP log registry
// (`createDnsidManagedVerificationRegistry`), then an explicit check of its governance against the configured policy.
// APIs: https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/sdk/src/node-identity-manager.ts and
// https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/log-c2sp-tlog/src/managed-verification-registry.ts
//
// Passing this stage means: exactly one RFC 9421 signature verified against an operational key of an identity whose
// signed `_dnsid` record, accountable-entity and operational keys, current status document (ACTIVE when fetched) and
// C2SP ISSUANCE binding the SDK verified, under a governance ID (and optional key pin) this deployment trusts. It is NOT
// an authorization: the explicit non-revocation check (`verifyNonRevocation()`) and the evidence-freshness check come
// after it (src/lifecycle.ts), in the same request scope (`withVerifiedIdentity`).
//
// Per request: the identity verifier, the log registry (its readers carry the request's signal) and a request-local
// identity cache, all built only once the signature stage asks for the signer's identity, and all bounded by the
// request's original deadline. Per process: the governance policy, the trusted checkpoint store and the identity
// material cache (src/material-cache.ts: TXT answers and key documents as data, reused at the verifier's DNS and HTTPS
// boundaries, so the SDK verifies them again on every request). Nothing that holds a log reader is shared between
// requests, and status documents and log resources are always fetched.

import {
  DNSSECMode,
  LogRegistry,
  VerificationCode,
  VerificationError,
  normalizeFQDN,
  validateDnsidConfig,
  type DnsidConfig,
  type IdentityCache,
  type IdentityManager,
  type IdentityManagerDependencies,
  type IdentityResolver,
  type LogReader,
  type VerifiedDomain,
} from '@dnsid-ai/sdk';
import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';
import { createDefaultDnsResolver, fetchJson as transportFetchJson } from '@dnsid-ai/transport';
import {
  C2spTlogError,
  createDefaultC2spBoundedResourceFetcher,
  createDnsidManagedVerificationRegistry,
  InMemoryTrustedC2spCheckpointStore,
  type C2spBoundedResourceFetcher,
  type TrustedC2spCheckpoint,
  type TrustedC2spCheckpointStore,
} from '@dnsid-ai/log-c2sp-tlog';

import { checkSerializedRequest, type DecodeRejection } from './ext-proc.ts';
import { SharedMaterialCache, type RequestMaterialView, type RequestTransport } from './material-cache.ts';
import type { EligibleForVerification, PreconditionDenial } from './preconditions.ts';
import {
  SDK_BACKSTOP_MS,
  verifyRequestSignature,
  type SignatureDenial,
  type SignatureStagePassed,
} from './signature.ts';

// ---------- governance policy ----------

/** The quick start's `DNSID_TRUSTED_GOVERNANCE` default (quickstart.json): the sandbox governance. */
export const DEFAULT_TRUSTED_GOVERNANCE = 'dnsid-sandbox.io';

export interface GovernanceEntry {
  /** A governance ID (the `gi` the accountable entity signs), normalized. */
  readonly governanceId: string;
  /** Optional RFC 7638 SHA-256 thumbprints, one of which the identity's current `ek` signing key must match. */
  readonly entityKeyThumbprints?: readonly string[];
}

/** A validated, frozen, non-empty list of trusted governance IDs. Built only by the two functions below. */
export interface GovernancePolicy {
  readonly entries: readonly GovernanceEntry[];
}

/** Refused governance configuration. The message names the problem, never the configured value. */
export class GovernanceConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GovernanceConfigError';
  }
}

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
// At least two labels, and a final label that isn't all digits, so an IP address or a single label is refused.
const DOMAIN = new RegExp(`^(?=.{1,253}$)(?:${LABEL}\\.)+(?=[a-z0-9-]*[a-z])${LABEL}$`);

function normalizedGovernanceId(raw: unknown, position: number): string {
  if (typeof raw !== 'string' || raw.trim() !== raw || raw.length === 0) {
    throw new GovernanceConfigError(`trusted governance entry ${position} is empty or padded`);
  }
  let normalized: string;
  try {
    normalized = normalizeFQDN(raw);
  } catch {
    throw new GovernanceConfigError(`trusted governance entry ${position} is not a domain name`);
  }
  if (!DOMAIN.test(normalized)) throw new GovernanceConfigError(`trusted governance entry ${position} is not a domain name`);
  return normalized;
}

/**
 * The typed policy, with optional key pins. Refuses an empty list, a malformed or duplicate governance ID, and pins the
 * SDK would refuse (an empty list, a non-canonical thumbprint, duplicates).
 */
export function governancePolicy(entries: readonly GovernanceEntry[]): GovernancePolicy {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new GovernanceConfigError('the trusted governance list must not be empty');
  }
  const seen = new Set<string>();
  const normalized = entries.map((entry, index) => {
    const governanceId = normalizedGovernanceId(entry?.governanceId, index + 1);
    if (seen.has(governanceId)) throw new GovernanceConfigError(`trusted governance entry ${index + 1} is a duplicate`);
    seen.add(governanceId);
    const pins = entry.entityKeyThumbprints;
    return Object.freeze(
      pins === undefined
        ? { governanceId }
        : { governanceId, entityKeyThumbprints: Object.freeze([...pins]) as readonly string[] },
    );
  });
  try {
    // The SDK's own validation of the same list (thumbprint form, duplicates), so both apply the same rules.
    validateDnsidConfig({ verification: { trustedEntities: normalized.map(toTrustedEntity) } });
  } catch {
    throw new GovernanceConfigError('a trusted governance key pin is malformed');
  }
  return Object.freeze({ entries: Object.freeze(normalized) });
}

/**
 * The `DNSID_TRUSTED_GOVERNANCE` setting: comma-separated governance IDs. Absent means the quick start's default; an
 * explicitly empty or malformed value is refused rather than read as "trust nothing" or "trust the default".
 */
export function governanceFromSetting(value: string | undefined): GovernancePolicy {
  if (value === undefined) return governancePolicy([{ governanceId: DEFAULT_TRUSTED_GOVERNANCE }]);
  if (value.trim().length === 0) throw new GovernanceConfigError('DNSID_TRUSTED_GOVERNANCE is set but empty');
  return governancePolicy(value.split(',').map((item) => ({ governanceId: item.trim() === '' ? '' : item.trim() })));
}

function toTrustedEntity(entry: GovernanceEntry) {
  return entry.entityKeyThumbprints === undefined
    ? { governanceId: entry.governanceId }
    : { governanceId: entry.governanceId, entityKeyThumbprints: [...entry.entityKeyThumbprints] };
}

/**
 * The SDK configuration every request's verifier gets: the trusted governance list (never empty), DNSSEC `auto`, status
 * fetched on every verification. No `transport` section: the SDK's own DNS resolver and HTTPS fetcher apply, with system
 * trust roots, no extra CA and no private-address exceptions.
 */
export function sdkVerificationConfig(policy: GovernancePolicy): DnsidConfig {
  return {
    verification: {
      trustedEntities: policy.entries.map(toTrustedEntity),
      dnssecMode: DNSSECMode.auto,
      statusCheckInterval: 0,
    },
  };
}

type GovernanceFailureKind = 'untrusted_governance' | 'governance_pin_mismatch';

/**
 * The explicit check after SDK verification: the same policy, applied to the record the SDK returned. Synchronous: the
 * key pin is compared with the thumbprint the SDK computed from the signing key during verification, so nothing here
 * can outlast the request's budget.
 */
function checkGovernance(policy: GovernancePolicy, result: VerifiedDomain): GovernanceFailureKind | undefined {
  const governanceId = result.record.governanceId();
  const entry = policy.entries.find((candidate) => candidate.governanceId === governanceId);
  if (entry === undefined) return 'untrusted_governance';
  if (entry.entityKeyThumbprints === undefined) return undefined;
  return entry.entityKeyThumbprints.includes(result.signingKeyThumbprint) ? undefined : 'governance_pin_mismatch';
}

// ---------- shared checkpoint store, request-bound access ----------

/**
 * One request's access to the per-process trusted checkpoint store. Every read and compare-and-swap also carries the
 * request's signal, so a request whose budget has run out or that was cancelled commits nothing: it is checked here
 * and, by the SDK's in-memory store, again immediately before the write.
 */
export class RequestBoundCheckpointStore implements TrustedC2spCheckpointStore {
  readonly #shared: TrustedC2spCheckpointStore;
  readonly #signal: AbortSignal;

  constructor(shared: TrustedC2spCheckpointStore, signal: AbortSignal) {
    this.#shared = shared;
    this.#signal = signal;
  }

  #combined(signal: AbortSignal | undefined): AbortSignal {
    return signal === undefined || signal === this.#signal ? this.#signal : AbortSignal.any([signal, this.#signal]);
  }

  async load(origin: string, signal?: AbortSignal): Promise<TrustedC2spCheckpoint | undefined> {
    const combined = this.#combined(signal);
    combined.throwIfAborted();
    return this.#shared.load(origin, combined);
  }

  async compareAndSwap(
    origin: string,
    expected: TrustedC2spCheckpoint | undefined,
    candidate: TrustedC2spCheckpoint,
    signal?: AbortSignal,
  ): Promise<boolean> {
    const combined = this.#combined(signal);
    combined.throwIfAborted();
    return this.#shared.compareAndSwap(origin, expected, candidate, combined);
  }
}

// ---------- request-local identity cache ----------

/**
 * The verifier's identity cache, for one request only. The SDK's default cache keeps each entry, log reader included,
 * on a timer until the DNS TTL runs out; this one has no timers and is emptied when the request ends.
 */
class RequestLocalIdentityCache implements IdentityCache {
  readonly #entries = new Map<string, { result: VerifiedDomain; expiresAt: number }>();

  get(domain: string): VerifiedDomain | null {
    const entry = this.#entries.get(domain);
    if (entry === undefined) return null;
    if (Date.now() >= entry.expiresAt) {
      this.#entries.delete(domain);
      return null;
    }
    return entry.result;
  }

  put(domain: string, result: VerifiedDomain): void {
    this.#entries.delete(domain);
    const expiresAt = result.expiry().getTime();
    if (result.dnsTTL <= 0 || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) return;
    this.#entries.set(domain, { result, expiresAt });
  }

  evict(domain: string): void {
    this.#entries.delete(domain);
  }

  clear(): void {
    this.#entries.clear();
  }
}

// ---------- strict log registry ----------

type LogReaderFactory = Parameters<LogRegistry['register']>[1];

/**
 * A log registry that refuses a log method nobody registered, where the SDK's registry would hand back a NoopLogReader.
 * `snapshot()` keeps the refusal, since the identity verifier works from a snapshot.
 */
export class StrictLogRegistry extends LogRegistry {
  readonly #methods = new Map<string, LogReaderFactory>();

  override register(method: string, factory: LogReaderFactory): void {
    super.register(method, factory);
    this.#methods.set(method, factory);
  }

  override snapshot(): LogRegistry {
    const copy = new StrictLogRegistry();
    for (const [method, factory] of this.#methods) copy.register(method, factory);
    return copy;
  }

  override newReader(lr: string, options?: { signal?: AbortSignal; revalidate?: boolean }): LogReader {
    const method = lr.slice(0, Math.max(0, lr.indexOf(':')));
    if (!this.#methods.has(method)) {
      throw new VerificationError('unsupported log method', { code: VerificationCode.LogError, transient: false });
    }
    return super.newReader(lr, options);
  }

  /** Only the given methods, each read through `source`. */
  static of(source: LogRegistry, methods: readonly string[]): StrictLogRegistry {
    const strict = new StrictLogRegistry();
    for (const method of methods) strict.register(method, (lr, options) => source.newReader(lr, options));
    return strict;
  }
}

/** The only log method this verifier accepts. */
export const SUPPORTED_LOG_METHODS: readonly string[] = Object.freeze(['c2sp-tlog']);

// ---------- backends ----------

export interface RegistryRequest {
  /** The request scope's signal: aborted when the request is cancelled, its deadline passes, or it ends. */
  readonly signal: AbortSignal;
  /** Request-bound access to the per-process checkpoint store. */
  readonly trustedCheckpointStore: TrustedC2spCheckpointStore;
}

export interface IdentityVerifierDependencies extends Required<Pick<IdentityManagerDependencies, 'logRegistry' | 'cache'>> {
  /**
   * Wraps the backend's own DNS resolver and JSON fetcher with this request's access to the shared material cache. A
   * backend passes the result to the verifier; misses go to the transport it was given, unchanged.
   */
  readonly transport: (base: RequestTransport) => RequestTransport;
}

/** Where the per-request verifier and log registry come from. Production uses PRODUCTION_BACKEND only. */
export interface VerificationBackend {
  readonly name: string;
  /**
   * Names the transport and trust the backend's DNS resolver and fetcher apply (resolver, trust roots, extra CAs,
   * private-address exceptions). Cached material is reused only within the same context.
   */
  readonly transportContext: string;
  createLogRegistry(request: RegistryRequest): Promise<LogRegistry>;
  createIdentityVerifier(config: DnsidConfig, dependencies: IdentityVerifierDependencies): Promise<IdentityManager>;
}

/**
 * The SDK's production construction. The identity verifier uses the SDK's Node DNS resolver and its HTTPS JSON fetcher
 * (HTTPS only, certificate verification against system roots, host-pinned and destination-checked redirects, refusal of
 * private, loopback and link-local destinations, bounded bodies). The managed registry trusts only the DNSid-managed
 * logs bundled with the SDK and reads them through the SDK's default bounded fetcher (no redirects, the same destination
 * checks, bounded bodies). No test trust, no extra CA, no private-address exception.
 */
export const PRODUCTION_BACKEND: VerificationBackend = Object.freeze({
  name: 'production',
  transportContext: 'production: @dnsid-ai/transport system resolver, system trust roots, no extra CA, no private-address exceptions',
  createLogRegistry: (request: RegistryRequest) =>
    createDnsidManagedVerificationRegistry({
      signal: request.signal,
      trustedCheckpointStore: request.trustedCheckpointStore,
    }),
  createIdentityVerifier: (config: DnsidConfig, dependencies: IdentityVerifierDependencies) => {
    // What createNodeIdentityVerifier builds by default for a configuration without a `transport` section (no DNS
    // server, CA bundle or private-address hosts), made explicit so the material cache can wrap it.
    const { dnsResolver, fetchJson } = dependencies.transport({
      dnsResolver: createDefaultDnsResolver({}),
      fetchJson: (url, options) => transportFetchJson(url, { ...options }),
    });
    return createNodeIdentityVerifier(config, {
      logRegistry: dependencies.logRegistry,
      cache: dependencies.cache,
      dnsResolver,
      fetchJson,
    });
  },
});

// ---------- results ----------

export type IdentityFailureKind =
  | 'not_found' // no `_dnsid` record
  | 'invalid' // the identity's evidence failed verification, or the SDK refused it permanently
  | 'inactive' // the status document reports a state other than ACTIVE
  | 'unavailable' // DNS, a key set, the status document or the log couldn't be read (transient)
  | 'construction_failed' // the request's verifier or registry couldn't be built
  | GovernanceFailureKind
  | 'cancelled'
  | 'budget_exhausted';

/**
 * Typed failure information, kept for logging and for the later lifecycle stage (an inactive identity must be told
 * apart from an outage). Enumerations only: no error message, URL or key material.
 */
export interface IdentityFailure {
  readonly kind: IdentityFailureKind;
  readonly code?: VerificationCode;
  readonly transient: boolean;
  /** The state the status document reported, for `inactive` only. */
  readonly agentState?: string;
}

export type IdentityDenyReason =
  | 'identity_not_found'
  | 'identity_invalid'
  | 'identity_inactive'
  | 'identity_unavailable'
  | 'governance_not_trusted';

/** A stable reason code for the response; `failure` is internal and never sent. */
export interface IdentityDenial {
  readonly outcome: 'deny';
  readonly status: 403;
  readonly reason: IdentityDenyReason;
  readonly failure: IdentityFailure;
}

/**
 * The identity stage passed. NOT an authorization: non-revocation and evidence freshness are still to be checked.
 * `signature` is the signature stage's result unchanged, with the SDK's evidence.
 */
/**
 * Where this request's identity material (TXT answers, key documents) came from: all from the shared material cache
 * (`hit`), all fetched (`miss`), some of each (`partial`), or no cache configured (`off`). The status document and the
 * log are read for every request either way.
 */
export type MaterialCacheUse = 'hit' | 'miss' | 'partial' | 'off';

export interface IdentityStagePassed {
  readonly outcome: 'identity_stage_passed';
  readonly signature: SignatureStagePassed;
  readonly identity: {
    readonly domain: string;
    readonly governanceId: string;
    readonly entityKeyThumbprint: string;
    readonly dnssecState: string;
    readonly materialCache: MaterialCacheUse;
  };
}

export type IdentityStageResult = IdentityStagePassed | IdentityDenial | SignatureDenial;

const DENY_REASON: Record<Exclude<IdentityFailureKind, 'cancelled' | 'budget_exhausted'>, IdentityDenyReason> = {
  not_found: 'identity_not_found',
  invalid: 'identity_invalid',
  inactive: 'identity_inactive',
  unavailable: 'identity_unavailable',
  construction_failed: 'identity_unavailable',
  untrusted_governance: 'governance_not_trusted',
  governance_pin_mismatch: 'governance_not_trusted',
};

function denial(failure: IdentityFailure): IdentityDenial | SignatureDenial {
  if (failure.kind === 'cancelled') return { outcome: 'deny', status: 403, reason: 'verification_cancelled' };
  if (failure.kind === 'budget_exhausted') return { outcome: 'deny', status: 403, reason: 'verification_budget_exhausted' };
  return { outcome: 'deny', status: 403, reason: DENY_REASON[failure.kind], failure: Object.freeze({ ...failure }) };
}

function classify(error: unknown, policy: GovernancePolicy): IdentityFailure {
  if (!(error instanceof VerificationError)) return { kind: 'invalid', transient: false };
  const { code, transient } = error;
  switch (code) {
    case VerificationCode.RecordNotFound:
      return { kind: 'not_found', code, transient };
    case VerificationCode.StatusNotActive:
      return error.agentState === undefined
        ? { kind: 'inactive', code, transient }
        : { kind: 'inactive', code, transient, agentState: error.agentState };
    case VerificationCode.CounterpartyNotAccepted: {
      // The SDK's own acceptance refused it: a trusted governance ID means its key pin didn't match.
      const trusted = policy.entries.some((entry) => entry.governanceId === error.verifiedGovernanceId);
      return { kind: trusted ? 'governance_pin_mismatch' : 'untrusted_governance', code, transient };
    }
    case VerificationCode.DNSResolution:
    case VerificationCode.StatusUnavailable:
      return { kind: 'unavailable', code, transient: true };
    default:
      return { kind: transient ? 'unavailable' : 'invalid', code, transient };
  }
}

// ---------- the per-process runtime and the per-request scope ----------

export interface VerificationRuntime {
  readonly governance: GovernancePolicy;
  readonly backend: VerificationBackend;
  /** Shared by every request of this process; in memory only (decision D-08). */
  readonly checkpointStore: TrustedC2spCheckpointStore;
  /** Shared by every request of this process; in memory only. Undefined only when a test turns it off. */
  readonly sharedMaterial: SharedMaterialCache | undefined;
}

export function createVerificationRuntime(options: {
  governance: GovernancePolicy;
  backend: VerificationBackend;
  checkpointStore?: TrustedC2spCheckpointStore;
  /** The material cache; a new one with the default limits when absent, none when `false`. */
  sharedMaterial?: SharedMaterialCache | false;
}): VerificationRuntime {
  if (options.governance?.entries?.length === undefined || options.governance.entries.length === 0) {
    throw new GovernanceConfigError('the trusted governance list must not be empty');
  }
  return Object.freeze({
    governance: options.governance,
    backend: options.backend,
    checkpointStore: options.checkpointStore ?? new InMemoryTrustedC2spCheckpointStore(),
    sharedMaterial: options.sharedMaterial === false ? undefined : (options.sharedMaterial ?? new SharedMaterialCache()),
  });
}

// ---------- how the log is read ----------

/**
 * `DNSID_LOG_EVIDENCE`: how the verifier establishes that it has an identity's complete log history. `bundle` (the
 * default, also when unset) is the SDK's managed behavior: the log's signed stream bundle for the identity, and a
 * complete raw scan of the log when no bundle is available. `full-scan` never asks for a bundle, so every lifecycle read
 * is the raw scan, every entry checked against the witnessed checkpoint's root (the SDK's own fallback path, with the
 * same trust and the same checks; slower, never weaker). It exists so the live tests can time the fallback (ADD-05);
 * the deployment never sets it.
 */
export type LogEvidenceMode = 'bundle' | 'full-scan';

export class LogEvidenceConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LogEvidenceConfigError';
  }
}

export function logEvidenceFromSetting(value: string | undefined): LogEvidenceMode {
  if (value === undefined || value === 'bundle') return 'bundle';
  if (value === 'full-scan') return 'full-scan';
  throw new LogEvidenceConfigError('DNSID_LOG_EVIDENCE must be bundle or full-scan');
}

/** A log stream bundle's URL, as the SDK requests it: `<log prefix>/streams/<agent FQDN>?format=bundle`. */
const STREAM_BUNDLE = /\/streams\/[^/?#]+\?format=bundle$/;

/**
 * `base`, except that a stream bundle is never fetched: the request is answered as the log's 404, which is the SDK's
 * documented signal to fall back to the complete raw scan (SDK 0.37.0 bundleFallbackAllowed: 404, 408, 429, 5xx).
 */
export function fullScanFetcher(base: C2spBoundedResourceFetcher): C2spBoundedResourceFetcher {
  return {
    securityGuarantees: () => base.securityGuarantees(),
    fetchBounded(url, maxBytes, options) {
      if (STREAM_BUNDLE.test(url)) return Promise.reject(new C2spTlogError('stream bundles are not read (DNSID_LOG_EVIDENCE=full-scan)', { status: 404 }));
      return base.fetchBounded(url, maxBytes, options);
    },
  };
}

/** PRODUCTION_BACKEND, reading the log by complete raw scan only (DNSID_LOG_EVIDENCE=full-scan). */
export const FULL_SCAN_BACKEND: VerificationBackend = Object.freeze({
  ...PRODUCTION_BACKEND,
  name: 'production-full-scan',
  createLogRegistry: (request: RegistryRequest) =>
    createDnsidManagedVerificationRegistry({
      signal: request.signal,
      trustedCheckpointStore: request.trustedCheckpointStore,
      resourceFetcher: fullScanFetcher(createDefaultC2spBoundedResourceFetcher()),
    }),
});

/**
 * The production runtime, from `DNSID_TRUSTED_GOVERNANCE` and `DNSID_LOG_EVIDENCE`; refuses an empty or malformed
 * setting before any request.
 */
export function createProductionVerificationRuntime(
  setting: string | undefined = process.env.DNSID_TRUSTED_GOVERNANCE,
  logEvidence: string | undefined = process.env.DNSID_LOG_EVIDENCE,
): VerificationRuntime {
  const backend = logEvidenceFromSetting(logEvidence) === 'full-scan' ? FULL_SCAN_BACKEND : PRODUCTION_BACKEND;
  return createVerificationRuntime({ governance: governanceFromSetting(setting), backend });
}

class ScopeEnded extends Error {
  readonly kind: 'cancelled' | 'budget_exhausted';
  constructor(kind: 'cancelled' | 'budget_exhausted') {
    super(kind);
    this.name = 'ScopeEnded';
    this.kind = kind;
  }
}

/**
 * One request's verification: its own abort controller (cancelled with the request, at the original deadline, or when
 * the request ends), its own verifier, registry and cache, and the resolver the signature stage calls.
 */
class RequestScope implements VerificationScope {
  readonly #controller = new AbortController();
  readonly #requestSignal: AbortSignal;
  readonly #deadline: number;
  readonly #runtime: VerificationRuntime;
  readonly #revalidate: boolean;
  readonly #cache = new RequestLocalIdentityCache();
  readonly #material: RequestMaterialView | undefined;
  readonly #onRequestAbort = () => this.#controller.abort(new ScopeEnded('cancelled'));
  #timer: ReturnType<typeof setTimeout> | undefined;
  #verifier: Promise<IdentityManager> | undefined;
  failure: IdentityFailure | undefined;
  verified: VerifiedDomain | undefined;
  lookups = 0;

  /** Where this request's identity material came from so far (MaterialCacheUse). */
  get materialCache(): MaterialCacheUse {
    if (this.#material === undefined) return 'off';
    const { reused, fetched } = this.#material.use;
    return fetched === 0 && reused > 0 ? 'hit' : reused === 0 ? 'miss' : 'partial';
  }

  constructor(runtime: VerificationRuntime, requestSignal: AbortSignal, deadline: number, revalidate: boolean) {
    this.#runtime = runtime;
    this.#requestSignal = requestSignal;
    this.#deadline = deadline;
    this.#revalidate = revalidate;
    this.#material = runtime.sharedMaterial?.view(runtime.backend.transportContext, {
      signal: this.#controller.signal,
      revalidate,
    });
    if (requestSignal.aborted) {
      this.#onRequestAbort();
      return;
    }
    const remaining = deadline - performance.now();
    if (remaining <= 0) {
      this.#controller.abort(new ScopeEnded('budget_exhausted'));
      return;
    }
    requestSignal.addEventListener('abort', this.#onRequestAbort, { once: true });
    this.#timer = setTimeout(() => this.#controller.abort(new ScopeEnded('budget_exhausted')), Math.ceil(remaining));
  }

  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  #ended(): ScopeEnded {
    const reason: unknown = this.#controller.signal.reason;
    if (reason instanceof ScopeEnded) return reason;
    return new ScopeEnded(this.#requestSignal.aborted ? 'cancelled' : 'budget_exhausted');
  }

  endedBy(error: unknown): 'cancelled' | 'budget_exhausted' | undefined {
    if (error instanceof ScopeEnded) return error.kind;
    return this.#controller.signal.aborted ? this.#ended().kind : undefined;
  }

  /**
   * Runs `operation` within this request's budget. It settles when the scope ends even if the operation ignores its
   * signal, and a result that arrives after the scope ended is discarded.
   */
  async bounded<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const signal = this.#controller.signal;
    if (signal.aborted) throw this.#ended();
    let onAbort = () => {};
    const ended = new Promise<never>((_, reject) => {
      onAbort = () => reject(this.#ended());
      signal.addEventListener('abort', onAbort, { once: true });
    });
    const work = Promise.resolve().then(() => operation(signal));
    work.catch(() => {}); // a late failure after the scope ended is not an unhandled rejection
    try {
      const value = await Promise.race([work, ended]);
      if (signal.aborted || performance.now() >= this.#deadline) throw this.#ended();
      return value;
    } finally {
      signal.removeEventListener('abort', onAbort);
    }
  }

  /** Built on first use and only once per request; a failure is this request's only, never kept for the next. */
  #identityVerifier(): Promise<IdentityManager> {
    this.#verifier ??= this.bounded(async (signal) => {
      const { backend, checkpointStore, governance } = this.#runtime;
      const trustedCheckpointStore = new RequestBoundCheckpointStore(checkpointStore, signal);
      const managed = await backend.createLogRegistry({ signal, trustedCheckpointStore });
      // A construction abandoned when its request ended goes no further.
      signal.throwIfAborted();
      const logRegistry = StrictLogRegistry.of(managed, SUPPORTED_LOG_METHODS);
      const material = this.#material;
      return backend.createIdentityVerifier(sdkVerificationConfig(governance), {
        logRegistry,
        cache: this.#cache,
        transport: (base) => (material === undefined ? base : material.wrap(base)),
      });
    });
    return this.#verifier;
  }

  #fail(failure: IdentityFailure): never {
    this.failure ??= failure;
    throw new VerificationError('identity verification failed', {
      code: failure.code ?? VerificationCode.RecordInvalid,
      transient: failure.transient,
    });
  }

  /** The resolver for the signature stage. It never supplies a peer certificate: the callout receives none. */
  readonly resolver: IdentityResolver = {
    verifyDomain: async (domain, _peerCertificate, options) => {
      this.lookups++;
      let verifier: IdentityManager;
      try {
        verifier = await this.#identityVerifier();
      } catch (error) {
        if (error instanceof ScopeEnded) this.#fail({ kind: error.kind, transient: true });
        this.#fail({ kind: 'construction_failed', transient: true });
      }
      let result: VerifiedDomain;
      try {
        result = await this.bounded((signal) => {
          const remaining = this.#deadline - performance.now();
          if (remaining <= 0) throw new ScopeEnded('budget_exhausted');
          // The scope's timer ends the budget; the SDK's timeout is only a backstop just after it.
          const combined = options?.signal === undefined ? signal : AbortSignal.any([signal, options.signal]);
          const budget = { signal: combined, timeoutMs: Math.ceil(remaining) + SDK_BACKSTOP_MS };
          // A revalidating request fetches every document again (and bypasses the material cache) through the SDK's
          // refresh path, with the same checks.
          return this.#revalidate
            ? verifier.refreshDomain(domain, undefined, budget)
            : verifier.verifyDomain(domain, undefined, budget);
        });
      } catch (error) {
        if (error instanceof ScopeEnded) this.#fail({ kind: error.kind, transient: true });
        if (this.#controller.signal.aborted) this.#fail({ kind: this.#ended().kind, transient: true });
        this.#fail(classify(error, this.#runtime.governance));
      }
      const governance = checkGovernance(this.#runtime.governance, result);
      if (governance !== undefined) {
        this.#fail({ kind: governance, code: VerificationCode.CounterpartyNotAccepted, transient: false });
      }
      this.verified = result;
      return result;
    },
  };

  /**
   * Offers the material this request fetched, for the identity it verified, to the shared cache. Called only by the
   * stage that made the final decision, synchronously after its final checks; checks again that the request is
   * uncancelled and within its original deadline, and admits nothing otherwise. Once only.
   */
  admitVerifiedMaterial(): void {
    const material = this.#material;
    const verified = this.verified;
    if (material === undefined || verified === undefined) return;
    if (this.#requestSignal.aborted || this.#controller.signal.aborted || performance.now() >= this.#deadline) {
      material.discard();
      return;
    }
    material.admit(verified);
  }

  dispose(): void {
    this.#material?.discard();
    clearTimeout(this.#timer);
    this.#requestSignal.removeEventListener('abort', this.#onRequestAbort);
    if (!this.#controller.signal.aborted) this.#controller.abort(new ScopeEnded('cancelled'));
    this.#cache.clear();
  }
}

// ---------- the stage ----------

export interface IdentityStageContext {
  readonly runtime: VerificationRuntime;
  /** The request's cancellation signal. */
  readonly signal: AbortSignal;
  /** When the request's verification budget runs out, on the `performance.now()` clock. Never restarted. */
  readonly deadline: number;
  /** Fetch the identity's documents again, bypassing cached material. */
  readonly revalidate?: boolean;
}

export function requireIdentityStageContext(context: IdentityStageContext): void {
  if (context?.runtime?.backend === undefined || context.runtime.checkpointStore === undefined) {
    throw new TypeError('the identity stage requires a verification runtime');
  }
  if (!(context.signal instanceof AbortSignal)) throw new TypeError('the identity stage requires an AbortSignal');
  if (!Number.isFinite(context.deadline)) throw new TypeError('the identity stage requires a finite deadline');
  if (context.revalidate !== undefined && typeof context.revalidate !== 'boolean') {
    throw new TypeError('the identity stage revalidate option must be a boolean');
  }
}

/** Test hook: how many identity lookups the last scopes made. Not part of any response. */
export interface IdentityStageObserver {
  scopeOpened?(scope: { readonly signal: AbortSignal }): void;
  scopeClosed?(scope: { readonly signal: AbortSignal; readonly lookups: number }): void;
}

/**
 * The identity stage within an open request scope; the caller owns the scope and disposes it. A request refused before
 * the signature stage reaches the resolver builds nothing and looks up nothing.
 */
async function identityStageWithin(
  scope: RequestScope,
  eligible: EligibleForVerification,
  context: IdentityStageContext,
): Promise<IdentityStageResult> {
  const signature = await verifyRequestSignature(eligible, {
    identityResolver: scope.resolver,
    signal: context.signal,
    deadline: context.deadline,
  });
  if (signature.outcome === 'deny') {
    if (signature.reason === 'signer_lookup_failed' && scope.failure !== undefined) return denial(scope.failure);
    return signature;
  }
  const verified = scope.verified;
  if (verified === undefined || signature.sdkResult !== verified) {
    return denial({ kind: 'invalid', transient: false });
  }
  // Built synchronously from what the SDK verified (its thumbprint included): nothing is awaited from here on.
  const identity = Object.freeze({
    domain: verified.domain,
    governanceId: verified.record.governanceId(),
    entityKeyThumbprint: verified.signingKeyThumbprint,
    dnssecState: verified.dnssecState,
    materialCache: scope.materialCache,
  });
  // A success that arrives after the request was cancelled or its budget ran out is not a success. Checked last,
  // immediately before returning, so nothing can end the request between this check and the result.
  if (context.signal.aborted) return denial({ kind: 'cancelled', transient: true });
  if (scope.signal.aborted || performance.now() >= context.deadline) {
    return denial({ kind: 'budget_exhausted', transient: true });
  }
  return { outcome: 'identity_stage_passed', signature, identity };
}

/**
 * The signature stage, with the signer's identity resolved by this request's own SDK verifier, then the explicit
 * governance check. The request's scope ends when this returns.
 */
export async function verifyRequestIdentity(
  eligible: EligibleForVerification,
  context: IdentityStageContext,
  observer?: IdentityStageObserver,
): Promise<IdentityStageResult> {
  return withVerifiedIdentity(eligible, context, observer, (passed) => passed);
}

/**
 * What a later stage gets of the request's scope: its signal (aborted when the request is cancelled, at the original
 * deadline, or when the request ends) and the same bounded runner the identity stage uses. Valid only inside
 * `withVerifiedIdentity`'s continuation.
 */
export interface VerificationScope {
  readonly signal: AbortSignal;
  /** Runs `operation` within the request's original budget; see RequestScope.bounded. */
  bounded<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T>;
  /** Why the scope ended, for an error `bounded` threw or one raised after the scope ended; undefined otherwise. */
  endedBy(error: unknown): 'cancelled' | 'budget_exhausted' | undefined;
  /**
   * After the final decision passed, and synchronously after its final checks: offers the material this request
   * fetched to the shared cache. Admits nothing if the request ended. See RequestScope.admitVerifiedMaterial.
   */
  admitVerifiedMaterial(): void;
}

/**
 * The identity stage, then `next` on its success, both within ONE request scope: the request's verifier, log registry
 * (and so the verified identity's log reader), checkpoint access and cancellation signal stay alive until `next` has
 * finished, and the scope is disposed exactly once, on every exit. A denial is returned as is and `next` never runs.
 */
export async function withVerifiedIdentity<T>(
  eligible: EligibleForVerification,
  context: IdentityStageContext,
  observer: IdentityStageObserver | undefined,
  next: (passed: IdentityStagePassed, scope: VerificationScope) => T | Promise<T>,
): Promise<T | IdentityDenial | SignatureDenial> {
  requireIdentityStageContext(context);
  const scope = new RequestScope(context.runtime, context.signal, context.deadline, context.revalidate === true);
  observer?.scopeOpened?.(scope);
  try {
    const result = await identityStageWithin(scope, eligible, context);
    if (result.outcome !== 'identity_stage_passed') return result;
    return await next(result, scope);
  } finally {
    scope.dispose();
    observer?.scopeClosed?.(scope);
  }
}

/** Serialized ext_proc `ProcessingRequest` bytes through decoding, the preconditions, the signature and identity. */
export async function checkSerializedRequestIdentity(
  bytes: Uint8Array,
  context: IdentityStageContext,
  observer?: IdentityStageObserver,
): Promise<IdentityStageResult | PreconditionDenial | DecodeRejection> {
  requireIdentityStageContext(context);
  const checked = checkSerializedRequest(bytes);
  if (checked.outcome !== 'eligible_for_verification') return checked;
  return verifyRequestIdentity(checked, context, observer);
}
