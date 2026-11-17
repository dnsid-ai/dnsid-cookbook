// The agent's lifecycle state, for deny-revoked (EDGE-05) and the demo's revoked request, from two independent sources:
//
// - its own DNSid status document (readAgentStatus). The verifier's answer for a revoked identity, identity_inactive, is
//   the same for a retired one; this read tells them apart.
// - its authenticated lifecycle history in the DNSid-managed log (readLoggedLifecycle). When the log already holds the
//   REVOCATION, the verifier's own log read refuses the identity first (identity_invalid, or lifecycle_not_established
//   when the revocation lands between its two reads), and SDK 0.37.0 says only "LogError" for it, the same as for a
//   tampered or unreachable log. This read obtains the history the SDK verified (entries signed by the identity's
//   accountable-entity key, the key that signed its DNS record, under the log's witnessed checkpoint) and lets the SDK's
//   own lifecycle rules (DomainLog) say which state it ends in. An error message is never read as evidence.
//
// Both are read through the verifier's own SDK construction (src/identity.ts: the trusted governance list, the production
// backend's DNS resolver and HTTPS fetcher, the DNSid-managed log registry, nothing cached), so they see what the verifier
// would, but from here, independently of the edge. Nothing is written, nothing is revoked. Neither read admits anything:
// they only classify a refusal the edge already gave.

import {
  DomainLog,
  jwkThumbprint,
  normalizeFQDN,
  VerificationCode,
  VerificationError,
  type DnsIdJWK,
  type IdentityCache,
  type LogEvent,
  type LogReader,
  type LogRegistry,
  type VerifiedDomain,
} from '@dnsid-ai/sdk';
import { InMemoryTrustedC2spCheckpointStore } from '@dnsid-ai/log-c2sp-tlog';

import {
  governanceFromSetting,
  PRODUCTION_BACKEND,
  sdkVerificationConfig,
  StrictLogRegistry,
  SUPPORTED_LOG_METHODS,
  type VerificationBackend,
} from '../../src/identity.ts';

export type AgentStatus =
  /** The status document was read and verified: ACTIVE, or the state it reports instead (REVOKED, RETIRED, …). */
  | { readonly kind: 'state'; readonly state: string; readonly at: string }
  /** It couldn't be read or verified, or the failure didn't say which state: no evidence either way. */
  | { readonly kind: 'unknown'; readonly reason: string; readonly at: string };

/** What the agent's authenticated lifecycle history in its log shows. */
export type LoggedLifecycle =
  /** The history was read and verified; `state` is where the SDK's lifecycle rules put it now. */
  | {
      readonly kind: 'logged';
      readonly state: 'ACTIVE' | 'REVOKED' | 'RETIRED';
      /** The REVOCATION's reason (keyCompromise, policyViolation, superseded, cessationOfOperation), when revoked. */
      readonly reason?: string;
      /** The terminal event's time, when there is one. */
      readonly since?: string;
      readonly events: number;
      readonly at: string;
    }
  /** It couldn't be read, verified or tied to this identity: no evidence either way. */
  | { readonly kind: 'unknown'; readonly reason: string; readonly at: string };

/** Both sources, read independently of each other and of the edge. */
export interface LifecycleEvidence {
  readonly status: AgentStatus;
  readonly log: LoggedLifecycle;
}

export const STATUS_READ_TIMEOUT_MS = 30_000;

/** Keeps nothing: every read goes to DNS and the status document. */
const NO_CACHE: IdentityCache = {
  get: () => null,
  put: () => {},
  evict: () => {},
};

export async function readAgentStatus(
  domain: string,
  trustedGovernance: string,
  backend: VerificationBackend = PRODUCTION_BACKEND,
  timeoutMs = STATUS_READ_TIMEOUT_MS,
): Promise<AgentStatus> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`no answer within ${timeoutMs} ms`)), timeoutMs);
  const at = () => new Date().toISOString();
  try {
    const read = (async (): Promise<VerifiedDomain> => {
      const registry = await backend.createLogRegistry({ signal: controller.signal, trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore() });
      const verifier = await backend.createIdentityVerifier(sdkVerificationConfig(governanceFromSetting(trustedGovernance)), {
        logRegistry: StrictLogRegistry.of(registry, SUPPORTED_LOG_METHODS),
        cache: NO_CACHE,
        transport: (base) => base,
      });
      return verifier.verifyDomain(domain);
    })();
    const aborted = new Promise<never>((_, reject) =>
      controller.signal.addEventListener('abort', () => reject(controller.signal.reason as Error), { once: true }),
    );
    // Whichever loses the race rejects with no one waiting for it (the finally below aborts after a read that won, too).
    aborted.catch(() => {});
    read.catch(() => {});
    await Promise.race([read, aborted]);
    return { kind: 'state', state: 'ACTIVE', at: at() };
  } catch (error) {
    if (error instanceof VerificationError && error.code === VerificationCode.StatusNotActive && typeof error.agentState === 'string') {
      return { kind: 'state', state: error.agentState, at: at() };
    }
    const reason = error instanceof VerificationError ? `${error.code}${error.transient ? ' (transient)' : ''}` : (error as Error).message;
    return { kind: 'unknown', reason, at: at() };
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

/** What a wrapped reader saw when the SDK checked the identity's binding to its log. */
interface Captured {
  readonly domain: string;
  readonly governanceId: string;
  readonly entityKey: DnsIdJWK;
  readonly events?: readonly LogEvent[];
  readonly error?: unknown;
}

/**
 * A LogReader that, once the SDK has checked the identity's binding to its log (verifyBilateralBinding: the history
 * loaded and verified under the entity key that signed the DNS record), passes on the history the reader verified, before
 * the SDK goes on and whether or not the binding was accepted. Everything else is the reader's own.
 */
function capturingReader(inner: LogReader, capture: (seen: Captured) => void): LogReader {
  return new Proxy(inner, {
    get(target, property) {
      const value = Reflect.get(target, property, target) as unknown;
      if (property !== 'verifyBilateralBinding' || typeof value !== 'function') {
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      }
      return async (record: unknown, entityKey: unknown, operationalKey: unknown) => {
        const shape = record as { agentFQDN?: unknown; gi?: unknown };
        const seen = { domain: String(shape.agentFQDN ?? ''), governanceId: String(shape.gi ?? ''), entityKey: entityKey as DnsIdJWK };
        try {
          return await target.verifyBilateralBinding(record, entityKey, operationalKey);
        } finally {
          // The history the binding check just verified (the reader keeps it), or why there is none.
          try {
            capture({ ...seen, events: await target.rebuildHistory(seen.domain) });
          } catch (error) {
            capture({ ...seen, error });
          }
        }
      };
    },
  });
}

/**
 * The agent's lifecycle state from its authenticated log history. The SDK resolves and authenticates the identity the
 * way the verifier does (DNS record, its signature by the entity key from the governance domain); the history is the one
 * its log reader verified under that key. Accepted only when the history's ISSUANCE names this domain, the record's
 * governance ID (trusted here) and the same entity key. The status document plays no part: its fetch is held until the
 * history has been read, so neither source can cut the other short.
 */
export async function readLoggedLifecycle(
  domain: string,
  trustedGovernance: string,
  backend: VerificationBackend = PRODUCTION_BACKEND,
  timeoutMs = STATUS_READ_TIMEOUT_MS,
): Promise<LoggedLifecycle> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`no answer within ${timeoutMs} ms`)), timeoutMs);
  const at = () => new Date().toISOString();
  let captured!: (seen: Captured) => void;
  const seen = new Promise<Captured>((resolve) => (captured = resolve));
  try {
    const policy = governanceFromSetting(trustedGovernance);
    const name = normalizeFQDN(domain);
    const aborted = new Promise<never>((_, reject) =>
      controller.signal.addEventListener('abort', () => reject(controller.signal.reason as Error), { once: true }),
    );
    aborted.catch(() => {});
    // Held until the abort below: the SDK fetches the status document with no allowedHost (its keys always have one).
    const held = () => aborted;
    const verified = (async (): Promise<never> => {
      const registry = await backend.createLogRegistry({ signal: controller.signal, trustedCheckpointStore: new InMemoryTrustedC2spCheckpointStore() });
      const capturing = { newReader: (lr: string, options?: { signal?: AbortSignal; revalidate?: boolean }) => capturingReader(registry.newReader(lr, options), captured) } as LogRegistry;
      const verifier = await backend.createIdentityVerifier(sdkVerificationConfig(policy), {
        logRegistry: StrictLogRegistry.of(capturing, SUPPORTED_LOG_METHODS),
        cache: NO_CACHE,
        transport: (base) => ({
          dnsResolver: base.dnsResolver,
          fetchJson: (url, options) => (options?.allowedHost === undefined ? held() : base.fetchJson(url, options)),
        }),
      });
      await verifier.verifyDomain(name);
      throw new Error('the identity was verified without its log being read');
    })();
    verified.catch(() => {});
    let got: Captured;
    try {
      got = await Promise.race([seen, verified, aborted]);
    } catch (error) {
      const reason = error instanceof VerificationError ? `${error.code}${error.transient ? ' (transient)' : ''}` : (error as Error).message;
      return { kind: 'unknown', reason: `the identity could not be resolved to its log: ${reason}`, at: at() };
    }
    if (got.events === undefined) {
      const error = got.error;
      const reason = error instanceof VerificationError ? `${error.code}${error.transient ? ' (transient)' : ''}` : (error as Error)?.message ?? 'no history';
      return { kind: 'unknown', reason: `the log history could not be verified: ${reason}`, at: at() };
    }
    const issuance = got.events.find((e) => e.type === 'ISSUANCE');
    const entry = policy.entries.find((e) => e.governanceId === got.governanceId);
    const thumbprint = await jwkThumbprint(got.entityKey);
    if (got.domain !== name || issuance === undefined || issuance.domain !== name) {
      return { kind: 'unknown', reason: 'the log history is not this identity\'s', at: at() };
    }
    if (entry === undefined || (entry.entityKeyThumbprints !== undefined && !entry.entityKeyThumbprints.includes(thumbprint))) {
      return { kind: 'unknown', reason: 'the identity is not under a trusted governance ID', at: at() };
    }
    const bound = issuance as { governanceId?: unknown; initialEntityThumbprint?: unknown };
    if (bound.governanceId !== got.governanceId || bound.initialEntityThumbprint !== thumbprint) {
      return { kind: 'unknown', reason: 'the log history is not bound to this identity\'s governance ID and entity key', at: at() };
    }
    const now = new Date();
    const snapshot = new DomainLog(name, [...got.events]).snapshotAt(now);
    const state = snapshot.historicalState;
    if (state !== 'ACTIVE' && state !== 'REVOKED' && state !== 'RETIRED') {
      return { kind: 'unknown', reason: `the log history ends in an unexpected state`, at: at() };
    }
    const terminal = got.events.findLast((e) => e.type === 'REVOCATION' || e.type === 'RETIREMENT' || e.type === 'ISSUANCE');
    const reason = terminal?.type === 'REVOCATION' ? (terminal as { reason?: unknown }).reason : undefined;
    return {
      kind: 'logged',
      state,
      ...(typeof reason === 'string' ? { reason } : {}),
      ...(state !== 'ACTIVE' && terminal !== undefined ? { since: terminal.timestamp.toISOString() } : {}),
      events: snapshot.events.length,
      at: at(),
    };
  } catch (error) {
    const reason = error instanceof VerificationError ? `${error.code}${error.transient ? ' (transient)' : ''}` : (error as Error).message;
    return { kind: 'unknown', reason, at: at() };
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

/** Both sources, read concurrently and independently. */
export async function readLifecycleEvidence(
  domain: string,
  trustedGovernance: string,
  backend: VerificationBackend = PRODUCTION_BACKEND,
  timeoutMs = STATUS_READ_TIMEOUT_MS,
): Promise<LifecycleEvidence> {
  const [status, log] = await Promise.all([
    readAgentStatus(domain, trustedGovernance, backend, timeoutMs),
    readLoggedLifecycle(domain, trustedGovernance, backend, timeoutMs),
  ]);
  return { status, log };
}
