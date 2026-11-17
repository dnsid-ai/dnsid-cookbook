// The lifecycle and freshness stage: after the signature, identity and governance checks pass, the verified identity's
// own log reader establishes that it is neither revoked nor retired NOW (`VerifiedDomain.verifyNonRevocation(at)`,
// @dnsid-ai/sdk 0.37.0), and this stage then checks the returned proof boundary and how fresh its evidence is.
// APIs: https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/protocol/src/verified-domain.ts ,
// https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/protocol/src/log.ts (LoggedStateEvidence) and
// https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/log-c2sp-tlog/src/reader.ts (C2spTlogReader)
//
// It runs inside the identity stage's request scope (`withVerifiedIdentity`): the log reader the SDK bound to the
// identity carries that scope's signal, its checkpoint writes go through that request's checkpoint access, and the
// whole call is raced against the same original deadline. It gets no budget of its own.
//
// Passing this stage is the verification decision: every check passed. Forwarding the request is a later step.

import { VerificationCode, VerificationError, type LoggedStateEvidence, type VerifiedDomain } from '@dnsid-ai/sdk';
import { parseC2spTlogLr, parseCheckpoint } from '@dnsid-ai/log-c2sp-tlog';

import { checkSerializedRequest, type DecodeRejection } from './ext-proc.ts';
import {
  requireIdentityStageContext,
  withVerifiedIdentity,
  type IdentityDenial,
  type IdentityStageContext,
  type IdentityStageObserver,
  type IdentityStagePassed,
  type VerificationScope,
} from './identity.ts';
import type { EligibleForVerification, PreconditionDenial } from './preconditions.ts';
import type { SignatureDenial, SignatureStagePassed } from './signature.ts';

/** The oldest log evidence accepted: its independently verified freshness time at most 300 s before the decision. */
export const MAX_EVIDENCE_AGE_MS = 300_000;
/** The furthest in the future that freshness time may be, for clock differences. The SDK's managed policy allows 0. */
export const MAX_EVIDENCE_FUTURE_MS = 5_000;

// ---------- the proof boundary and its freshness ----------

export type EvidenceProblem = 'evidence_invalid' | 'evidence_stale' | 'evidence_future';

export type EvidenceCheck =
  | { readonly ok: true; readonly freshnessMs: number; readonly ageMs: number }
  | { readonly ok: false; readonly kind: EvidenceProblem }
  | { readonly ok: false; readonly kind: 'inactive'; readonly loggedState: string };

/** The SDK's other lifecycle states (AgentStatusState); anything else in `loggedState` is malformed evidence. */
const NOT_ACTIVE_STATES: ReadonlySet<unknown> = new Set(['REVOKED', 'RETIRED', 'PENDING', 'PROVISIONING', 'VERIFYING']);

const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

/** The entry index of `ref` when it is exactly `<lr>@<decimal index>`; undefined otherwise. */
function entryIndexIn(ref: unknown, lr: string): number | undefined {
  if (typeof ref !== 'string' || !ref.startsWith(`${lr}@`)) return undefined;
  const index = ref.slice(lr.length + 1);
  if (!DECIMAL.test(index)) return undefined;
  const value = Number(index);
  return Number.isSafeInteger(value) ? value : undefined;
}

/**
 * Checks a non-revocation proof boundary the SDK returned for an identity whose log reference is `expectedLogReference`,
 * at `nowMs`. Fails closed on anything absent or malformed. Checks, in order:
 * - the logged state is ACTIVE (another known state is `inactive`, so it is told apart from bad evidence);
 * - it is for that log reference;
 * - the final applied event (`historyEnd`) is an entry of that log, within the complete prefix (`completeThrough`);
 * - the genesis reference (`historyStart`) is well formed and, when in the same log, not after `historyEnd`;
 * - a completeness mode is named;
 * - the accepted checkpoint is a C2SP checkpoint of that log's origin whose tree size is `completeThrough`;
 * - `freshnessTime` (the independently verified witness time, never the SDK's `verifiedAt` or an event time) is a valid
 *   date at most MAX_EVIDENCE_FUTURE_MS ahead of `nowMs` and at most MAX_EVIDENCE_AGE_MS behind it.
 */
export function checkLoggedStateEvidence(evidence: unknown, expectedLogReference: string, nowMs: number): EvidenceCheck {
  const invalid = { ok: false, kind: 'evidence_invalid' } as const;
  if (typeof evidence !== 'object' || evidence === null) return invalid;
  const fields = evidence as Partial<Record<keyof LoggedStateEvidence, unknown>>;
  if (fields.loggedState !== 'ACTIVE') {
    if (NOT_ACTIVE_STATES.has(fields.loggedState)) return { ok: false, kind: 'inactive', loggedState: fields.loggedState as string };
    return invalid;
  }
  if (typeof fields.logReference !== 'string' || fields.logReference !== expectedLogReference) return invalid;
  let reference;
  try {
    reference = parseC2spTlogLr(expectedLogReference);
  } catch {
    return invalid;
  }
  if (reference.lr !== expectedLogReference || reference.entryIndex !== undefined) return invalid;

  if (typeof fields.completeThrough !== 'string' || !DECIMAL.test(fields.completeThrough)) return invalid;
  const completeThrough = Number(fields.completeThrough);
  if (!Number.isSafeInteger(completeThrough) || completeThrough < 1) return invalid;
  const end = entryIndexIn(fields.historyEnd, expectedLogReference);
  if (end === undefined || end >= completeThrough) return invalid;
  if (typeof fields.historyStart !== 'string') return invalid;
  const sameLogStart = entryIndexIn(fields.historyStart, expectedLogReference);
  if (sameLogStart !== undefined) {
    if (sameLogStart > end) return invalid;
  } else {
    // A migrated identity's history starts in an earlier log: still a bound reference with an entry index.
    try {
      if (parseC2spTlogLr(fields.historyStart).entryIndex === undefined) return invalid;
    } catch {
      return invalid;
    }
  }
  if (typeof fields.completenessMode !== 'string' || fields.completenessMode.length === 0) return invalid;

  if (!(fields.checkpoint instanceof Uint8Array) || fields.checkpoint.length === 0) return invalid;
  try {
    const checkpoint = parseCheckpoint(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(fields.checkpoint));
    if (checkpoint.origin !== reference.origin || checkpoint.treeSize !== completeThrough) return invalid;
  } catch {
    return invalid;
  }

  if (!(fields.freshnessTime instanceof Date)) return invalid;
  const freshnessMs = fields.freshnessTime.getTime();
  if (!Number.isFinite(freshnessMs) || !Number.isFinite(nowMs)) return invalid;
  const ageMs = nowMs - freshnessMs;
  if (-ageMs > MAX_EVIDENCE_FUTURE_MS) return { ok: false, kind: 'evidence_future' };
  if (ageMs > MAX_EVIDENCE_AGE_MS) return { ok: false, kind: 'evidence_stale' };
  return { ok: true, freshnessMs, ageMs };
}

// ---------- results ----------

export type LifecycleFailureKind =
  | 'inactive' // the evidence reports a lifecycle state other than ACTIVE
  | 'log_unavailable' // the log couldn't be read (transient)
  | 'log_rejected' // the SDK did not establish non-revocation; see the limitation below
  | EvidenceProblem
  | 'identity_evidence_expired' // the identity evidence itself expired before the decision
  | 'cancelled'
  | 'budget_exhausted';

/**
 * Typed failure information for logging. Enumerations only: no error message, URL or key material.
 *
 * Limitation (SDK 0.37.0): `verifyNonRevocation` reports a REVOKED or RETIRED history, stale evidence beyond its own
 * limit, and several kinds of invalid evidence all as the same non-transient `LogError`, distinguishable only by message
 * text. The message is not read here, so a revocation the log alone shows is `log_rejected`, not `inactive`. A status
 * document reporting REVOKED is still refused as inactive by the identity stage.
 */
export interface LifecycleFailure {
  readonly kind: LifecycleFailureKind;
  readonly code?: VerificationCode;
  readonly transient: boolean;
  /** The logged state the evidence reported, for `inactive` only. */
  readonly loggedState?: string;
}

export type LifecycleDenyReason =
  | 'identity_inactive'
  | 'lifecycle_unavailable'
  | 'lifecycle_not_established'
  | 'lifecycle_evidence_invalid'
  | 'lifecycle_evidence_stale'
  | 'identity_evidence_expired';

/** A stable reason code for the response; `failure` is internal and never sent. */
export interface LifecycleDenial {
  readonly outcome: 'deny';
  readonly status: 403;
  readonly reason: LifecycleDenyReason;
  readonly failure: LifecycleFailure;
}

/** What the response and logging layer may record about the evidence: bounded, no checkpoint bytes. */
export interface FreshnessSummary {
  readonly loggedState: 'ACTIVE';
  readonly logReference: string;
  readonly historyEnd: string;
  readonly completeThrough: string;
  readonly completenessMode: string;
  /** The evidence's verified freshness time, ISO 8601. */
  readonly freshnessTime: string;
  /** Its age at the decision, in ms: at most MAX_EVIDENCE_AGE_MS, negative (to -MAX_EVIDENCE_FUTURE_MS) if ahead. */
  readonly evidenceAgeMs: number;
}

/** Every check passed. The request isn't forwarded yet: that is the response layer's step. */
export interface VerificationPassed {
  readonly outcome: 'verification_passed';
  readonly signature: SignatureStagePassed;
  readonly identity: IdentityStagePassed['identity'];
  readonly lifecycle: FreshnessSummary;
}

export type VerificationResult = VerificationPassed | LifecycleDenial | IdentityDenial | SignatureDenial;

const DENY_REASON: Record<Exclude<LifecycleFailureKind, 'cancelled' | 'budget_exhausted'>, LifecycleDenyReason> = {
  inactive: 'identity_inactive',
  log_unavailable: 'lifecycle_unavailable',
  log_rejected: 'lifecycle_not_established',
  evidence_invalid: 'lifecycle_evidence_invalid',
  evidence_future: 'lifecycle_evidence_invalid',
  evidence_stale: 'lifecycle_evidence_stale',
  identity_evidence_expired: 'identity_evidence_expired',
};

function denial(failure: LifecycleFailure): LifecycleDenial | SignatureDenial {
  if (failure.kind === 'cancelled') return { outcome: 'deny', status: 403, reason: 'verification_cancelled' };
  if (failure.kind === 'budget_exhausted') return { outcome: 'deny', status: 403, reason: 'verification_budget_exhausted' };
  return { outcome: 'deny', status: 403, reason: DENY_REASON[failure.kind], failure: Object.freeze({ ...failure }) };
}

/** A failed `verifyNonRevocation`, classified on the SDK's structured fields only (never its message). */
function classify(error: unknown, scope: VerificationScope): LifecycleFailure {
  const ended = scope.endedBy(error);
  if (ended !== undefined) return { kind: ended, transient: true };
  if (!(error instanceof VerificationError)) return { kind: 'log_rejected', transient: false };
  const { code, transient } = error;
  if (transient) return { kind: 'log_unavailable', code, transient };
  if (error.errorCategory === 'INVALID_EVIDENCE') return { kind: 'evidence_invalid', code, transient };
  return { kind: 'log_rejected', code, transient };
}

// ---------- the stage ----------

/** Test hooks. Not part of any response. */
export interface VerificationObserver extends IdentityStageObserver {
  /** The identity stage passed and the non-revocation check is about to start, in the same scope. */
  lifecycleStarting?(scope: { readonly signal: AbortSignal }, verified: VerifiedDomain): void;
  /** Called while the success result is being built, after every check and before the final cancellation checks. */
  buildingResult?(): void;
}

async function lifecycleWithin(
  passed: IdentityStagePassed,
  scope: VerificationScope,
  context: IdentityStageContext,
  observer: VerificationObserver | undefined,
): Promise<VerificationResult> {
  const verified = passed.signature.sdkResult;
  observer?.lifecycleStarting?.(scope, verified);
  let evidence: LoggedStateEvidence;
  try {
    // Always, whether or not the record asks for log checking, and at the time of this call: never the signature's
    // created time or a caller's. The reader's reads and checkpoint writes carry this request's signal; `bounded` also
    // cuts off a read that ignores it, at the original deadline.
    evidence = await scope.bounded(() => verified.verifyNonRevocation(new Date()));
  } catch (error) {
    return denial(classify(error, scope));
  }
  // Freshness is judged now, after the awaited work, not when the check started. Nothing is awaited from here on.
  const nowMs = Date.now();
  const checked = checkLoggedStateEvidence(evidence, verified.record.lr, nowMs);
  if (!checked.ok) {
    // With SDK 0.37.0 a REVOKED or RETIRED history is thrown as an error above, never returned; checked all the same.
    if (checked.kind === 'inactive') return denial({ kind: 'inactive', transient: false, loggedState: checked.loggedState });
    return denial({ kind: checked.kind, transient: false });
  }
  try {
    // The identity evidence (DNS TTL, TLS certificates, key age) must also still hold at the decision.
    verified.assertFresh();
  } catch (error) {
    if (!(error instanceof VerificationError)) return denial({ kind: 'identity_evidence_expired', transient: false });
    return denial({ kind: 'identity_evidence_expired', code: error.code, transient: false });
  }
  const lifecycle: FreshnessSummary = Object.freeze({
    loggedState: 'ACTIVE',
    logReference: evidence.logReference,
    historyEnd: evidence.historyEnd as string,
    completeThrough: evidence.completeThrough,
    completenessMode: evidence.completenessMode,
    freshnessTime: new Date(checked.freshnessMs).toISOString(),
    evidenceAgeMs: checked.ageMs,
  });
  observer?.buildingResult?.();
  // As in the identity stage: checked last, immediately before returning, with nothing awaited after.
  if (context.signal.aborted) return denial({ kind: 'cancelled', transient: true });
  if (scope.signal.aborted || performance.now() >= context.deadline) {
    return denial({ kind: 'budget_exhausted', transient: true });
  }
  // Only a request whose whole verification passed offers its fetched records and keys to the shared cache, and only
  // now, synchronously: nothing can end the request between the checks above and this.
  scope.admitVerifiedMaterial();
  return { outcome: 'verification_passed', signature: passed.signature, identity: passed.identity, lifecycle };
}

/**
 * The whole verification of an eligible request: the signature, the signer's identity and governance, then
 * non-revocation and evidence freshness, all in one request scope within one original deadline.
 */
export async function verifyRequest(
  eligible: EligibleForVerification,
  context: IdentityStageContext,
  observer?: VerificationObserver,
): Promise<VerificationResult> {
  return withVerifiedIdentity(eligible, context, observer, (passed, scope) =>
    lifecycleWithin(passed, scope, context, observer),
  );
}

/** Serialized ext_proc `ProcessingRequest` bytes through decoding, the preconditions and every verification check. */
export async function checkSerializedRequestVerification(
  bytes: Uint8Array,
  context: IdentityStageContext,
  observer?: VerificationObserver,
): Promise<VerificationResult | PreconditionDenial | DecodeRejection> {
  requireIdentityStageContext(context);
  const checked = checkSerializedRequest(bytes);
  if (checked.outcome !== 'eligible_for_verification') return checked;
  return verifyRequest(checked, context, observer);
}
