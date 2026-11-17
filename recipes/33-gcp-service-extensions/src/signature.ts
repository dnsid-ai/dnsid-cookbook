// The signature stage: the RFC 9421 HTTP message signature on a request that passed the preconditions, verified with the
// DNSid SDK's HTTP message signatures profile (`verifySignedHttpRequest`, @dnsid-ai/sdk 0.37.0).
// API: https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/http-signatures/src/index.ts
//
// Passing this stage means only that exactly one signature, covering the method, authority and target URI, verified
// against a key the caller's IdentityResolver returned for the signer's claimed domain, within the signature's age
// limits. It is not an authorization: the DNSid identity, governance, lifecycle (non-revocation) and evidence freshness
// checks come after it, and what the resolver returned is only as trustworthy as that resolver.

import {
  createHttpSignaturesProfile,
  httpSignatures,
  VerificationCode,
  VerificationError,
  type IdentityResolver,
  type VerifiedDomain,
} from '@dnsid-ai/sdk';

import { checkSerializedRequest, type DecodeRejection } from './ext-proc.ts';
import type { EligibleForVerification, PreconditionDenial, ReceivedHeader } from './preconditions.ts';

/** The approved signature policy (architecture, Checks 2). The SDK's own clock-skew default is 5 s, so both are set. */
export const SIGNATURE_PROFILE_CONFIG = Object.freeze({ maxAge: 300, clockSkew: 30 });
export const REQUIRED_COMPONENTS: readonly string[] = Object.freeze(['@method', '@authority', '@target-uri']);
/** The load balancer's forwarding rule is HTTPS only; the target URI is always rebuilt with this scheme. */
export const TARGET_SCHEME = 'https';
/** How long after the request's deadline the SDK's own timeout would fire, were this stage's timer ever late. */
export const SDK_BACKSTOP_MS = 25;
// A verification-only profile never signs, so its own domain is never used; `.invalid` can't name a real agent.
const VERIFIER_PROFILE_DOMAIN = 'verifier.invalid';

export type SignatureDenyReason =
  | 'header_not_representable' // a header the SDK's Request can't carry byte for byte
  | 'authority_missing'
  | 'authority_ambiguous' // more than one :authority or Host, or the two disagree
  | 'path_missing'
  | 'path_ambiguous'
  | 'target_not_representable' // the authority and path don't survive URL parsing unchanged
  | 'signature_missing' // no Signature or no Signature-Input field
  | 'signature_ambiguous' // either field sent more than once, or with more than one member
  | 'signature_malformed'
  | 'signature_label_mismatch'
  | 'signature_coverage_insufficient' // @method, @authority or @target-uri not covered
  | 'signature_keyid_missing'
  | 'signature_created_missing'
  | 'signature_expired' // created more than 300 s ago, or expires (plus 30 s) passed
  | 'signature_created_in_future' // created more than 30 s ahead
  | 'signature_lifetime_invalid' // expires before created, or more than 300 s after it
  | 'signer_lookup_failed' // the IdentityResolver couldn't give the claimed domain's keys
  | 'signature_key_unknown' // the keyid's key isn't among the keys the resolver returned
  | 'signature_invalid' // anything else the SDK refused, the cryptographic check included
  | 'verification_cancelled'
  | 'verification_budget_exhausted';

/** A fixed reason code only: no header, no SDK error text and no key material is ever carried. */
export interface SignatureDenial {
  readonly outcome: 'deny';
  readonly status: 403;
  readonly reason: SignatureDenyReason;
}

/**
 * The signature stage passed. This does NOT mean the request is authorized, that the identity is trusted, current or
 * not revoked, or that its evidence is fresh; `sdkResult` is kept for those later checks and must not be read as them.
 */
export interface SignatureStagePassed {
  readonly outcome: 'signature_stage_passed';
  readonly keyId: string;
  readonly sdkResult: VerifiedDomain;
}

export type SignatureStageResult = SignatureStagePassed | SignatureDenial;

export interface SignatureStageContext {
  /** Resolves the signer's claimed domain to its keys. Required: there is no default. */
  readonly identityResolver: IdentityResolver;
  /** The request's cancellation signal. */
  readonly signal: AbortSignal;
  /** When the request's verification budget runs out, on the `performance.now()` clock. */
  readonly deadline: number;
}

function deny(reason: SignatureDenyReason): SignatureDenial {
  return { outcome: 'deny', status: 403, reason };
}

const HTAB = 0x09;
const SP = 0x20;

// The SDK reads headers through a fetch `Headers`, which trims leading and trailing whitespace, refuses NUL, CR and LF,
// and holds bytes above 0x7F as Latin-1 characters that the signature base then writes as UTF-8. So only visible ASCII,
// with spaces and tabs inside, is carried unchanged; anything else is refused rather than altered.
function representable(value: Uint8Array): boolean {
  if (value.length === 0) return true;
  const first = value[0] as number;
  const last = value[value.length - 1] as number;
  if (first === SP || first === HTAB || last === SP || last === HTAB) return false;
  return value.every((byte) => (byte >= 0x21 && byte <= 0x7e) || byte === SP || byte === HTAB);
}

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const ascii = new TextDecoder('ascii');
const text = (value: Uint8Array) => ascii.decode(value);

function valuesOf(headers: readonly ReceivedHeader[], name: string): string[] {
  return headers.filter((header) => header.name.toLowerCase() === name).map((header) => text(header.value));
}

/** @authority as RFC 9421 and the SDK derive it: the lowercased host, and the port only when it isn't the default. */
function normalizedAuthority(url: URL): string {
  return url.port ? `${url.hostname.toLowerCase()}:${url.port}` : url.hostname.toLowerCase();
}

type Target = { readonly target: string } | SignatureDenial;

/**
 * The target the agent signed: `https` and the received `:authority` and `:path` exactly as received. Forwarding
 * headers (X-Forwarded-*, Forwarded) are never consulted. When URL parsing would change any part of the target (dot
 * segments, percent-encoding, case, a default port, an empty query, a fragment), the request is refused rather than
 * verified against a target the agent didn't send.
 */
function signedTarget(headers: readonly ReceivedHeader[]): Target {
  for (const header of headers) {
    if (!representable(header.value)) return deny('header_not_representable');
    if (!header.name.startsWith(':') && !TOKEN.test(header.name)) return deny('header_not_representable');
  }

  const authorities = valuesOf(headers, ':authority');
  const hosts = valuesOf(headers, 'host');
  if (authorities.length === 0) return deny('authority_missing');
  if (authorities.length > 1 || hosts.length > 1) return deny('authority_ambiguous');
  const authority = authorities[0] as string;
  if (hosts.length === 1 && hosts[0] !== authority) return deny('authority_ambiguous');

  const paths = valuesOf(headers, ':path');
  if (paths.length === 0) return deny('path_missing');
  if (paths.length > 1) return deny('path_ambiguous');
  const path = paths[0] as string;

  if (authority.length === 0 || !path.startsWith('/')) return deny('target_not_representable');
  const target = `${TARGET_SCHEME}://${authority}${path}`;
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return deny('target_not_representable');
  }
  const unchanged =
    url.protocol === `${TARGET_SCHEME}:` &&
    url.username === '' &&
    url.password === '' &&
    url.hash === '' &&
    normalizedAuthority(url) === authority &&
    `${url.pathname}${url.search}` === path &&
    url.href === target;
  if (!unchanged) return deny('target_not_representable');
  return { target };
}

/**
 * The SDK's input. Built only after every ambiguity check has run on the received list, because a fetch `Headers`
 * combines repeated fields into one. Pseudo-headers carry the method, authority and path; every other field goes in as
 * received, repeats combined with ", " as fetch and RFC 9421 do.
 */
function sdkRequest(eligible: EligibleForVerification, target: string): Request | SignatureDenial {
  let request: Request;
  try {
    const headers = new Headers();
    for (const header of eligible.headers) {
      if (!header.name.startsWith(':')) headers.append(header.name, text(header.value));
    }
    request = new Request(target, { method: eligible.method, headers });
  } catch {
    return deny('header_not_representable');
  }
  if (request.url !== target || request.method !== eligible.method) return deny('target_not_representable');
  return request;
}

type Selected = { readonly params: httpSignatures.SignatureParams } | SignatureDenial;

/**
 * Exactly one Signature and one Signature-Input field, each a dictionary of exactly one member, under the same label.
 * The SDK on its own accepts one valid signature among several candidates; this integration accepts only one candidate.
 */
function selectSignature(headers: readonly ReceivedHeader[]): Selected {
  const signatures = valuesOf(headers, 'signature');
  const inputs = valuesOf(headers, 'signature-input');
  if (signatures.length === 0 || inputs.length === 0) return deny('signature_missing');
  if (signatures.length > 1 || inputs.length > 1) return deny('signature_ambiguous');
  const signatureField = signatures[0] as string;
  const inputField = inputs[0] as string;

  let signatureLabels: string[];
  let inputLabels: string[];
  try {
    signatureLabels = [...httpSignatures.parseDictionaryField(signatureField).keys()];
    inputLabels = [...httpSignatures.parseDictionaryField(inputField).keys()];
  } catch {
    return deny('signature_malformed');
  }
  if (signatureLabels.length === 0 || inputLabels.length === 0) return deny('signature_malformed');
  if (signatureLabels.length > 1 || inputLabels.length > 1) return deny('signature_ambiguous');

  let parsedInputs: Map<string, httpSignatures.SignatureParams>;
  let parsedSignatures: Map<string, Uint8Array>;
  try {
    parsedInputs = httpSignatures.parseSignatureInput(inputField);
    parsedSignatures = httpSignatures.parseSignature(signatureField);
  } catch {
    return deny('signature_malformed');
  }
  if (parsedInputs.size !== 1 || parsedSignatures.size !== 1) return deny('signature_ambiguous');
  const label = inputLabels[0] as string;
  if (signatureLabels[0] !== label || !parsedSignatures.has(label)) return deny('signature_label_mismatch');
  const params = parsedInputs.get(label);
  if (params === undefined) return deny('signature_label_mismatch');
  return { params };
}

/**
 * The checks the SDK makes before it resolves the signer, made here first only so that each has its own reason code
 * and the resolver isn't called for them. The SDK, configured with the same policy, still makes every one of them.
 */
function precheck(params: httpSignatures.SignatureParams): SignatureDenial | undefined {
  for (const component of REQUIRED_COMPONENTS) {
    if (!params.components.some((covered) => httpSignatures.sameComponent(covered, component))) {
      return deny('signature_coverage_insufficient');
    }
  }
  if (params.keyId === undefined || params.keyId.length === 0) return deny('signature_keyid_missing');
  if (params.created === undefined) return deny('signature_created_missing');

  const { maxAge, clockSkew } = SIGNATURE_PROFILE_CONFIG;
  const now = Math.floor(Date.now() / 1000);
  const { created, expires } = params;
  if (now - created > maxAge) return deny('signature_expired');
  if (created > now + clockSkew) return deny('signature_created_in_future');
  if (expires !== undefined && (expires < created || expires - created > maxAge)) {
    return deny('signature_lifetime_invalid');
  }
  if (expires !== undefined && now > expires + clockSkew) return deny('signature_expired');
  return undefined;
}

function requireContext(context: SignatureStageContext): void {
  if (typeof context?.identityResolver?.verifyDomain !== 'function') {
    throw new TypeError('the signature stage requires an IdentityResolver');
  }
  if (!(context.signal instanceof AbortSignal)) throw new TypeError('the signature stage requires an AbortSignal');
  if (!Number.isFinite(context.deadline)) throw new TypeError('the signature stage requires a finite deadline');
}

/**
 * Verifies the signature on a request that passed the preconditions. The caller's resolver, signal and deadline apply
 * to this request only: the SDK profile and the resolver wrapper are built per call and share no state.
 */
export async function verifyRequestSignature(
  eligible: EligibleForVerification,
  context: SignatureStageContext,
): Promise<SignatureStageResult> {
  requireContext(context);
  const { identityResolver, signal, deadline } = context;

  const target = signedTarget(eligible.headers);
  if ('outcome' in target) return target;
  const selected = selectSignature(eligible.headers);
  if ('outcome' in selected) return selected;
  const early = precheck(selected.params);
  if (early !== undefined) return early;
  const request = sdkRequest(eligible, target.target);
  if (!(request instanceof Request)) return request;

  if (signal.aborted) return deny('verification_cancelled');
  // The SDK gets what is left of the request's budget, never a fresh one. The budget is this stage's own timer, so that
  // running out is told apart from a resolver failure even when a timer fires before the clock reads the deadline; the
  // SDK's own timeout is only a backstop just after it.
  const remaining = deadline - performance.now();
  if (remaining <= 0) return deny('verification_budget_exhausted');
  const budget = new AbortController();
  const timer = setTimeout(() => budget.abort(), Math.ceil(remaining));
  const sdkSignal = AbortSignal.any([signal, budget.signal]);
  const outOfBudget = () => budget.signal.aborted || performance.now() >= deadline;

  let resolverFailed = false;
  const boundResolver: IdentityResolver = {
    async verifyDomain(domain, peerCert, options) {
      try {
        return await identityResolver.verifyDomain(domain, peerCert, options);
      } catch (error) {
        resolverFailed = true;
        throw error;
      }
    },
  };
  const profile = createHttpSignaturesProfile({
    domain: VERIFIER_PROFILE_DOMAIN,
    identityResolver: boundResolver,
    httpMessageSignatures: { ...SIGNATURE_PROFILE_CONFIG },
  });

  try {
    const sdkResult = await profile.verifySignedHttpRequest(request, {
      requiredComponents: [...REQUIRED_COMPONENTS],
      signal: sdkSignal,
      timeoutMs: Math.ceil(remaining) + SDK_BACKSTOP_MS,
    });
    if (signal.aborted) return deny('verification_cancelled');
    if (outOfBudget()) return deny('verification_budget_exhausted');
    return { outcome: 'signature_stage_passed', keyId: selected.params.keyId as string, sdkResult };
  } catch (error) {
    if (signal.aborted) return deny('verification_cancelled');
    if (outOfBudget()) return deny('verification_budget_exhausted');
    if (resolverFailed) return deny('signer_lookup_failed');
    if (error instanceof VerificationError && error.code === VerificationCode.KeyNotFound) {
      return deny('signature_key_unknown');
    }
    return deny('signature_invalid');
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Serialized ext_proc `ProcessingRequest` bytes through decoding, the preconditions and the signature stage. A message
 * refused before the signature stage never reaches the resolver.
 */
export async function checkSerializedRequestSignature(
  bytes: Uint8Array,
  context: SignatureStageContext,
): Promise<SignatureStageResult | PreconditionDenial | DecodeRejection> {
  requireContext(context);
  const checked = checkSerializedRequest(bytes);
  if (checked.outcome !== 'eligible_for_verification') return checked;
  return verifyRequestSignature(checked, context);
}
