// One request's headers through the whole callout: serialized ext_proc `ProcessingRequest` bytes in, one serialized
// `ProcessingResponse` out. Decoding (src/ext-proc.ts), the request preconditions (src/preconditions.ts), the full
// verification (src/lifecycle.ts `verifyRequest`: signature, identity, governance, lifecycle and freshness) and the
// response (src/response.ts), each run exactly once, in that order. Verification sees the headers exactly as received;
// the response's header mutations are planned from those same received headers, after verification has decided.
//
// This is the application's answer only. Nothing here listens for gRPC, and a failure of the callout stream itself
// (a message the gRPC layer can't deserialize, a stopped or timed-out service) is the load balancer's to answer: with
// the extension not failing open, that is its own 500 (decision D-05), not one of these 403s.

import { decodeProcessingRequest } from './ext-proc.ts';
import { requireIdentityStageContext, type IdentityStageContext } from './identity.ts';
import { verifyRequest, type VerificationObserver } from './lifecycle.ts';
import { checkRequestPreconditions } from './preconditions.ts';
import { denialResponse, respond, type CalloutResponse, type ResponseObserver } from './response.ts';

/** Test hooks, from verification through the response. Not part of any response. */
export interface CalloutObserver extends VerificationObserver, ResponseObserver {}

/** The request's verification context and, when the deployment has one, its attestation key (src/attestation.ts). */
export type CalloutContext = IdentityStageContext & { readonly attestationKey?: Uint8Array };

/**
 * Answers one serialized `ProcessingRequest`. Never throws and never rejects: an unexpected failure anywhere is the
 * fixed `internal_error` 403. The caller's signal and original deadline in `context` bound verification and are
 * checked again after the response is built; the budget is never restarted. `bytes` is not changed.
 */
export async function processRequestHeaders(
  bytes: Uint8Array,
  context: CalloutContext,
  observer?: CalloutObserver,
): Promise<CalloutResponse> {
  try {
    requireIdentityStageContext(context);
    const decoded = decodeProcessingRequest(bytes);
    if (decoded.outcome === 'reject') return respond(decoded, [], context, observer);
    const checked = checkRequestPreconditions(decoded.message);
    if (checked.outcome !== 'eligible_for_verification') return respond(checked, [], context, observer);
    const result = await verifyRequest(checked, context, observer);
    return respond(result, checked.headers, context, observer);
  } catch {
    return denialResponse('internal_error');
  }
}
