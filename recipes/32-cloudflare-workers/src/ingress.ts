import {
  createIdentityVerifier,
  VerificationError,
  type IdentityResolver,
  type VerifiedDomain,
} from "@dnsid-ai/sdk";
import {
  HttpSignaturesProfile,
  parseKeyId,
  parseSignatureInput,
  type SignatureParams,
} from "@dnsid-ai/http-signatures";
import { dohResolver } from "./shared/dns.ts";
import { workersFetchJson } from "./shared/fetch-json.ts";
import { NonceStore } from "./shared/replay.ts";
import {
  createC2spTlogVerificationRegistry,
  createFetchBackedC2spResourceFetcher,
  requiredC2spResourceFetchGuarantees,
} from "@dnsid-ai/log-c2sp-tlog";

import { z } from "zod";

export { NonceStore };

export interface IngressEnv {
  /** HTTPS URL of the origin receiving verified requests and identity headers. */
  ORIGIN_URL: string;

  /** Shared secret the origin checks so requests cannot bypass the Worker. */
  ORIGIN_SECRET: string;

  /** Independently trusted C2SP tlog-policy URL. Never derived from a verified record. */
  DNSID_LOG_POLICY_URL: string;

  /** DoH JSON endpoint; defaults to Cloudflare's resolver. */
  DNSID_DOH_URL?: string;

  NONCES: DurableObjectNamespace<NonceStore>;
}

const httpsUrlSchema = z.url({ protocol: /^https$/ });
const ingressConfigurationSchema = z.object({
  ORIGIN_URL: httpsUrlSchema,
  ORIGIN_SECRET: z.string().min(1),
  DNSID_LOG_POLICY_URL: httpsUrlSchema,
  DNSID_DOH_URL: httpsUrlSchema.optional(),
});

const MAX_AGE_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 5;

function validateIngressConfiguration(env: IngressEnv): void {
  const result = ingressConfigurationSchema.safeParse(env);
  if (!result.success) {
    const fields = [...new Set(result.error.issues.map(issue => issue.path.join(".")))];
    // Report field names only; configuration may contain secrets or private URLs.
    throw new Error(`Invalid ingress configuration: ${fields.join(", ")}. URLs must use HTTPS and ORIGIN_SECRET must not be empty.`);
  }
}

function deny(status: number, code: string, message: string): Response {
  return Response.json({ error: code, message }, { status });
}

async function claimSignatureNonce(
  stores: DurableObjectNamespace<NonceStore>,
  signatureParameters: SignatureParams,
): Promise<boolean> {
  const { domain: signerDomain } = parseKeyId(signatureParameters.keyId!);
  const nonceStore = stores.get(stores.idFromName(signerDomain));
  const expiresAtMs =
    ((signatureParameters.created ?? 0) + MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS) * 1000;

  return nonceStore.claim(signatureParameters.nonce!, expiresAtMs);
}

function prepareOriginHeaders(
  request: Request,
  agentDomain: string,
  entityDomain: string | undefined,
  originSecret: string,
): Headers {
  const headers = new Headers(request.headers);
  for (const name of [...headers.keys()]) {
    if (name.startsWith("dnsid-")) {
      headers.delete(name);
    }
  }

  headers.set("DNSid-Agent", agentDomain);
  if (entityDomain) {
    headers.set("DNSid-Accountable-Entity", entityDomain);
  }
  headers.set("DNSid-Origin-Auth", originSecret);

  return headers;
}

export function createIngressHandler(
  resolver: IdentityResolver,
  fetcher: typeof fetch = fetch,
) {
  const verifier = new HttpSignaturesProfile({
    // The SDK requires a signing identity, but ingress only verifies requests.
    // This placeholder does not identify the caller or configure the origin URL.
    domain: "ingress.invalid",
    identityResolver: resolver,
    httpMessageSignatures: {
      maxAge: MAX_AGE_SECONDS,
      clockSkew: CLOCK_SKEW_SECONDS,
    },
  });

  return async function handle(
    request: Request,
    env: IngressEnv,
  ): Promise<Response> {
    // The SDK reports the verified identity, not which signature verified, so a second
    // signature could carry a different nonce. Accept exactly one to keep replay checks sound.
    const signatureInput = request.headers.get("Signature-Input");
    if (!signatureInput) {
      return deny(401, "unsigned", "request is not signed");
    }

    let signatureParameters: SignatureParams;
    try {
      const signatures = [...parseSignatureInput(signatureInput).values()];
      if (signatures.length !== 1) {
        return deny(
          401,
          "signature_count",
          "exactly one signature is required",
        );
      }

      signatureParameters = signatures[0]!;
    } catch {
      return deny(401, "signature_malformed", "Signature-Input is malformed");
    }

    if (!signatureParameters.nonce) {
      return deny(401, "nonce_required", "signature must include a nonce");
    }

    let verified: VerifiedDomain;
    try {
      verified = await verifier.verifySignedHttpRequest(request, {
        timeoutMs: 10_000,
        signal: request.signal,
      });
    } catch (error) {
      if (error instanceof VerificationError) {
        return deny(401, `verification_failed:${error.code}`, error.message);
      }

      throw error;
    }

    const agentDomain = verified.domain;
    const entityDomain = verified.record.gi;
    const nonceAccepted = await claimSignatureNonce(env.NONCES, signatureParameters);
    if (!nonceAccepted) {
      return deny(401, "replay", "nonce already used");
    }

    const headers = prepareOriginHeaders(
      request, agentDomain, entityDomain, env.ORIGIN_SECRET,
    );

    const url = new URL(request.url);
    const target = new URL(url.pathname + url.search, env.ORIGIN_URL);
    const outbound = new Request(target, {
      method: request.method,
      headers,
      body: request.body,
      redirect: "manual",
    });
    const response = await fetcher(outbound);

    return response;
  };
}

async function createIngressHandlerFromConfig(env: IngressEnv) {
  // The factory installs an in-memory trusted-checkpoint store by default;
  // that protects against rollback only for the process lifetime.
  const logRegistry = await createC2spTlogVerificationRegistry({
    policyUrl: env.DNSID_LOG_POLICY_URL,
    checkpointMaxAge: 24 * 60 * 60 * 1000,
    resourceFetcher: createFetchBackedC2spResourceFetcher(
      fetch,
      requiredC2spResourceFetchGuarantees(),
    ),
  });

  const identityResolver = createIdentityVerifier(
    {},
    {
      dnsResolver: dohResolver(env.DNSID_DOH_URL),
      fetchJson: workersFetchJson(),
      logRegistry,
    },
  );

  return createIngressHandler(identityResolver);
}

// Reuse identity evidence only while the verifier's configuration is unchanged.
let cachedSetup: {
  logPolicyUrl: string;
  dohUrl: string | undefined;
  handlerPromise: Promise<ReturnType<typeof createIngressHandler>>;
} | undefined;

async function getIngressHandler(env: IngressEnv) {
  if (
    cachedSetup === undefined ||
    cachedSetup.logPolicyUrl !== env.DNSID_LOG_POLICY_URL ||
    cachedSetup.dohUrl !== env.DNSID_DOH_URL
  ) {
    const setup = {
      logPolicyUrl: env.DNSID_LOG_POLICY_URL,
      dohUrl: env.DNSID_DOH_URL,
      handlerPromise: createIngressHandlerFromConfig(env),
    };
    cachedSetup = setup;

    void setup.handlerPromise.catch(() => {
      // Clear the cache only if it still holds the setup that failed.
      if (cachedSetup === setup) {
        cachedSetup = undefined;
      }
    });
  }

  return cachedSetup.handlerPromise;
}

/**
 * Cloudflare's HTTP entry point. Reuses the ingress handler to verify DNSid
 * requests, reject replays, and forward requests with verified identity headers
 * to the configured origin URL. Returns the origin's response to the caller.
 */
export default {
  async fetch(request: Request, env: IngressEnv): Promise<Response> {
    validateIngressConfiguration(env);

    const handleRequest = await getIngressHandler(env);
    const response = await handleRequest(request, env);

    return response;
  },
} satisfies ExportedHandler<IngressEnv>;
