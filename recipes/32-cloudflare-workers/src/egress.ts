import {
  HttpSignaturesProfile,
  readBoundedBody,
} from "@dnsid-ai/http-signatures";
import { type KeyProvider } from "@dnsid-ai/protocol";
import { z } from "zod";
import { secretKeyProvider } from "./shared/key-provider.ts";

export interface EgressEnv {
  /** Secret JSON map: agent domain -> { privateJwk, tokenHashes }. */
  DNSID_AGENTS: string;
}

export type DnsIdDomain = string;

export type EgressAgents = Record<
  DnsIdDomain,
  {
    keyProvider: KeyProvider;
    tokenHashes: string[];
  }
>;

const agentConfigurationSchema = z.record(
  z.string().refine((domain) => domain.trim().length > 0),
  z.object({
    privateJwk: z.string(),
    tokenHashes: z.array(z.string().regex(/^[a-f0-9]{64}$/)),
  }),
);

const DESTINATION_HEADER = "DNSid-Destination";

const MAX_AGE_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 5;

// Signing buffers the body to compute Content-Digest; matches the SDK's verification limit.
const MAX_BODY_BYTES = 8 * 1024 * 1024;

const HOP_HEADERS = [
  "authorization",
  DESTINATION_HEADER.toLowerCase(),
  "host",
  "cf-connecting-ip",
  "x-forwarded-for",
  "x-real-ip",
];

const noResolver = {
  verifyDomain: () => Promise.reject(new Error("egress does not verify")),
};

function deny(status: number, code: string, message: string): Response {
  return Response.json({ error: code, message }, { status });
}

function prepareForwardingHeaders(request: Request): Headers {
  const headers = new Headers(request.headers);
  for (const name of HOP_HEADERS) {
    headers.delete(name);
  }

  return headers;
}

async function hashBearerToken(token: string): Promise<string> {
  return [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
    ),
  ]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function authenticate(
  request: Request,
  agentsByTokenHash: Map<string, DnsIdDomain>,
): Promise<DnsIdDomain | null> {
  const authorizationHeader = request.headers.get("authorization");
  const bearerMatch = /^Bearer (.+)$/.exec(
    authorizationHeader === null ? "" : authorizationHeader,
  );
  if (bearerMatch === null) {
    return null;
  }

  const token = bearerMatch[1];
  if (!token) {
    return null;
  }

  const digest = await hashBearerToken(token);

  const domain = agentsByTokenHash.get(digest);
  if (!domain) {
    return null;
  }

  return domain;
}

function buildTokenToAgentLookup(agents: EgressAgents): Map<string, DnsIdDomain> {
  const agentsByTokenHash = new Map<string, DnsIdDomain>();
  for (const [domain, agent] of Object.entries(agents)) {
    for (const hash of agent.tokenHashes) {
      const existing = agentsByTokenHash.get(hash);
      if (existing && existing !== domain) {
        throw new Error("A token hash cannot belong to multiple agents");
      }
      agentsByTokenHash.set(hash, domain);
    }
  }

  return agentsByTokenHash;
}

export function createEgressHandler(
  agents: EgressAgents,
  fetcher: typeof fetch = fetch,
) {
  const agentsByTokenHash = buildTokenToAgentLookup(agents);

  return async function handle(request: Request): Promise<Response> {
    const domain = await authenticate(request, agentsByTokenHash);
    if (!domain) {
      return deny(401, "unauthenticated", "missing or unknown bearer token");
    }

    const agent = agents[domain]!;

    const url = new URL(request.url);
    const destination = request.headers.get(DESTINATION_HEADER);
    let origin: string;
    try {
      const destinationUrl = new URL(destination ?? "");
      if (destinationUrl.protocol !== "https:") {
        return deny(
          400,
          "destination_required",
          `${DESTINATION_HEADER} must be an absolute HTTPS URL`,
        );
      }

      origin = destinationUrl.origin;
    } catch {
      return deny(
        400,
        "destination_required",
        `${DESTINATION_HEADER} must be an absolute HTTPS URL`,
      );
    }

    const headers = prepareForwardingHeaders(request);

    let body: ArrayBuffer | null = null;
    if (request.body) {
      try {
        body = await readBoundedBody(request, request.signal, MAX_BODY_BYTES);
      } catch {
        return deny(
          413,
          "too_large",
          `request body exceeds ${MAX_BODY_BYTES} bytes`,
        );
      }
    }

    const outbound = new Request(new URL(url.pathname + url.search, origin), {
      method: request.method,
      headers,
      body,
      redirect: "manual",
    });

    const profile = new HttpSignaturesProfile({
      domain,
      keyProvider: agent.keyProvider,
      identityResolver: noResolver,
      httpMessageSignatures: {
        maxAge: MAX_AGE_SECONDS,
        clockSkew: CLOCK_SKEW_SECONDS,
      },
    });
    const signed = await profile.createSignedHttpRequest(outbound, {
      expiresInSeconds: 60,
    });

    const response = await fetcher(signed, { redirect: "manual" });

    return response;
  };
}

async function createEgressHandlerFromConfig(serializedAgents: string) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serializedAgents);
  } catch {
    throw new Error("DNSID_AGENTS must be valid JSON");
  }

  const result = agentConfigurationSchema.safeParse(parsed);
  if (!result.success) {
    throw new Error(
      "DNSID_AGENTS must map nonblank agent domains to entries with a privateJwk string and SHA-256 tokenHashes array",
    );
  }

  const agents: EgressAgents = Object.create(null);
  for (const [domain, configurationEntry] of Object.entries(result.data)) {
    try {
      agents[domain] = {
        tokenHashes: configurationEntry.tokenHashes,
        keyProvider: await secretKeyProvider(configurationEntry.privateJwk),
      };
    } catch {
      throw new Error("DNSID_AGENTS contains an invalid signing key");
    }
  }

  return createEgressHandler(agents);
}

// Cache only the current fixed registry. A changed secret rebuilds providers,
// including after key rotation; concurrent requests share initialization.
let cachedSetup: {
  serializedAgents: string;
  handlerPromise: Promise<ReturnType<typeof createEgressHandler>>;
} | undefined;

async function getEgressHandler(serializedAgents: string) {
  if (
    cachedSetup === undefined ||
    cachedSetup.serializedAgents !== serializedAgents
  ) {
    const setup = {
      serializedAgents,
      handlerPromise: createEgressHandlerFromConfig(serializedAgents),
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

export default {
  async fetch(request: Request, env: EgressEnv): Promise<Response> {
    const handleRequest = await getEgressHandler(env.DNSID_AGENTS);
    const response = await handleRequest(request);

    return response;
  },
} satisfies ExportedHandler<EgressEnv>;
