import { createEgressHandler } from '../src/egress.ts';
import { secretKeyProvider } from '../src/shared/key-provider.ts';
import type { Fixture } from './fixture.ts';

export async function hashToken(token: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Builds a real signer with one fixture identity and an injected destination. */
export async function createTestEgress(
  identity: Fixture,
  forward: (request: Request) => Promise<Response>,
  token = 'agent-token',
) {
  const agents = {
    [identity.domain]: {
      tokenHashes: [await hashToken(token)],
      keyProvider: await secretKeyProvider(identity.privateJwk),
    },
  };
  return createEgressHandler(agents, forward as typeof fetch);
}
