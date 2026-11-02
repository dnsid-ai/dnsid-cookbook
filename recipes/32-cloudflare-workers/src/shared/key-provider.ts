import { jwkSignatureAlg, jwkThumbprint, type DnsIdJWK, type KeyProvider } from '@dnsid-ai/protocol';
import { z } from 'zod';

const keyMaterial = z.string().min(1);
const privateJwkSchema = z.discriminatedUnion('kty', [
  z.object({
    kty: z.literal('OKP'),
    crv: z.literal('Ed25519'),
    x: keyMaterial,
    d: keyMaterial,
    kid: z.string().optional(),
  }),
  z.object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: keyMaterial,
    y: keyMaterial,
    d: keyMaterial,
    kid: z.string().optional(),
  }),
]);

/**
 * Validates a private JWK JSON string and imports its key for SDK signing.
 * Supports Ed25519 and P-256; public-key methods omit private key material.
 * Key generation and rotation are external operations and are rejected here.
 * Throws for malformed configuration or a key Web Crypto cannot import.
 */
export async function secretKeyProvider(privateJwkJson: string): Promise<KeyProvider> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(privateJwkJson);
  } catch {
    throw new Error('signing secret must be valid JSON');
  }

  const result = privateJwkSchema.safeParse(parsed);
  if (!result.success) {
    // Do not expose validation details that could contain private key material.
    throw new Error('signing secret must be an Ed25519 or P-256 private JWK');
  }

  const privateJwk = result.data;
  const isEd25519 = privateJwk.kty === 'OKP';
  const pub: DnsIdJWK = {
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
    kid: '',
  };
  if (privateJwk.kty === 'EC') {
    pub.y = privateJwk.y;
  }

  const publicJwk: DnsIdJWK = {
    ...pub,
    alg: jwkSignatureAlg(pub),
    use: 'sig',
    kid: privateJwk.kid || await jwkThumbprint(pub),
  };

  const algorithm = isEd25519 ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  const signParams = isEd25519 ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' };
  const key = await crypto.subtle.importKey(
    'jwk', { ...pub, d: privateJwk.d } as JsonWebKey, algorithm, false, ['sign'],
  );

  const sign = async (payload: Uint8Array) => {
    const signature = await crypto.subtle.sign(signParams, key, payload);
    return new Uint8Array(signature);
  };

  const readOnly = async (): Promise<never> => {
    throw new Error('key management is not available in the Worker');
  };

  return {
    signingKey: async () => publicJwk,
    jwk: async kid => {
      if (kid !== publicJwk.kid) {
        throw new Error(`key not found: ${kid}`);
      }
      return publicJwk;
    },
    listKeyIds: async () => [publicJwk.kid],
    sign,
    signKey: async (kid, payload) => {
      if (kid !== publicJwk.kid) {
        throw new Error(`key not found: ${kid}`);
      }
      return sign(payload);
    },
    generateKey: readOnly,
    activate: readOnly,
    supersede: readOnly,
  };
}
