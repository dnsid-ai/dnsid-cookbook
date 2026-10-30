import { describe, expect, it } from 'vitest';
import { secretKeyProvider } from '../src/shared/key-provider.ts';

describe('secret key provider', () => {
  for (const curve of ['Ed25519', 'P-256']) {
    it(`signs verifiable ${curve} signatures and exposes only the public key`, async () => {
      const algorithm = curve === 'Ed25519'
        ? { name: 'Ed25519' }
        : { name: 'ECDSA', namedCurve: 'P-256' };
      const signParams = curve === 'Ed25519'
        ? { name: 'Ed25519' }
        : { name: 'ECDSA', hash: 'SHA-256' };
      const pair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']) as CryptoKeyPair;
      const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
      const provider = await secretKeyProvider(JSON.stringify(privateJwk));
      const publicJwk = await provider.signingKey();
      const payload = new TextEncoder().encode('request to sign');

      for (const signature of [await provider.sign(payload), await provider.signKey(publicJwk.kid, payload)]) {
        expect(await crypto.subtle.verify(signParams, pair.publicKey, signature, payload)).toBe(true);
        expect(await crypto.subtle.verify(signParams, pair.publicKey, signature, new Uint8Array([0]))).toBe(false);
      }

      expect(publicJwk).not.toHaveProperty('d');
      expect(publicJwk.kid).toBeTruthy();
      expect(await provider.jwk(publicJwk.kid)).toEqual(publicJwk);
      await expect(provider.signKey('unknown-key', payload)).rejects.toThrow('key not found');
    });
  }

  it('rejects malformed configuration without exposing private material', async () => {
    for (const input of ['secret-invalid-json', 'null', '[]', JSON.stringify({
      kty: 'EC', crv: 'P-256', x: 'x', d: 'secret-private-material',
    })]) {
      await expect(secretKeyProvider(input)).rejects.toThrow(/^signing secret must be/);
    }
  });

  it('rejects structurally valid but unusable key material during import', async () => {
    await expect(secretKeyProvider(JSON.stringify({
      kty: 'OKP', crv: 'Ed25519', x: 'AA', d: 'AA',
    }))).rejects.toThrow();
  });
});
