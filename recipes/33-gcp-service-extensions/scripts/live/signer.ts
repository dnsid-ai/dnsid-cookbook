// Signing for the live tests: the agent's private key from DNSID_AGENT_KEY_FILE and the SDK's own RFC 9421 signing
// (@dnsid-ai/sdk 0.37.0), exactly as an agent signs. The key is read by the SDK's file-backed key provider and never
// leaves it: nothing here prints, logs or copies key material, and a key that can't be read is reported with a fixed
// message that doesn't quote the file.
//
// Accepted key files: a private JWK (what the DNSid CLI writes, and what LocalKeyProvider.fromFile reads), or a PKCS #8
// PEM private key (read through LocalKeyProvider.fromDirectory, via a private temporary directory holding only a
// symbolic link to the file).

import { mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { createHttpSignaturesProfile, httpSignatures, type IdentityResolver, type KeyProvider } from '@dnsid-ai/sdk';
import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

export class SignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignerError';
  }
}

/** An agent ID is its DNSid domain name. */
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function checkAgentId(name: string, value: string | undefined): string {
  const normalized = (value ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!DOMAIN.test(normalized)) throw new SignerError(`${name} is not a DNSid agent ID (a domain name)`);
  return normalized;
}

const neverVerifies: IdentityResolver = {
  verifyDomain() {
    throw new Error('the live-test signer never verifies');
  },
};

// The PKCS #8 PEM armour line, assembled so the source itself never carries a private-key marker.
const PKCS8_PEM_LABEL = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');

export async function loadKeyProvider(keyFile: string): Promise<KeyProvider> {
  let head: string;
  try {
    head = readFileSync(keyFile, 'utf8').trimStart().slice(0, 64);
  } catch {
    throw new SignerError('DNSID_AGENT_KEY_FILE cannot be read');
  }
  try {
    if (head.startsWith('{')) return await LocalKeyProvider.fromFile(keyFile);
    if (head.startsWith(PKCS8_PEM_LABEL)) {
      const dir = mkdtempSync(join(tmpdir(), 'dnsid-live-key-'));
      try {
        symlinkSync(resolve(keyFile), join(dir, 'private.pem'));
        return await LocalKeyProvider.fromDirectory(dir);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  } catch {
    throw new SignerError('DNSID_AGENT_KEY_FILE is not a usable private key (a private JWK or a PKCS #8 PEM)');
  }
  throw new SignerError('DNSID_AGENT_KEY_FILE is not a private JWK or a PKCS #8 PEM private key');
}

export interface SignOptions {
  /** The `created` parameter, Unix seconds; the profile's default (now) when absent. */
  readonly created?: number;
  /** The domain claimed in `keyid`, instead of the agent's own (deny-other-identity). */
  readonly claimedDomain?: string;
}

export interface Signer {
  readonly domain: string;
  readonly kid: string;
  /**
   * The `Signature-Input` and `Signature` fields for `method url`, covering @method, @authority and @target-uri. With
   * no options this is the SDK profile's own signing, as an agent does it.
   */
  sign(method: string, url: string, options?: SignOptions): Promise<[string, string][]>;
}

export async function createSigner(domain: string, keyProvider: KeyProvider): Promise<Signer> {
  const key = await keyProvider.signingKey();
  const profile = createHttpSignaturesProfile({ domain, keyProvider, identityResolver: neverVerifies });
  const alg = httpSignatures.joseAlgToHttpSigAlg(String(key.alg));
  const fields = (request: Request): [string, string][] =>
    [...request.headers].filter(([name]) => name === 'signature' || name === 'signature-input').map(([n, v]) => [n, v]);
  return {
    domain,
    kid: String(key.kid),
    async sign(method, url, options = {}) {
      const request = new Request(url, { method });
      if (options.created === undefined && options.claimedDomain === undefined) {
        return fields(await profile.createSignedHttpRequest(request));
      }
      const signed = await httpSignatures.signHttpMessage(
        request,
        {
          label: 'sig1',
          components: ['@method', '@authority', '@target-uri'],
          keyId: `${options.claimedDomain ?? domain}#${String(key.kid)}`,
          ...(alg === undefined ? {} : { alg }),
          created: options.created ?? Math.floor(Date.now() / 1000),
          nonce: httpSignatures.generateNonce(),
        },
        keyProvider,
      );
      return fields(signed);
    },
  };
}
