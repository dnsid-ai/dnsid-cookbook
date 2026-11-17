// TLS to the deployment's endpoint, trusting exactly the self-signed certificate the deployment created and nothing
// else: the certificate is the only trust anchor, the endpoint's address must be named in it, and the certificate the
// endpoint presents must have the SHA-256 fingerprint recorded in DEPLOY_OUT. A different certificate, a wrong pin or
// a hostname mismatch fails the connection. There is no setting that skips verification.
//
// No dependencies: scripts/deploy.sh uses this before anything is installed.

import { createHash, X509Certificate } from 'node:crypto';
import { checkServerIdentity, type ConnectionOptions, type PeerCertificate } from 'node:tls';

export interface PinnedTls {
  /** The certificate, PEM. */
  readonly certificatePem: string;
  /** Its SHA-256 fingerprint, uppercase hex pairs separated by colons (Node's `fingerprint256` form). */
  readonly fingerprint256: string;
}

export class PinError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PinError';
  }
}

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

/** The SHA-256 fingerprint of a PEM certificate, in `fingerprint256` form. */
export function fingerprintOf(certificatePem: string): string {
  return new X509Certificate(certificatePem).fingerprint256;
}

/** Checks the recorded pin is well formed and belongs to the recorded certificate. */
export function checkedPin(pin: PinnedTls): PinnedTls {
  if (typeof pin.certificatePem !== 'string' || !pin.certificatePem.includes('-----BEGIN CERTIFICATE-----')) {
    throw new PinError('the recorded certificate is not a PEM certificate');
  }
  if (typeof pin.fingerprint256 !== 'string' || !FINGERPRINT.test(pin.fingerprint256)) {
    throw new PinError('the recorded fingerprint is not a SHA-256 fingerprint');
  }
  let actual: string;
  try {
    actual = fingerprintOf(pin.certificatePem);
  } catch {
    throw new PinError('the recorded certificate cannot be parsed');
  }
  if (actual !== pin.fingerprint256) throw new PinError('the recorded fingerprint does not match the recorded certificate');
  return pin;
}

/**
 * Connection options for `host` (an IP address or a name the certificate must cover). The certificate is the only CA;
 * Node verifies the chain and the name, then the presented certificate's fingerprint must equal the pin.
 */
export function pinnedConnectionOptions(host: string, pin: PinnedTls): ConnectionOptions {
  checkedPin(pin);
  return {
    host,
    ca: [pin.certificatePem],
    rejectUnauthorized: true,
    // SNI is only sent for names; an IP address is checked against the certificate's IP addresses.
    ...(isIp(host) ? {} : { servername: host }),
    checkServerIdentity(hostname: string, cert: PeerCertificate): Error | undefined {
      const nameError = checkServerIdentity(hostname, cert);
      if (nameError !== undefined) return nameError;
      if (cert.fingerprint256 !== pin.fingerprint256) {
        return new PinError('the endpoint presented a certificate other than the pinned one');
      }
      return undefined;
    },
  };
}

export function isIp(host: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

/** sha256 of arbitrary bytes, hex. */
export function sha256Hex(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}
