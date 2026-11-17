// TEST ONLY. A local HTTPS origin for exercising the SDK's real transports: a self-signed ECDSA P-256 certificate made in
// memory when a test starts (never committed; the certificate alone goes to a temporary CA file), an HTTPS server on
// 127.0.0.1, and a minimal DNS server on 127.0.0.1 that answers A records for the test names only. Certificate DER
// encoding per RFC 5280 and X.690; DNS messages per RFC 1035.

import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function length(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let rest = n; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, ...content: Buffer[]) => {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const seq = (...content: Buffer[]) => tlv(0x30, ...content);

function oid(dotted: string): Buffer {
  const [first, second, ...rest] = dotted.split('.').map(Number) as [number, number, ...number[]];
  const out = [first * 40 + second];
  for (const arc of rest) {
    const chunk: number[] = [arc & 0x7f];
    for (let value = Math.floor(arc / 128); value > 0; value = Math.floor(value / 128)) chunk.unshift((value & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

function utcTime(date: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return tlv(0x17, Buffer.from(text, 'ascii'));
}

const pem = (label: string, der: Buffer) =>
  `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END ${label}-----\n`;

export interface LocalCertificate {
  readonly key: string;
  readonly cert: string;
}

/**
 * A certificate for `hostname` (and nothing else), valid from an hour ago for one day. An IPv4 address is named as an
 * IP address (iPAddress SAN), anything else as a DNS name.
 */
export function selfSignedCertificate(hostname: string): LocalCertificate {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const algorithm = seq(oid('1.2.840.10045.4.3.2')); // ecdsa-with-SHA256
  const name = seq(tlv(0x31, seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(hostname)))));
  // A positive INTEGER in minimal DER form: the first byte is 0x40..0x7f, never 0x00 (which would be illegal padding
  // when the next byte's top bit is clear) and never 0x80 or above (which would read as negative).
  const serial = randomBytes(8);
  serial[0] = ((serial[0] as number) & 0x3f) | 0x40;
  const now = Date.now();
  const ipv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
  const altName = ipv4 ? tlv(0x87, Buffer.from(hostname.split('.').map(Number))) : tlv(0x82, Buffer.from(hostname));
  const san = seq(oid('2.5.29.17'), tlv(0x04, seq(altName)));
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, serial),
    algorithm,
    name,
    seq(utcTime(new Date(now - 3_600_000)), utcTime(new Date(now + 86_400_000))),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
    tlv(0xa3, seq(san)),
  );
  const signature = sign('sha256', tbs, privateKey);
  const certificate = seq(tbs, algorithm, tlv(0x03, Buffer.from([0]), signature));
  return {
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    cert: pem('CERTIFICATE', certificate),
  };
}

// ---------- DNS ----------

function encodeName(name: string): Buffer {
  return Buffer.concat([...name.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0])]);
}

/** Answers A queries for the given names with 127.0.0.1, other types with no data, and other names with NXDOMAIN. */
export async function localDns(names: readonly string[]): Promise<{ server: string; queries: string[]; close(): void }> {
  const socket = createSocket('udp4');
  const queries: string[] = [];
  socket.on('message', (query, peer) => {
    let offset = 12;
    const labels: string[] = [];
    while (offset < query.length && query[offset] !== 0) {
      const size = query[offset] as number;
      labels.push(query.subarray(offset + 1, offset + 1 + size).toString('ascii'));
      offset += size + 1;
    }
    const question = query.subarray(12, offset + 5);
    const type = query.readUInt16BE(offset + 1);
    const name = labels.join('.').toLowerCase();
    queries.push(`${name}/${type}`);
    const known = names.includes(name);
    const answer =
      known && type === 1
        ? Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]), Buffer.from([127, 0, 0, 1])])
        : Buffer.alloc(0);
    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180 | (known ? 0 : 3), 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answer.length > 0 ? 1 : 0, 6);
    socket.send(Buffer.concat([header, question, answer]), peer.port, peer.address);
  });
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
  return {
    server: `127.0.0.1:${(socket.address() as AddressInfo).port}`,
    queries,
    close: () => socket.close(),
  };
}

// ---------- HTTPS ----------

export interface LocalOrigin {
  readonly hostname: string;
  readonly port: number;
  readonly origin: string;
  /** A PEM file holding only the certificate, for `caBundlePath`. */
  readonly caBundlePath: string;
  readonly dnsServer: string;
  /** Paths requested, in order. */
  readonly requests: string[];
  close(): Promise<void>;
}

export type Route = (request: IncomingMessage, response: ServerResponse, origin: LocalOrigin) => void;

/** An HTTPS server for `hostname` on 127.0.0.1, reachable by that name through its own DNS server. */
export async function localOrigin(hostname: string, routes: Record<string, Route>): Promise<LocalOrigin> {
  const certificate = selfSignedCertificate(hostname);
  const directory = mkdtempSync(join(tmpdir(), 'local-origin-'));
  const caBundlePath = join(directory, 'ca.pem');
  writeFileSync(caBundlePath, certificate.cert);
  const dns = await localDns([hostname]);
  const requests: string[] = [];
  let origin: LocalOrigin;
  let server: Server;
  try {
    server = createServer({ key: certificate.key, cert: certificate.cert }, (request, response) => {
      const path = request.url ?? '';
      requests.push(path);
      const route = routes[path.split('?')[0] as string];
      if (route === undefined) {
        response.statusCode = 404;
        response.end();
        return;
      }
      route(request, response, origin);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  } catch (error) {
    // Nothing a failed start opened may keep the test process alive.
    dns.close();
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
  const port = (server.address() as AddressInfo).port;
  origin = {
    hostname,
    port,
    origin: `https://${hostname}:${port}`,
    caBundlePath,
    dnsServer: dns.server,
    requests,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      dns.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
  return origin;
}
