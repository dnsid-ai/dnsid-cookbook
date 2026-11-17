// TEST ONLY: a DNSID LOCAL LOOK-ALIKE on loopback. It is NOT DNSid Local: no registry, no CLI, no containers, no
// issuance workflow. It serves offline test identities (tests/support/identity-fixture.ts) the way DNSid Local serves
// its own, over real sockets, so the local mode's backend (local/backend.ts) can be run through the SDK's real Node
// transport with the settings DNSid Local hands out:
//
//   - DNS over UDP on 127.0.0.1 (DNSID_DNS_SERVER): `_dnsid.<fqdn>` TXT records, A records (127.0.0.1) for the served
//     names, nothing for other types (no AAAA: the SDK's private-address exception can't cover `::1`), NXDOMAIN for the
//     rest;
//   - one HTTPS listener on 127.0.0.1 for every served name, each with its own self-signed certificate chosen by SNI;
//     the certificates together are the CA bundle (DNSID_CA_BUNDLE). It serves the governance's `ek` key set and the
//     status documents (on `gov.test`), each agent's `ku` key set, and the C2SP log with its tlog-policy (on
//     `log.test`, DNSID_LOG_POLICY_URL);
//   - the agents' private keys as the CLI leaves them, `<config dir>/<fqdn>/private.pem`, for local/client.ts.
//
// Because the HTTPS listener can't take port 443 here, every URL names its port; DNSid Local's own URLs name none.

import { generateKeyPairSync } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSecureContext } from 'node:tls';

import { LocalKeyProvider } from '@dnsid-ai/sdk/node';

import { fixtureLog, issueIdentity, lifecycleEntry, type FixtureIdentity, type FixtureLog } from './identity-fixture.ts';
import { selfSignedCertificate } from './local-https.ts';

export const LOOKALIKE_GOVERNANCE = 'gov.test';
const LOG_HOST = 'log.test';

export interface Lookalike {
  readonly port: number;
  readonly dnsServer: string;
  readonly caBundlePath: string;
  readonly policyUrl: string;
  readonly log: FixtureLog;
  /** The CLI-like config directory: `<fqdn>/private.pem` for each agent. */
  readonly configDir: string;
  readonly identities: Readonly<Record<string, FixtureIdentity>>;
  /** What `dnsid local env --format json` would print for this network (plus the variables the verifier ignores). */
  readonly env: Readonly<Record<string, string>>;
  /** DNS questions (`name/type`) and HTTPS requests (`host path`) received, in order. */
  readonly dnsQueries: string[];
  readonly httpsRequests: string[];
  /** Sets an identity's status document. */
  setStatus(domain: string, state: 'ACTIVE' | 'REVOKED' | 'RETIRED'): void;
  /** Appends a REVOCATION to the identity's log stream, leaving its status document as it is. */
  revokeInLog(domain: string): Promise<void>;
  close(): Promise<void>;
}

function encodeName(name: string): Buffer {
  return Buffer.concat([...name.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0])]);
}

/** TXT RDATA: the value as character-strings of at most 255 bytes. */
function txtRdata(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  const parts: Buffer[] = [];
  for (let at = 0; at < bytes.length; at += 255) {
    const chunk = bytes.subarray(at, at + 255);
    parts.push(Buffer.from([chunk.length]), chunk);
  }
  return Buffer.concat(parts);
}

async function dnsServer(hosts: readonly string[], txt: Map<string, string>, queries: string[]) {
  const socket = createSocket('udp4');
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
    const known = hosts.includes(name) || txt.has(name);
    let answer = Buffer.alloc(0);
    if (type === 1 && hosts.includes(name)) {
      answer = Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]), Buffer.from([127, 0, 0, 1])]);
    } else if (type === 16 && txt.has(name)) {
      const rdata = txtRdata(txt.get(name) as string);
      const head = Buffer.from([0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 0]);
      head.writeUInt16BE(rdata.length, 10);
      answer = Buffer.concat([head, rdata]);
    }
    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180 | (known ? 0 : 3), 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answer.length > 0 ? 1 : 0, 6);
    // Additional records (an EDNS OPT a resolver sent) are not echoed: the answer is plain DNS.
    socket.send(Buffer.concat([header, question, answer]), peer.port, peer.address);
  });
  await new Promise<void>((resolve) => socket.bind(0, '127.0.0.1', resolve));
  return { server: `127.0.0.1:${(socket.address() as AddressInfo).port}`, close: () => socket.close() };
}

export async function dnsidLocalLookalike(agents: readonly string[] = ['alice.test', 'bob.test']): Promise<Lookalike> {
  const directory = mkdtempSync(join(tmpdir(), 'dnsid-local-lookalike-'));
  const configDir = join(directory, 'cli');
  const hosts = [LOOKALIKE_GOVERNANCE, LOG_HOST, ...agents];
  const certificates = new Map(hosts.map((host) => [host, selfSignedCertificate(host)]));
  const caBundlePath = join(directory, 'root-ca.pem');
  writeFileSync(caBundlePath, [...certificates.values()].map((c) => c.cert).join(''));
  const dnsQueries: string[] = [];
  const httpsRequests: string[] = [];
  const txt = new Map<string, string>();
  const documents = new Map<string, () => { type: string; body: Buffer } | undefined>();
  const statuses = new Map<string, string>();

  const contexts = new Map([...certificates].map(([host, c]) => [host, createSecureContext({ key: c.key, cert: c.cert })]));
  const first = certificates.get(LOOKALIKE_GOVERNANCE) as { key: string; cert: string };
  let log: FixtureLog | undefined;
  const server: Server = createServer(
    {
      key: first.key,
      cert: first.cert,
      SNICallback: (name, callback) => callback(null, contexts.get(name.toLowerCase())),
    },
    (request, response) => {
      const host = String(request.headers.host ?? '').replace(/:\d+$/, '').toLowerCase();
      const path = request.url ?? '';
      httpsRequests.push(`${host} ${path}`);
      const url = `https://${host}:${(server.address() as AddressInfo).port}${path}`;
      const document = documents.get(url)?.();
      if (document !== undefined) {
        response.writeHead(200, { 'content-type': document.type, 'content-length': document.body.length });
        response.end(document.body);
        return;
      }
      if (host === LOG_HOST && log !== undefined) {
        log.fetcher.fetchBounded(url, 64 * 1024 * 1024, { timeoutMs: 10_000 }).then(
          (body) => {
            response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': body.length });
            response.end(Buffer.from(body));
          },
          () => {
            response.writeHead(404);
            response.end();
          },
        );
        return;
      }
      response.writeHead(404);
      response.end();
    },
  );
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const origin = (host: string) => `https://${host}:${port}`;
  log = fixtureLog(origin(LOG_HOST));
  const policyUrl = `${origin(LOG_HOST)}/policy`;
  const fixedLog = log;
  documents.set(policyUrl, () => ({ type: 'text/plain', body: Buffer.from(fixedLog.policyDocument) }));
  const dns = await dnsServer(hosts, txt, dnsQueries);

  const identities: Record<string, FixtureIdentity> = {};
  let entity: FixtureIdentity['entity'] | undefined;
  for (const domain of agents) {
    const keyDir = join(configDir, domain);
    mkdirSync(keyDir, { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(join(keyDir, 'private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, { mode: 0o600 });
    const identity = await issueIdentity(log, domain, {
      governanceId: LOOKALIKE_GOVERNANCE,
      operational: await LocalKeyProvider.fromDirectory(keyDir),
      // One governance, one accountable-entity key document, as under DNSid Local.
      ...(entity === undefined ? {} : { entity }),
      urls: {
        ekUrl: `${origin(LOOKALIKE_GOVERNANCE)}/.well-known/dnsid/ek.json`,
        kuUrl: `${origin(domain)}/.well-known/dnsid/ku.json`,
        statusUrl: `${origin(LOOKALIKE_GOVERNANCE)}/status/${domain}`,
      },
    });
    entity ??= identity.entity;
    identities[domain] = identity;
    txt.set(`_dnsid.${domain}`, identity.txt);
    documents.set(identity.kuUrl, () => ({ type: 'application/json', body: Buffer.from(JSON.stringify({ keys: [identity.operationalKey] })) }));
    documents.set(identity.ekUrl, () => ({ type: 'application/json', body: Buffer.from(JSON.stringify({ keys: [identity.entityKey] })) }));
    statuses.set(domain, 'ACTIVE');
    documents.set(identity.statusUrl, () => {
      const state = statuses.get(domain) as string;
      const body: Record<string, string> = { state, lastTransitionAt: new Date(Date.now() - 60_000).toISOString() };
      if (state === 'REVOKED') body['revocationReason'] = 'ownerRequest';
      return { type: 'application/json', body: Buffer.from(JSON.stringify(body)) };
    });
  }

  return {
    port,
    dnsServer: dns.server,
    caBundlePath,
    policyUrl,
    log,
    configDir,
    identities,
    env: {
      DNSID_LOG_POLICY_URL: policyUrl,
      DNSID_DNS_SERVER: dns.server,
      DNSID_CA_BUNDLE: caBundlePath,
      DNSID_PRIVATE_HOSTS: '.test',
      DNSID_GOVERNANCE_ID: LOOKALIKE_GOVERNANCE,
      // What DNSid Local prints besides; the verifier never reads these, and local/recipe.ts never passes them on.
      DNSID_API_KEY: 'testnet',
      DNSID_SERVER: 'http://127.0.0.1:9',
      DNSID_REGISTRY_URL: 'http://127.0.0.1:9',
      DNSID_DNSSEC_MODE: 'auto',
      DNSID_TESTNET_ZONE: 'test',
    },
    dnsQueries,
    httpsRequests,
    setStatus(domain, state) {
      statuses.set(domain, state);
    },
    async revokeInLog(domain) {
      const identity = identities[domain] as FixtureIdentity;
      fixedLog.append(await lifecycleEntry(identity, 'REVOCATION'));
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      dns.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}
