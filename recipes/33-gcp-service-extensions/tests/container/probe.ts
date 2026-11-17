// TEST ONLY. Probes for scripts/container-smoke.sh: they talk to a running container, print one JSON line with what
// they observed, and exit 1 if it isn't what is expected. Locally they run on the host against the container's port
// published on loopback; in the image build they run in a throwaway container on the build's network and are given the
// container's name there.
//
//   node tests/container/probe.ts verifier <port> [host]   an unsigned GET, sent as an ext_proc message: one 403, signature_missing
//   node tests/container/probe.ts origin <port> [host]     Demo Bank's routes, methods, identity context, its
//                                                          attestation (under DNSID_ATTESTATION_KEY, the run's key) and no-store
//
// Nothing here signs a request or contacts anything but the given host (127.0.0.1 when none is given).

import { attest, attestationKeyFromSetting } from '../../src/attestation.ts';
import { byteClient, exchange, status } from '../support/grpc-client.ts';
import { call } from '../support/http-client.ts';
import { decodeDenial } from '../support/response-wire.ts';
import { serialize } from '../support/signing.ts';

const CLAIMED: [string, string][] = [
  ['x-dnsid-verified-domain', 'agent-example.test'],
  ['x-dnsid-governance-id', 'governance-example.test'],
];

/** The claimed identity with the attestation the verifier would add, under the run's key, made now. */
function attested(): [string, string][] {
  const key = attestationKeyFromSetting(process.env['DNSID_ATTESTATION_KEY']);
  return [...CLAIMED, ['x-dnsid-attestation', attest(key, 'agent-example.test', 'governance-example.test')]];
}

async function verifier(port: number, host: string): Promise<boolean> {
  const client = byteClient(port, {}, host);
  try {
    const unsigned = serialize([[':method', 'GET'], [':authority', 'api-example.test'], [':path', '/accounts'], [':scheme', 'https']]);
    const { stream, status: final } = await exchange(client, unsigned, { deadlineMs: 10_000 });
    const denial = stream.responses.length === 1 ? decodeDenial(stream.responses[0] as Buffer) : undefined;
    const observed = {
      probe: 'verifier',
      grpcStatus: final.code,
      responses: stream.responses.length,
      httpStatus: denial?.status,
      reason: denial?.body.toString('latin1'),
      headers: denial?.headers.map((h) => [h.key, h.rawValue.toString('latin1')]),
    };
    console.log(JSON.stringify(observed));
    return final.code === status.OK && observed.responses === 1 && observed.httpStatus === 403 && observed.reason === 'signature_missing';
  } finally {
    client.close();
  }
}

async function origin(port: number, host: string): Promise<boolean> {
  const IDENTITY = attested();
  const forged = `v1.${Math.floor(Date.now() / 1000)}.${'A'.repeat(43)}`;
  const cases: [method: string, path: string, headers: [string, string][], status: number, body: string | undefined][] = [
    ['GET', '/accounts', IDENTITY, 200, undefined],
    ['HEAD', '/accounts', IDENTITY, 200, ''],
    ['GET', '/accounts', [], 403, '{"error":"identity_context_required"}'],
    ['GET', '/accounts', [IDENTITY[0] as [string, string], IDENTITY[0] as [string, string], IDENTITY[1] as [string, string]], 403, '{"error":"identity_context_invalid"}'],
    ['GET', '/accounts', CLAIMED, 403, '{"error":"identity_attestation_required"}'],
    ['GET', '/accounts', [...CLAIMED, ['x-dnsid-attestation', forged]], 403, '{"error":"identity_attestation_invalid"}'],
    ['POST', '/accounts', IDENTITY, 405, '{"error":"method_not_allowed"}'],
    ['GET', '/other', IDENTITY, 404, '{"error":"not_found"}'],
  ];
  let ok = true;
  const observed = [];
  for (const [method, path, headers, expected, body] of cases) {
    const reply = await call(port, method, path, headers, host);
    const pass =
      reply.status === expected &&
      reply.headers['cache-control'] === 'no-store' &&
      (body === undefined ? JSON.parse(reply.body).synthetic === true : reply.body === body);
    ok &&= pass;
    observed.push({ request: `${method} ${path}`, identityHeaders: headers.length, status: reply.status, cacheControl: reply.headers['cache-control'], body: reply.body.slice(0, 120), pass });
  }
  console.log(JSON.stringify({ probe: 'origin', cases: observed }));
  return ok;
}

const [what, portText, hostText] = process.argv.slice(2);
const port = Number(portText);
const host = hostText ?? '127.0.0.1';
// A container name on a docker network, or an IPv4 address: nothing a shell or URL could reinterpret.
const hostShape = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
if (!Number.isInteger(port) || port < 1 || port > 65_535 || (what !== 'verifier' && what !== 'origin') || !hostShape.test(host)) {
  console.error('usage: node tests/container/probe.ts verifier|origin <port> [host]');
  process.exit(2);
}
try {
  process.exitCode = (await (what === 'verifier' ? verifier(port, host) : origin(port, host))) ? 0 : 1;
} catch (error) {
  console.log(JSON.stringify({ probe: what, error: (error as { code?: unknown }).code ?? 'failed' }));
  process.exitCode = 1;
}
