// TEST ONLY: a test forwarding harness. It is NOT Google's load balancer and NOT Envoy, and proves nothing about what
// either forwards. It joins two real local listeners the way the deployment joins them, so a test can see what reaches
// the origin:
//
//   1. the request's header fields go to the verifier's gRPC service as one ext_proc request-headers message (with end
//      of stream), over a real local connection;
//   2. a 403 immediate response is returned to the caller as is, and nothing is sent to the origin;
//   3. only a continuation is forwarded: its header mutation is applied with tests/support/response-wire.ts's local
//      model (removals, then sets), and the result goes to the origin over HTTP/1.1 on loopback, with the method and
//      path of the pseudo-headers and the `:authority` as `host`.
//
// Anything else (no response, more than one, a non-OK gRPC status) is refused here too: the harness never forwards a
// request the verifier did not explicitly continue.

import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';

import { exchange, status, type ByteClient } from './grpc-client.ts';
import { applyMutation, decodeContinuation, decodeDenial, viaService, type HeaderList } from './response-wire.ts';
import { serialize, type Field } from './signing.ts';

export type Forwarded =
  | { readonly kind: 'denied'; readonly status: number; readonly reason: string }
  | { readonly kind: 'refused'; readonly why: string }
  | {
      readonly kind: 'forwarded';
      /** The header list sent to the origin, after the mutation. */
      readonly sent: HeaderList;
      readonly status: number;
      readonly headers: IncomingHttpHeaders;
      readonly body: string;
    };

function originRequest(port: number, method: string, path: string, headers: HeaderList) {
  const raw = headers.flatMap(([name, value]) => [name, value.toString('latin1')]);
  return new Promise<{ status: number; headers: IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, method, path, agent: false, headers: raw }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * `eos`: whether the request-headers message marks the end of the stream (a request with no content). `deadlineMs`: the
 * gRPC deadline of the verifier call, none when absent; a call past it ends with a non-OK status and is refused.
 */
export async function forwardThroughVerifier(verifier: ByteClient, originPort: number, fields: Field[], eos = true, deadlineMs?: number): Promise<Forwarded> {
  const { stream, status: final } = await exchange(verifier, serialize(fields, eos), deadlineMs === undefined ? {} : { deadlineMs });
  if (final.code !== status.OK) return { kind: 'refused', why: `grpc status ${final.code}` };
  if (stream.responses.length !== 1) return { kind: 'refused', why: `${stream.responses.length} responses` };
  const response = stream.responses[0] as Buffer;
  const kind = viaService(response)['response'];
  if (kind === 'immediate_response') {
    const denial = decodeDenial(response);
    return { kind: 'denied', status: denial.status, reason: denial.body.toString('latin1') };
  }
  if (kind !== 'request_headers') return { kind: 'refused', why: `response ${String(kind)}` };
  const continuation = decodeContinuation(response);
  const value = (name: string) => {
    const found = fields.find(([key]) => key === name)?.[1];
    return typeof found === 'string' ? found : Buffer.from(found ?? '').toString('latin1');
  };
  const incoming: HeaderList = fields.map(([name, v]) => [name, Buffer.from(typeof v === 'string' ? Buffer.from(v, 'latin1') : v)]);
  const mutated = applyMutation(incoming, continuation);
  const sent: HeaderList = [['host', Buffer.from(value(':authority'), 'latin1')], ...mutated.filter(([name]) => !name.startsWith(':'))];
  const reply = await originRequest(originPort, value(':method'), value(':path'), sent);
  return { kind: 'forwarded', sent, ...reply };
}
