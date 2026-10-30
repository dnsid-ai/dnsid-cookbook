// Experiment: does the SDK's shared in-flight verification survive across request contexts
// in workerd, including when the request that started it is canceled?
//   npx wrangler dev -c test/wrangler.xreq.jsonc --port 8799
//   curl -m 0.3 localhost:8799/ & sleep 0.1; for i in 1 2 3 4 5; do curl localhost:8799/ & done; wait
//   curl localhost:8799/stats   # expect five "200 origin ok" and {"dnsLookups":1}
// Result (local workerd, 2026-10-29): followers succeed after the initiator is canceled. Confirm on the edge.
import { createIngressHandler } from '../src/ingress.ts';
import { createTestEgress } from './signing-fixture.ts';
import { fixtureIdentity, fixtureVerifier } from './fixture.ts';
import type { IngressEnv } from '../src/ingress.ts';

let setup: Promise<{ ingress: ReturnType<typeof createIngressHandler>; sign: () => Promise<Request>; stats: { dnsLookups: number } }> | undefined;

async function init() {
  const id = await fixtureIdentity('enrolled.example');
  const { verifier, stats } = fixtureVerifier(id);
  const slow = verifier as unknown as { dnsResolver: { fetchTXT: (n: string) => Promise<unknown> } };
  // Make the shared verification do real network I/O owned by whichever request started it.
  const inner = slow.dnsResolver.fetchTXT.bind(slow.dnsResolver);
  slow.dnsResolver.fetchTXT = async n => {
    await (await fetch('https://cloudflare-dns.com/dns-query?name=example.com&type=TXT', { headers: { accept: 'application/dns-json' } })).text();
    await scheduler.wait(800);
    return inner(n);
  };
  const ingress = createIngressHandler(verifier, (async () => new Response('origin ok')) as typeof fetch);
  const token = 'agent-token';
  const sign = async () => {
    let captured!: Request;
    const egress = await createTestEgress(id, async request => {
      captured = request;
      return new Response();
    }, token);
    await egress(new Request('https://egress.example/accounts/1/balance', { headers: { authorization: `Bearer ${token}`, 'DNSid-Destination': 'https://bank.example' } }));
    return captured;
  };
  return { ingress, sign, stats };
}

export default {
  async fetch(request: Request, env: IngressEnv): Promise<Response> {
    setup ??= init();
    const { ingress, sign, stats } = await setup;
    if (new URL(request.url).pathname === '/stats') return Response.json(stats);
    const res = await ingress(await sign(), {
      ...env,
      ORIGIN_SECRET: 's',
      ORIGIN_URL: 'https://o.internal',
    });
    return new Response(`${res.status} ${await res.text()}`);
  },
};
export { NonceStore } from '../src/shared/replay.ts';
