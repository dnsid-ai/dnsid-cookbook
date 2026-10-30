import { createServer } from 'node:http';

/** Local HTTP fixture: authenticates ingress, echoes requests, and supplies a fixed denial. */
export async function startTestOrigin(originSecret: string) {
  const server = createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');

    if (request.headers['dnsid-origin-auth'] !== originSecret) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: 'origin_auth_required' }));
      return;
    }

    if (request.url === '/denied') {
      response.writeHead(403, { 'x-test-origin': 'denied' });
      response.end(JSON.stringify({ error: 'origin_denied' }));
      return;
    }

    try {
      const chunks: Buffer[] = [];
      for await (const chunk of request) {
        chunks.push(Buffer.from(chunk));
      }

      response.end(JSON.stringify({
        method: request.method,
        path: request.url,
        agent: request.headers['dnsid-agent'],
        entity: request.headers['dnsid-accountable-entity'],
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    } catch {
      response.writeHead(400);
      response.end(JSON.stringify({ error: 'body_read_failed' }));
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Test origin did not acquire a TCP port');
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
        server.closeIdleConnections();
      });
    },
  };
}
