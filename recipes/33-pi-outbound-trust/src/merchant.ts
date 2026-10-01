import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

export async function startMerchant() {
  const state = { catalogCalls: 0, mode: 'normal' as 'normal' | 'redirect' | 'oversized' };
  const server = createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/catalog') {
      res.writeHead(404).end();
      return;
    }
    state.catalogCalls++;
    if (state.mode === 'redirect') {
      res.writeHead(302, { Location: 'https://paypal-payments.test/catalog' }).end();
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ item: 'tea', amountCents: 4200, currency: 'USD',
        ...(state.mode === 'oversized' ? { padding: 'x'.repeat(70_000) } : {}) }));
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    // Docker's TLS proxy reaches the host gateway on Linux, not host loopback.
    server.listen(Number(process.env.MERCHANT_PORT ?? 3133), '0.0.0.0', resolve);
  });
  return { server, state };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await startMerchant();
  console.log('Merchant serving /catalog; stop with Ctrl-C');
}
