// TEST ONLY. A plain HTTP/1.1 client for the origin on loopback: one request per connection, headers sent as a flat raw
// list so a repeated header is sent as a repeat.

import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';

export interface HttpReply {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

export function call(port: number, method: string, path: string, headers: [string, string][] = [], host = '127.0.0.1'): Promise<HttpReply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host, port, method, path, agent: false, headers: ['host', `${host}:${port}`, ...headers.flat()] }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}
