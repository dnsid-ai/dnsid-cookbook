import { DNSSECState, type DNSResolver, type TXTRecord } from '@dnsid-ai/protocol';

import { z } from 'zod';

const dohResponseSchema = z.object({
  Status: z.number().int().nonnegative(),
  AD: z.boolean(),
  Answer: z.array(z.object({
    name: z.string(),
    type: z.number().int().min(0).max(65535),
    TTL: z.number().int().min(0).max(4294967295),
    data: z.string(),
  })).optional(),
  Comment: z.union([z.string(), z.array(z.string())]).optional(),
});

const TXT = 16;

// RFC 8914 EDE codes 1-12 are DNSSEC validation outcomes (bogus, expired, missing DNSKEY/RRSIG/NSEC...).
const DNSSEC_EDE = /EDE\((?:[1-9]|1[0-2])\)/;

/**
 * Creates an SDK TXT-record resolver backed by a DNS-over-HTTPS JSON endpoint.
 * Trusts the validating resolver's AD bit: AD → VALID, NOERROR without AD → UNSIGNED.
 * ponytail: Supports the Cloudflare/Google JSON response format only. Other DoH
 * services may require the standard binary DNS-message format (RFC 8484).
 * @param endpoint URL of the validating JSON DNS resolver.
 * @param fetcher Fetch implementation; injectable for local DNS and tests.
 */
export function dohResolver(
  endpoint = 'https://cloudflare-dns.com/dns-query',
  fetcher: typeof fetch = fetch,
): DNSResolver {
  return {
    async fetchTXT(name, options) {
      const url = new URL(endpoint);
      url.searchParams.set('name', name.endsWith('.') ? name : `${name}.`);
      url.searchParams.set('type', 'TXT');
      url.searchParams.set('do', '1');

      const res = await fetcher(url, {
        headers: { accept: 'application/dns-json' },
        signal: options?.signal,
      });
      if (!res.ok) {
        throw new Error(`DoH HTTP ${res.status}`);
      }

      const result = dohResponseSchema.safeParse(await res.json());
      if (!result.success) {
        throw new Error('malformed DoH JSON response');
      }

      const body = result.data;
      const comments = typeof body.Comment === 'string' ? [body.Comment] : body.Comment;
      if (body.Status === 2 && comments?.some(c => DNSSEC_EDE.test(c))) {
        return [[], DNSSECState.FAILED];
      }

      const state = body.AD ? DNSSECState.VALID : DNSSECState.UNSIGNED;
      if (body.Status === 3) {
        return [[], state]; // NXDOMAIN: the name does not exist.
      }
      if (body.Status !== 0) {
        throw new Error(`DoH rcode ${body.Status}`);
      }

      const records: TXTRecord[] = (body.Answer ?? [])
        .filter(a => a.type === TXT)
        .map(a => ({ strings: parseCharacterStrings(a.data), ttl: a.TTL }));

      return [records, state];
    },
  };
}

/**
 * Parses quoted DNS TXT data into separate strings, decoding escaped characters
 * and three-digit decimal byte escapes. Throws for unquoted or unterminated data.
 */
export function parseCharacterStrings(data: string): string[] {
  const out: string[] = [];
  let i = 0;

  while (i < data.length) {
    if (data[i] === ' ') {
      i++;
      continue;
    }

    if (data[i] !== '"') {
      throw new Error('malformed TXT data');
    }
    i++;

    const bytes: number[] = [];
    while (data[i] !== '"') {
      if (i >= data.length) {
        throw new Error('unterminated TXT string');
      }

      if (data[i] === '\\') {
        const ddd = /^\d{3}/.exec(data.slice(i + 1, i + 4));
        if (ddd) {
          bytes.push(Number(ddd[0]));
          i += 4;
          continue;
        }
        i++;
      }

      const ch = String.fromCodePoint(data.codePointAt(i)!);
      bytes.push(...new TextEncoder().encode(ch));
      i += ch.length;
    }

    i++;
    out.push(new TextDecoder().decode(new Uint8Array(bytes)));
  }

  return out;
}
