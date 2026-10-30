import { describe, expect, it } from 'vitest';
import { DNSSECState } from '@dnsid-ai/protocol';
import { dohResolver, parseCharacterStrings } from '../src/shared/dns.ts';

function resolverFor(body: unknown) {
  return dohResolver('https://dns.example/query', (async () => Response.json(body)) as typeof fetch);
}

const answer = { name: 'agent.example.', type: 16, TTL: 60, data: '"one" "two"' };

describe('DoH response validation', () => {
  it('accepts TXT answers and ignores unrelated response fields and record types', async () => {
    const resolver = resolverFor({
      Status: 0, AD: true, Extra: 'ignored',
      Answer: [answer, { ...answer, type: 5, data: 'alias.example.' }],
    });
    expect(await resolver.fetchTXT('agent.example')).toEqual([
      [{ strings: ['one', 'two'], ttl: 60 }], DNSSECState.VALID,
    ]);
  });

  it('accepts empty and negative answers without an Answer array', async () => {
    for (const Status of [0, 3]) {
      expect(await resolverFor({ Status, AD: false }).fetchTXT('agent.example'))
        .toEqual([[], DNSSECState.UNSIGNED]);
    }
  });

  it('preserves DNSSEC failure detection for string and array comments', async () => {
    for (const Comment of ['EDE(6): DNSSEC Bogus', ['EDE(6): DNSSEC Bogus']]) {
      expect(await resolverFor({ Status: 2, AD: false, Comment }).fetchTXT('agent.example'))
        .toEqual([[], DNSSECState.FAILED]);
    }
  });

  it('rejects malformed response fields instead of trusting their TypeScript shape', async () => {
    for (const body of [
      null, [], {},
      { Status: '0', AD: true },
      { Status: 0, AD: 'false' },
      { Status: 0, AD: false, Answer: {} },
      ...[{ TTL: -1 }, { TTL: 1.5 }, { type: '16' }, { data: 42 }, { name: null }]
        .map(fields => ({ Status: 0, AD: false, Answer: [{ ...answer, ...fields }] })),
      { Status: 2, AD: false, Comment: [42] },
    ]) {
      await expect(resolverFor(body).fetchTXT('agent.example')).rejects.toThrow('malformed DoH JSON response');
    }
  });
});

describe('TXT presentation parsing', () => {
  it('handles multiple strings, escapes and \\DDD', () => {
    expect(parseCharacterStrings('"a b" "c\\"d" "\\065\\066"')).toEqual(['a b', 'c"d', 'AB']);
    expect(parseCharacterStrings('"é"')).toEqual(['é']);
  });
});
