// The per-process cache of identity material: `_dnsid` TXT answers and the record-signing (`ek`) and operational (`ku`)
// key documents, reused across requests at the identity verifier's injected dependency boundaries (`DNSResolver` and
// `JsonFetcher`, @dnsid-ai/sdk 0.37.0). APIs: https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/protocol/src/identity-manager.ts
//
// It holds data only: a TXT answer's strings, TTL and DNSSEC state, and a key document's JSON text with its original TLS
// certificate metadata, each with the time it was acquired. Never a VerifiedDomain, an SDK IdentityCache, a log reader,
// a promise, a callback or a signal. A hit hands the SDK fresh copies, and the SDK then runs every check it runs on a
// miss with the request's own verifier and registry: the record signature, the key sets, governance and key pins, key
// binding and continuity in the log, and the status document, which is never cached. So a hit saves fetches, not checks.
//
// What enters: only what one request fetched itself (a miss), for the identity it then fully verified, and only once
// that request's whole verification passed, before its deadline and uncancelled (`RequestMaterialView.admit`). A key
// document is cached only when the request positively identified it: its URL is the `ek` or `ku` URI of a `_dnsid`
// record this request resolved, AND it was fetched with exactly the host restriction, domain-boundary setting and size
// bound the SDK uses for that role. Everything else (status documents, log resources, any other fetch) bypasses it.
//
// Expiry, from what the SDK exposes (JsonFetcher returns no HTTP cache headers, so none are assumed):
// - a TXT answer: its acquisition time plus min(its TTL, DNS_REUSE_CAP); a hit returns the remaining whole seconds,
//   rounded down, so the SDK's own DNS expiry only ever moves earlier; under one second left, or a zero TTL, is a miss;
// - a key document: the earliest of its acquisition time plus KEY_REUSE_CAP, its TLS certificate's notAfter, and the
//   verified identity's evidence expiry (`VerifiedDomain.expiry()`: DNS expiry, both certificates, key age).
// Every lifetime is checked on both the monotonic clock and the wall clock, and the earlier wins, so moving the wall
// clock backwards never lengthens a reuse. A hit never extends an entry.
//
// Order: every fetch takes a sequence number when it starts, before it awaits anything, so a fetch that began earlier is
// older data however late it completes. An entry is replaced only by a fill that started after it; and when an entry
// leaves (expiry, eviction), its sequence number stays behind as a guard for its key, so a pending older fill cannot
// come back in after it. Guards are bounded (`maxEntries`, keys stored as SHA-256 digests); the oldest guard dropped
// raises a cache-wide floor below which no fill is admitted, so dropping a guard only ever refuses more.
//
// A key document entry belongs to one identity: its key carries the agent domain as well as the role, URL, exact fetch
// bounds and transport context, so two identities under one governance never share an entry for the same `ek` URL.

import { createHash } from 'node:crypto';

import {
  DnsIdTxtRecord,
  DNSSECState,
  JWKS_MAX_RESPONSE_BYTES,
  type DNSResolver,
  type FetchResult,
  type JsonFetcher,
  type JsonFetchOptions,
  type TXTRecord,
  type VerifiedDomain,
} from '@dnsid-ai/sdk';

export interface MaterialCacheLimits {
  /** Most entries held. */
  readonly maxEntries: number;
  /** Most bytes held (entry text, URLs and names, counted as UTF-8). */
  readonly maxBytes: number;
  /** Longest a TXT answer is reused, whatever its TTL. */
  readonly dnsReuseCapMs: number;
  /** Longest a key document is reused, whatever its certificate and the identity's evidence allow. */
  readonly keyReuseCapMs: number;
}

/** Internal defaults; not a deployment setting. */
export const DEFAULT_MATERIAL_CACHE_LIMITS: MaterialCacheLimits = Object.freeze({
  maxEntries: 256,
  maxBytes: 4 * 1024 * 1024,
  dnsReuseCapMs: 300_000,
  keyReuseCapMs: 300_000,
});

export type KeyRole = 'record_signing_keys' | 'operational_keys';

interface Instant {
  readonly wall: number;
  readonly mono: number;
}

const instant = (): Instant => ({ wall: Date.now(), mono: performance.now() });

interface Lifetime {
  readonly acquiredWall: number;
  readonly expiresWall: number;
  readonly expiresMono: number;
}

/** Milliseconds of reuse left: the earlier of the two clocks' answers, never more than the original allowance. */
function remainingMs(life: Lifetime, at: Instant): number {
  return Math.min(life.expiresWall - at.wall, life.expiresMono - at.mono);
}

interface DnsData {
  readonly kind: 'dns';
  readonly name: string;
  /** JSON text of the answer's strings. */
  readonly strings: string;
  readonly dnssecState: DNSSECState;
  readonly ttlSeconds: number;
}

interface KeyData {
  readonly kind: 'key';
  readonly role: KeyRole;
  readonly url: string;
  /** JSON text of the document. */
  readonly document: string;
  /** JSON text of its `keys` member, to match it with the key set the SDK verified. */
  readonly keys: string;
  readonly notAfterMs: number;
  /** JSON text of the certificate's SAN list. */
  readonly san: string;
}

type EntryData = DnsData | KeyData;

interface Entry {
  /** The identity it was admitted for. */
  readonly domain: string;
  readonly data: EntryData;
  readonly life: Lifetime;
  /** Start order of the fetch that produced it: a fetch started later is newer data. */
  readonly seq: number;
  readonly bytes: number;
}

/** One request's fetch, held until that request's verification passes, then offered to the cache. */
interface Fill {
  readonly key: string;
  readonly domain: string;
  readonly data: EntryData;
  readonly fetched: Instant;
  readonly seq: number;
  /** For a TXT answer: the parsed record's canonical form and signature, to match it with what the SDK verified. */
  readonly record?: { readonly canonical: string; readonly sg: string };
}

export interface MaterialCacheStats {
  dnsHits: number;
  dnsMisses: number;
  keyHits: number;
  keyMisses: number;
  admitted: number;
  /** Fills not admitted because a newer fetch's entry is (or was, before it left) there. */
  supersededFills: number;
  evicted: number;
  expired: number;
}

/** What an entry is, for evidence and tests: no document contents. */
export interface MaterialEntryDescription {
  readonly kind: 'dns' | KeyRole;
  readonly domain: string;
  readonly name: string;
  readonly remainingMs: number;
  readonly bytes: number;
}

function validLimits(limits: MaterialCacheLimits): MaterialCacheLimits {
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`material cache limit ${name} must be a positive integer`);
  }
  return Object.freeze({ ...limits });
}

const digest = (key: string) => createHash('sha256').update(key).digest('base64');

const byteLength = (...parts: string[]) => parts.reduce((total, part) => total + Buffer.byteLength(part), 0);

/** Identifies the transport and trust a fetch ran under, and the exact fetch bounds, so no weaker fetch serves a stricter one. */
function dnsKey(context: string, name: string): string {
  return JSON.stringify([context, 'dns', name]);
}

function keyKey(context: string, domain: string, role: KeyRole, url: string, options: JsonFetchOptions): string {
  return JSON.stringify([context, domain, role, url, options.allowedHost ?? null, options.domainBoundary === true, options.maxResponseBytes ?? null]);
}

export class SharedMaterialCache {
  readonly limits: MaterialCacheLimits;
  readonly #entries = new Map<string, Entry>();
  #bytes = 0;
  #seq = 0;
  /** Per key (digest), the newest sequence number of an entry that left; at most `maxEntries`, oldest first. */
  readonly #guards = new Map<string, number>();
  /** No fill at or below this sequence number is admitted: raised when a guard is dropped, and by `clear`. */
  #floor = 0;
  readonly #stats: MaterialCacheStats = {
    dnsHits: 0,
    dnsMisses: 0,
    keyHits: 0,
    keyMisses: 0,
    admitted: 0,
    supersededFills: 0,
    evicted: 0,
    expired: 0,
  };

  constructor(limits: MaterialCacheLimits = DEFAULT_MATERIAL_CACHE_LIMITS) {
    this.limits = validLimits(limits);
  }

  get size(): number {
    return this.#entries.size;
  }

  get bytes(): number {
    return this.#bytes;
  }

  stats(): Readonly<MaterialCacheStats> {
    return Object.freeze({ ...this.#stats });
  }

  /** How many ordering guards are held, and the floor: for evidence and tests. */
  ordering(): { guards: number; floor: number } {
    return { guards: this.#guards.size, floor: this.#floor };
  }

  describe(): MaterialEntryDescription[] {
    const at = instant();
    return [...this.#entries.values()].map(({ domain, data, life, bytes }) => ({
      kind: data.kind === 'dns' ? 'dns' : data.role,
      domain,
      name: data.kind === 'dns' ? data.name : data.url,
      remainingMs: remainingMs(life, at),
      bytes,
    }));
  }

  /**
   * Empties the cache (for instance at shutdown). Requests in flight are unaffected: they hold no entry. Fetches started
   * before this are never admitted afterwards.
   */
  clear(): void {
    this.#entries.clear();
    this.#bytes = 0;
    this.#guards.clear();
    this.#floor = this.#seq;
  }

  /** A request's access to the cache, for one transport context. */
  view(context: string, options: { signal: AbortSignal; revalidate?: boolean }): RequestMaterialView {
    return new RequestMaterialView(this, context, options.signal, options.revalidate === true);
  }

  /** @internal The order of a fetch; taken when it starts. */
  nextSeq(): number {
    return ++this.#seq;
  }

  #live(key: string, at: Instant): Entry | undefined {
    const entry = this.#entries.get(key);
    if (entry === undefined) return undefined;
    if (remainingMs(entry.life, at) <= 0) {
      this.#leave(key, entry);
      this.#stats.expired++;
      return undefined;
    }
    // Most recently used last, for eviction.
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    return entry;
  }

  #remove(key: string, entry: Entry): void {
    this.#entries.delete(key);
    this.#bytes -= entry.bytes;
  }

  /** Removes an entry that expired or was evicted, keeping its order as the key's guard. */
  #leave(key: string, entry: Entry): void {
    this.#remove(key, entry);
    const id = digest(key);
    const seq = Math.max(entry.seq, this.#guards.get(id) ?? 0);
    this.#guards.delete(id);
    this.#guards.set(id, seq);
    for (const [oldest, guard] of this.#guards) {
      if (this.#guards.size <= this.limits.maxEntries) break;
      this.#guards.delete(oldest);
      this.#floor = Math.max(this.#floor, guard);
    }
  }

  /** The newest order a fill for `key` must exceed: its live entry's, the guard left by a removed one, and the floor. */
  #newestSeen(key: string, existing: Entry | undefined): number {
    return Math.max(existing?.seq ?? 0, this.#guards.get(digest(key)) ?? 0, this.#floor);
  }

  /** @internal A fresh copy of a live TXT answer, with its TTL reduced to the whole seconds left. */
  lookupDns(context: string, name: string): { records: TXTRecord[]; state: DNSSECState } | undefined {
    const at = instant();
    const entry = this.#live(dnsKey(context, name), at);
    const data = entry?.data;
    if (entry === undefined || data?.kind !== 'dns') {
      this.#stats.dnsMisses++;
      return undefined;
    }
    const ttl = Math.floor(remainingMs(entry.life, at) / 1000);
    if (ttl < 1) {
      this.#stats.dnsMisses++;
      return undefined;
    }
    this.#stats.dnsHits++;
    return { records: [{ strings: JSON.parse(data.strings) as string[], ttl }], state: data.dnssecState };
  }

  /** @internal A fresh copy of a live key document with its original certificate metadata. */
  lookupKey(context: string, domain: string, role: KeyRole, url: string, options: JsonFetchOptions): FetchResult | undefined {
    const entry = this.#live(keyKey(context, domain, role, url, options), instant());
    const data = entry?.data;
    if (entry === undefined || data?.kind !== 'key') {
      this.#stats.keyMisses++;
      return undefined;
    }
    this.#stats.keyHits++;
    return {
      data: JSON.parse(data.document) as unknown,
      tlsCert: { notAfter: new Date(data.notAfterMs), san: JSON.parse(data.san) as string[] },
    };
  }

  /**
   * @internal Admits one request's fills for `verified`'s identity. Synchronous. A fill is admitted only when it is the
   * material the SDK verified (the same signed record; the same key document URL, certificate and keys), still has time
   * left, its fetch started after every entry for its key so far (live or gone), and it is for this identity's domain.
   */
  admit(fills: Iterable<Fill>, verified: VerifiedDomain): void {
    const at = instant();
    const evidenceExpiry = verified.expiry().getTime();
    if (!Number.isFinite(evidenceExpiry)) return;
    const record = verified.record;
    for (const fill of fills) {
      if (fill.domain !== verified.domain) continue;
      const data = fill.data;
      let expiresWall: number;
      if (data.kind === 'dns') {
        if (fill.record === undefined || fill.record.canonical !== record.canonical() || fill.record.sg !== record.sg) continue;
        expiresWall = fill.fetched.wall + Math.min(data.ttlSeconds * 1000, this.limits.dnsReuseCapMs);
      } else {
        const signing = data.role === 'record_signing_keys';
        const url = signing ? record.signatureVerificationKeyURI() : record.runtimeKeyURI();
        const certificate = signing ? verified.recordSigningTlsCert : verified.tlsCert;
        // The SDK's JWKS keeps the fetched `keys` array as is, so the verified key set serializes to the same text.
        const keys = signing ? verified.recordSigningJwks.keys : verified.jwks.keys;
        if (data.url !== url || data.notAfterMs !== certificate.notAfter.getTime() || data.keys !== JSON.stringify(keys)) continue;
        expiresWall = Math.min(fill.fetched.wall + this.limits.keyReuseCapMs, data.notAfterMs, evidenceExpiry);
      }
      const life: Lifetime = {
        acquiredWall: fill.fetched.wall,
        expiresWall,
        expiresMono: fill.fetched.mono + (expiresWall - fill.fetched.wall),
      };
      if (!Number.isFinite(life.expiresWall) || remainingMs(life, at) <= (data.kind === 'dns' ? 1000 : 0)) continue;
      const existing = this.#entries.get(fill.key);
      if (fill.seq <= this.#newestSeen(fill.key, existing)) {
        this.#stats.supersededFills++;
        continue;
      }
      const bytes = byteLength(fill.key, data.kind === 'dns' ? data.strings : data.document + data.san);
      if (bytes > this.limits.maxBytes) continue;
      if (existing !== undefined) this.#remove(fill.key, existing);
      this.#guards.delete(digest(fill.key));
      this.#entries.set(fill.key, { domain: fill.domain, data, life, seq: fill.seq, bytes });
      this.#bytes += bytes;
      this.#stats.admitted++;
    }
    this.#bound(at);
  }

  /** Drops expired entries, then the least recently used, until within the limits. No timers. */
  #bound(at: Instant): void {
    for (const [key, entry] of this.#entries) {
      if (remainingMs(entry.life, at) <= 0) {
        this.#leave(key, entry);
        this.#stats.expired++;
      }
    }
    for (const [key, entry] of this.#entries) {
      if (this.#entries.size <= this.limits.maxEntries && this.#bytes <= this.limits.maxBytes) break;
      this.#leave(key, entry);
      this.#stats.evicted++;
    }
  }
}

export interface RequestTransport {
  readonly dnsResolver: DNSResolver;
  readonly fetchJson: JsonFetcher;
}

interface ObservedRecord {
  readonly ekUrl: string;
  readonly ekHost: string;
  readonly kuUrl: string;
  readonly kuHost: string;
  readonly statusUrl: string;
}

const DNSID_OWNER = '_dnsid.';
const VALID_DNSSEC_STATES: ReadonlySet<unknown> = new Set(Object.values(DNSSECState));

/**
 * One request's access to the shared cache: wraps that request's DNS resolver and JSON fetcher, serves hits as fresh
 * copies, and holds what the request itself fetched until `admit` (after its verification passed) or `discard`.
 * Holds no reference to the request's verifier, registry or results.
 */
export class RequestMaterialView {
  readonly #cache: SharedMaterialCache;
  readonly #context: string;
  readonly #signal: AbortSignal;
  readonly #revalidate: boolean;
  readonly #observed = new Map<string, ObservedRecord>();
  #fills: Map<string, Fill> | undefined = new Map();
  #reused = 0;
  #fetched = 0;

  constructor(cache: SharedMaterialCache, context: string, signal: AbortSignal, revalidate: boolean) {
    this.#cache = cache;
    this.#context = context;
    this.#signal = signal;
    this.#revalidate = revalidate;
  }

  /** How many of this request's TXT answers and key documents came from the cache, and how many were fetched. */
  get use(): { readonly reused: number; readonly fetched: number } {
    return { reused: this.#reused, fetched: this.#fetched };
  }

  wrap(base: RequestTransport): RequestTransport {
    const inner = base.dnsResolver;
    const fetchJson = base.fetchJson;
    return {
      dnsResolver: { fetchTXT: (name, options) => this.#fetchTXT(inner, name, options) },
      fetchJson: (url, options) => this.#fetchJson(fetchJson, url, options),
    };
  }

  #observe(name: string, strings: readonly string[]): { canonical: string; sg: string } | undefined {
    if (!name.startsWith(DNSID_OWNER)) return undefined;
    const domain = name.slice(DNSID_OWNER.length);
    try {
      const record = DnsIdTxtRecord.parse(strings.join(''));
      record.agentFQDN = domain;
      this.#observed.set(domain, {
        ekUrl: record.signatureVerificationKeyURI(),
        ekHost: record.signatureVerificationKeyAllowedHost(),
        kuUrl: record.runtimeKeyURI(),
        kuHost: record.runtimeKeyAllowedHost(),
        statusUrl: record.su,
      });
      return { canonical: record.canonical(), sg: record.sg };
    } catch {
      this.#observed.delete(domain);
      return undefined;
    }
  }

  async #fetchTXT(
    inner: DNSResolver,
    name: string,
    options: { signal?: AbortSignal } | undefined,
  ): Promise<[TXTRecord[], DNSSECState]> {
    if (!this.#revalidate) {
      const hit = this.#cache.lookupDns(this.#context, name);
      if (hit !== undefined) {
        const only = hit.records[0];
        if (only !== undefined) this.#observe(name, only.strings);
        this.#reused += 1;
        return [hit.records, hit.state];
      }
    }
    this.#fetched += 1;
    const fetched = instant();
    const seq = this.#cache.nextSeq();
    const answer = await inner.fetchTXT(name, options);
    // Snapshot now, before the SDK sees the answer. Only one well-formed record with a positive TTL is cacheable.
    const [records, state] = Array.isArray(answer) ? answer : [undefined, undefined];
    const only = Array.isArray(records) && records.length === 1 ? records[0] : undefined;
    const strings = only?.strings;
    if (Array.isArray(strings) && strings.every((part) => typeof part === 'string')) {
      const record = this.#observe(name, strings);
      const ttl = only?.ttl;
      if (
        record !== undefined &&
        typeof ttl === 'number' &&
        Number.isFinite(ttl) &&
        ttl > 0 &&
        VALID_DNSSEC_STATES.has(state) &&
        state !== DNSSECState.FAILED
      ) {
        const data: DnsData = { kind: 'dns', name, strings: JSON.stringify(strings), dnssecState: state as DNSSECState, ttlSeconds: ttl };
        this.#hold({ key: dnsKey(this.#context, name), domain: name.slice(DNSID_OWNER.length), data, record, fetched, seq });
      }
    }
    return answer;
  }

  /** The key role of a fetch, only when its URL and its exact options are the SDK's for that role of a resolved record. */
  #identify(url: string, options: JsonFetchOptions | undefined): { role: KeyRole; domain: string } | undefined {
    if (options === undefined || options.maxResponseBytes !== JWKS_MAX_RESPONSE_BYTES) return undefined;
    const matches: { role: KeyRole; domain: string }[] = [];
    for (const [domain, record] of this.#observed) {
      if (url === record.statusUrl) return undefined;
      if (url === record.ekUrl && options.allowedHost === record.ekHost && options.domainBoundary === true) {
        matches.push({ role: 'record_signing_keys', domain });
      } else if (
        url === record.kuUrl &&
        url !== record.ekUrl &&
        options.allowedHost === record.kuHost &&
        options.domainBoundary !== true
      ) {
        matches.push({ role: 'operational_keys', domain });
      }
    }
    return matches.length === 1 ? matches[0] : undefined;
  }

  async #fetchJson(inner: JsonFetcher, url: string, options: JsonFetchOptions | undefined): Promise<FetchResult> {
    const identified = this.#identify(url, options);
    if (identified === undefined || options === undefined) return inner(url, options);
    const revalidate = this.#revalidate || options.revalidate === true;
    const key = keyKey(this.#context, identified.domain, identified.role, url, options);
    if (!revalidate) {
      const hit = this.#cache.lookupKey(this.#context, identified.domain, identified.role, url, options);
      if (hit !== undefined) {
        this.#reused += 1;
        return hit;
      }
    }
    this.#fetched += 1;
    const fetched = instant();
    const seq = this.#cache.nextSeq();
    const result = await inner(url, options);
    const notAfter = result?.tlsCert?.notAfter;
    const san = result?.tlsCert?.san;
    const notAfterMs = notAfter instanceof Date ? notAfter.getTime() : Number.NaN;
    let document: string | undefined;
    let keys: string | undefined;
    try {
      document = JSON.stringify(result.data);
      keys = JSON.stringify((result.data as { keys?: unknown }).keys);
    } catch {
      document = undefined;
    }
    if (
      document !== undefined &&
      keys !== undefined &&
      Buffer.byteLength(document) <= (options.maxResponseBytes ?? 0) &&
      Number.isFinite(notAfterMs) &&
      Array.isArray(san) &&
      san.every((name) => typeof name === 'string')
    ) {
      const data: KeyData = { kind: 'key', role: identified.role, url, document, keys, notAfterMs, san: JSON.stringify(san) };
      this.#hold({ key, domain: identified.domain, data, fetched, seq });
    }
    return result;
  }

  /**
   * Holds a fill, unless the request already ended: a late fetch is never offered to the cache. `fetched` and `seq` are
   * both taken when the fetch started, so lifetimes count from no later than the SDK's own and a fetch that started
   * earlier stays older however late it completes.
   */
  #hold(fill: Fill): void {
    if (this.#fills === undefined || this.#signal.aborted) return;
    this.#fills.set(fill.key, fill);
  }

  /** Offers this request's fills for the identity it verified; once only. The caller has checked the request is live. */
  admit(verified: VerifiedDomain): void {
    const fills = this.#fills;
    this.#fills = undefined;
    if (fills === undefined || this.#signal.aborted) return;
    this.#cache.admit(fills.values(), verified);
  }

  /** Drops this request's fills unadmitted. */
  discard(): void {
    this.#fills = undefined;
  }
}
