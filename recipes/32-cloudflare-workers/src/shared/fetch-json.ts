import { VerificationCode, VerificationError, type JsonFetcher } from '@dnsid-ai/protocol';
import { readBoundedBody } from '@dnsid-ai/http-signatures';

const MAX_REDIRECTS = 5;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/**
 * Creates the SDK's JSON downloader using Workers fetch.
 * Requires HTTPS, checks allowedHost when supplied on every hop, follows at most
 * five redirects, and bounds the response body before parsing JSON.
 * Host checks compare names; they do not validate or pin resolved IP addresses.
 * @param evidenceTtlMs Lifetime in milliseconds for synthetic cache metadata.
 * @param fetcher Fetch implementation; defaults to the Workers global fetch.
 *
 * TODO: Replace synthetic tlsCert metadata with an explicit evidence-cache lifetime
 * when the SDK supports fetchers without certificate access.
 * Workers validates TLS but does not expose the certificate. Until then, notAfter
 * is a cache deadline, not the certificate's actual expiry.
 */
export function workersFetchJson(
  evidenceTtlMs = 60 * 60 * 1000,
  fetcher: typeof fetch = fetch,
): JsonFetcher {
  return async (url, opts = {}) => {
    const signal = opts.signal ?? new AbortController().signal;
    let target = new URL(url);

    for (let hop = 0; ; hop++) {
      if (target.protocol !== 'https:') {
        throw tlsError(`non-HTTPS URL: ${target}`);
      }

      if (opts.allowedHost && !hostAllowed(target.hostname, opts.allowedHost, opts.domainBoundary)) {
        throw tlsError(`URL host not permitted: expected ${opts.allowedHost}, got ${target.hostname}`);
      }

      let res: Response;
      try {
        res = await fetcher(target, {
          redirect: 'manual',
          signal,
          headers: { accept: 'application/json' },
        });
      } catch (e) {
        throw new VerificationError(`fetch failed: ${(e as Error).message}`, {
          code: VerificationCode.TLSError,
          transient: true,
        });
      }

      if (res.status >= 300 && res.status < 400) {
        void res.body?.cancel();
        const location = res.headers.get('location');
        if (!location || hop >= MAX_REDIRECTS) {
          throw tlsError('bad or excessive redirect');
        }

        target = new URL(location, target);
        continue;
      }

      if (res.status !== 200) {
        void res.body?.cancel();
        throw new VerificationError(`HTTP ${res.status} from ${target.host}`, {
          code: VerificationCode.TLSError,
          transient: res.status >= 500,
        });
      }

      const bytes = await readBoundedBody(
        res,
        signal,
        opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      );

      let data: unknown;
      try {
        data = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        throw new VerificationError('response body is not valid JSON', {
          code: VerificationCode.RecordInvalid,
        });
      }

      return {
        data,
        tlsCert: {
          notAfter: new Date(Date.now() + evidenceTtlMs),
          san: [target.hostname],
        },
      };
    }
  };
}

/** Matches the exact host, or its subdomains when domain-boundary matching is enabled. */
function hostAllowed(host: string, allowed: string, boundary = false): boolean {
  return host === allowed || (boundary && host.endsWith(`.${allowed}`));
}

/** Creates a non-transient SDK transport error for a rejected URL or redirect. */
function tlsError(message: string): VerificationError {
  return new VerificationError(message, { code: VerificationCode.TLSError });
}
