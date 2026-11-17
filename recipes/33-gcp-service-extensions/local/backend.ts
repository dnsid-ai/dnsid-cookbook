// LOCAL MODE ONLY. The verification backend for DNSid Local: the same per-request construction as PRODUCTION_BACKEND
// (src/identity.ts), with DNSid Local's trust in place of the managed one. Everything else, the signature, identity,
// governance, lifecycle (non-revocation) and evidence-freshness stages, the shared records-and-keys cache, the ext_proc
// responses and the gRPC service, is the production code, unchanged.
//
// What differs from production, and only here:
// - the log registry is the SDK's generic C2SP registry (`createC2spTlogVerificationRegistry`, @dnsid-ai/log-c2sp-tlog
//   0.37.0) with the independently trusted DNSid Local policy URL, fetched through DNSid Local's DNS, CA and `.test`
//   private-address exception, with the managed registry's time policy (checkpoints at most ten minutes old for
//   non-revocation, no clock skew). This is what the SDK's own environment constructor builds for `DNSID_LOG_POLICY_URL`
//   (`logRegistryFromTrust` in @dnsid-ai/sdk 0.37.0 dist/node.js);
// - the identity verifier's DNS resolver and HTTPS fetcher get DNSid Local's DNS server, CA bundle and `.test`
//   private-address exception: what `createNodeIdentityVerifier` builds itself for a `transport` section (dist/node.js,
//   `createNodeIdentityManager`), made explicit so the shared material cache can wrap it, as production does.
// Its transport context is its own, so cached material is never shared with production's.
//
// APIs: https://github.com/dnsid-ai/dnsid-ts/blob/v0.37.0/packages/log-c2sp-tlog/src/verification-registry.ts and
// https://docs.dnsid.ai/sdk-transparency-log ("DNSid Local and configured policy trust").

import { createNodeIdentityVerifier } from '@dnsid-ai/sdk/node';
import type { DnsidConfig } from '@dnsid-ai/sdk';
import { createC2spTlogVerificationRegistry } from '@dnsid-ai/log-c2sp-tlog';
import { createDefaultDnsResolver, fetchJson as transportFetchJson } from '@dnsid-ai/transport';

import type { IdentityVerifierDependencies, RegistryRequest, VerificationBackend } from '../src/identity.ts';
import type { LocalSettings } from './settings.ts';

/** The managed registry's `checkpointMaxAge` in @dnsid-ai/log-c2sp-tlog 0.37.0 (and the SDK's environment constructor's). */
export const LOCAL_CHECKPOINT_MAX_AGE_MS = 600_000;

/** The SDK functions the backend calls; tests substitute recording ones. */
export interface LocalTransportFunctions {
  readonly createC2spTlogVerificationRegistry: typeof createC2spTlogVerificationRegistry;
  readonly createDefaultDnsResolver: typeof createDefaultDnsResolver;
  readonly fetchJson: typeof transportFetchJson;
  readonly createNodeIdentityVerifier: typeof createNodeIdentityVerifier;
}

const SDK: LocalTransportFunctions = Object.freeze({
  createC2spTlogVerificationRegistry,
  createDefaultDnsResolver,
  fetchJson: transportFetchJson,
  createNodeIdentityVerifier,
});

export function dnsidLocalBackend(settings: LocalSettings, sdk: LocalTransportFunctions = SDK): VerificationBackend {
  const transport = {
    dnsServer: settings.dnsServer,
    caBundlePath: settings.caBundlePath,
    privateAddressHosts: [...settings.privateAddressHosts],
  };
  return Object.freeze({
    name: 'dnsid-local',
    transportContext:
      `dnsid-local: DNS ${settings.dnsServer}, CA bundle ${settings.caBundlePath}, private-address hosts ` +
      `${settings.privateAddressHosts.join(',')}, log policy ${settings.policyUrl}`,
    createLogRegistry: (request: RegistryRequest) =>
      sdk.createC2spTlogVerificationRegistry({
        policyUrl: settings.policyUrl,
        transport: { ...transport, privateAddressHosts: [...transport.privateAddressHosts] },
        signal: request.signal,
        trustedCheckpointStore: request.trustedCheckpointStore,
        checkpointMaxAge: LOCAL_CHECKPOINT_MAX_AGE_MS,
        allowedClockSkew: 0,
      }),
    createIdentityVerifier: (config: DnsidConfig, dependencies: IdentityVerifierDependencies) => {
      const { dnsResolver, fetchJson } = dependencies.transport({
        dnsResolver: sdk.createDefaultDnsResolver({ dnsServer: transport.dnsServer }),
        fetchJson: (url, options) => sdk.fetchJson(url, { ...options, ...transport, privateAddressHosts: [...transport.privateAddressHosts] }),
      });
      return sdk.createNodeIdentityVerifier(config, {
        logRegistry: dependencies.logRegistry,
        cache: dependencies.cache,
        dnsResolver,
        fetchJson,
      });
    },
  });
}
