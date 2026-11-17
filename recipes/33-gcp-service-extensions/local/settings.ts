// LOCAL MODE ONLY. The DNSid Local settings the local verifier runs with, read from the `DNSID_*` variables that
// `dnsid local env` prints for the recipe's own DNSid Local state (local/recipe.ts passes exactly these five through).
// Nothing under src/ reads them: the production verifier (src/main.ts) builds PRODUCTION_BACKEND, with the managed
// log catalog, system trust roots and no private-address exceptions, whatever its environment holds.
//
// What each is, and how far it is trusted:
// - DNSID_LOG_POLICY_URL: the independently trusted C2SP tlog-policy for DNSid Local's log. It comes only from this
//   variable, never from a `_dnsid` record, its `lr=` or a log prefix (a log that could name its own policy could vouch
//   for itself). HTTPS only.
// - DNSID_DNS_SERVER: DNSid Local's DNS server. Loopback only (`127.0.0.1:<port>` or `localhost:<port>`).
// - DNSID_CA_BUNDLE: DNSid Local's CA certificate, added to the trust roots of the local verifier's HTTPS fetches. An
//   existing regular file.
// - DNSID_PRIVATE_HOSTS: the names whose loopback or private addresses the SDK may connect to. Only the local zone:
//   `.test`, or names under it. Anything else is refused, so no private-address exception can reach a public name.
// - DNSID_GOVERNANCE_ID: the governance DNSid Local signs its identities under, which the local verifier trusts.
//
// Errors name the variable and the problem, never its value.

import { statSync } from 'node:fs';

import { GovernanceConfigError, governancePolicy, type GovernancePolicy } from '../src/identity.ts';

export const LOCAL_ZONE = 'test';

/** The variables the local verifier reads, and the only ones local/recipe.ts passes to it from `dnsid local env`. */
export const LOCAL_VARIABLES = Object.freeze([
  'DNSID_LOG_POLICY_URL',
  'DNSID_DNS_SERVER',
  'DNSID_CA_BUNDLE',
  'DNSID_PRIVATE_HOSTS',
  'DNSID_GOVERNANCE_ID',
] as const);

export interface LocalSettings {
  readonly policyUrl: string;
  readonly dnsServer: string;
  readonly caBundlePath: string;
  readonly privateAddressHosts: readonly string[];
  readonly governance: GovernancePolicy;
}

export class LocalConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalConfigError';
  }
}

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
// `.test` itself, or a name or `.suffix` under it: label-bounded, so `attest` or `test.example` never match.
const LOCAL_HOST = new RegExp(`^(?:\\.${LOCAL_ZONE}|\\.?(?:${LABEL}\\.)+${LOCAL_ZONE})$`);
const LOOPBACK_DNS = /^(?:127\.0\.0\.1|localhost):([0-9]{1,5})$/;

function required(env: Readonly<Record<string, string | undefined>>, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value === '') throw new LocalConfigError(`${name} is not set: run the local mode through local/recipe.ts`);
  return value;
}

function policyUrlFrom(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new LocalConfigError('DNSID_LOG_POLICY_URL is not a URL');
  }
  if (url.protocol !== 'https:') throw new LocalConfigError('DNSID_LOG_POLICY_URL is not an https URL');
  if (url.username !== '' || url.password !== '') throw new LocalConfigError('DNSID_LOG_POLICY_URL carries credentials');
  return url.href;
}

function dnsServerFrom(value: string): string {
  const match = LOOPBACK_DNS.exec(value);
  const port = Number(match?.[1]);
  if (match === null || port < 1 || port > 65_535) throw new LocalConfigError('DNSID_DNS_SERVER is not a loopback host:port');
  return value;
}

function caBundleFrom(value: string): string {
  let file: ReturnType<typeof statSync>;
  try {
    file = statSync(value);
  } catch {
    throw new LocalConfigError('DNSID_CA_BUNDLE is not a readable file');
  }
  if (!file.isFile()) throw new LocalConfigError('DNSID_CA_BUNDLE is not a regular file');
  return value;
}

function privateHostsFrom(value: string): string[] {
  const hosts = value.split(',').map((host) => host.trim().toLowerCase());
  if (hosts.some((host) => host === '' || !LOCAL_HOST.test(host))) {
    throw new LocalConfigError(`DNSID_PRIVATE_HOSTS may name only the .${LOCAL_ZONE} zone`);
  }
  return hosts;
}

function governanceFrom(value: string): GovernancePolicy {
  try {
    return governancePolicy([{ governanceId: value }]);
  } catch (error) {
    throw new LocalConfigError(error instanceof GovernanceConfigError ? `DNSID_GOVERNANCE_ID: ${error.message}` : 'DNSID_GOVERNANCE_ID is invalid');
  }
}

export function localSettingsFromEnvironment(env: Readonly<Record<string, string | undefined>>): LocalSettings {
  return Object.freeze({
    policyUrl: policyUrlFrom(required(env, 'DNSID_LOG_POLICY_URL')),
    dnsServer: dnsServerFrom(required(env, 'DNSID_DNS_SERVER')),
    caBundlePath: caBundleFrom(required(env, 'DNSID_CA_BUNDLE')),
    privateAddressHosts: Object.freeze(privateHostsFrom(required(env, 'DNSID_PRIVATE_HOSTS'))),
    governance: governanceFrom(required(env, 'DNSID_GOVERNANCE_ID')),
  });
}
