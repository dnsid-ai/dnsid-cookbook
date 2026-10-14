/**
 * The DNSid Local operations the lab needs, mostly through the `dnsid` CLI:
 * provision an identity, read its registry status, revoke it.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRegistryClientFromEnvironment } from '@dnsid-ai/sdk/node';

const run = promisify(execFile);

export type AgentEnv = Record<string, string>;

/**
 * Registers the agent if it is missing and returns its DNSID_* environment.
 * Researchers and the coordinator serve nothing over HTTPS: the proxy routes
 * their JWKS and status paths to the registry, so their upstream is a port
 * nobody listens on.
 */
export async function ensureAgent(fqdn: string, upstream = 'http://127.0.0.1:9'): Promise<AgentEnv> {
  const { stdout } = await run('dnsid', [
    'local', 'agent', 'ensure', fqdn, '--upstream', upstream, '--format', 'json',
  ]);
  return JSON.parse(stdout);
}

/** Registration status as the registry reports it (READY, VERIFIED, REVOKED, ...). */
export async function registrationStatus(fqdn: string, env: AgentEnv): Promise<string | undefined> {
  try {
    const { stdout } = await run('dnsid', ['status', '--domain', fqdn, '--output', 'json'], {
      env: { ...process.env, ...env },
    });
    return JSON.parse(stdout).status;
  } catch {
    return undefined;
  }
}

/**
 * Revokes permanently, with the owner credential from the lab's environment
 * (DNSID_REGISTRY_URL, DNSID_API_KEY). `dnsid revoke` would make the same
 * call, but it first looks the agent up through the registry's agent list,
 * which this DNSid Local build returns empty.
 */
export async function revokeAgent(fqdn: string, labEnv: AgentEnv) {
  const registry = await createRegistryClientFromEnvironment(labEnv);
  const registration = await registry.getRegistration(fqdn);
  if (!registration) throw new Error(`${fqdn} is not registered`);
  return registry.revokeAgent(fqdn, registration.id, 'owner_request');
}

/**
 * Countersigns the agent's ISSUANCE, which publishes its `_dnsid` record.
 * Agents on the Agent SDK plugin do this in their SessionStart hook; the
 * data service is a plain server, so it does it here.
 */
export async function issueAgent(fqdn: string, env: AgentEnv): Promise<void> {
  await run('dnsid', ['log', 'issue', '--domain', fqdn], { env: { ...process.env, ...env } });
}
