import { domainToUnicode } from 'node:url';
import { constructIdentityManager, loadEnvironment } from '@dnsid-ai/sdk/node';
import { createSsrfSafeFetch } from '@dnsid-ai/transport';
import type { ClassifierContext, ClassifierResult } from '@earendil-works/pi-ai';
import { policy, questions } from './policy.ts';

export type Classify = (context: ClassifierContext) => Promise<ClassifierResult>;
export type Confirmation = (summary: string) => Promise<boolean>;

export function validateDomain(domain: string): string {
  const name = domain.toLowerCase();
  if (name.length > 253 || name.split('.').length < 2 ||
      !name.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error('Supply a DNS hostname only (use punycode for international names), not a URL, port or path');
  }
  return name;
}

export async function createGuard() {
  const policyUrl = process.env.DNSID_LOG_POLICY_URL?.trim();
  if (!policyUrl) throw new Error('DNSID_LOG_POLICY_URL must be independently configured');
  const loaded = await loadEnvironment();
  // Verification only: do not load the personal agent's private keys or registry credential.
  const manager = await constructIdentityManager({
    dnsid: { verification: loaded.dnsid?.verification, transport: loaded.dnsid?.transport },
    logTrust: { policyUrl },
  }, { cache: { get: () => null, put: () => {}, evict: () => {} } });
  const transport = loaded.dnsid?.transport ?? {};
  const request = createSsrfSafeFetch(transport, { privateAddressHosts: transport.privateAddressHosts });

  async function inspect(domain: string, classify: Classify, signal?: AbortSignal) {
    signal?.throwIfAborted();
    const verified = await manager.verifyDomain(validateDomain(domain), undefined, { signal });
    const evidence = await verified.verifyNonRevocation(); // Required even without fl=logchk.
    signal?.throwIfAborted();
    const naming = await classify({
      state: {
        agent_name: verified.domain,
        agent_name_unicode: domainToUnicode(verified.domain),
        accountable_entity: verified.record.gi,
      },
      questions,
    });
    if (naming.stopReason !== 'stop') throw new Error('Naming classifier unavailable');
    const probabilities = Object.keys(questions).map(name => {
      const answer = naming.answers[name];
      if (answer?.type !== 'bool' || !Number.isFinite(answer.probability) ||
          answer.probability < 0 || answer.probability > 1) {
        throw new Error(`Malformed naming answer: ${name}`);
      }
      return answer.probability;
    });
    const [namesOrg, sameOrg, actsFor] = probabilities;
    // Thresholded AND, not a calibrated probability that this domain is unsafe.
    const impersonation = Math.min(namesOrg, 1 - sameOrg, actsFor);
    return {
      domain: verified.domain,
      accountableEntity: verified.record.gi,
      dnssec: verified.dnssecState,
      freshnessTime: evidence.freshnessTime.toISOString(),
      policy: policy.version,
      namingRestricted: impersonation >= policy.impersonationThreshold,
      impersonation,
      usage: naming.usage,
    };
  }

  async function catalog(domain: string, classify: Classify, signal?: AbortSignal) {
    const checked = await inspect(domain, classify, signal);
    if (checked.namingRestricted) throw new Error('Refused: possible organization impersonation');
    const response = await request(`https://${checked.domain}/catalog`, {
      signal: AbortSignal.any([AbortSignal.timeout(15_000), ...(signal ? [signal] : [])]),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Catalog refused: HTTP ${response.status}; redirects are not followed`);
    }
    // Bound untrusted response bytes; do not buffer an unlimited merchant response.
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 64 * 1024) throw new Error('Catalog exceeds 64 KiB');
        chunks.push(value);
      }
    } finally {
      await reader?.cancel();
    }
    const data: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return { checked, catalog: data }; // Merchant content remains untrusted, not instructions.
  }

  async function pay(domain: string, amountCents: number, classify: Classify,
                     confirm: Confirmation, signal?: AbortSignal) {
    const name = validateDomain(domain);
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0 || amountCents > policy.maxPaymentCents) {
      throw new Error(`Payment must be 1–${policy.maxPaymentCents} integer USD cents`);
    }
    const check = async () => {
      const checked = await inspect(name, classify, signal);
      if (checked.namingRestricted) throw new Error('Refused: possible organization impersonation');
      if (!(policy.paymentEntities as readonly string[]).includes(checked.accountableEntity)) {
        throw new Error('Refused: accountable entity is not approved for payments');
      }
      return checked;
    };
    const before = await check();
    const summary = `SIMULATION ONLY\nMerchant: ${name}\nAccountable entity: ${before.accountableEntity}\nAmount: USD ${(amountCents / 100).toFixed(2)}\nPolicy: ${policy.version}`;
    if (!(await confirm(summary))) throw new Error('Payment not approved (interactive confirmation required)');
    const checked = await check(); // Re-check after the human pause; no reusable approval token.
    if (checked.accountableEntity !== before.accountableEntity) throw new Error('Counterparty changed during approval');
    signal?.throwIfAborted();
    return { checked, payment: { merchant: name, amountCents, currency: 'USD', simulated: true } };
    // No money, credentials or payment request is sent anywhere.
  }

  return { inspect, catalog, pay };
}
