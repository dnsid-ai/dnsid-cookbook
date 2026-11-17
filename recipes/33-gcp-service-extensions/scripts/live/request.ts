// One request against a deployment, shown and checked: for trying the edge by hand and for a presenter's demo. It reads
// DEPLOY_OUT, signs (when the step signs) as DNSID_AGENT_ID with the key in DNSID_AGENT_KEY_FILE, sends over TLS pinned
// to the deployment's certificate, prints what it sent and what came back, and says whether that is what the step
// expects. The key and the signature values are never printed.
//
//   node scripts/live/request.ts unsigned            GET /accounts with no signature: the verifier's 403 signature_missing
//   node scripts/live/request.ts signed              a signed GET: Demo Bank's data, for this agent
//   node scripts/live/request.ts tampered            signed for ?view=summary, sent with ?view=everything: 403 signature_invalid
//   node scripts/live/request.ts forged              a signed GET carrying forged x-dnsid-* headers: Demo Bank sees only the
//                                                    verified identity
//   node scripts/live/request.ts claim <agent>       signed with this agent's key while claiming <agent>'s identity: a 403
//                                                    from the verifier
//   node scripts/live/request.ts revoked             a freshly signed GET as DNSID_REVOKED_AGENT_ID, with the key in
//                                                    DNSID_REVOKED_AGENT_KEY_FILE: refused by the verifier with a
//                                                    revocation reason, and that agent's lifecycle evidence (its status
//                                                    document, its authenticated log history), read independently,
//                                                    identifies the revocation (the live tests' deny-revoked judgment)
//   node scripts/live/request.ts status <agent>      <agent>'s lifecycle state from its own DNSid status document (no request
//                                                    to the edge): expected REVOKED
//
// Exit codes: 0 the step saw what it expects; 1 it saw something else (printed); 2 an input is missing or invalid.

import { readDeployOut, pinOf, DeployOutError, type DeployOut } from '../lib/deploy-out.ts';
import { describe as describeExchange, isBankData, isVerifierDenial, judgeRevoked } from './cases.ts';
import { h1, type Exchange, type RequestSpec, type Target } from './http.ts';
import { checkAgentId, createSigner, loadKeyProvider, SignerError, type Signer } from './signer.ts';
import { readAgentStatus, readLifecycleEvidence, type AgentStatus, type LifecycleEvidence } from './status.ts';

export const STEPS = ['unsigned', 'signed', 'tampered', 'forged', 'claim', 'revoked', 'status'] as const;
export type Step = (typeof STEPS)[number];

/** The forged identity a `forged` request carries; Demo Bank must never see it. */
export const FORGED_IDENTITY = 'forged-identity.invalid';

export interface StepOptions {
  readonly out: DeployOut;
  /** For the signing steps: this agent and its key file. */
  readonly agent?: string;
  readonly keyFile?: string;
  /** For `claim` and `status`: the other agent. */
  readonly other?: string;
  /** For `revoked`: the revoked agent and its key file. */
  readonly revokedAgent?: string;
  readonly revokedKeyFile?: string;
  readonly send?: (target: Target, spec: RequestSpec) => Promise<Exchange>;
  readonly agentStatus?: (domain: string) => Promise<AgentStatus>;
  readonly lifecycle?: (domain: string) => Promise<LifecycleEvidence>;
}

export interface Shown {
  readonly lines: string[];
  readonly ok: boolean;
}

export class RequestInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RequestInputError';
  }
}

function targetOf(out: DeployOut): Target {
  const url = new URL(out.endpoint);
  return { host: url.hostname, port: url.port === '' ? 443 : Number(url.port), pin: pinOf(out) };
}

function bankCaller(e: Exchange): { verifiedDomain?: unknown; governanceId?: unknown } | undefined {
  try {
    return (JSON.parse(e.body) as { caller?: { verifiedDomain?: unknown; governanceId?: unknown } }).caller;
  } catch {
    return undefined;
  }
}

/** The account IDs Demo Bank listed: its own account policy's answer for this caller. */
function bankAccounts(e: Exchange): string[] {
  try {
    const accounts = (JSON.parse(e.body) as { accounts?: unknown }).accounts;
    return Array.isArray(accounts) ? accounts.map((a) => String((a as { id?: unknown })?.id)) : [];
  } catch {
    return [];
  }
}

/** What came back, in a few lines: never a request header. */
function answer(e: Exchange): string[] {
  if (e.error !== undefined) return [`← no HTTP answer (${e.error})`];
  const lines = [`← ${e.status} in ${e.ms} ms${e.headers['cache-control'] === undefined ? '' : `, cache-control: ${e.headers['cache-control']}`}`];
  if (isBankData(e)) {
    const caller = bankCaller(e);
    lines.push(`  Demo Bank (synthetic data) served the request for: ${String(caller?.verifiedDomain)} (governance ${String(caller?.governanceId)})`);
    const accounts = bankAccounts(e);
    if (accounts.length > 0) lines.push(`  Demo Bank's own account policy lists this agent's accounts only: ${accounts.join(', ')}`);
  } else if (isVerifierDenial(e)) {
    lines.push(`  refused by the verifier: ${e.body}`);
  } else {
    lines.push(`  ${describeExchange(e)}`);
  }
  return lines;
}

async function signerFor(options: StepOptions, which: 'agent' | 'revoked' = 'agent'): Promise<Signer> {
  const [idName, keyName, id, keyFile] =
    which === 'agent'
      ? ['DNSID_AGENT_ID', 'DNSID_AGENT_KEY_FILE', options.agent, options.keyFile]
      : ['DNSID_REVOKED_AGENT_ID', 'DNSID_REVOKED_AGENT_KEY_FILE', options.revokedAgent, options.revokedKeyFile];
  const agent = checkAgentId(idName, id);
  if (keyFile === undefined || keyFile.trim() === '') throw new RequestInputError(`${keyName} is not set`);
  try {
    return await createSigner(agent, await loadKeyProvider(keyFile));
  } catch (error) {
    throw new RequestInputError(error instanceof SignerError ? error.message : 'the signing key could not be loaded');
  }
}

function otherAgent(options: StepOptions): string {
  try {
    return checkAgentId('the other agent', options.other);
  } catch (error) {
    throw new RequestInputError(error instanceof SignerError ? error.message : 'the other agent is not a domain name');
  }
}

export async function runStep(step: Step, options: StepOptions): Promise<Shown> {
  const send = options.send ?? h1;
  const target = targetOf(options.out);
  const path = options.out.protected_path;
  const at = (p: string) => `${options.out.endpoint}${p}`;
  const verdict = (ok: boolean, expected: string, lines: string[]): Shown => ({
    ok,
    lines: [...lines, ok ? `✓ as expected: ${expected}` : `✗ UNEXPECTED: expected ${expected}`],
  });

  switch (step) {
    case 'unsigned': {
      const e = await send(target, { method: 'GET', path });
      return verdict(isVerifierDenial(e, ['signature_missing']), "the verifier's 403 signature_missing", [`→ GET ${at(path)}  (no signature)`, ...answer(e)]);
    }
    case 'signed': {
      const signer = await signerFor(options);
      const e = await send(target, { method: 'GET', path, headers: await signer.sign('GET', at(path)) });
      const ok = isBankData(e) && bankCaller(e)?.verifiedDomain === signer.domain;
      return verdict(ok, `200 with Demo Bank's data, served for ${signer.domain}`, [`→ GET ${at(path)}  (signed as ${signer.domain})`, ...answer(e)]);
    }
    case 'tampered': {
      const signer = await signerFor(options);
      const headers = await signer.sign('GET', at(`${path}?view=summary`));
      const e = await send(target, { method: 'GET', path: `${path}?view=everything`, headers });
      return verdict(isVerifierDenial(e, ['signature_invalid']), "the verifier's 403 signature_invalid", [
        `→ GET ${at(`${path}?view=everything`)}  (signed as ${signer.domain} for ?view=summary, changed after signing)`,
        ...answer(e),
      ]);
    }
    case 'forged': {
      const signer = await signerFor(options);
      const headers = [...(await signer.sign('GET', at(path))), ['x-dnsid-verified-domain', FORGED_IDENTITY] as const, ['x-dnsid-governance-id', FORGED_IDENTITY] as const];
      const e = await send(target, { method: 'GET', path, headers });
      const ok = isBankData(e) && bankCaller(e)?.verifiedDomain === signer.domain;
      return verdict(ok, `Demo Bank sees ${signer.domain}, not the forged name ${FORGED_IDENTITY}`, [
        `→ GET ${at(path)}  (signed as ${signer.domain}, carrying x-dnsid-verified-domain: ${FORGED_IDENTITY})`,
        ...answer(e),
      ]);
    }
    case 'claim': {
      const signer = await signerFor(options);
      const other = otherAgent(options);
      const headers = await signer.sign('GET', at(path), { claimedDomain: other });
      const e = await send(target, { method: 'GET', path, headers });
      return verdict(isVerifierDenial(e), "a 403 from the verifier", [`→ GET ${at(path)}  (signed with ${signer.domain}'s key, claiming ${other})`, ...answer(e)]);
    }
    case 'revoked': {
      const signer = await signerFor(options, 'revoked');
      const e = await send(target, { method: 'GET', path, headers: await signer.sign('GET', at(path)) });
      const read = options.lifecycle ?? ((domain: string) => readLifecycleEvidence(domain, options.out.trusted_governance));
      let evidence: LifecycleEvidence | undefined;
      const lines = [`→ GET ${at(path)}  (freshly signed as ${signer.domain}, the revoked agent)`, ...answer(e)];
      if (isVerifierDenial(e)) {
        try {
          evidence = await read(signer.domain);
        } catch (error) {
          const now = new Date().toISOString();
          const reason = `the lifecycle evidence could not be read: ${(error as Error).message}`;
          evidence = { status: { kind: 'unknown', reason, at: now }, log: { kind: 'unknown', reason, at: now } };
        }
        const { status, log } = evidence;
        lines.push(`→ ${signer.domain}'s lifecycle evidence, read here, independently of the edge`);
        lines.push(status.kind === 'state' ? `← its DNSid status document: ${status.state} (read at ${status.at})` : `← its DNSid status document: not read (${status.reason})`);
        lines.push(
          log.kind === 'logged'
            ? `← its authenticated log history: ${log.state}${log.reason ? ` (${log.reason})` : ''}${log.since ? ` since ${log.since}` : ''}, ${log.events} event(s)`
            : `← its authenticated log history: not established (${log.reason})`,
        );
      }
      const judged = judgeRevoked(e, evidence, isBankData(e) && bankCaller(e)?.verifiedDomain === signer.domain);
      if (judged.pass) lines.push(`  ${judged.detail.slice(judged.detail.lastIndexOf(': ') + 2)}`);
      else lines.push(`  ${judged.detail}`);
      return verdict(judged.pass, 'refused by the verifier with a revocation reason, and the lifecycle evidence identifies the revocation', lines);
    }
    case 'status': {
      const other = otherAgent(options);
      const read = options.agentStatus ?? ((domain: string) => readAgentStatus(domain, options.out.trusted_governance));
      const status = await read(other);
      const line = status.kind === 'state' ? `← ${other}: ${status.state} (its DNSid status document, read at ${status.at})` : `← ${other}: unknown (${status.reason})`;
      return verdict(status.kind === 'state' && status.state === 'REVOKED', `${other} is REVOKED`, [`→ the status document of ${other}`, line]);
    }
  }
}

export async function main(argv: readonly string[], env: Readonly<Record<string, string | undefined>>, print: (line: string) => void): Promise<number> {
  try {
    const step = argv[0];
    if (step === undefined || !(STEPS as readonly string[]).includes(step)) {
      throw new RequestInputError(`usage: node scripts/live/request.ts ${STEPS.filter((s) => s !== 'claim' && s !== 'status').join('|')} | claim <agent> | status <agent>`);
    }
    if ((step === 'claim' || step === 'status') && argv[1] === undefined) throw new RequestInputError(`${step} needs the other agent's domain`);
    const deployOut = env['DEPLOY_OUT']?.trim();
    if (deployOut === undefined || deployOut === '') throw new RequestInputError('DEPLOY_OUT is not set: the deployment record scripts/deploy.sh wrote');
    let out: DeployOut;
    try {
      out = readDeployOut(deployOut);
    } catch (error) {
      throw new RequestInputError(error instanceof DeployOutError ? error.message : 'DEPLOY_OUT cannot be read');
    }
    const shown = await runStep(step as Step, {
      out,
      ...(env['DNSID_AGENT_ID'] === undefined ? {} : { agent: env['DNSID_AGENT_ID'] }),
      ...(env['DNSID_AGENT_KEY_FILE'] === undefined ? {} : { keyFile: env['DNSID_AGENT_KEY_FILE'] }),
      ...(argv[1] === undefined ? {} : { other: argv[1] }),
      ...(env['DNSID_REVOKED_AGENT_ID'] === undefined ? {} : { revokedAgent: env['DNSID_REVOKED_AGENT_ID'] }),
      ...(env['DNSID_REVOKED_AGENT_KEY_FILE'] === undefined ? {} : { revokedKeyFile: env['DNSID_REVOKED_AGENT_KEY_FILE'] }),
    });
    for (const line of shown.lines) print(line);
    return shown.ok ? 0 : 1;
  } catch (error) {
    if (error instanceof RequestInputError || error instanceof SignerError) {
      print(`request: ${error.message}`);
      return 2;
    }
    print('request: failed unexpectedly');
    return 1;
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2), process.env, (line) => void process.stdout.write(`${line}\n`));
