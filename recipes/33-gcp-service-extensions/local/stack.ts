// LOCAL MODE ONLY. The local request path, in one supervised process on 127.0.0.1:
//
//   client --HTTPS--> local edge (local/edge.ts, a forwarding harness, NOT Google's load balancer)
//                       --ext_proc over gRPC--> verifier (src/service.ts, the production service and pipeline,
//                                                with the DNSid Local backend, local/backend.ts)
//                       --HTTP, only on a continuation--> Demo Bank (origin/server.ts, unchanged)
//
// Two edges run, each with its own verifier: `trusted`, whose verifier trusts DNSid Local's governance, and
// `untrusted`, whose verifier trusts only UNTRUSTED_GOVERNANCE (no identity's), so a valid DNSid Local identity can be
// seen refused for its governance. Both share the same Demo Bank.
//
// `node local/stack.ts <run directory>` runs it with DNSid Local's settings from the environment (local/settings.ts;
// local/recipe.ts starts it so). Once every listener is up it writes `ready.json` in the run directory: the process id,
// the ports and the edges' certificates (no private key). Every component's records go to `stack.jsonl` there, one
// JSON object per line: the verifier's terminal records, Demo Bank's request records and the edges' records, none with
// a header value, a signature or key material. SIGTERM or SIGINT stops everything within the components' grace periods
// and removes `ready.json`. Configuration that DNSid Local didn't supply, or a listener that can't start, ends the
// process with a fixed diagnostic and exit 1 before `ready.json` exists.

import { randomBytes } from 'node:crypto';
import { appendFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { listen as listenOrigin, type Origin } from '../origin/server.ts';
import { createVerificationRuntime, governancePolicy, type GovernancePolicy, type VerificationBackend } from '../src/identity.ts';
import { createCalloutService, type CalloutService } from '../src/service.ts';
import { dnsidLocalBackend } from './backend.ts';
import { startLocalEdge, type LocalEdge } from './edge.ts';
import { LocalConfigError, localSettingsFromEnvironment } from './settings.ts';

/** The only governance the `untrusted` edge's verifier trusts: a name in the local zone that no identity uses. */
export const UNTRUSTED_GOVERNANCE = 'no-identity-uses-this.test';
export const READY_FILE = 'ready.json';
export const LOG_FILE = 'stack.jsonl';

export type Component = 'verifier' | 'origin' | 'edge';
export type StackLog = (component: Component, record: object) => void;

export interface Ready {
  readonly pid: number;
  readonly host: string;
  readonly originPort: number;
  readonly edges: {
    readonly trusted: { readonly port: number; readonly certificatePem: string; readonly verifierPort: number };
    readonly untrusted: { readonly port: number; readonly certificatePem: string; readonly verifierPort: number };
  };
  readonly governanceId: string;
  readonly startedAt: string;
}

export interface LocalStack {
  readonly ready: Omit<Ready, 'pid' | 'startedAt'>;
  stop(): Promise<void>;
}

export interface StackOptions {
  readonly backend: VerificationBackend;
  readonly governance: GovernancePolicy;
  readonly log?: StackLog;
  readonly shutdownGraceMs?: number;
}

/** Starts Demo Bank, both verifiers and both edges; on a failure, stops whatever had started and rethrows. */
export async function startLocalStack(options: StackOptions): Promise<LocalStack> {
  const host = '127.0.0.1';
  const log: StackLog = options.log ?? (() => {});
  const grace = options.shutdownGraceMs ?? 3_000;
  const stops: (() => Promise<void>)[] = [];
  const stopAll = async () => {
    // Edges first (no new requests), then the verifiers, then Demo Bank.
    for (const stop of stops.reverse().splice(0)) await stop().catch(() => {});
  };
  try {
    // This stack's own attestation key, shared by its verifiers and Demo Bank only, as Terraform's is in a deployment.
    const attestationKey = randomBytes(32);
    const origin: Origin = await listenOrigin(host, 0, { attestationKey, log: (record) => log('origin', record), shutdownGraceMs: grace });
    stops.push(() => origin.stop());
    const verifier = async (governance: GovernancePolicy, name: string) => {
      const runtime = createVerificationRuntime({ governance, backend: options.backend });
      const service: CalloutService = createCalloutService({
        runtime,
        attestationKey,
        log: (record) => log('verifier', { ...record, verifier: name }),
        shutdownGraceMs: grace,
      });
      stops.push(() => service.shutdown());
      return service.listen(host, 0);
    };
    const trustedPort = await verifier(options.governance, 'trusted');
    const untrustedPort = await verifier(governancePolicy([{ governanceId: UNTRUSTED_GOVERNANCE }]), 'untrusted');
    const edge = async (name: string, verifierPort: number): Promise<LocalEdge> => {
      const started = await startLocalEdge({ name, verifierPort, originPort: origin.port, host, log: (record) => log('edge', record) });
      stops.push(() => started.stop());
      return started;
    };
    const trusted = await edge('trusted', trustedPort);
    const untrusted = await edge('untrusted', untrustedPort);
    return {
      ready: {
        host,
        originPort: origin.port,
        edges: {
          trusted: { port: trusted.port, certificatePem: trusted.certificatePem, verifierPort: trustedPort },
          untrusted: { port: untrusted.port, certificatePem: untrusted.certificatePem, verifierPort: untrustedPort },
        },
        governanceId: options.governance.entries[0]?.governanceId ?? '',
      },
      stop: stopAll,
    };
  } catch (error) {
    await stopAll();
    throw error;
  }
}

function fail(reason: string): never {
  process.stderr.write(`${JSON.stringify({ severity: 'ERROR', event: 'local_stack_startup_failed', reason })}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  const runDir = process.argv[2];
  if (runDir === undefined) fail('usage: node local/stack.ts <run directory>');
  try {
    if (!statSync(runDir).isDirectory()) fail('the run directory is not a directory');
  } catch {
    fail('the run directory does not exist');
  }
  let settings;
  try {
    settings = localSettingsFromEnvironment(process.env);
  } catch (error) {
    fail(error instanceof LocalConfigError ? error.message : 'invalid DNSid Local settings');
  }
  const logFile = join(runDir, LOG_FILE);
  const log: StackLog = (component, record) => appendFileSync(logFile, `${JSON.stringify({ component, at: new Date().toISOString(), ...record })}\n`);
  let stack: LocalStack;
  try {
    stack = await startLocalStack({ backend: dnsidLocalBackend(settings), governance: settings.governance, log });
  } catch {
    fail('a local listener could not start');
  }
  const ready: Ready = { pid: process.pid, ...stack.ready, startedAt: new Date().toISOString() };
  const readyFile = join(runDir, READY_FILE);
  writeFileSync(`${readyFile}.tmp`, `${JSON.stringify(ready, null, 2)}\n`, { mode: 0o600 });
  renameSync(`${readyFile}.tmp`, readyFile);
  process.stdout.write(`${JSON.stringify({ severity: 'INFO', event: 'local_stack_ready', trustedEdge: ready.edges.trusted.port, untrustedEdge: ready.edges.untrusted.port })}\n`);
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    rmSync(readyFile, { force: true });
    stack.stop().then(
      () => {
        process.stdout.write(`${JSON.stringify({ severity: 'INFO', event: 'local_stack_stopped' })}\n`);
        process.exit(0);
      },
      () => process.exit(1),
    );
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (import.meta.main) await main();
