// The verifier's executable: `node src/main.ts`. Builds the production verification runtime and its governance policy
// from `DNSID_TRUSTED_GOVERNANCE` (and, for the live tests' timing case only, `DNSID_LOG_EVIDENCE`) and its attestation
// key from `DNSID_ATTESTATION_KEY` (required: src/attestation.ts) first, then serves the callout on 0.0.0.0 at Cloud Run's `PORT` (8080 when unset), in
// plaintext HTTP/2. `PORT` is set by the platform; it is not a quick-start input. Invalid configuration or a port that
// can't be bound ends the process with a fixed diagnostic and a nonzero exit code, before any request is accepted.
// SIGTERM or SIGINT shuts the service down within its grace period (src/service.ts) and the process exits.
//
// Importing this module starts nothing; only running it as the entry point does.

import { logVerbosity, setLogVerbosity, setLogger } from '@grpc/grpc-js';

import { ATTESTATION_KEY_SETTING, AttestationKeyError, attestationKeyFromSetting } from './attestation.ts';
import { GovernanceConfigError, LogEvidenceConfigError, createProductionVerificationRuntime, type VerificationRuntime } from './identity.ts';
import { createCalloutService, type CalloutService, type LogSink } from './service.ts';

export const DEFAULT_PORT = 8080;
export const LISTEN_HOST = '0.0.0.0';

/** Startup refused. The message is fixed or names the problem only, never a configured value or system error text. */
export class StartupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StartupError';
  }
}

/** Cloud Run's `PORT`: absent means 8080; anything but a whole number from 1 to 65535 is refused. */
export function portFromSetting(value: string | undefined): number {
  if (value === undefined) return DEFAULT_PORT;
  if (!/^[0-9]{1,5}$/.test(value)) throw new StartupError('PORT is not a port number');
  const port = Number(value);
  if (port < 1 || port > 65_535) throw new StartupError('PORT is not a port number');
  return port;
}

export interface StartOptions {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly log?: LogSink;
}

/** Configuration first, then the listener. Resolves to the listening service; rejects with a StartupError. */
export async function start(options: StartOptions = {}): Promise<{ service: CalloutService; port: number }> {
  const env = options.env ?? process.env;
  const port = portFromSetting(env['PORT']);
  let runtime: VerificationRuntime;
  try {
    runtime = createProductionVerificationRuntime(env['DNSID_TRUSTED_GOVERNANCE'], env['DNSID_LOG_EVIDENCE']);
  } catch (error) {
    const known = error instanceof GovernanceConfigError || error instanceof LogEvidenceConfigError;
    throw new StartupError(known ? `invalid configuration: ${error.message}` : 'invalid configuration');
  }
  let attestationKey: Buffer;
  try {
    attestationKey = attestationKeyFromSetting(env[ATTESTATION_KEY_SETTING]);
  } catch (error) {
    throw new StartupError(error instanceof AttestationKeyError ? `invalid configuration: ${error.message}` : 'invalid configuration');
  }
  const service = createCalloutService(options.log === undefined ? { runtime, attestationKey } : { runtime, attestationKey, log: options.log });
  try {
    return { service, port: await service.listen(LISTEN_HOST, port) };
  } catch {
    await service.shutdown();
    throw new StartupError(`could not listen on port ${port}`);
  }
}

function line(record: Record<string, unknown>): string {
  return `${JSON.stringify(record)}\n`;
}

/**
 * grpc-js writes its own diagnostics to stderr, with addresses and system error text in them. In the executable they
 * become one fixed record each, errors only, with none of that text.
 */
function quietGrpcLogging(): void {
  const fixed = () => void process.stderr.write(line({ severity: 'ERROR', event: 'grpc_library_error' }));
  setLogger({ error: fixed, info: () => {}, debug: () => {}, log: () => {}, warn: () => {} });
  setLogVerbosity(logVerbosity.ERROR);
}

async function main(): Promise<void> {
  quietGrpcLogging();
  let started: { service: CalloutService; port: number };
  try {
    started = await start();
  } catch (error) {
    const reason = error instanceof StartupError ? error.message : 'startup failed';
    process.stderr.write(line({ severity: 'ERROR', event: 'ext_proc_startup_failed', reason }));
    process.exitCode = 1;
    return;
  }
  process.stdout.write(line({ severity: 'INFO', event: 'ext_proc_listening', port: started.port }));
  const stop = () => {
    process.off('SIGTERM', stop);
    process.off('SIGINT', stop);
    started.service.shutdown().then(
      () => process.stdout.write(line({ severity: 'INFO', event: 'ext_proc_stopped' })),
      () => (process.exitCode = 1),
    );
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (import.meta.main) await main();
