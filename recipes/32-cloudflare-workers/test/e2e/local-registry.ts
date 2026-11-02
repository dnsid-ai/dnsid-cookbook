import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { createSocket } from 'node:dgram';
import { promisify } from 'node:util';
import { Resolver } from 'node:dns/promises';
import { setTimeout as delay } from 'node:timers/promises';

const execFileAsync = promisify(execFile);

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Could not allocate a local test port');
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function unusedDnsPort(): Promise<number> {
  const port = await unusedPort();
  const socket = createSocket('udp4');
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(port, '127.0.0.1', resolve);
    });
  } finally {
    socket.close();
  }
  return port;
}

/** Owns only a temporary DNSid Local environment; never resets the user's registry. */
export async function startLocalRegistry(domains: string[]) {
  const directory = await mkdtemp(join(tmpdir(), 'dnsid-worker-integration-'));
  const state = join(directory, 'registry');
  // CoreDNS runs unprivileged inside the container and must traverse its mounted root.
  // The parent temporary directory remains private on the host.
  await mkdir(state, { mode: 0o755 });
  const registryPort = await unusedPort();
  const dnsPort = await unusedDnsPort();
  const proxyPort = await unusedPort();
  const cli = process.env.DNSID_CLI ?? 'dnsid';
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('DNSID_')));
  environment.DNSID_CONFIG_DIR = join(directory, 'cli');
  if (process.env.DNSID_LOCAL_IMAGE) {
    environment.DNSID_LOCAL_IMAGE = process.env.DNSID_LOCAL_IMAGE;
  }

  async function run(args: string[], label: string) {
    try {
      await execFileAsync(cli, args, { env: environment, timeout: 180_000, maxBuffer: 4 * 1024 * 1024 });
    } catch (error) {
      // CLI output can contain credentials; do not print it in test reports.
      const code = (error as NodeJS.ErrnoException).code;
      throw new Error(`${label} failed (${code ?? 'command error'}). Check Docker and DNSid CLI prerequisites. Test state: ${state}`);
    }
  }

  async function stop() {
    await run(['local', 'down', '--state', state], 'Stopping the isolated registry');
    await rm(directory, { recursive: true, force: true });
  }

  try {
    await run(['local', 'up', '--zone', 'test', '--state', state,
      '--registry-port', String(registryPort), '--dns-port', String(dnsPort),
      '--proxy-port', String(proxyPort)], 'Starting the isolated registry');

    for (const domain of domains) {
      await run(['local', 'agent', 'ensure', '--state', state,
        '--upstream', 'http://127.0.0.1:3999', domain, '--',
        cli, 'log', 'issue', '--domain', domain], `Issuing test identity ${domain}`);
    }

    // CoreDNS reloads generated zone files asynchronously after issuance.
    const resolver = new Resolver({ timeout: 1000, tries: 1 });
    resolver.setServers([`127.0.0.1:${dnsPort}`]);
    const deadline = Date.now() + 30_000;
    for (const domain of domains) {
      while (true) {
        try {
          const records = await resolver.resolveTxt(`_dnsid.${domain}`);
          if (records.length > 0) {
            break;
          }
        } catch {
          // Retry until the local DNS service has loaded the new identity.
        }
        if (Date.now() >= deadline) {
          throw new Error(`Local DNS did not publish test identity ${domain}`);
        }
        await delay(250);
      }
    }
  } catch (error) {
    try {
      await stop();
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'Registry setup and cleanup failed');
    }
    throw error;
  }

  const { stdout } = await execFileAsync(cli, ['local', 'run', '--state', state, domains[0], '--',
    process.execPath, '-e', 'process.stdout.write(process.env.DNSID_LOG_POLICY_URL || "")'],
    { env: environment, timeout: 180_000 });
  const logPolicyUrl = stdout.trim();
  if (!logPolicyUrl.startsWith('https://')) {
    await stop();
    throw new Error('Local registry did not supply DNSID_LOG_POLICY_URL');
  }

  return {
    state, dnsPort, proxyPort, logPolicyUrl, stop,
    async revoke(domain: string) {
      if (!domains.includes(domain)) {
        throw new Error('Refusing to revoke an identity outside this test fixture');
      }
      await run(['local', 'agent', 'ensure', '--state', state,
        '--upstream', 'http://127.0.0.1:3999', domain, '--', cli,
        'revoke', '--domain', domain, '--reason', 'owner_request', '--yes'], 'Revoking isolated test identity');
    },
  };
}
