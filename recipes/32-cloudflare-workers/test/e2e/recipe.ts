import { readFile, writeFile, rm } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { startLocalRegistry } from './local-registry.ts';

const manifest = resolve('.recipe-state.json');
const cli = process.env.DNSID_CLI ?? 'dnsid';
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('DNSID_')));

async function loadState() {
  return JSON.parse(await readFile(manifest, 'utf8')) as {
    state: string; dnsPort: number; proxyPort: number; logPolicyUrl: string;
  };
}

switch (process.argv[2]) {
  case 'bootstrap': {
    try {
      await loadState();
      console.log('Recipe registry already provisioned; make clean to reprovision.');
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
    }
    const local = await startLocalRegistry(['enrolled.test', 'stranger.test', 'revoked.test']);
    try {
      await local.revoke('revoked.test');
      await writeFile(manifest, JSON.stringify({
        state: local.state, dnsPort: local.dnsPort, proxyPort: local.proxyPort,
        logPolicyUrl: local.logPolicyUrl,
      }), { mode: 0o600 });
    } catch (error) {
      await local.stop();
      throw error;
    }
    console.log('Provisioned enrolled.test, stranger.test, and revoked.test in an isolated registry.');
    break;
  }
  case 'run': {
    const local = await loadState();
    const result = spawnSync(cli, ['local', 'run', '--state', local.state, 'enrolled.test', '--',
      process.execPath, '--test', '--test-concurrency=1', '--test-timeout=900000', 'test/e2e/flow.test.ts'], {
      stdio: 'inherit', env: { ...environment, DNSID_RECIPE_STATE: manifest },
    });
    if (result.error) {
      throw result.error;
    }
    process.exitCode = result.status ?? 1;
    break;
  }
  case 'clean': {
    let local;
    try {
      local = await loadState();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        break;
      }
      throw error;
    }
    execFileSync(cli, ['local', 'down', '--state', local.state], { stdio: 'inherit', env: environment });
    await rm(dirname(local.state), { recursive: true, force: true });
    await rm(manifest);
    break;
  }
  default:
    throw new Error('Expected bootstrap, run, or clean');
}
