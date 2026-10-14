/**
 * A researcher: one Agent SDK session with the DNSid plugin, running as its
 * own identity researcher-N.researchlab.test.
 *
 * - The plugin's SessionStart hook brings the identity online (countersigns
 *   its ISSUANCE) before the model does anything.
 * - The model's only tool is the plugin's `fetch`, which signs every request
 *   with the researcher's operational key. The plugin's PreToolUse hook
 *   verifies publicdata.test before each request is sent.
 *
 * Run one directly (the coordinator normally does this):
 *   node src/researcher.ts <n> <ISO3,ISO3,...> [brief]
 */
import { fileURLToPath } from 'node:url';
import { mkdir } from 'node:fs/promises';
import { query } from '@anthropic-ai/claude-agent-sdk';
import { ensureAgent, registrationStatus } from './dnsid-local.ts';

const PLUGIN_ROOT = fileURLToPath(
  new URL('.', import.meta.resolve('@dnsid-ai/agent-sdk-plugin/package.json')),
);
const FETCH = 'mcp__plugin_dnsid_dnsid__fetch';
const VERIFY = 'mcp__plugin_dnsid_dnsid__verify';
const MODEL = process.env.RESEARCHER_MODEL ?? 'claude-sonnet-5-5';

export const researcherDomain = (n: number) => `researcher-${n}.researchlab.test`;

export interface Assignment {
  countries: string[];
  brief: string;
}

export interface ResearcherResult {
  domain: string;
  countries: string[];
  statusBefore?: string;
  statusAfter?: string;
  requests: { url: string; outcome: string }[];
  report: string;
}

function systemPrompt(domain: string) {
  return `You are ${domain}, a researcher agent of the research lab researchlab.test.

Get data only from the public data service at https://publicdata.test, using the \`fetch\` tool. Every request to publicdata.test must set \`tag\` to "publicdata-v1"; the service refuses requests without it.

Endpoints (GET):
- https://publicdata.test/v1/countries
- https://publicdata.test/v1/health-spending/{ISO3}

Fetch each assigned country's record. Then report, in plain text: one line per country with every figure you retrieved and its year, followed by two or three sentences comparing them. Quote the data source string once.

If a request is refused (an HTTP 401, or a tool result starting with "DNSid:"), do not retry it and do not fill in figures from memory. Report the refusal word for word as the result for that country.`;
}

const log = (domain: string, line: string) => console.error(`[${domain.split('.')[0]}] ${line}`);

/** The researcher's own process environment: its identity, not the caller's. */
function researcherEnv(identity: Record<string, string>, domain: string) {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith('DNSID_')),
  );
  return {
    ...inherited,
    ...identity,
    // DNSid Local only: the registry expects its HTTPS name as the audience of
    // the bring-online hook's token, but DNSID_REGISTRY_URL is a local HTTP port.
    DNSID_AGENT_AUTH_AUDIENCE: `https://registry.${identity.DNSID_TESTNET_ZONE ?? 'test'}`,
    // A private verdict cache per agent, instead of a shared file in $TMPDIR.
    DNSID_CACHE_FILE: `.dnsid-verdicts/${domain}.json`,
    CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1',
    ENABLE_CLAUDEAI_MCP_SERVERS: 'false',
  };
}

export async function runResearcher(n: number, assignment: Assignment): Promise<ResearcherResult> {
  const domain = researcherDomain(n);
  const identity = await ensureAgent(domain);
  const result: ResearcherResult = {
    domain,
    countries: assignment.countries,
    statusBefore: await registrationStatus(domain, identity),
    requests: [],
    report: '',
  };
  log(domain, `identity provisioned (registration ${result.statusBefore}); starting session`);
  await mkdir('.dnsid-verdicts', { recursive: true });

  const pendingUrls = new Map<string, string>();
  for await (const message of query({
    prompt: `Assignment: ${assignment.brief}\nCountries (ISO3): ${assignment.countries.join(', ')}`,
    options: {
      model: MODEL,
      systemPrompt: systemPrompt(domain),
      plugins: [{ type: 'local', path: PLUGIN_ROOT }],
      // No built-in tools at all: no WebFetch (unsigned) and no Bash (unverified).
      tools: [],
      allowedTools: [FETCH, VERIFY],
      permissionMode: 'dontAsk',
      settingSources: [],
      env: researcherEnv(identity, domain),
      maxTurns: 12,
      stderr: (data) => {
        if (process.env.LAB_DEBUG) process.stderr.write(data);
      },
    },
  })) {
    if (message.type === 'system' && message.subtype === 'hook_response' && message.hook_event === 'SessionStart') {
      log(domain, `bring-online hook: ${hookContext(message.stdout)}`);
    }
    if (message.type === 'assistant') {
      for (const block of message.message.content) {
        if (block.type === 'tool_use' && block.name === FETCH) {
          const { method = 'GET', url, tag } = block.input as Record<string, string>;
          pendingUrls.set(block.id, url);
          log(domain, `signed ${method} ${url} (tag ${tag ?? 'none'})`);
        }
      }
    }
    if (message.type === 'user' && Array.isArray(message.message.content)) {
      for (const block of message.message.content) {
        if (block.type !== 'tool_result' || !pendingUrls.has(block.tool_use_id)) continue;
        const outcome = describeToolResult(block.content);
        result.requests.push({ url: pendingUrls.get(block.tool_use_id)!, outcome });
        log(domain, `  -> ${outcome}`);
      }
    }
    if (message.type === 'result') {
      result.report = message.subtype === 'success' ? message.result : `session ended: ${message.subtype}`;
    }
  }
  result.statusAfter = await registrationStatus(domain, identity);
  return result;
}

/** The context the plugin's SessionStart hook handed the model. */
function hookContext(output: string): string {
  try {
    return JSON.parse(output).hookSpecificOutput?.additionalContext ?? output.trim();
  } catch {
    return output.trim();
  }
}

/** "HTTP 200" for a response the tool returned, or the hook's DNSid: denial. */
function describeToolResult(content: unknown): string {
  const text = Array.isArray(content)
    ? content.map((c) => (c && typeof c === 'object' && 'text' in c ? String(c.text) : '')).join('')
    : String(content ?? '');
  try {
    const { status, body } = JSON.parse(text);
    return status === 200 ? 'HTTP 200' : `HTTP ${status}: ${String(body).trim()}`;
  } catch {
    return text.trim().split('\n')[0];
  }
}

if (import.meta.main) {
  const [n, countries, ...brief] = process.argv.slice(2);
  if (!n || !countries) {
    console.error('usage: node src/researcher.ts <n> <ISO3,ISO3,...> [brief]');
    process.exit(2);
  }
  const result = await runResearcher(Number(n), {
    countries: countries.split(','),
    brief: brief.join(' ') || 'Retrieve current health spending figures.',
  });
  console.log(`\n=== ${result.domain} ===\n${result.report}`);
}
