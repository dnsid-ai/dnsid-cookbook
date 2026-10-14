/**
 * The coordinator: an Agent SDK session running as researchlab.test, the
 * lab's own identity and the accountable entity for every researcher. It gets
 * a research task, splits it, and dispatches researchers through its one tool.
 * Each researcher is a separate session with its own DNSid identity
 * (researcher-N.researchlab.test); see researcher.ts.
 *
 *   npm run lab -- "<research task>"
 */
import { fileURLToPath } from 'node:url';
import { mkdir, writeFile } from 'node:fs/promises';
import { query, createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import { ensureAgent, registrationStatus } from './dnsid-local.ts';
import { researcherDomain, runResearcher, type Assignment } from './researcher.ts';

const LAB = 'researchlab.test';
const PLUGIN_ROOT = fileURLToPath(
  new URL('.', import.meta.resolve('@dnsid-ai/agent-sdk-plugin/package.json')),
);
const MODEL = process.env.LAB_MODEL ?? 'claude-opus-5-5';
const DEFAULT_TASK =
  'Compare public health spending across the United States, Germany, the United Kingdom, Japan, and Brazil.';

/**
 * Picks researcher numbers for this run. A revoked identity can never come
 * back, so its number is skipped; any other existing researcher is reused.
 */
async function allocateResearchers(count: number): Promise<number[]> {
  const numbers: number[] = [];
  for (let n = 1; numbers.length < count; n++) {
    const domain = researcherDomain(n);
    const status = await registrationStatus(domain, await ensureAgent(domain));
    if (status === 'REVOKED') continue;
    numbers.push(n);
  }
  return numbers;
}

const dispatch = tool(
  'dispatch_researchers',
  'Start one researcher agent per assignment, in parallel, and wait for their reports. ' +
    'Each researcher gets its own DNSid identity under researchlab.test and pulls data from ' +
    'the public data service publicdata.test, which has health spending records keyed by ISO3 ' +
    'country code. Returns each researcher’s identity, the requests it made, and its report.',
  {
    assignments: z
      .array(
        z.object({
          countries: z.array(z.string().length(3)).min(1).describe('ISO3 codes, e.g. ["DEU"]'),
          brief: z.string().describe('What this researcher should find out'),
        }),
      )
      .min(1)
      .max(5),
  },
  async ({ assignments }) => {
    const numbers = await allocateResearchers(assignments.length);
    const results = await Promise.all(
      assignments.map((a: Assignment, i: number) => runResearcher(numbers[i], a)),
    );
    await mkdir('reports', { recursive: true });
    await writeFile('reports/researchers.json', JSON.stringify(results, null, 2) + '\n');
    return { content: [{ type: 'text', text: JSON.stringify(results, null, 2) }] };
  },
);

const SYSTEM_PROMPT = `You are the coordinator of the research lab ${LAB}.

You do no data gathering yourself. Split the research task into two to four assignments of one or two countries each, and call dispatch_researchers once with all of them. Each researcher reports figures it fetched from publicdata.test.

When the reports come back, write the comparison: a markdown table with one row per country (health spending as % of GDP, per capita in USD PPP, public share, out-of-pocket share, year), then a short analysis. Name which researcher identity supplied each country's figures. Use only figures the researchers reported. If a researcher was refused or reported no data, say so; do not fill gaps from memory.`;

if (import.meta.main) {
  const task = process.argv.slice(2).join(' ') || DEFAULT_TASK;
  const lab = await ensureAgent(LAB);
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith('DNSID_')),
  );
  await mkdir(`.dnsid-verdicts`, { recursive: true });
  console.error(`[coordinator] ${LAB} (registration ${await registrationStatus(LAB, lab)})`);
  console.error(`[coordinator] task: ${task}`);

  let report = '';
  for await (const message of query({
    prompt: task,
    options: {
      model: MODEL,
      systemPrompt: SYSTEM_PROMPT,
      // The plugin brings researchlab.test online at session start.
      plugins: [{ type: 'local', path: PLUGIN_ROOT }],
      mcpServers: { lab: createSdkMcpServer({ name: 'lab', tools: [dispatch] }) },
      tools: [],
      allowedTools: ['mcp__lab__dispatch_researchers'],
      permissionMode: 'dontAsk',
      settingSources: [],
      env: {
        ...inherited,
        ...lab,
        DNSID_AGENT_AUTH_AUDIENCE: `https://registry.${lab.DNSID_TESTNET_ZONE ?? 'test'}`,
        DNSID_CACHE_FILE: `.dnsid-verdicts/${LAB}.json`,
        CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1',
        ENABLE_CLAUDEAI_MCP_SERVERS: 'false',
        // Researchers run inside the tool call and can take a few minutes.
        MCP_TOOL_TIMEOUT: '900000',
      },
      maxTurns: 6,
      stderr: (data) => {
        if (process.env.LAB_DEBUG) process.stderr.write(data);
      },
    },
  })) {
    if (message.type === 'system' && message.subtype === 'hook_response' && message.hook_event === 'SessionStart') {
      console.error(`[coordinator] bring-online hook: ${message.outcome}`);
    }
    if (message.type === 'assistant') {
      for (const block of message.message.content) {
        if (block.type === 'tool_use') {
          const { assignments } = block.input as { assignments: Assignment[] };
          for (const a of assignments) {
            console.error(`[coordinator] assign ${a.countries.join(', ')}: ${a.brief}`);
          }
        }
      }
    }
    if (message.type === 'result') {
      report = message.subtype === 'success' ? message.result : `coordinator ended: ${message.subtype}`;
    }
  }

  console.log(report);
  await mkdir('reports', { recursive: true });
  await writeFile('reports/latest.md', report + '\n');
  console.error(`[coordinator] report saved to reports/latest.md`);
}
