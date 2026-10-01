// Scripted naming replies and tool proposals; real SDK, DNSid registry, Pi and codemode.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAssistantMessageEventStream, type AssistantMessage, type ClassifierContext,
  type ClassifierResult, type JsonObject, type ToolCall } from '@earendil-works/pi-ai';
import { createAgentSession, createCodemodeExtension, DefaultResourceLoader, ModelRuntime,
  SessionManager, SettingsManager, type ProviderConfig } from '@earendil-works/pi-coding-agent';
import { createGuard, validateDomain } from './guard.ts';
import { startMerchant } from './merchant.ts';

let classifierCalls = 0;
let classifierMode: 'normal' | 'malformed' | 'unavailable' = 'normal';
async function classify(context: ClassifierContext): Promise<ClassifierResult> {
  classifierCalls++;
  assert.deepEqual(Object.keys(context.state).sort(), ['accountable_entity', 'agent_name', 'agent_name_unicode']);
  assert.deepEqual(Object.keys(context.questions).sort(), ['acts_for', 'names_org', 'same_org']);
  if (classifierMode === 'unavailable') throw new Error('Fixture classifier unavailable');
  const lookalike = context.state.agent_name === 'paypal-payments.test';
  return {
    api: 'recipe-classifier', provider: 'recipe-fixture', model: 'scripted',
    stopReason: 'stop', timestamp: Date.now(), answers: {
      names_org: { type: 'bool', probability: classifierMode === 'malformed' ? NaN : lookalike ? 1 : 0 },
      acts_for: { type: 'bool', probability: lookalike ? 1 : 0 },
      same_org: { type: 'bool', probability: 0 },
    },
  };
}

function scriptedProvider(calls: Array<{ name: string; arguments: JsonObject }>): ProviderConfig {
  let next = 0;
  return {
    api: 'recipe-chat', apiKey: 'fixture-not-a-secret', baseUrl: 'https://fixture.invalid',
    models: [
      { id: 'scripted', name: 'Scripted tool proposals', api: 'recipe-chat', reasoning: false,
        input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 32_000, maxTokens: 1024 },
      { type: 'classifier', id: 'scripted', name: 'Scripted naming replies', api: 'recipe-classifier',
        input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 32_000 },
    ],
    classifiers: { 'recipe-classifier': { classify: (_model, context) => classify(context) } },
    streamSimple: model => {
      const stream = createAssistantMessageEventStream();
      const call = calls[next++];
      const content: AssistantMessage['content'] = call
        ? [{ type: 'toolCall', id: `proposal-${next}`, ...call }]
        : [{ type: 'text', text: 'Script completed.' }];
      const message: AssistantMessage = {
        role: 'assistant', api: model.api, provider: model.provider, model: model.id, timestamp: Date.now(),
        content, stopReason: call ? 'toolUse' : 'stop',
        usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      };
      stream.push({ type: 'start', partial: message });
      if (call) {
        stream.push({ type: 'toolcall_start', contentIndex: 0, partial: message });
        stream.push({ type: 'toolcall_end', contentIndex: 0, toolCall: content[0] as ToolCall, partial: message });
      } else {
        stream.push({ type: 'text_start', contentIndex: 0, partial: message });
        stream.push({ type: 'text_delta', contentIndex: 0, delta: 'Script completed.', partial: message });
        stream.push({ type: 'text_end', contentIndex: 0, content: 'Script completed.', partial: message });
      }
      stream.push({ type: 'done', reason: message.stopReason as 'stop' | 'toolUse', message });
      stream.end();
      return stream;
    },
  };
}

const { server, state } = await startMerchant();
const agentDir = await mkdtemp(join(tmpdir(), 'dnsid-pi-'));
try {
  for (const bad of ['https://merchant.test', 'merchant.test/path', 'merchant.test:443', 'user@merchant.test', 'merchant..test']) {
    assert.throws(() => validateDomain(bad));
  }
  const savedPolicy = process.env.DNSID_LOG_POLICY_URL;
  delete process.env.DNSID_LOG_POLICY_URL;
  await assert.rejects(createGuard(), /DNSID_LOG_POLICY_URL/);
  process.env.DNSID_LOG_POLICY_URL = savedPolicy;
  const guard = await createGuard();
  const beforeInvalid = classifierCalls;
  await assert.rejects(guard.catalog('missing-counterparty.test', classify));
  assert.equal(classifierCalls, beforeInvalid);
  assert.equal(state.catalogCalls, 0);
  console.log('ok    unverifiable domain stops before Jev and catalog');

  const inspected = await guard.inspect('merchant.test', classify);
  assert.equal(inspected.accountableEntity, 'merchant.test');
  assert.equal(inspected.namingRestricted, false);
  assert.equal(state.catalogCalls, 0);
  console.log('ok    inspection grants no call permission');

  classifierMode = 'malformed';
  await assert.rejects(guard.catalog('merchant.test', classify), /Malformed/);
  classifierMode = 'unavailable';
  await assert.rejects(guard.catalog('merchant.test', classify), /unavailable/);
  classifierMode = 'normal';
  assert.equal(state.catalogCalls, 0);
  console.log('ok    malformed/unavailable classifier fails closed');

  for (const mode of ['redirect', 'oversized'] as const) {
    state.mode = mode;
    const before: number = state.catalogCalls;
    await assert.rejects(guard.catalog('merchant.test', classify), mode === 'redirect' ? /redirects/ : /64 KiB/);
    assert.equal(state.catalogCalls, before + 1); // No second request to the redirect destination.
  }
  state.mode = 'normal';
  console.log('ok    redirects refused and response size bounded');

  let approvals = 0;
  const approve = async (summary: string) => {
    approvals++;
    assert.match(summary, /Merchant: merchant.test/);
    assert.match(summary, /Amount: USD 42.00/);
    return true;
  };
  await assert.rejects(guard.pay('shopper.test', 4200, classify, approve), /not approved for payments/);
  await assert.rejects(guard.pay('merchant.test', 5001, classify, approve), /integer USD cents/);
  assert.equal(approvals, 0);
  await assert.rejects(guard.pay('merchant.test', 4200, classify, async () => false), /not approved/);
  const payment = await guard.pay('merchant.test', 4200, classify, approve);
  assert.equal(payment.payment.simulated, true);
  assert.equal(approvals, 1);
  await assert.rejects(guard.pay('merchant.test', 4200, classify, async () => {
    classifierMode = 'unavailable';
    return true;
  }), /unavailable/); // Even a human approval cannot waive the second policy check.
  classifierMode = 'normal';
  console.log('ok    payment pins entity and amount; explicit approval only; no money sent');

  // Real Pi execution, including nested codemode calls and restoring the same branch.
  process.env.DNSID_JEV_PROVIDER = 'recipe-fixture';
  process.env.DNSID_JEV_MODEL = 'scripted';
  const manager = SessionManager.inMemory();
  let nestedCalls = 0;
  for (const resumed of [false, true]) {
    const calls: Array<{ name: string; arguments: JsonObject }> = resumed ? [{ name: 'codemode', arguments: { code: `
      const remembered = load("approved");
      const payment = await tools.dnsid_pay({domain: "merchant.test", amountCents: 4200});
      if (!remembered || payment.status !== "refused") throw new Error("resumed approval bypass");
      return payment;
    ` } }] : [
      { name: 'dnsid_catalog', arguments: { domain: 'merchant.test' } },
      { name: 'dnsid_catalog', arguments: { domain: 'paypal-payments.test' } },
      { name: 'codemode', arguments: { code: `
        store("approved", true);
        const catalog = await tools.dnsid_catalog({domain: "paypal-payments.test"});
        const payment = await tools.dnsid_pay({domain: "merchant.test", amountCents: 4200});
        if (catalog.status !== "refused" || payment.status !== "refused") throw new Error("nested bypass");
        return {catalog, payment};
      ` } },
    ];
    const settings = SettingsManager.inMemory({ defaultTools: ['codemode', 'dnsid_inspect', 'dnsid_catalog', 'dnsid_pay'],
      compaction: { enabled: false }, retry: { enabled: false } });
    const resources = new DefaultResourceLoader({ agentDir, cwd: process.cwd(), settingsManager: settings,
      noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
      additionalExtensionPaths: [join(process.cwd(), 'src/extension.ts')],
      extensionFactories: [createCodemodeExtension(),
        pi => { pi.on('tool_call', event => { if (event.parentToolCallId) nestedCalls++; }); }],
    });
    await resources.reload();
    assert.deepEqual(resources.getExtensions().errors, []);
    const runtime = await ModelRuntime.create({ authPath: join(agentDir, 'auth.json'), modelsPath: join(agentDir, 'models.json') });
    runtime.registerProvider('recipe-fixture', scriptedProvider(calls));
    const { session } = await createAgentSession({ agentDir, resourceLoader: resources, modelRuntime: runtime,
      sessionManager: manager, settingsManager: settings,
      tools: ['codemode', 'dnsid_inspect', 'dnsid_catalog', 'dnsid_pay'], thinkingLevel: 'off' });
    const results: Array<{ name: string; error: boolean; text: string }> = [];
    try {
      await session.bindExtensions({ onError: error => { throw new Error(JSON.stringify(error)); } });
      const model = runtime.getModel('recipe-fixture', 'scripted');
      assert.ok(model);
      await session.setModel(model);
      session.setActiveToolsByName(['codemode', 'dnsid_inspect', 'dnsid_catalog', 'dnsid_pay']);
      session.subscribe(event => {
        if (event.type === 'tool_execution_end' && !event.parentToolCallId) {
          results.push({ name: event.toolName, error: event.isError,
            text: JSON.stringify(event.result) });
        }
      });
      const before: number = state.catalogCalls;
      await session.prompt('Execute the scripted verification proposals.');
      assert.equal(state.catalogCalls, before + (resumed ? 0 : 1));
      assert.equal(results.length, resumed ? 1 : 3);
      assert.equal(results.at(-1)?.error, false, results.at(-1)?.text);
      if (!resumed) {
        assert.equal(results[0].error, false, results[0].text);
        assert.equal(results[1].error, true);
        assert.match(results[1].text, /impersonation/);
      }
    } finally {
      session.dispose();
    }
  }
  assert.equal(nestedCalls, 3);
  console.log('ok    Pi direct and codemode calls enforce policy; resumed approval is refused');
  console.log('verify passed (scripted naming replies; real DNSid TS SDK and Pi codemode)');
} finally {
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
  await rm(agentDir, { recursive: true, force: true });
}
