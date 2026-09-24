import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AgentCoreStack } from '../lib/cdk-stack';
import { readFileSync } from 'fs';
import * as path from 'path';

test('AgentCoreStack synthesizes with empty spec', () => {
  const app = new cdk.App();
  const stack = new AgentCoreStack(app, 'TestStack', {
    spec: {
      name: 'testproject',
      version: 1,
      managedBy: 'CDK' as const,
      runtimes: [],
      memories: [],
      credentials: [],
      evaluators: [],
      onlineEvalConfigs: [],
      policyEngines: [],
      agentCoreGateways: [],
      mcpRuntimeTools: [],
      unassignedTargets: [],
    },
  });
  const template = Template.fromStack(stack);
  template.hasOutput('StackNameOutput', {
    Description: 'Name of the CloudFormation Stack',
  });
});

test('ReviewGateway authorizer binds the deployed bot subject and audience', () => {
  const gateway = JSON.parse(readFileSync(path.join(__dirname, '../../agentcore.json'), 'utf8')).agentCoreGateways[0];
  gateway.targets = []; // No backend packaging needed to check the gateway policy.
  const previousDomain = process.env.BOT_DOMAIN;
  const previousAudience = process.env.REVIEW_GATEWAY_AUDIENCE;
  process.env.BOT_DOMAIN = 'reviewer.example.com';
  process.env.REVIEW_GATEWAY_AUDIENCE = 'https://review.example.com/mcp';
  try {
    const stack = new AgentCoreStack(new cdk.App(), 'GatewayTest', {
      spec: {
        name: 'testproject',
        version: 1,
        managedBy: 'CDK',
        runtimes: [],
        memories: [],
        credentials: [],
        evaluators: [],
        onlineEvalConfigs: [],
        policyEngines: [],
        agentCoreGateways: [],
        mcpRuntimeTools: [],
        unassignedTargets: [],
      },
      mcpSpec: { agentCoreGateways: [gateway] },
    });
    Template.fromStack(stack).hasResourceProperties('AWS::BedrockAgentCore::Gateway', {
      AuthorizerConfiguration: {
        CustomJWTAuthorizer: {
          AllowedAudience: ['https://review.example.com/mcp'],
          AllowedScopes: ['dnsid:review'],
          CustomClaims: [
            {
              InboundTokenClaimName: 'sub',
              AuthorizingClaimMatchValue: {
                ClaimMatchOperator: 'EQUALS',
                ClaimMatchValue: { MatchValueString: 'reviewer.example.com' },
              },
            },
          ],
        },
      },
    });
  } finally {
    if (previousDomain === undefined) delete process.env.BOT_DOMAIN;
    else process.env.BOT_DOMAIN = previousDomain;
    if (previousAudience === undefined) delete process.env.REVIEW_GATEWAY_AUDIENCE;
    else process.env.REVIEW_GATEWAY_AUDIENCE = previousAudience;
  }
});
