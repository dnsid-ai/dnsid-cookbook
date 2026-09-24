import {
  AgentCoreApplication,
  AgentCoreMcp,
  type AgentCoreProjectSpec,
  type AgentCoreMcpSpec,
} from '@aws/agentcore-cdk';
import { CfnOutput, Stack, type StackProps, aws_secretsmanager as sm } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface AgentCoreStackProps extends StackProps {
  /**
   * The AgentCore project specification containing agents, memories, and credentials.
   */
  spec: AgentCoreProjectSpec;
  /**
   * The MCP specification containing gateways and servers.
   */
  mcpSpec?: AgentCoreMcpSpec;
  /**
   * Credential provider ARNs from deployed state, keyed by credential name.
   */
  credentials?: Record<string, { credentialProviderArn: string; clientSecretArn?: string }>;
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} must be set before deploying GitHubReviewBot.`);
  }
  return value;
}

/**
 * CDK Stack that deploys AgentCore infrastructure.
 *
 * This is a thin wrapper that instantiates L3 constructs.
 * All resource logic and outputs are contained within the L3 constructs.
 */
export class AgentCoreStack extends Stack {
  /** The AgentCore application containing all agent environments */
  public readonly application: AgentCoreApplication;

  constructor(scope: Construct, id: string, props: AgentCoreStackProps) {
    super(scope, id, props);

    const { spec, mcpSpec, credentials } = props;

    // Create AgentCoreApplication with all agents
    this.application = new AgentCoreApplication(this, 'Application', {
      spec,
    });

    // Wire the configured GitHub App credentials into the runtime.
    const env = this.application.environments.get('GitHubReviewBot');
    if (env) {
      const githubAppId = requiredEnv('GITHUB_APP_ID');
      const githubAppKeySecretName = requiredEnv('GITHUB_APP_KEY_SECRET_NAME');
      const botDomain = requiredEnv('BOT_DOMAIN');
      const gatewayAudience = requiredEnv('REVIEW_GATEWAY_AUDIENCE');
      const githubAppKeySecret = sm.Secret.fromSecretNameV2(this, 'GithubAppKeySecret', githubAppKeySecretName);
      githubAppKeySecret.grantRead(env.runtime.role);
      env.runtime.addEnvironmentVariable('GITHUB_APP_ID', githubAppId);
      env.runtime.addEnvironmentVariable('GITHUB_APP_KEY_SECRET_ARN', githubAppKeySecret.secretArn);
      env.runtime.addEnvironmentVariable('BOT_DOMAIN', botDomain);
      env.runtime.addEnvironmentVariable('REVIEW_GATEWAY_AUDIENCE', gatewayAudience);
    }

    // The gateway spec has fail-closed placeholders; bind its JWT checks to
    // the same values used by the runtime before creating the gateway.
    if (mcpSpec?.agentCoreGateways && mcpSpec.agentCoreGateways.length > 0) {
      const authorizer = mcpSpec.agentCoreGateways.find(g => g.name === 'ReviewGateway')?.authorizerConfiguration
        ?.customJwtAuthorizer;
      if (!authorizer) throw new Error('ReviewGateway CUSTOM_JWT authorizer is required');
      authorizer.allowedAudience = [requiredEnv('REVIEW_GATEWAY_AUDIENCE')];
      authorizer.customClaims = [
        {
          inboundTokenClaimName: 'sub',
          inboundTokenClaimValueType: 'STRING',
          authorizingClaimMatchValue: {
            claimMatchOperator: 'EQUALS',
            claimMatchValue: { matchValueString: requiredEnv('BOT_DOMAIN') },
          },
        },
      ];
      new AgentCoreMcp(this, 'Mcp', {
        projectName: spec.name,
        mcpSpec,
        agentCoreApplication: this.application,
        credentials,
        projectTags: spec.tags,
      });
    }

    // Stack-level output
    new CfnOutput(this, 'StackNameOutput', {
      description: 'Name of the CloudFormation Stack',
      value: this.stackName,
    });
  }
}
