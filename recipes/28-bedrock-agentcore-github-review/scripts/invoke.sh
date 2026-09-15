#!/usr/bin/env bash
# invoke.sh — call a deployed AgentCore Runtime agent with a DNSid OIDC token
#
# Usage:
#   ./scripts/invoke.sh \
#     --runtime-arn arn:aws:bedrock-agentcore:us-east-1:123456789012:... \
#     --token "$(dnsid token --domain ci-bot._dnsid.example.com)" \
#     --prompt "Review PR #42 in owner/repo"
#
# The token is sent to the Runtime endpoint. This recipe does not configure or
# claim DNSid verification for Runtime callers; that boundary is deployment-specific.
#
# OAuth-authenticated invocations use direct HTTPS, not the
# AWS SDK (boto3 invoke_agent_runtime). This script uses curl.

set -euo pipefail

RUNTIME_ARN=""
TOKEN=""
PROMPT=""
SESSION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

while [[ $# -gt 0 ]]; do
    case $1 in
        --runtime-arn) RUNTIME_ARN="$2"; shift 2 ;;
        --token)       TOKEN="$2";       shift 2 ;;
        --prompt)      PROMPT="$2";      shift 2 ;;
        --session-id)  SESSION_ID="$2";  shift 2 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

if [[ -z "$RUNTIME_ARN" || -z "$TOKEN" || -z "$PROMPT" ]]; then
    echo "Usage: $0 --runtime-arn ARN --token TOKEN --prompt PROMPT"
    exit 1
fi

# Derive the HTTPS endpoint from the ARN.
# ARN format: arn:aws:bedrock-agentcore:<region>:<account>:agent-runtime/<id>
REGION=$(echo "$RUNTIME_ARN" | cut -d: -f4)
ENDPOINT="https://bedrock-agentcore-runtime.${REGION}.amazonaws.com"

PAYLOAD=$(jq -n \
    --arg prompt "$PROMPT" \
    '{prompt: $prompt}')

curl -fSs -X POST \
    "${ENDPOINT}/runtimes/${RUNTIME_ARN##*/}/invocations" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-Amzn-Bedrock-AgentCore-Session-Id: ${SESSION_ID}" \
    -d "$PAYLOAD" | jq .
