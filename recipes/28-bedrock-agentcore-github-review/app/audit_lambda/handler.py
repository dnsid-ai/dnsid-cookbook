"""Audit Lambda — records code review entries.

The AgentCore Gateway validates the caller's DNSid OIDC token (CUSTOM_JWT)
before this Lambda is invoked, so no additional auth is needed here.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: dict, context) -> dict:
    pr_url = event.get("pr_url", "")
    summary = event.get("summary", "")

    logger.info(json.dumps({"pr_url": pr_url, "summary_len": len(summary)}))

    if not pr_url:
        return {"statusCode": 400, "body": json.dumps({"error": "pr_url is required"})}

    return {
        "recorded": True,
        "pr_url": pr_url,
        "message": f"Review recorded for {pr_url}",
    }
