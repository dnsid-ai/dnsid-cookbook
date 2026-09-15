from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class McpClient:
    def __init__(self, url: str, token: str) -> None:
        self.url = url
        self.token = token
        self.session_id = ""

    def initialize(self) -> None:
        response = self.request(
            {
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "dnsid-recipe", "version": "0.1"},
                },
            }
        )
        if response["status"] != 200:
            raise RuntimeError(f"Gateway initialization failed: {response['body']}")
        self.session_id = response["headers"].get("mcp-session-id", "")
        self.request({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call_tool(self, target_name: str, arguments: dict[str, Any], proof: str) -> dict[str, Any]:
        return self.request(
            {
                "jsonrpc": "2.0",
                "id": "place-order",
                "method": "tools/call",
                "params": {"name": f"{target_name}___place_order", "arguments": arguments},
            },
            {"x-action-proof": proof},
        )

    def request(self, body: dict[str, Any], extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        request = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode()
                return {
                    "status": response.status,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "body": json.loads(raw) if raw else {},
                }
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                body = {"message": raw}
            return {"status": exc.code, "headers": {}, "body": body}


def tool_result(response: dict[str, Any]) -> dict[str, Any]:
    content = response.get("body", {}).get("result", {}).get("content", [])
    if not content:
        return {}
    parsed = json.loads(content[0].get("text", "{}"))
    return parsed if isinstance(parsed, dict) else {}
