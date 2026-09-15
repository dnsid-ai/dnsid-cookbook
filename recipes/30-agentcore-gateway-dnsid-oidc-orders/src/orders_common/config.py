from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    aws_region: str
    agentcore_region: str
    dnsid_config_dir: str
    dnsid_log_policy_url: str
    dnsid_server: str
    artifact_dir: Path

    @property
    def state_path(self) -> Path:
        return self.artifact_dir / "state.json"


def load_settings() -> Settings:
    server = os.environ.get("DNSID_SERVER", "https://api.dnsid.dev").rstrip("/")
    policy_url = os.environ.get("DNSID_LOG_POLICY_URL", "").strip()
    parsed = urlparse(server)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("DNSID_SERVER must be an https URL")
    if policy_url:
        parsed = urlparse(policy_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("DNSID_LOG_POLICY_URL must be an https URL")
    return Settings(
        aws_region=os.environ.get("AWS_REGION", "us-east-1"),
        agentcore_region=os.environ.get("AGENTCORE_REGION", "us-east-1"),
        dnsid_config_dir=os.environ.get("DNSID_CONFIG_DIR", "").strip(),
        dnsid_log_policy_url=policy_url,
        dnsid_server=server,
        artifact_dir=Path(os.environ.get("DNSID_RECIPE_ARTIFACT_DIR", ".artifacts")),
    )
