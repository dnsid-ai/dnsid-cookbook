from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_DNSID_AGENT_DOMAIN = ""
DEFAULT_DNSID_SERVER = "https://api.dev.dnsid.ai"
DEFAULT_DNSID_CLI = "dnsid"
DEFAULT_GATEWAY_STATE_PATH = ".artifacts/gateway/phase3-state.json"
LOCAL_TEST_MODE = "local-test"
GATEWAY_MODE = "gateway"


@dataclass(frozen=True)
class DnsidSettings:
    cli: str
    server: str
    agent_domain: str


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    aws_region: str
    bedrock_model_id: str
    artifact_dir: Path
    audit_path: Path
    image_poc_mode: str
    gateway_state_path: Path
    dnsid: DnsidSettings


def env_value(name: str, default: str, environ: dict[str, str] | None = None) -> str:
    values = environ if environ is not None else os.environ
    value = values.get(name, "").strip()
    return value or default


def load_dnsid_settings(
    environ: dict[str, str] | None = None,
    require_https: bool = False,
    require_agent_domain: bool = True,
) -> DnsidSettings:
    cli = env_value("DNSID_CLI", DEFAULT_DNSID_CLI, environ)
    server = env_value("DNSID_SERVER", DEFAULT_DNSID_SERVER, environ).rstrip("/")
    if not server:
        server = DEFAULT_DNSID_SERVER
    agent_domain = env_value("DNSID_AGENT_DOMAIN", DEFAULT_DNSID_AGENT_DOMAIN, environ)
    if require_agent_domain and not agent_domain:
        raise ValueError("DNSID_AGENT_DOMAIN is required.")
    if require_https:
        parsed = urlparse(server)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("DNSID_SERVER must be an https URL.")
    return DnsidSettings(cli=cli, server=server, agent_domain=agent_domain)


def load_mode(environ: dict[str, str] | None = None) -> str:
    mode = env_value("IMAGE_POC_MODE", GATEWAY_MODE, environ)
    if mode not in {GATEWAY_MODE, LOCAL_TEST_MODE}:
        raise ValueError("IMAGE_POC_MODE must be 'gateway' or 'local-test'.")
    return mode


def load_settings() -> Settings:
    mode = load_mode()
    artifact_dir = Path(os.environ.get("ARTIFACT_DIR", ".artifacts/images"))
    audit_path = Path(os.environ.get("AUDIT_PATH", ".artifacts/audit/audit.jsonl"))
    dnsid = load_dnsid_settings(
        require_https=mode == GATEWAY_MODE,
        require_agent_domain=mode == GATEWAY_MODE,
    )
    return Settings(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8787")),
        aws_region=os.environ.get("AWS_REGION", "us-west-2"),
        bedrock_model_id=os.environ.get(
            "BEDROCK_IMAGE_MODEL_ID", "stability.sd3-5-large-v1:0"
        ),
        artifact_dir=artifact_dir,
        audit_path=audit_path,
        image_poc_mode=mode,
        gateway_state_path=Path(os.environ.get("GATEWAY_STATE_PATH", DEFAULT_GATEWAY_STATE_PATH)),
        dnsid=dnsid,
    )
