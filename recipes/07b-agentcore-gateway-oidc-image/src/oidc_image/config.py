from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


DEFAULT_AGENTCORE_REGION = "us-east-1"
DEFAULT_BEDROCK_REGION = "us-west-2"
DEFAULT_BEDROCK_IMAGE_MODEL_ID = "stability.sd3-5-large-v1:0"
DEFAULT_DNSID_AGENT_DOMAIN = ""
DEFAULT_DNSID_SERVER = "https://oidc.dnsid.dev"


@dataclass(frozen=True)
class DnsidSettings:
    server: str
    agent_domain: str


def env_value(name: str, default: str, environ: dict[str, str] | None = None) -> str:
    values = environ if environ is not None else os.environ
    value = values.get(name, "").strip()
    return value or default


def load_dnsid_settings(
    environ: dict[str, str] | None = None,
    require_https: bool = True,
    require_agent_domain: bool = True,
) -> DnsidSettings:
    server = env_value("DNSID_SERVER", DEFAULT_DNSID_SERVER, environ).rstrip("/")
    if require_https:
        parsed = urlparse(server)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("DNSID_SERVER must be an https URL.")
    agent_domain = env_value("DNSID_AGENT_DOMAIN", DEFAULT_DNSID_AGENT_DOMAIN, environ)
    if require_agent_domain and not agent_domain:
        raise ValueError("DNSID_AGENT_DOMAIN is required.")
    return DnsidSettings(server=server, agent_domain=agent_domain)
