#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".artifacts",
    ".cache",
    ".cli",
    ".dnsid-local",
    ".dnsid-testnet",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "cdk.out",
    "dist",
    "node_modules",
    "vendor",
}

SKIP_SUFFIXES = {
    ".gif",
    ".gz",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".pyc",
    ".tar",
    ".webp",
    ".zip",
}

ALLOWED_AWS_ACCOUNT_IDS = {"123456789012"}
ALLOWED_DNSID_HOSTS = {
    "api.dnsid.ai",
    "api.dev.dnsid.ai",
    "app.dnsid.ai",
    "dev.dnsid.ai",
    "docs.dnsid.ai",
    "downloads.dnsid.ai",
    "oidc.dev.dnsid.ai",
    "sandbox.dev.dnsid.ai",
    "oidc.dnsid.ai",
}

ALLOWED_NESTED_EXAMPLE_HOSTS = {
    # Delegated key hosts and simulated service endpoints, not agent identities.
    "dnsid.alice.test",
    "dnsid.publish.test",
    "dnsid.writer.test",
    "dnsid.example.test",
    "issuer.example.test",
    "gateway.example.com",
    "review.example.com",
    # DNS parsing and URL-boundary cases intentionally retain their shape.
    "example.example.com",
    "bad_label.example.com",
    "-bad.example.com",
    "writer.test.evil.example",
}

DENYLISTED_IDENTITY_PARTS = {
    "legacy AWS account ID": (("446872", "464738"),),
    "legacy DNSid lab subject": (("4da8580c9975", ".lab.dnsid", ".dev"),),
    "legacy DNSid bot subject": (("e24def51d939", ".dev.dnsid.ai"),),
    "legacy GitHub App ID": (("381", "8219"),),
    "legacy AgentCore Gateway ID": (("githubreviewbot-reviewgateway-", "i1e4rjp8d6"),),
    "legacy AgentCore runtime ID": (("GitHubReviewBot_GitHubReviewBot-", "mVbA0l93ir"),),
    "legacy GitHub App secret name": (("dnsid-github-app", "/private-key"),),
    "legacy GitHub App key filename": (("dnsid-ai", ".private-key.pem"),),
}

DENYLISTED_IDENTITIES = tuple(
    (label, "".join(parts))
    for label, values in DENYLISTED_IDENTITY_PARTS.items()
    for parts in values
)

AWS_ACCOUNT_ID_RE = re.compile(r"(?<![A-Za-z0-9])([0-9]{12})(?![A-Za-z0-9])")
DNSID_HOST_RE = re.compile(
    r"\b("
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"\.dnsid\.(?:dev|ai)"
    r")\b",
    re.IGNORECASE,
)

# ponytail: reserved example hosts only; add context-aware checks if public identities recur.
NESTED_EXAMPLE_HOST_RE = re.compile(
    r"(?<![\w.-])((?:[a-z0-9_-]+\.){2,}(?:test|example)"
    r"|(?:[a-z0-9_-]+\.)+example\.com)(?![\w-]|\.[\w-])",
    re.IGNORECASE,
)


def should_skip(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
        return True
    return path.suffix.lower() in SKIP_SUFFIXES


def text_files() -> list[Path]:
    paths: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or should_skip(path):
            continue
        paths.append(path)
    return sorted(paths)


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def findings_for(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    rel = path.relative_to(ROOT)
    for match in AWS_ACCOUNT_ID_RE.finditer(text):
        account_id = match.group(1)
        if account_id in ALLOWED_AWS_ACCOUNT_IDS:
            continue
        findings.append(
            f"{rel}:{line_number(text, match.start())}: "
            f"real AWS account ID {account_id}"
        )
    for match in DNSID_HOST_RE.finditer(text):
        host = match.group(1).lower()
        if host in ALLOWED_DNSID_HOSTS:
            continue
        findings.append(
            f"{rel}:{line_number(text, match.start())}: "
            f"concrete DNSid identity {match.group(1)}"
        )
    for match in NESTED_EXAMPLE_HOST_RE.finditer(text):
        host = match.group(1).lower().removeprefix("_dnsid.")
        if host.count(".") < 2 or host in ALLOWED_NESTED_EXAMPLE_HOSTS:
            continue
        findings.append(
            f"{rel}:{line_number(text, match.start())}: "
            f"nested example identity {match.group(1)}; use a distinct 2LD"
        )
    for label, needle in DENYLISTED_IDENTITIES:
        start = text.find(needle)
        if start == -1:
            continue
        findings.append(
            f"{rel}:{line_number(text, start)}: "
            f"{label} {needle}"
        )
    return findings


def main() -> int:
    findings: list[str] = []
    for path in text_files():
        text = read_text(path)
        if text is None:
            continue
        findings.extend(findings_for(path, text))

    if findings:
        print("Hard-coded identity scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    print("Hard-coded identity scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
