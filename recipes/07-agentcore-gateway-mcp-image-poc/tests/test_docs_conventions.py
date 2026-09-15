import re
from pathlib import Path


RECIPE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = RECIPE_ROOT.parents[1]


def markdown_section(text: str, heading: str) -> str:
    start = text.index(f"## {heading}")
    next_heading = text.find("\n## ", start + 1)
    if next_heading == -1:
        return text[start:]
    return text[start:next_heading]


def test_index_links_numbered_recipe_and_calls_out_lab_limits():
    index = (REPO_ROOT / "INDEX.md").read_text(encoding="utf-8")

    assert "[recipes/07-agentcore-gateway-mcp-image-poc/]" in index
    assert "lab deploy-only PoC" in index
    assert "configured DNSid lab agent and AWS account" in index


def test_readme_uses_deploy_only_status_and_step_heading_style():
    readme = (RECIPE_ROOT / "README.md").read_text(encoding="utf-8")
    limits = markdown_section(readme, "Lab and AWS account PoC limits")
    step_headings = re.findall(r"^## Step \d+.*$", readme, flags=re.MULTILINE)

    assert "**Status:** deploy-only" in readme
    assert "`DNSID_AGENT_DOMAIN` is required" in limits
    assert "https://api.dnsid.dev" in limits
    assert "your active AWS account" in limits
    assert "us-east-1" in limits
    assert "us-west-2" in limits
    assert "does not automate DNSid identity creation" in limits
    assert "hosted browser authentication" in limits
    assert "production revocation policy" in limits
    assert "The local UI is a convenience client for the deployed Gateway path" in readme
    assert step_headings
    assert all(re.match(r"^## Step \d+ — ", heading) for heading in step_headings)
    assert "## Step 1 — Install the recipe environment" in readme
    assert "cd recipes/07-agentcore-gateway-mcp-image-poc" in readme


def test_makefile_exposes_verify_wrapper_for_deploy_only_closeout():
    makefile = (RECIPE_ROOT / "Makefile").read_text(encoding="utf-8")

    assert ".PHONY: setup probe-model probe-gateway deploy-gateway verify verify-gateway" in makefile
    assert re.search(r"^verify: verify-gateway$", makefile, flags=re.MULTILINE)


def test_cedar_policy_is_documented_as_illustrative_not_enforced():
    readme = (RECIPE_ROOT / "README.md").read_text(encoding="utf-8")
    controls = markdown_section(readme, "Authorization controls")
    policy = (RECIPE_ROOT / "infra/policy/image-tools.cedar").read_text(encoding="utf-8")

    assert "Gateway `CUSTOM_JWT` validation" in controls
    assert "subject_enforcement" in controls
    assert "Gateway also enforces the lab `sub`" in controls
    assert "`gateway_custom_claims`" in controls
    assert "lab `sub` check is left to the request interceptor" in controls
    assert "`downstream`" in controls
    assert "interceptor check runs in both modes" in controls
    assert "API Gateway resource policy" in controls
    assert "deploy and verify commands do not read it" in controls
    assert "Cedar is not part of the enforced control plane" in controls
    assert policy.startswith("// Illustrative only.")
    assert "not read by the Recipe 07 deploy or verify" in policy
    assert "README's \"Authorization controls\" section" in policy
    assert "Final Cedar policy is generated" not in policy


def test_step4_describes_subject_enforcement_as_reported_mode():
    readme = (RECIPE_ROOT / "README.md").read_text(encoding="utf-8")
    deploy_step = markdown_section(readme, "Step 4 — Deploy the Gateway target")

    assert "It enforces the lab DNSid subject" not in deploy_step
    assert "requests Gateway custom-claim checks for the lab DNSid subject" in deploy_step
    assert "falling back when the control plane rejects them" in deploy_step
    assert "`subject_enforcement` reports whether Gateway accepted the custom-claims check" in deploy_step
    assert "in addition to the interceptor check" in deploy_step
    assert "lab `sub` check remains interceptor-only" in deploy_step
    assert "The interceptor check runs in both modes" in deploy_step
    assert "`gateway_custom_claims`" in deploy_step
    assert "`downstream`" in deploy_step


def test_step7_describes_sub_propagation_not_enforcement():
    readme = (RECIPE_ROOT / "README.md").read_text(encoding="utf-8")
    claims = markdown_section(readme, "Step 7 — Know what this PoC does not claim")

    # Guard the old misleading Step 7 phrase across the whole README.
    assert "lab `sub` enforcement through" not in readme
    assert "lab `sub` propagation as trusted context" in claims
    assert "deploy output's `subject_enforcement` field" in claims


def test_cedar_policy_is_not_wired_into_deploy_or_verify_paths():
    script_files = sorted(path for path in (RECIPE_ROOT / "scripts").rglob("*.py") if path.is_file())
    runtime_files = sorted(path for path in (RECIPE_ROOT / "src/image_poc").rglob("*.py") if path.is_file())
    static_files = sorted(path for path in (RECIPE_ROOT / "src/image_poc/static").rglob("*") if path.is_file())
    execution_files = [
        RECIPE_ROOT / "Makefile",
        RECIPE_ROOT / "pyproject.toml",
        RECIPE_ROOT / "infra/openapi/image-api.openapi.json",
        *script_files,
        *runtime_files,
        *static_files,
    ]

    assert script_files
    assert runtime_files
    assert static_files
    for path in execution_files:
        assert b"cedar" not in path.read_bytes().lower(), path
