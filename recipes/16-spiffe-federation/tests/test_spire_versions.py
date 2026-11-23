"""One SPIRE version across the recipe: the controller's spire-server CLI (images/dnsidfed), the SPIRE server it
drives (images/spire-server) and the agents (images/spire-agent) must be pinned to the same release, and the two
spire-server pins must be the identical image (tag AND digest). A Dependabot bump that updates only some of them
fails here."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
SPIRE_FROM = re.compile(r"^FROM\s+ghcr\.io/spiffe/(spire-server|spire-agent):(\S+?)@(sha256:[0-9a-f]{64})\b", re.MULTILINE)
SEMVER = re.compile(r"\b\d+\.\d+\.\d+\b")


def spire_pins():
    pins = []
    for df in sorted(ROOT.glob("**/Dockerfile")):
        if ".venv" in df.parts:
            continue
        for image, tag, digest in SPIRE_FROM.findall(df.read_text()):
            pins.append((df.relative_to(ROOT).as_posix(), image, tag, digest))
    return pins


def test_every_spire_base_image_is_pinned_by_tag_and_digest():
    pinned = {(p, i) for p, i, _, _ in spire_pins()}
    for df in ROOT.glob("images/*/Dockerfile"):
        for line in df.read_text().splitlines():
            if re.match(r"^FROM\s+ghcr\.io/spiffe/", line):
                assert "@sha256:" in line, f"{df}: {line}"
    assert {i for _, i in pinned} == {"spire-server", "spire-agent"}
    assert ("images/dnsidfed/Dockerfile", "spire-server") in pinned
    assert ("images/spire-server/Dockerfile", "spire-server") in pinned
    assert ("images/spire-agent/Dockerfile", "spire-agent") in pinned


def test_one_spire_release_everywhere():
    tags = {(p, i): t for p, i, t, _ in spire_pins()}
    assert len(set(tags.values())) == 1, f"inconsistent SPIRE versions: {tags}"


def test_controller_cli_and_server_are_the_identical_image():
    server = {(t, d) for _, i, t, d in spire_pins() if i == "spire-server"}
    assert len(server) == 1, f"spire-server pinned differently (tag or digest): {server}"


def test_compose_and_bootstrap_do_not_repeat_the_version():
    compose = (ROOT / "compose.yaml").read_text()
    for image in ("spire-server", "spire-agent"):
        tags = re.findall(rf"/{image}:(\S+)", compose)
        assert tags == ["dev"], f"{image} local tag should be :dev, not a version: {tags}"
    code = "\n".join(ln for ln in (ROOT / "scripts" / "bootstrap.sh").read_text().splitlines()
                     if not ln.lstrip().startswith("#"))
    assert not re.search(r"SPIRE\s+" + SEMVER.pattern, code)


def test_dependabot_updates_all_spire_images_together():
    text = (REPO / ".github" / "dependabot.yml").read_text()
    dirs = [f"/recipes/16-spiffe-federation/images/{d}" for d in ("dnsidfed", "spire-server", "spire-agent")]
    blocks = re.split(r"\n  - package-ecosystem: ", text)
    docker = [b for b in blocks if b.startswith("docker") and any(d in b for d in dirs)]
    assert len(docker) == 1, "the SPIRE image directories must share ONE Dependabot entry"
    block = docker[0]
    assert all(f"      - {d}\n" in block for d in dirs)
    assert "directory: /recipes/16-spiffe-federation/images" not in text
    assert re.search(r'groups:\s*\n\s+spire:\s*\n\s+patterns:\s*\n\s+- "\*spiffe/spire-\*"\s*\n'
                     r"\s+group-by: dependency-name", block)
