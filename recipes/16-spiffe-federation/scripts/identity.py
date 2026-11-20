"""Rackloria's federation SIGNER identities on this recipe's own DNSid local registry.

Everything goes through the `dnsid` CLI against the recipe's isolated state directory:
  * identities are provisioned with `dnsid local agent ensure <fqdn> -- dnsid log issue --domain <fqdn>`
  * their environment comes from `dnsid local agent ensure <fqdn> --format dotenv`
  * revocation is `dnsid local agent ensure <fqdn> -- dnsid revoke --domain <fqdn> ...`

The signer is NOT Rackloria's organizational identity. Each run issues a fresh, disposable signer named
spire-fed-<utc>-<hex>.rackloria.test under the governance domain rackloria.test. Revocation is permanent,
so a revoked signer is never reused, and Rackloria's organization (governance ID and entity key) stays
unchanged.

usage (run by the Makefile and verify/verify.sh):
  identity.py ensure-active [--first-enrollment]
                                        print the current signer once it is positively verified ACTIVE.
                                        Never replaces a signer: a revoked, retired, missing or unverifiable
                                        signer stops with an explanation. --first-enrollment (bootstrap only)
                                        authorizes issuing the FIRST signer, and only when there is no prior
                                        signer, pin, checkpoint store or signer in the local registry.
  identity.py current                   print the current signer
  identity.py state [FQDN]              ACTIVE / REVOKED / ... from the local registry
  identity.py publisher-env OUT DIR     write the publisher's env (allowlisted, never the API key) and copy
                                        ONLY the signer's key directory to DIR (group-readable)
  identity.py pin OUT                   write the governance entity-key thumbprint(s), from DNSID_EK_URL
  identity.py pin --check FILE          fail if the registry no longer serves a pinned entity key
  identity.py log-policy OUT            write the C2SP log trust policy, from DNSID_LOG_POLICY_URL
  identity.py revoke --yes              PERMANENTLY revoke the current signer
  identity.py local-env KEY             print one value of the local registry's base CLI environment

Failures exit with a category code (see EXIT_*), which bootstrap.sh reports by name.

Environment (set by the Makefile): DNSID_LOCAL_STATE, DNSID_LOCAL_REGISTRY_PORT, DNSID_LOCAL_DNS_PORT,
RECIPE_STATE. The state
paths must be exactly this recipe's <recipe>/.dnsid-local and <recipe>/.state (see paths.py); every output
must be inside <recipe>/.state/dnsid/.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# The path guards live next to this script; -I keeps the script directory off sys.path, so add it explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from paths import UnsafePath, check_local_state, check_recipe_state, require_under  # noqa: E402

GOVERNANCE = "rackloria.test"
SIGNER_RE = re.compile(r"^spire-fed-[0-9]{14}-[0-9a-f]{4}\.rackloria\.test$")
UPSTREAM = "http://127.0.0.1:18099"  # unused: the signer serves nothing through the local TLS proxy
PUBLISHER_ENV_KEYS = {  # explicit allowlist: never DNSID_API_KEY, never registry URLs
    "DNSID_DOMAIN", "DNSID_GOVERNANCE_ID", "DNSID_KU_URL", "DNSID_STATUS_URL", "DNSID_EK_URL",
    "DNSID_DNSSEC_MODE", "DNSID_PRIVATE_HOSTS", "DNSID_LOG_POLICY_URL", "DNSID_LOG_REF",
}
PUBLISHER_ENV_REQUIRED = {"DNSID_DOMAIN", "DNSID_GOVERNANCE_ID", "DNSID_KU_URL", "DNSID_STATUS_URL",
                          "DNSID_LOG_POLICY_URL", "DNSID_LOG_REF"}


def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


# Failure categories. bootstrap.sh maps each exit code to a named reason; messages never carry credentials,
# keys or environment values other than host:port pairs.
EXIT_USAGE = 2               # configuration / usage error
EXIT_REFUSED = 3             # a deliberate refusal (e.g. re-pinning)
EXIT_RESOLVER = 10           # this recipe's own DNS resolver could not be established (wrong instance, down)
EXIT_REGISTRY_UNCERTAIN = 11  # registry status timed out / unreachable / ambiguous: nothing created or replaced
EXIT_SIGNER_UNUSABLE = 12    # signer revoked, retired, missing, or prior enrollment without a usable signer
EXIT_RECORD = 13             # missing or malformed _dnsid record / entity-key document
EXIT_GOVERNANCE = 14         # gi= is not the independently configured governance identity
EXIT_ENTITY_KEY = 15         # the served entity key does not match the preserved pin


def fail(code: int, msg: str):
    die(msg, code)


# Set by configure(): only this recipe's own local registry state and working state are ever used.
LOCAL: Path
RECIPE_STATE: Path
DNSID_DIR: Path
REGISTRY: str
CURRENT: Path
DNS_PORT: int

# Indirections so the offline tests can stub the outside world (no network, Docker or CLI in tests).
_run = subprocess.run
_urlopen = urllib.request.urlopen
_sleep = time.sleep


def configure(env: dict[str, str] | None = None) -> None:
    """Validate and load configuration. Refuses any other DNSid Local instance, path traversal and symlinks."""
    global LOCAL, RECIPE_STATE, DNSID_DIR, REGISTRY, CURRENT, DNS_PORT
    env = os.environ if env is None else env
    try:
        local = check_local_state(env.get("DNSID_LOCAL_STATE", ""))
        recipe_state = check_recipe_state(env.get("RECIPE_STATE", ""))
    except UnsafePath as exc:
        die(str(exc), EXIT_USAGE)
    port = env.get("DNSID_LOCAL_REGISTRY_PORT", "")
    if not port.isdigit():
        die("DNSID_LOCAL_REGISTRY_PORT is not set (run through make)", EXIT_USAGE)
    dns_port = env.get("DNSID_LOCAL_DNS_PORT", "")
    if not dns_port.isdigit() or not 0 < int(dns_port) < 65536:
        die("DNSID_LOCAL_DNS_PORT is not set (run through make)", EXIT_USAGE)
    LOCAL, RECIPE_STATE = local, recipe_state
    DNSID_DIR = recipe_state / "dnsid"
    REGISTRY = f"http://127.0.0.1:{port}"
    CURRENT = DNSID_DIR / "current-signer"
    DNS_PORT = int(dns_port)


def output_path(path: str) -> Path:
    """Every file or directory this script writes must be inside <recipe>/.state/dnsid/."""
    try:
        return require_under(path, DNSID_DIR)
    except UnsafePath as exc:
        die(str(exc), 2)


def guard(name: str) -> str:
    name = name.lower().rstrip(".")
    if not SIGNER_RE.match(name):
        die(f"{name!r} is not a recipe signer identity", 2)
    return name


def dnsid(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run the dnsid CLI against THIS recipe's local registry only. Output is never echoed (it can hold
    environment values); stderr is CLI diagnostics."""
    env = dict(os.environ, DNSID_SERVER=REGISTRY)
    cp = subprocess.run(["dnsid", *args], capture_output=True, text=True, timeout=180, env=env)
    if check and cp.returncode != 0:
        die(f"dnsid {' '.join(args[:3])} failed: {cp.stderr.strip()[:400]}")
    return cp


def ensure(name: str, *cmd: str, fmt: str | None = None) -> subprocess.CompletedProcess:
    args = ["local", "agent", "ensure", "--state", str(LOCAL), "--upstream", UPSTREAM]
    if fmt:
        args += ["--format", fmt]
    args.append(name)
    if cmd:
        args += ["--", *cmd]
    return dnsid(*args)


def parse_dotenv(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        k, _, v = line.partition("=")
        out[k.strip()] = shlex.split(v)[0] if v.strip() else ""
    return out


def agent_env(name: str) -> dict[str, str]:
    return parse_dotenv(ensure(name, fmt="dotenv").stdout)


def base_env() -> dict[str, str]:
    return parse_dotenv(dnsid("local", "env", "--state", str(LOCAL), "--format", "dotenv").stdout)


_STATE_WORD = re.compile(r"^[A-Z][A-Z_]{1,31}$")

# Signer status outcomes. Only a parsed registry answer is definitive; everything else is "uncertain".
DEFINITE, MISSING, UNCERTAIN = "state", "missing", "uncertain"


def signer_status(name: str) -> tuple[str, str]:
    """One status query: (DEFINITE, "ACTIVE"|"REVOKED"|...), (MISSING, "NOT_FOUND") on an explicit 404, or
    (UNCERTAIN, reason) for timeouts, connection errors, other HTTP errors and unparseable answers."""
    try:
        with _urlopen(f"{REGISTRY}/v1/status/{name}", timeout=5) as r:
            body = json.load(r)
    except urllib.error.HTTPError as exc:
        return (MISSING, "NOT_FOUND") if exc.code == 404 else (UNCERTAIN, f"HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return UNCERTAIN, type(exc).__name__
    except ValueError:
        return UNCERTAIN, "unparseable status response"
    state = body.get("state") if isinstance(body, dict) else None
    if not isinstance(state, str) or not _STATE_WORD.match(state):
        return UNCERTAIN, "status response has no recognizable state"
    return DEFINITE, state


def verified_status(name: str, attempts: int = 10, delay: float = 2.0) -> tuple[str, str]:
    """Retry only while the answer is uncertain (e.g. the registry is still starting); a definite answer or
    an explicit NOT_FOUND is returned at once."""
    kind, val = UNCERTAIN, "no attempt"
    for i in range(attempts):
        kind, val = signer_status(name)
        if kind != UNCERTAIN:
            break
        if i + 1 < attempts:
            _sleep(delay)
    return kind, val


def registry_state(name: str) -> str:
    """Display form for `identity.py state` and revocation checks: the state, NOT_FOUND, or UNKNOWN (why)."""
    kind, val = signer_status(name)
    return f"UNKNOWN ({val})" if kind == UNCERTAIN else val


def current() -> str:
    if not CURRENT.exists():
        die("no current signer (run: identity.py ensure-active)")
    return guard(CURRENT.read_text().strip())


def wait_state(name: str, want: str, secs: int) -> bool:
    for _ in range(secs):
        if registry_state(name) == want:
            return True
        _sleep(1)
    return False


def enrollment_evidence() -> list[str]:
    """Signs that this recipe has enrolled before. Any of them forbids issuing a signer: a restart must reuse
    the existing one, never quietly start a new trust history. Returns descriptions only, never contents."""
    found = []
    if CURRENT.exists():
        found.append(f"{CURRENT.relative_to(RECIPE_STATE.parent)}")
    for p in (DNSID_DIR / "pins.json", DNSID_DIR / "signer",
              RECIPE_STATE / "controller" / "data" / "trusted-checkpoints.json",
              RECIPE_STATE / "controller" / "data" / "trusted-checkpoints.journal"):
        if p.exists():
            found.append(str(p.relative_to(RECIPE_STATE.parent)))
    try:
        agents = json.loads((LOCAL / "state.json").read_text()).get("agents", {})
    except FileNotFoundError:
        agents = {}
    except (OSError, ValueError, AttributeError):
        found.append(".dnsid-local/state.json (unreadable: cannot rule out an earlier signer)")
        agents = {}
    signers = sorted(a for a in agents if isinstance(a, str) and SIGNER_RE.match(a.lower().rstrip(".")))
    if signers:
        found.append(f"{len(signers)} recipe signer(s) in the local registry")
    return found


def create() -> str:
    name = guard(f"spire-fed-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(2)}.{GOVERNANCE}")
    ensure(name, "dnsid", "log", "issue", "--domain", name)
    if not wait_state(name, "ACTIVE", 60):
        fail(EXIT_REGISTRY_UNCERTAIN, f"{name} was issued but did not report ACTIVE within 60 s")
    CURRENT.parent.mkdir(parents=True, exist_ok=True)
    CURRENT.write_text(name + "\n")
    return name


def cmd_ensure_active(first_enrollment: bool = False) -> None:
    """Reuse the existing signer only after ACTIVE is positively verified. Never replace or reissue one.

    A new signer is issued only for an explicitly authorized first enrollment (--first-enrollment, passed by
    bootstrap) with no evidence of an earlier one. Uncertainty is never treated as absence.
    """
    if CURRENT.exists():
        name = guard(CURRENT.read_text().strip())
        kind, val = verified_status(name)
        if kind == DEFINITE and val == "ACTIVE":
            print(name)
            return
        if kind == UNCERTAIN:
            fail(EXIT_REGISTRY_UNCERTAIN,
                 f"could not verify the status of signer {name} ({val}) at {REGISTRY}. It was NOT replaced: "
                 "check that this recipe's local registry is running, then re-run make bootstrap.")
        why = "is missing from the local registry" if kind == MISSING else f"is {val}"
        fail(EXIT_SIGNER_UNUSABLE,
             f"signer {name} {why}. Signers are never reissued or replaced automatically, and a revoked signer "
             "is never reused. Starting a new trust history is a deliberate operator decision (see README, "
             "\"Stopping vs. cleaning\").")
    evidence = enrollment_evidence()
    if evidence:
        fail(EXIT_SIGNER_UNUSABLE,
             "no current signer, but this recipe has enrolled before (" + "; ".join(evidence) + "). Refusing to "
             "issue a replacement signer during a restart.")
    if not first_enrollment:
        fail(EXIT_SIGNER_UNUSABLE, "no signer has been enrolled yet; only make bootstrap may issue the first one")
    print(create())


class RecordError(ValueError):
    pass


class GovernanceMismatch(RecordError):
    """gi= names a governance identity other than the independently configured one."""


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def parse_dnsid_record(txt: str) -> dict[str, str]:
    """Parse `dig +short` output of a _dnsid TXT record: quoted 255-byte chunks, `;`-separated key=value."""
    joined = "".join(re.findall(r'"([^"]*)"', txt)) if '"' in txt else txt.strip()
    out: dict[str, str] = {}
    for part in joined.split(";"):
        k, sep, v = part.strip().partition("=")
        if not sep or not k:
            continue
        if k in out:
            raise RecordError(f"duplicate {k}= in _dnsid record")
        out[k] = v.strip()
    return out


def _dns_name(host: str) -> bool:
    return 0 < len(host) <= 253 and all(_LABEL.match(lbl) for lbl in host.split("."))


def validate_entity_key_url(record: dict[str, str], governance: str, cli_ek: str | None = None) -> str:
    """Return the record's ek= URL if, and only if, it is the governance domain's own HTTPS entity-key URL.

    `governance` is the independently configured expected governance ID, never taken from the record. This
    locates the key; it does not make it trustworthy. Trust comes from the pin captured at trusted setup and
    from the SDK's verification of the record signature against that pin on every controller cycle.
    """
    gov = governance.lower().rstrip(".")
    gi = (record.get("gi") or "").strip()
    if not gi:
        raise RecordError("_dnsid record has no gi=")
    if gi.lower().rstrip(".") != gov or gi.rstrip(".") != gi.rstrip(".").lower():
        raise GovernanceMismatch(f"gi={gi!r} is not the expected governance identity {gov}")
    ek = (record.get("ek") or "").strip()
    if not ek:
        raise RecordError("_dnsid record has no ek=")
    if not ek.isascii() or any(c.isspace() for c in ek):
        raise RecordError(f"malformed ek= URL {ek!r}")
    try:
        u = urllib.parse.urlsplit(ek)
        port = u.port
    except ValueError as exc:
        raise RecordError(f"malformed ek= URL {ek!r}: {exc}") from exc
    if u.scheme != "https":
        raise RecordError(f"ek= must be https, got {u.scheme or 'no scheme'!r}")
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise RecordError("ek= URL must not contain userinfo")
    if port not in (None, 443):
        raise RecordError(f"ek= URL has unexpected port {port}")
    if u.query or u.fragment:
        raise RecordError("ek= URL must not contain a query or fragment")
    host = u.hostname or ""  # urlsplit lowercases this; compare against the raw netloc to catch case tricks
    if u.netloc.removesuffix(":443") != host:
        raise RecordError(f"ek= host {u.netloc!r} is not a plain lowercase DNS name")
    if not _dns_name(host):
        raise RecordError(f"ek= host {host!r} is not a valid DNS name")
    if not (host == gov or host.endswith("." + gov)):
        raise RecordError(f"ek= host {host!r} is not {gov} or a subdomain of it")
    if not u.path.startswith("/"):
        raise RecordError("ek= URL has no path")
    if cli_ek is not None and cli_ek != ek:
        raise RecordError(f"CLI-provided DNSID_EK_URL {cli_ek!r} differs from the published ek= {ek!r}")
    return ek


_DNS_PORT_LINE = re.compile(r'^\s+dnsPort:\s*"?([0-9]{1,5})"?\s*$')
_PUBLISHED_DNS = re.compile(r"(?:^|,\s*)127\.0\.0\.1:([0-9]{1,5})->53/udp(?:,|$)")
_ZONE = "test"


def configured_dns_port(config_text: str, expected: int) -> int:
    """The DNS port from this instance's own .dnsid-local/config.yml. It is authoritative only if it is stated
    exactly once and agrees with the port this recipe was started with (DNSID_LOCAL_DNS_PORT)."""
    ports = [int(m.group(1)) for line in config_text.splitlines() if (m := _DNS_PORT_LINE.match(line))]
    if len(ports) != 1:
        fail(EXIT_RESOLVER, f"this recipe's DNSid Local config.yml states {len(ports)} dnsPort values; expected 1")
    if ports[0] != expected:
        fail(EXIT_RESOLVER, f"this recipe's DNSid Local config.yml has dnsPort {ports[0]}, but the recipe runs it "
                            f"on {expected}: refusing to guess which resolver is its own")
    return ports[0]


def owned_dns_ports(docker_ps_ports: str) -> list[int]:
    """Host ports at which the running dns-host container(s) of THIS instance publish DNS (one line each)."""
    lines = [ln for ln in docker_ps_ports.splitlines() if ln.strip()]
    if len(lines) != 1:
        return []
    return sorted({int(p) for p in _PUBLISHED_DNS.findall(lines[0])})


def verify_resolver_owner(port: int) -> None:
    """Fail closed unless this recipe's own DNSid Local (selected by its Docker Compose working-dir label, the
    exact .dnsid-local path) is the one publishing DNS on 127.0.0.1:<port>."""
    try:
        cp = _run(["docker", "ps", "--filter", "status=running",
                   "--filter", f"label=com.docker.compose.project.working_dir={LOCAL}",
                   "--filter", "label=com.docker.compose.service=dns-host", "--format", "{{.Ports}}"],
                  capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(EXIT_RESOLVER, f"could not inspect Docker to confirm resolver ownership ({type(exc).__name__})")
    if cp.returncode != 0:
        fail(EXIT_RESOLVER, "could not inspect Docker to confirm resolver ownership")
    owned = owned_dns_ports(cp.stdout)
    if port not in owned:
        fail(EXIT_RESOLVER, f"127.0.0.1:{port} is not served by this recipe's own running DNSid Local DNS "
                            f"container (it publishes {owned or 'nothing'}); start it with make bootstrap")


def resolver_healthy(port: int) -> bool:
    try:
        cp = _run(["dig", "@127.0.0.1", "-p", str(port), "+time=2", "+tries=1", _ZONE, "SOA", "+short"],
                  capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return cp.returncode == 0 and bool(cp.stdout.strip())


_RESOLVER: str | None = None


def local_resolver() -> str:
    """This recipe's own resolver, independently established. The CLI's DNSID_DNS_SERVER is only compared,
    never trusted: it has been observed to name the default port (7753, possibly another instance)."""
    global _RESOLVER
    if _RESOLVER:
        return _RESOLVER
    try:
        cfg = (LOCAL / "config.yml").read_text()
    except OSError:
        fail(EXIT_RESOLVER, "this recipe's DNSid Local config.yml is missing: cannot establish its resolver")
    port = configured_dns_port(cfg, DNS_PORT)
    verify_resolver_owner(port)
    ours = f"127.0.0.1:{port}"
    cli = base_env().get("DNSID_DNS_SERVER", "")
    if cli != ours:
        print(f"NOTE: the dnsid CLI reports DNSID_DNS_SERVER={cli or '(unset)'}, but this recipe's DNSid Local "
              f"serves DNS on {ours} (config.yml dnsPort, confirmed by its running container); "
              "ignoring the CLI value", file=sys.stderr)
    if not resolver_healthy(port):
        fail(EXIT_RESOLVER, f"this recipe's DNS resolver {ours} does not answer for the {_ZONE} zone")
    _RESOLVER = ours
    return ours


def published_record(name: str) -> dict[str, str]:
    """The signer's PUBLISHED _dnsid record, read from this recipe's own, verified resolver."""
    host, _, port = local_resolver().rpartition(":")
    for _ in range(20):
        try:
            cp = _run(["dig", f"@{host}", "-p", port, "+time=2", "+tries=1", f"_dnsid.{name}", "TXT", "+short"],
                      capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            fail(EXIT_RESOLVER, f"this recipe's DNS resolver {host}:{port} stopped answering")
        if cp.returncode == 0 and cp.stdout.strip():
            try:
                return parse_dnsid_record(cp.stdout)
            except RecordError as exc:
                fail(EXIT_RECORD, f"malformed _dnsid record for {name}: {exc}")
        if cp.returncode == 9:  # dig: no reply from server
            fail(EXIT_RESOLVER, f"this recipe's DNS resolver {host}:{port} stopped answering")
        _sleep(1)
    fail(EXIT_RECORD, f"no published _dnsid record for {name} on this recipe's resolver {host}:{port}")


def published_lr(name: str) -> str:
    """The lr= value from the PUBLISHED _dnsid record (the authoritative log reference)."""
    lr = published_record(name).get("lr", "").replace(" ", "")
    if not lr:
        fail(EXIT_RECORD, f"no published lr= for {name}")
    return lr


def cmd_publisher_env(out: str, signer_dir: str) -> None:
    name = current()
    env = agent_env(name)
    missing = PUBLISHER_ENV_REQUIRED - env.keys()
    if missing:
        die(f"CLI environment for {name} lacks {sorted(missing)}")
    if env["DNSID_DOMAIN"].lower().rstrip(".") != name:
        die("CLI environment is for a different identity")
    if env["DNSID_GOVERNANCE_ID"].lower().rstrip(".") != GOVERNANCE:
        die(f"signer governance is {env['DNSID_GOVERNANCE_ID']!r}, expected {GOVERNANCE}")
    # Prefer the published record's log reference if the exported one differs (it is what verifiers use).
    lr = published_lr(name)
    if lr != env.get("DNSID_LOG_REF"):
        print(f"note: using the published lr= for {name} (the exported DNSID_LOG_REF differed)", file=sys.stderr)
        env["DNSID_LOG_REF"] = lr
    # Copy ONLY this signer's key directory; it must live inside this recipe's local registry state.
    out_p, dst = output_path(out), output_path(signer_dir)
    src = Path(env.get("DNSID_CONFIG_DIR", "")).resolve()
    if not src.is_dir() or LOCAL not in src.parents:
        die("signer key directory is not inside this recipe's local registry state")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=False)
    for p in [dst, *dst.rglob("*")]:
        os.chmod(p, 0o750 if p.is_dir() else 0o640)  # group-readable for the container, never world
    lines = [f"{k}={env[k]}\n" for k in sorted(PUBLISHER_ENV_KEYS & env.keys())]
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text("".join(lines))
    os.chmod(out_p, 0o640)
    print(f"publisher env written for {name} ({len(lines)} keys, no API key)")


def fetch_local_https(url: str, ca: str) -> bytes:
    """GET a local-registry HTTPS URL from the host: resolve its .test host to the local TLS proxy."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not (u.hostname or "").endswith(".test"):
        die(f"refusing non-local URL {url}")
    port = u.port or 443
    try:
        cp = _run(["curl", "-sf", "--max-time", "10", "--resolve", f"{u.hostname}:{port}:127.0.0.1",
                   "--cacert", ca, url], capture_output=True, timeout=20)
    except subprocess.TimeoutExpired:
        fail(EXIT_REGISTRY_UNCERTAIN, f"timed out fetching {url} from this recipe's local TLS proxy")
    if cp.returncode != 0:
        fail(EXIT_REGISTRY_UNCERTAIN, f"could not fetch {url} from this recipe's local TLS proxy "
                                      f"(curl exit {cp.returncode})")
    return cp.stdout


def entity_key_url(name: str) -> str:
    """Locate the governance entity-key document from the signer's published record (the CLI does not
    export DNSID_EK_URL; if a future CLI does, it must match)."""
    cli_ek = agent_env(name).get("DNSID_EK_URL")
    try:
        return validate_entity_key_url(published_record(name), GOVERNANCE, cli_ek)
    except GovernanceMismatch as exc:
        fail(EXIT_GOVERNANCE, str(exc))
    except RecordError as exc:
        fail(EXIT_RECORD, str(exc))


def entity_thumbprints(doc_bytes: bytes) -> list[str]:
    """Thumbprints of the keys in an entity-key document; a malformed or empty document is EXIT_RECORD."""
    from dnsid.models import JWK  # noqa: PLC0415
    try:
        doc = json.loads(doc_bytes)
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(keys, list):
            raise ValueError("no keys array")
        thumbs = sorted(JWK.from_dict(k).thumbprint() for k in keys)
    except Exception as exc:  # noqa: BLE001 - any parse failure is a malformed document
        fail(EXIT_RECORD, f"malformed {GOVERNANCE} entity-key document ({type(exc).__name__})")
    if not thumbs:
        fail(EXIT_RECORD, f"the {GOVERNANCE} entity-key document lists no keys")
    return thumbs


def current_entity_thumbprints() -> list[str]:
    ek = entity_key_url(current())
    return entity_thumbprints(fetch_local_https(ek, base_env()["DNSID_CA_BUNDLE"]))


def cmd_pin(out: str) -> None:
    """Trusted first-time setup only: write the pin. Never replaces an existing pin (use `pin --check`)."""
    out_p = output_path(out)
    if out_p.exists():
        die(f"{out_p} already exists: refusing to re-pin (compare with `pin --check`; start over deliberately "
            "with make clean CONFIRM=delete-checkpoint-history)", 3)
    thumbs = current_entity_thumbprints()
    out_p.write_text(json.dumps(thumbs) + "\n")
    os.chmod(out_p, 0o644)
    print(f"pinned {GOVERNANCE} entity key thumbprint(s): {thumbs}")


def cmd_pin_check(pinned: str) -> None:
    """Fail if the local registry no longer serves the pinned entity key (its state was replaced). Restarting
    must reuse preserved trust, never quietly adopt a new baseline."""
    try:
        want = json.loads(output_path(pinned).read_text())
    except (OSError, ValueError):
        fail(EXIT_USAGE, f"the preserved pin file {pinned} is missing or unreadable")
    have = current_entity_thumbprints()
    if not set(want) & set(have):
        fail(EXIT_ENTITY_KEY,
             f"the local registry's {GOVERNANCE} entity key {have} does not match the pinned {want}: its state "
             "was replaced. Keep the pin (the controller will deny) or start over deliberately: "
             "make clean CONFIRM=delete-checkpoint-history")
    print("pinned entity key still served")


def cmd_log_policy(out: str) -> None:
    env = base_env()
    doc = fetch_local_https(env["DNSID_LOG_POLICY_URL"], env["DNSID_CA_BUNDLE"])
    if not doc.startswith(b"log "):
        die("unexpected log policy document")
    output_path(out).write_bytes(doc)
    print(f"log trust policy captured from DNSID_LOG_POLICY_URL ({len(doc)} bytes)")


def cmd_revoke(yes: bool) -> None:
    name = current()
    if not yes:
        die("revocation is permanent; pass --yes", 2)
    if registry_state(name) == "REVOKED":
        print(json.dumps({"revoked": name, "registry_state": "REVOKED", "note": "already revoked"}))
        return
    t0 = time.time()
    cp = ensure(name, "dnsid", "revoke", "--domain", name, "--reason", "owner_request", "--yes")
    # The local registry can take a while to append and witness the REVOCATION event; confirm the
    # outcome from the registry rather than trusting the CLI call's exit status alone.
    if not wait_state(name, "REVOKED", 90):
        die(f"revoke did not take effect (CLI exit {cp.returncode}): {cp.stderr.strip()[-300:]}")
    print(json.dumps({"revoked": name, "registry_state": "REVOKED", "confirmed_after_s": round(time.time() - t0, 1)}))


def main(argv: list[str]) -> None:
    if not argv:
        print(__doc__)
        sys.exit(2)
    configure()
    cmd, rest = argv[0], argv[1:]
    if cmd == "ensure-active" and rest in ([], ["--first-enrollment"]):
        cmd_ensure_active(first_enrollment=bool(rest))
    elif cmd == "current":
        print(current())
    elif cmd == "state":
        print(registry_state(guard(rest[0]) if rest else current()))
    elif cmd == "publisher-env" and len(rest) == 2:
        cmd_publisher_env(rest[0], rest[1])
    elif cmd == "pin" and len(rest) == 1:
        cmd_pin(rest[0])
    elif cmd == "pin" and len(rest) == 2 and rest[0] == "--check":
        cmd_pin_check(rest[1])
    elif cmd == "log-policy" and len(rest) == 1:
        cmd_log_policy(rest[0])
    elif cmd == "revoke":
        cmd_revoke("--yes" in rest)
    elif cmd == "local-env" and len(rest) == 1:
        val = base_env().get(rest[0], "")
        if not val:
            die(f"{rest[0]} is not in the local registry environment")
        print(val)
    else:
        die(f"unknown or incomplete command: {' '.join(argv)}", 2)


if __name__ == "__main__":
    main(sys.argv[1:])
