"""Idempotent, verified SPIRE registration (scripts/spire_entry.py and ensure_entry in scripts/lib.sh). Offline:
the shell functions run in bash against a stubbed `spire_server`; no Docker or SPIRE."""
import json
import re
import subprocess
from pathlib import Path

import pytest

import spire_entry as SE

ROOT = Path(__file__).resolve().parents[1]
LIB = (ROOT / "scripts" / "lib.sh").read_text()

SUPPLIER = "spiffe://rackloria.test/supplier-api"
PARENT = "spiffe://rackloria.test/node/agent"


def entry(path="/supplier-api", td="rackloria.test", parent=("rackloria.test", "/node/agent"),
          selectors=(("unix", "uid:10003"),), fed=("acme.test",), **over):
    e = {"admin": False, "created_at": "1795131938", "dns_names": [], "downstream": False, "expires_at": "0",
         "federates_with": list(fed), "hint": "", "id": "6024c1a5", "jwt_svid_ttl": 0,
         "parent_id": {"path": parent[1], "trust_domain": parent[0]}, "revision_number": "0",
         "selectors": [{"type": t, "value": v} for t, v in selectors],
         "spiffe_id": {"path": path, "trust_domain": td}, "store_svid": False, "x509_svid_ttl": 0}
    e.update(over)
    return e


def answer(*entries, token=""):
    return json.dumps({"entries": list(entries), "next_page_token": token})


WANT = SE.expected(SUPPLIER, PARENT, ["unix:uid:10003"], ["spiffe://acme.test"])


# ------------------------------------------------------------------ classification (spire_entry.py)
def test_existing_matching_entry():
    assert SE.classify(answer(entry()), WANT)[0] == SE.MATCH


def test_confirmed_missing_entry():
    assert SE.classify(answer(), WANT)[0] == SE.MISSING


@pytest.mark.parametrize("bad", [
    entry(selectors=(("unix", "uid:0"),)),                               # wrong selector
    entry(selectors=(("unix", "uid:10003"), ("unix", "gid:0"))),         # extra selector
    entry(selectors=()),                                                 # no selector
    entry(parent=("rackloria.test", "/node/other")),                     # wrong parent
    entry(parent=("acme.test", "/node/agent")),                          # parent in another trust domain
    entry(fed=()),                                                       # federation relationship missing
    entry(fed=("acme.test", "evil.test")),                               # extra federation relationship
    entry(fed=("other.test",)),                                          # wrong federation relationship
    entry(admin=True),                                                   # privileged constraints
    entry(downstream=True),
    entry(store_svid=True),
    entry(dns_names=["supplier.rackloria.test"]),
    entry(x509_svid_ttl=31536000),
    entry(expires_at="1"),
    entry(hint="x"),
])
def test_security_relevant_differences_are_mismatches(bad):
    code, msg = SE.classify(answer(bad), WANT)
    assert code == SE.MISMATCH and "differs" in msg


def test_unrelated_metadata_is_ignored():
    assert SE.classify(answer(entry(id="other", created_at="1", revision_number="7")), WANT)[0] == SE.MATCH


def test_federation_spelled_either_way_is_equivalent():
    want = SE.expected(SUPPLIER, PARENT, ["unix:uid:10003"], ["acme.test"])
    assert SE.classify(answer(entry(fed=("acme.test",))), want)[0] == SE.MATCH


def test_duplicate_entries_are_ambiguous_even_if_one_matches():
    assert SE.classify(answer(entry(), entry(id="dup")), WANT)[0] == SE.AMBIGUOUS


def test_paged_answer_is_ambiguous():
    assert SE.classify(answer(entry(), token="next"), WANT)[0] == SE.AMBIGUOUS


@pytest.mark.parametrize("out", [
    "", "Entry ID : 6024c1a5", "not json", "[]", '{"entries": "x"}', '{"next_page_token": ""}',
    answer({"spiffe_id": "flat-string"}),
    answer(dict(entry(), selectors=None)),
    answer(entry(federates_with="acme.test")),
    answer("not-an-object"),
    answer(entry(path="/other")),                                        # answer for a different SPIFFE ID
])
def test_unreadable_output_is_malformed(out):
    assert SE.classify(out, WANT)[0] == SE.MALFORMED


# ------------------------------------------------------------------ ensure_entry in bash, spire_server stubbed
def shell_fn(name):
    return re.search(rf"^{name}\(\) \{{.*?^\}}", LIB, re.S | re.M).group(0)


HARNESS = f"""
set -euo pipefail
ROOT={str(ROOT)!r}
ok()  {{ printf 'OK %s\\n' "$*"; }}
die() {{ printf 'DIE %s\\n' "$*"; exit 1; }}
CALLS=$1; shift
# spire_server stub: lookups replay queued answers ($LOOKUPS dir, one file per call); creates are logged.
spire_server() {{   # called inside $(...): the lookup counter must live in a file, not a shell variable
  printf '%s\\n' "$*" >> "$CALLS"
  local n
  case "$3" in
    show)
      n=$(( $(cat "$LOOKUPS/n" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$LOOKUPS/n"
      if [ -f "$LOOKUPS/$n.rc" ]; then cat "$LOOKUPS/$n.out" 2>/dev/null; return "$(cat "$LOOKUPS/$n.rc")"; fi
      cat "$LOOKUPS/$n.out" ;;
    create) cat "$LOOKUPS/create.out" 2>/dev/null; return "$(cat "$LOOKUPS/create.rc" 2>/dev/null || echo 0)" ;;
    *) echo "unexpected spire_server call: $*" >&2; return 99 ;;
  esac
}}
{shell_fn("entry_check")}
{shell_fn("ensure_entry")}
ensure_entry rackloria {SUPPLIER} 10003 spiffe://acme.test
"""


def run_ensure(tmp_path, lookups, create=(0, "")):
    d = tmp_path / "lookups"
    d.mkdir()
    for i, item in enumerate(lookups, 1):
        out, rc = item if isinstance(item, tuple) else (item, None)
        (d / f"{i}.out").write_text(out)
        if rc is not None:
            (d / f"{i}.rc").write_text(str(rc))
    (d / "create.rc").write_text(str(create[0]))
    (d / "create.out").write_text(create[1])
    calls = tmp_path / "calls"
    calls.write_text("")
    p = subprocess.run(["bash", "-c", HARNESS, "harness", str(calls)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "LOOKUPS": str(d)})
    verbs = [ln.split()[2] for ln in calls.read_text().splitlines()]   # "<org> entry <verb> ..."
    return p, verbs


ALREADY = 'Failed to create the following entry (code: AlreadyExists, msg: "similar entry already exists")'


def test_bash_existing_matching_entry_is_reused(tmp_path):
    p, verbs = run_ensure(tmp_path, [answer(entry())])
    assert p.returncode == 0 and "existing registration verified" in p.stdout
    assert verbs == ["show"]                                   # never creates


def test_bash_confirmed_missing_entry_is_created(tmp_path):
    p, verbs = run_ensure(tmp_path, [answer()])
    assert p.returncode == 0 and "(created)" in p.stdout
    assert verbs == ["show", "create"]


def test_bash_already_exists_then_matching_is_accepted(tmp_path):
    p, verbs = run_ensure(tmp_path, [answer(), answer(entry())], create=(1, ALREADY))
    assert p.returncode == 0 and "already present; verified matching" in p.stdout
    assert verbs == ["show", "create", "show"]


@pytest.mark.parametrize("second", [
    answer(entry(selectors=(("unix", "uid:0"),))),
    answer(entry(parent=("rackloria.test", "/node/other"))),
    answer(entry(fed=())),
    answer(entry(), entry(id="dup")),
    "garbage",
    (answer(entry()), 1),                                      # the fresh lookup itself fails
])
def test_bash_already_exists_then_mismatch_fails_and_touches_nothing(tmp_path, second):
    p, verbs = run_ensure(tmp_path, [answer(), second], create=(1, ALREADY))
    assert p.returncode != 0 and "DIE SPIRE REGISTRATION" in p.stdout and "not modified" in p.stdout
    assert verbs == ["show", "create", "show"]                 # no second create, no update, no delete


def test_bash_other_create_error_fails(tmp_path):
    p, verbs = run_ensure(tmp_path, [answer()], create=(1, "Error: permission denied"))
    assert p.returncode != 0 and "failed to create entry" in p.stdout and verbs == ["show", "create"]


@pytest.mark.parametrize("first", [
    (answer(entry()), 1),                                      # lookup failed (exit 1) even with output
    ("", 137),                                                 # lookup killed
])
def test_bash_lookup_failure_never_creates(tmp_path, first):
    p, verbs = run_ensure(tmp_path, [first])
    assert p.returncode != 0 and "could not confirm" in p.stdout
    assert verbs == ["show"]


@pytest.mark.parametrize("first", ["Entry ID : 6024c1a5", "", answer(entry(), entry(id="dup")),
                                   answer(entry(selectors=(("unix", "uid:0"),)))])
def test_bash_unreadable_ambiguous_or_mismatched_existing_never_creates(tmp_path, first):
    p, verbs = run_ensure(tmp_path, [first])
    assert p.returncode != 0 and "could not confirm" in p.stdout
    assert verbs == ["show"]


# ------------------------------------------------------------------ the original pipeline failure
PRODUCER = """
spire_server() {  # a present entry, followed by more output than a pipe buffer holds
  printf 'Entry ID : 6024c1a5\\n'
  printf '%s\\n' "$1" > /dev/null
  head -c 300000 /dev/zero | tr '\\0' ' '
}
"""


def test_original_grep_q_pipefail_pattern_reports_a_present_entry_as_absent():
    """Reproduces the bootstrap failure deterministically: grep -q exits at the first match, the writer is
    killed by SIGPIPE, and pipefail turns the pipeline false although the entry is present."""
    script = "set -o pipefail\n" + PRODUCER + (
        "if spire_server x | grep -q 'Entry ID'; then echo present; else echo absent; fi")
    assert subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout.strip() == "absent"


def test_new_lookup_with_large_output_still_matches(tmp_path):
    padded = answer(entry()) + " " * 300000                  # same size class as the failing case
    p, verbs = run_ensure(tmp_path, [padded])
    assert p.returncode == 0 and "existing registration verified" in p.stdout and verbs == ["show"]


def test_no_early_exit_reader_in_bootstrap_or_lib():
    for f in ("scripts/bootstrap.sh", "scripts/lib.sh"):
        code = "\n".join(ln for ln in (ROOT / f).read_text().splitlines() if not ln.lstrip().startswith("#"))
        assert not re.search(r"spire_server[^\n]*\|\s*grep -q", code), f


# ------------------------------------------------------------------ controller-managed federation on purchasing
# After an ALLOW, Acme's DNSid controller adds rackloria.test to purchasing's federatesWith (reconcile.py,
# ensure_federates). A bootstrap re-run must accept exactly that, and nothing more.
PURCHASING = "spiffe://acme.test/purchasing"
ACME_PARENT = "spiffe://acme.test/node/agent"
CONTROLLER_TD = "rackloria.test"
WANT_P = SE.expected(PURCHASING, ACME_PARENT, ["unix:uid:10001"], [])


def purchasing(fed=(), **over):
    e = entry(path="/purchasing", td="acme.test", parent=("acme.test", "/node/agent"),
              selectors=(("unix", "uid:10001"),), fed=fed)
    e.update(over)      # raw SPIRE-JSON overrides (selectors, parent_id, admin, ...)
    return e


@pytest.mark.parametrize("fed", [(), (CONTROLLER_TD,)])
def test_purchasing_accepts_no_federation_or_the_controller_managed_one(fed):
    assert SE.classify(answer(purchasing(fed=fed)), WANT_P, [CONTROLLER_TD])[0] == SE.MATCH


def test_allowance_spelled_as_spiffe_uri_is_equivalent():
    assert SE.classify(answer(purchasing(fed=(CONTROLLER_TD,))), WANT_P, ["spiffe://rackloria.test"])[0] == SE.MATCH


def test_without_the_allowance_controller_federation_is_still_a_mismatch():
    code, msg = SE.classify(answer(purchasing(fed=(CONTROLLER_TD,))), WANT_P)
    assert code == SE.MISMATCH and "federates_with" in msg


@pytest.mark.parametrize("fed", [
    ("evil.test",),                        # an unexpected domain instead
    (CONTROLLER_TD, "evil.test"),          # the allowed domain plus an unexpected one
    ("acme.test",),                        # its own trust domain
    (CONTROLLER_TD, CONTROLLER_TD),        # duplicated
])
def test_purchasing_rejects_unexpected_federation(fed):
    code, msg = SE.classify(answer(purchasing(fed=fed)), WANT_P, [CONTROLLER_TD])
    assert code == SE.MISMATCH and "federates_with" in msg


@pytest.mark.parametrize("over", [
    {"admin": True}, {"downstream": True}, {"store_svid": True}, {"dns_names": ["purchasing-dns.test"]},
    {"x509_svid_ttl": 31536000}, {"expires_at": "1"}, {"hint": "x"},
    {"selectors": [{"type": "unix", "value": "uid:0"}]},
    {"parent_id": {"trust_domain": "acme.test", "path": "/node/other"}},
])
def test_allowance_never_relaxes_any_other_field(over):
    code, msg = SE.classify(answer(purchasing(fed=(CONTROLLER_TD,), **over)), WANT_P, [CONTROLLER_TD])
    assert code == SE.MISMATCH and "federates_with" not in msg


def test_allowance_does_not_satisfy_a_required_federation():
    # supplier REQUIRES acme.test; allowing it is not the same as having it.
    assert SE.classify(answer(entry(fed=())), WANT, ["acme.test"])[0] == SE.MISMATCH


def test_cli_passes_the_allowance(tmp_path):
    args = ["check", "--spiffe-id", PURCHASING, "--parent", ACME_PARENT, "--selector", "unix:uid:10001"]
    data = answer(purchasing(fed=(CONTROLLER_TD,)))
    strict = subprocess.run(["python3", "-I", str(ROOT / "scripts" / "spire_entry.py"), *args],
                            input=data, capture_output=True, text=True, check=False)
    allowed = subprocess.run(["python3", "-I", str(ROOT / "scripts" / "spire_entry.py"), *args,
                              "--allow-federates-with", CONTROLLER_TD], input=data, capture_output=True, text=True,
                             check=False)
    assert (strict.returncode, allowed.returncode) == (SE.MISMATCH, SE.MATCH)


PURCHASING_CALL = f'ensure_entry acme {PURCHASING} 10001 "" {CONTROLLER_TD}'


def run_ensure_call(tmp_path, call, lookups, create=(0, "")):
    global HARNESS
    saved = HARNESS
    HARNESS = saved.replace(f"ensure_entry rackloria {SUPPLIER} 10003 spiffe://acme.test", call)
    assert HARNESS != saved
    try:
        p, _ = run_ensure(tmp_path, lookups, create)
    finally:
        HARNESS = saved
    return p, [ln for ln in (tmp_path / "calls").read_text().splitlines() if ln]


def test_bash_purchasing_with_controller_federation_is_reused(tmp_path):
    p, calls = run_ensure_call(tmp_path, PURCHASING_CALL, [answer(purchasing(fed=(CONTROLLER_TD,)))])
    assert p.returncode == 0 and "existing registration verified" in p.stdout
    assert [c.split()[2] for c in calls] == ["show"]


def test_bash_purchasing_unexpected_federation_dies_and_touches_nothing(tmp_path):
    p, calls = run_ensure_call(tmp_path, PURCHASING_CALL, [answer(purchasing(fed=(CONTROLLER_TD, "evil.test")))])
    assert p.returncode != 0 and "DIE SPIRE REGISTRATION" in p.stdout
    assert [c.split()[2] for c in calls] == ["show"]


def test_bash_missing_purchasing_is_created_without_federation(tmp_path):
    p, calls = run_ensure_call(tmp_path, PURCHASING_CALL, [answer()])
    assert p.returncode == 0 and "(created)" in p.stdout
    create = [c for c in calls if c.split()[2] == "create"]
    assert len(create) == 1 and "federatesWith" not in create[0] and CONTROLLER_TD not in create[0]


@pytest.mark.parametrize("second,ok", [
    (answer(purchasing(fed=(CONTROLLER_TD,))), True),     # controller federated it meanwhile: accepted
    (answer(purchasing()), True),
    (answer(purchasing(fed=("evil.test",))), False),
    (answer(purchasing(fed=(CONTROLLER_TD,), admin=True)), False),
])
def test_bash_purchasing_already_exists_recovery_uses_the_same_allowance(tmp_path, second, ok):
    p, calls = run_ensure_call(tmp_path, PURCHASING_CALL, [answer(), second], create=(1, ALREADY))
    assert (p.returncode == 0) is ok
    assert [c.split()[2] for c in calls] == ["show", "create", "show"]
    if not ok:
        assert "not modified" in p.stdout


def test_bash_supplier_stays_strict(tmp_path):
    # The supplier call carries no allowance: an extra federation is still fatal.
    p, verbs = run_ensure(tmp_path, [answer(entry(fed=("acme.test", CONTROLLER_TD)))])
    assert p.returncode != 0 and verbs == ["show"]


# ------------------------------------------------------------------ bootstrap <-> controller policy consistency
def _policy_template():
    import tomllib
    text = (ROOT / "config" / "federation-policy.template.toml").read_text().replace("__PINS__", "[]")
    return tomllib.loads(text)["federation"]


def _bootstrap_entries():
    out = {}
    for ln in (ROOT / "scripts" / "bootstrap.sh").read_text().splitlines():
        if ln.startswith("ensure_entry "):
            args = [a.strip('"') for a in ln.split()[1:]]
            out[args[1]] = args
    return out


def test_bootstrap_allowance_matches_the_controller_policy():
    fed, entries = _policy_template(), _bootstrap_entries()
    allowed = {sid: args[4] for sid, args in entries.items() if len(args) >= 5 and args[4]}
    # Exactly the policy's federated entries get an allowance, and only for the policy's trust domain.
    assert allowed == {sid: fed["trust_domain"] for sid in fed["federated_entries"]}
    for sid in fed["federated_entries"]:
        assert entries[sid][3] == "", "a controller-managed entry must not be created already federated"


def test_bootstrap_never_grants_the_controller_trust_domain_itself():
    # Only the controller writes rackloria.test trust into Acme: bootstrap neither creates an entry federated with
    # it nor sets its bundle in Acme's server.
    td = _policy_template()["trust_domain"]
    code = "\n".join(ln for ln in (ROOT / "scripts" / "bootstrap.sh").read_text().splitlines()
                     if not ln.lstrip().startswith("#"))
    assert not re.search(rf"-federatesWith\s+\S*{re.escape(td)}", code)
    assert not re.search(rf"spire_server acme bundle set[^\n]*{re.escape(td)}", code)
    for sid, args in _bootstrap_entries().items():
        assert len(args) < 4 or td not in args[3], sid
