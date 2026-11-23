"""verify/verify.sh compares Python results as strings. lib.sh's `json` helper prints a str as-is and anything
else through json.dumps, so a bare boolean prints `true` and never equals `True`. Every value compared with
True/False must therefore be converted with str(...) or produced by a %-format string."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFY = (ROOT / "verify" / "verify.sh").read_text()
LIB = (ROOT / "scripts" / "lib.sh").read_text()
JSON_FN = re.search(r"^json\(\) \{.*?\}$", LIB, re.M).group(0)


def run_json(doc: str, expr: str) -> str:
    script = f'PY=python3\n{JSON_FN}\nprintf %s "$1" | json "$2"'
    return subprocess.run(["bash", "-c", script, "t", doc, expr], capture_output=True, text=True,
                          check=True).stdout.strip()


def test_json_helper_pitfall_and_fix():
    assert run_json('{"ok": true}', 'd["ok"]') == "true"         # the bug: never equal to "True"
    assert run_json('{"ok": true}', 'str(d["ok"])') == "True"    # the fix
    assert run_json('{"ok": false}', 'str(d["ok"])') == "False"


# `is "$(pf|dj|json 'EXPR')" EXPECTED` where EXPECTED mentions True/False
CMP = re.compile(r'''is\s+"\$\((?:pf|dj|json)\s+(['"])(?P<expr>.*?)\1\)"\s+"?(?P<want>[^"\s]*(?:True|False)[^"\s]*)"?''')


def _converted(expr: str) -> bool:
    e = expr.strip()
    return e.startswith("str(") or e.startswith('"') or e.startswith("'")


def test_every_boolean_comparison_is_string_converted():
    found = list(CMP.finditer(VERIFY))
    assert len(found) >= 8                                        # the comparisons exist and were all scanned
    bad = [m.group("expr") for m in found if not _converted(m.group("expr"))]
    assert not bad, f"bare boolean compared with True/False: {bad}"


def test_checkpoint_store_health_check_is_string_converted():
    m = re.search(r"st=\$\(curl[^\n]*\| json '(?P<expr>[^']*)'\)\n\[ \"\$st\" = True \]", VERIFY)
    assert m and m.group("expr").startswith("str("), "checkpoint store health must compare str(...) with True"


def test_handshake_and_store_health_comparisons_evaluate_to_True():
    probe = '{"results": {"inventory": {"new_handshake": {"ok": true}}, "supplier": {"new_handshake": {"ok": true}}}}'
    status = '{"checkpoint_store": {"healthy": true}}'
    exprs = [m.group("expr") for m in CMP.finditer(VERIFY) if "new_handshake\"][\"ok\"]" in m.group("expr")
             and "%" not in m.group("expr")]
    # Acts 1 and 3 internal-mTLS checks and the Act 2 cross-domain check compare a new_handshake "ok" flag
    # with True; each must str() the boolean, or a passing handshake prints "true" and the check fails.
    assert len(exprs) == 3
    assert all(run_json(probe, e) == "True" for e in exprs)
    st = re.search(r"\| json '(str\(d\[\"checkpoint_store\"\]\[\"healthy\"\]\))'", VERIFY).group(1)
    assert run_json(status, st) == "True"                         # starting-point checkpoint store health check
