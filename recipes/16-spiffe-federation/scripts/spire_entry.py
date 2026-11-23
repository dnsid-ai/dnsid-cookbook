"""Check a SPIRE registration entry against the exact registration this recipe expects (stdlib only).

    spire-server entry show -spiffeID ID -output json | (captured, then fed on stdin to)
    python3 -I scripts/spire_entry.py check --spiffe-id ID --parent PARENT --selector TYPE:VALUE \
        [--selector ...] [--federates-with TRUST_DOMAIN ...] [--allow-federates-with TRUST_DOMAIN ...]

--federates-with names federation the entry MUST have (it is created with it). --allow-federates-with names a
federation the entry MAY ALSO carry because another component adds and removes it at runtime (in this recipe,
Acme's DNSid federation controller on purchasing). It only widens the accepted federates_with set to
required <= found <= required + allowed; every other field is still compared exactly, any other trust domain
is still a mismatch, and nothing is ever created with an allowed-only federation.

Exit codes (bootstrap.sh acts on them; it never overwrites or deletes an entry):
    0   exactly one entry, and every security-relevant field matches
    10  confirmed missing: a well-formed, complete answer with no entry for this SPIFFE ID
    20  an entry exists but differs from the expected registration
    21  ambiguous: more than one entry for this SPIFFE ID, or an incomplete (paged) answer
    22  unreadable: the lookup output is not a well-formed SPIRE entry list
"""
from __future__ import annotations

import argparse
import json
import sys

MATCH, MISSING, MISMATCH, AMBIGUOUS, MALFORMED = 0, 10, 20, 21, 22


def _id(v) -> str:
    """spiffe://td/path from SPIRE's {"trust_domain": ..., "path": ...} form."""
    if not isinstance(v, dict) or not isinstance(v.get("trust_domain"), str) or not isinstance(v.get("path"), str):
        raise ValueError("malformed SPIFFE ID")
    return f"spiffe://{v['trust_domain']}{v['path']}"


def _td(v: str) -> str:
    return v[len("spiffe://"):] if v.startswith("spiffe://") else v


def describe(entry: dict) -> dict:
    """The security-relevant registration of one entry, normalized for comparison."""
    sels = entry.get("selectors")
    if not isinstance(sels, list) or not all(isinstance(s, dict) and isinstance(s.get("type"), str)
                                            and isinstance(s.get("value"), str) for s in sels):
        raise ValueError("malformed selectors")
    fed = entry.get("federates_with", [])
    dns = entry.get("dns_names", [])
    if not isinstance(fed, list) or not all(isinstance(t, str) for t in fed):
        raise ValueError("malformed federates_with")
    if not isinstance(dns, list) or not all(isinstance(d, str) for d in dns):
        raise ValueError("malformed dns_names")
    return {
        "spiffe_id": _id(entry.get("spiffe_id")),
        "parent_id": _id(entry.get("parent_id")),
        "selectors": sorted(f"{s['type']}:{s['value']}" for s in sels),
        "federates_with": sorted(_td(t) for t in fed),
        # Constraints this recipe never sets: any other value is an unexpected (more privileged) entry.
        "admin": entry.get("admin", False),
        "downstream": entry.get("downstream", False),
        "store_svid": entry.get("store_svid", False),
        "dns_names": sorted(dns),
        "x509_svid_ttl": int(entry.get("x509_svid_ttl", 0) or 0),
        "jwt_svid_ttl": int(entry.get("jwt_svid_ttl", 0) or 0),
        "expires_at": int(entry.get("expires_at", 0) or 0),
        "hint": entry.get("hint", ""),
    }


def expected(spiffe_id: str, parent: str, selectors: list[str], federates_with: list[str]) -> dict:
    return {"spiffe_id": spiffe_id, "parent_id": parent, "selectors": sorted(selectors),
            "federates_with": sorted(_td(t) for t in federates_with), "admin": False, "downstream": False,
            "store_svid": False, "dns_names": [], "x509_svid_ttl": 0, "jwt_svid_ttl": 0, "expires_at": 0,
            "hint": ""}


def _federation_ok(found: list[str], required: list[str], allowed: list[str]) -> bool:
    if len(set(found)) != len(found):
        return False
    return set(required) <= set(found) <= set(required) | set(allowed)


def classify(output: str, want: dict, allow_federates_with: list[str] | tuple[str, ...] = ()) -> tuple[int, str]:
    try:
        doc = json.loads(output)
    except ValueError:
        return MALFORMED, "lookup output is not JSON"
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        return MALFORMED, "lookup output has no entries list"
    if doc.get("next_page_token"):
        return AMBIGUOUS, "lookup answer is paged (incomplete)"
    entries = doc["entries"]
    try:
        described = [describe(e) if isinstance(e, dict) else None for e in entries]
    except (ValueError, TypeError) as exc:
        return MALFORMED, f"unreadable entry ({exc})"
    if any(d is None for d in described):
        return MALFORMED, "unreadable entry"
    mine = [d for d in described if d["spiffe_id"] == want["spiffe_id"]]
    if len(mine) != len(described):
        return MALFORMED, "lookup returned entries for another SPIFFE ID"
    if not mine:
        return MISSING, f"no entry for {want['spiffe_id']}"
    if len(mine) > 1:
        return AMBIGUOUS, f"{len(mine)} entries for {want['spiffe_id']}"
    allowed = sorted(_td(t) for t in allow_federates_with)
    diff = sorted(k for k in want if k != "federates_with" and mine[0].get(k) != want[k])
    if not _federation_ok(mine[0]["federates_with"], want["federates_with"], allowed):
        diff = sorted(diff + ["federates_with"])
    if diff:
        detail = "; ".join(f"{k}: found {mine[0].get(k)!r}, expected {want[k]!r}"
                           + (f" (optionally also {allowed!r})" if k == "federates_with" and allowed else "")
                           for k in diff)
        return MISMATCH, f"entry for {want['spiffe_id']} differs: {detail}"
    return MATCH, f"entry for {want['spiffe_id']} matches"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="spire_entry.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--spiffe-id", required=True)
    c.add_argument("--parent", required=True)
    c.add_argument("--selector", action="append", required=True)
    c.add_argument("--federates-with", action="append", default=[])
    c.add_argument("--allow-federates-with", action="append", default=[])
    a = ap.parse_args(argv)
    code, msg = classify(sys.stdin.read(), expected(a.spiffe_id, a.parent, a.selector, a.federates_with),
                         a.allow_federates_with)
    print(msg, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
