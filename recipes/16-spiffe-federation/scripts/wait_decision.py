"""Wait for a controller decision in the audit log (JSON Lines) and print it as JSON.

usage: wait_decision.py AUDIT START_INDEX TIMEOUT_S MATCH [MATCH...]
  MATCH = DECISION[:ACTION[:REASON]]   e.g. ALLOW   DENY:WITHDRAWN   DENY:WITHDRAWN:IDENTITY_NOT_ACTIVE
Prints the first decision at index >= START_INDEX that matches any MATCH, plus "_waited_s" (seconds this
script waited). Exit 0 on a match; 1 on timeout (the last decision seen goes to stdout so callers can show it).
Used by verify/verify.sh so each act shows the controller's OWN background decision, not a forced cycle.
"""
import json
import sys
import time

path, start, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
matches = [m.split(":") for m in sys.argv[4:]]


def entries():
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass  # partially written last line
    return out


def ok(e):
    vals = (e.get("decision"), e.get("action"), e.get("reason"))
    return any(all(want == got for want, got in zip(m, vals, strict=False)) for m in matches)  # prefix match


t0 = time.monotonic()
last = {}
while True:
    new = entries()[start:]
    for e in new:
        if ok(e):
            e["_waited_s"] = round(time.monotonic() - t0, 1)
            print(json.dumps(e))
            sys.exit(0)
    if new:
        last = new[-1]
    if time.monotonic() - t0 > timeout:
        print(json.dumps(last))
        sys.exit(1)
    time.sleep(0.5)
