"""Start decisions for this recipe's DNSid-layer containers (controller, publisher), stdlib only.

The CLI-managed local registry network is deleted by `dnsid local down` and recreated by `dnsid local up` under
the SAME name with a NEW Docker ID. A stopped container still references the old ID and cannot start, and
Compose does not notice (its configuration is unchanged). This module decides, from `docker inspect` JSON,
whether a service's container can be kept, started normally, or must be recreated, and fails closed on
anything it cannot attribute to this recipe.

    NET_JSON='<docker network inspect NET>' CTR_JSON='<docker inspect IDS or []>' \
    python3 -I scripts/dnsid_service.py plan --service S --project P --working-dir DIR \
        --network NET --local-project LP
        stdout: keep | start | recreate   (exit 0);  a reason on stderr and exit 1 otherwise

    CTR_JSON=... NET_JSON=... python3 -I scripts/dnsid_service.py verify-controller --project P \
        --working-dir DIR --network NET --root-ca PATH
        exit 0 and a secret-free summary, or exit 1 with the first discrepancy
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import PurePosixPath

KEEP, START, RECREATE = "keep", "start", "recreate"
_NET_ID = re.compile(r"^[0-9a-f]{64}$")
STOPPED = {"exited", "created"}
# Environment variable names that must never reach the controller (it holds no registry credentials).
FORBIDDEN_ENV = re.compile(r"^(DNSID_API_KEY|.*(SECRET|PASSWORD|PRIVATE_KEY|TOKEN)[A-Z_]*)$")


class Uncertain(Exception):
    """Ownership, state or configuration could not be established: do nothing."""


def _labels(obj: dict, where: str) -> dict:
    labels = (obj.get("Labels") if "Labels" in obj else (obj.get("Config") or {}).get("Labels")) or {}
    if not isinstance(labels, dict):
        raise Uncertain(f"{where} has unreadable labels")
    return labels


def check_network(net: object, name: str, local_project: str) -> str:
    """Return the current network ID if `net` is exactly this recipe's DNSid Local network."""
    if isinstance(net, list):
        if len(net) != 1:
            raise Uncertain(f"expected exactly one network named {name}, got {len(net)}")
        net = net[0]
    if not isinstance(net, dict):
        raise Uncertain("unreadable network inspection")
    if net.get("Name") != name:
        raise Uncertain(f"network inspection returned {net.get('Name')!r}, expected {name!r}")
    lab = _labels(net, f"network {name}")
    if lab.get("com.docker.compose.project") != local_project or lab.get("com.docker.compose.network") != "local":
        raise Uncertain(f"network {name} is not owned by this recipe's DNSid Local ({local_project})")
    nid = net.get("Id", "")
    if not isinstance(nid, str) or not _NET_ID.match(nid):
        raise Uncertain(f"network {name} has no valid ID")
    return nid


def check_container_owner(c: dict, project: str, service: str, working_dir: str) -> None:
    lab = _labels(c, "container")
    want = {"com.docker.compose.project": project, "com.docker.compose.service": service,
            "com.docker.compose.project.working_dir": working_dir, "com.docker.compose.oneoff": "False"}
    for k, v in want.items():
        if lab.get(k) != v:
            raise Uncertain(f"container {c.get('Name', '?')} does not belong to {project}/{service} ({k})")


def plan(net: object, containers: object, *, service: str, project: str, working_dir: str, network: str,
         local_project: str) -> tuple[str, str]:
    net_id = check_network(net, network, local_project)
    if not isinstance(containers, list):
        raise Uncertain("unreadable container inspection")
    if not containers:
        return START, f"no {service} container yet"
    if len(containers) > 1:
        raise Uncertain(f"{len(containers)} {service} containers exist; expected at most one")
    c = containers[0]
    if not isinstance(c, dict):
        raise Uncertain("unreadable container inspection")
    check_container_owner(c, project, service, working_dir)
    state = (c.get("State") or {})
    status = state.get("Status")
    nets = ((c.get("NetworkSettings") or {}).get("Networks")) or {}
    if not isinstance(nets, dict) or network not in nets or not isinstance(nets[network], dict):
        raise Uncertain(f"{service} container is not attached to {network}")
    attached = nets[network].get("NetworkID", "")
    if status == "running":
        health = (state.get("Health") or {}).get("Status")
        if attached == net_id and health == "healthy":
            return KEEP, f"{service} is running and healthy on the current {network}"
        raise Uncertain(f"{service} is running but {'unhealthy (' + str(health) + ')' if attached == net_id else 'attached to a previous ' + network}; not restarting it automatically")
    if status not in STOPPED:
        raise Uncertain(f"{service} container is {status!r}; expected running or stopped")
    if attached == net_id:
        return START, f"stopped {service} is attached to the current {network}"
    return RECREATE, (f"stopped {service} references a previous {network} (ID {str(attached)[:12]}, now "
                      f"{net_id[:12]}): DNSid Local recreated its network")


def _norm(src: str) -> str:
    """Docker Desktop reports some bind sources as /host_mnt/<host path>."""
    return src[len("/host_mnt"):] if src.startswith("/host_mnt/") else src


def controller_mounts(working_dir: str, root_ca: str, project: str) -> dict[str, tuple[str, str, bool]]:
    """destination -> (type, source or volume name, read-write). All controller state is in the recipe's
    .state directory or the shared SPIRE socket volume, so recreating the container loses nothing."""
    r = PurePosixPath(working_dir)
    return {
        "/var/lib/dnsidfed": ("bind", str(r / ".state/controller/data"), True),
        "/etc/dnsidfed/policy.toml": ("bind", str(r / ".state/controller/policy.toml"), False),
        "/etc/dnsidfed/log-policy.txt": ("bind", str(r / ".state/dnsid/log-policy.txt"), False),
        "/etc/dnsidfed/admin-token": ("bind", str(r / ".state/controller/admin-token"), False),
        "/dnsid/root-ca.pem": ("bind", root_ca, False),
        "/run/spire/server": ("volume", f"{project}_acme-server-admin", True),
    }


def verify_controller(c: object, net: object, *, project: str, working_dir: str, network: str,
                      local_project: str, root_ca: str) -> str:
    if isinstance(c, list):
        if len(c) != 1:
            raise Uncertain(f"expected one controller container, got {len(c)}")
        c = c[0]
    if not isinstance(c, dict):
        raise Uncertain("unreadable container inspection")
    net_id = check_network(net, network, local_project)
    check_container_owner(c, project, "acme-dnsid-controller", working_dir)
    state = c.get("State") or {}
    if state.get("Status") != "running" or (state.get("Health") or {}).get("Status") != "healthy":
        raise Uncertain("controller is not running and healthy")
    nets = (c.get("NetworkSettings") or {}).get("Networks") or {}
    if set(nets) != {network, f"{project}_default"}:
        raise Uncertain(f"controller networks are {sorted(nets)}, expected {network} and {project}_default")
    if nets[network].get("NetworkID") != net_id:
        raise Uncertain(f"controller is not attached to the current {network}")
    want = controller_mounts(working_dir, root_ca, project)
    got = {}
    for m in c.get("Mounts") or []:
        src = m.get("Name") if m.get("Type") == "volume" else _norm(m.get("Source", ""))
        got[m.get("Destination")] = (m.get("Type"), src, bool(m.get("RW")))
    if got != want:
        diff = sorted(d for d in set(got) | set(want) if got.get(d) != want.get(d))
        raise Uncertain(f"controller mounts differ from the expected configuration at {diff}")
    cfg = c.get("Config") or {}
    if cfg.get("User") != "1000:1000":
        raise Uncertain("controller does not run as uid/gid 1000")
    names = sorted({e.split("=", 1)[0] for e in cfg.get("Env") or []})
    bad = [n for n in names if FORBIDDEN_ENV.match(n)]
    if bad:
        raise Uncertain(f"controller environment contains credential-like variables {bad}")
    return (f"networks: {network} (current ID {net_id[:12]}) + {project}_default; mounts: {len(want)} as "
            f"expected (state in .state/, bind-mounted); user 1000:1000; env names: {', '.join(names)}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="dnsid_service.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "verify-controller"):
        p = sub.add_parser(name)
        p.add_argument("--project", required=True)
        p.add_argument("--working-dir", required=True)
        p.add_argument("--network", required=True)
        p.add_argument("--local-project", required=True)
        if name == "plan":
            p.add_argument("--service", required=True)
        else:
            p.add_argument("--root-ca", required=True)
    a = ap.parse_args(argv)
    try:
        net = json.loads(os.environ.get("NET_JSON", ""))
        ctr = json.loads(os.environ.get("CTR_JSON", ""))
    except ValueError:
        print("unreadable docker inspection output", file=sys.stderr)
        return 1
    common = dict(project=a.project, working_dir=a.working_dir, network=a.network, local_project=a.local_project)
    try:
        if a.cmd == "plan":
            action, why = plan(net, ctr, service=a.service, **common)
            print(action)
            print(why, file=sys.stderr)
        else:
            print(verify_controller(ctr, net, root_ca=a.root_ca, **common))
    except Uncertain as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
