"""Thin adapter over the supported SPIRE server admin CLI (no plugins, no protocol work)."""
from __future__ import annotations

import json
import subprocess


class SpireError(RuntimeError):
    pass


class SpireAdmin:
    def __init__(self, socket_path: str, binary: str = "spire-server", timeout: float = 20.0):
        self.socket, self.binary, self.timeout = socket_path, binary, timeout

    def _run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        cp = subprocess.run([self.binary, *args, "-socketPath", self.socket], input=stdin,
                            capture_output=True, text=True, timeout=self.timeout)
        return cp

    def get_bundle(self, trust_domain: str) -> dict | None:
        cp = self._run("bundle", "list", "-id", f"spiffe://{trust_domain}", "-format", "spiffe")
        if cp.returncode != 0:
            if "NotFound" in cp.stderr or "not found" in cp.stderr:
                return None
            raise SpireError(f"bundle list failed: {cp.stderr.strip()}")
        return json.loads(cp.stdout)

    def own_bundle(self) -> dict:
        cp = self._run("bundle", "show", "-format", "spiffe")
        if cp.returncode != 0:
            raise SpireError(f"bundle show failed: {cp.stderr.strip()}")
        return json.loads(cp.stdout)

    def set_bundle(self, trust_domain: str, bundle: dict) -> None:
        cp = self._run("bundle", "set", "-format", "spiffe", "-id", f"spiffe://{trust_domain}",
                       stdin=json.dumps(bundle))
        if cp.returncode != 0:
            raise SpireError(f"bundle set failed: {cp.stderr.strip()}")

    def delete_bundle(self, trust_domain: str, mode: str = "dissociate") -> bool:
        """Delete a federated bundle. Returns False if there was nothing to delete.

        mode "dissociate" (enforcement withdrawals) also strips the trust domain from every entry's
        federatesWith. mode "restrict" (orderly shutdown) refuses, raising SpireError, while ANY entry still
        federates with the trust domain, so relationships this controller does not manage are never cut.
        """
        if mode not in ("dissociate", "restrict"):
            raise ValueError(f"unsupported bundle delete mode {mode!r}")
        cp = self._run("bundle", "delete", "-id", f"spiffe://{trust_domain}", "-mode", mode)
        if cp.returncode != 0:
            if "NotFound" in cp.stderr or "not found" in cp.stderr:
                return False
            raise SpireError(f"bundle delete failed: {cp.stderr.strip()}")
        return True

    def _entry(self, spiffe_id: str) -> dict:
        cp = self._run("entry", "show", "-spiffeID", spiffe_id, "-output", "json")
        if cp.returncode != 0:
            raise SpireError(f"entry show failed: {cp.stderr.strip()}")
        entries = json.loads(cp.stdout).get("entries", [])
        if len(entries) != 1:
            raise SpireError(f"expected exactly one entry for {spiffe_id}, found {len(entries)}")
        return entries[0]

    def _update_federates(self, e: dict, spiffe_id: str, feds: list[str]) -> None:
        parent = e["parent_id"]
        args = ["entry", "update", "-entryID", e["id"],
                "-parentID", f"spiffe://{parent['trust_domain']}{parent['path']}", "-spiffeID", spiffe_id]
        for s in e.get("selectors", []):
            args += ["-selector", f"{s['type']}:{s['value']}"]
        for td in feds:
            args += ["-federatesWith", f"spiffe://{td}"]
        cp = self._run(*args)
        if cp.returncode != 0:
            raise SpireError(f"entry update failed: {cp.stderr.strip()}")

    def remove_federates(self, spiffe_id: str, trust_domain: str) -> bool:
        """Remove ONLY `trust_domain` from the entry's federatesWith; other federations are kept. True if changed."""
        e = self._entry(spiffe_id)
        feds = list(e.get("federates_with") or [])
        if trust_domain not in feds:
            return False
        self._update_federates(e, spiffe_id, [td for td in feds if td != trust_domain])
        return True

    def ensure_federates(self, spiffe_id: str, trust_domain: str) -> bool:
        """Add `trust_domain` to the entry's federatesWith if missing. Returns True if changed."""
        cp = self._run("entry", "show", "-spiffeID", spiffe_id, "-output", "json")
        if cp.returncode != 0:
            raise SpireError(f"entry show failed: {cp.stderr.strip()}")
        entries = json.loads(cp.stdout).get("entries", [])
        if len(entries) != 1:
            raise SpireError(f"expected exactly one entry for {spiffe_id}, found {len(entries)}")
        e = entries[0]
        feds = list(e.get("federates_with") or [])
        if trust_domain in feds:
            return False
        parent = e["parent_id"]
        args = ["entry", "update", "-entryID", e["id"],
                "-parentID", f"spiffe://{parent['trust_domain']}{parent['path']}", "-spiffeID", spiffe_id]
        for s in e.get("selectors", []):
            args += ["-selector", f"{s['type']}:{s['value']}"]
        for td in feds + [trust_domain]:
            args += ["-federatesWith", f"spiffe://{td}"]
        cp = self._run(*args)
        if cp.returncode != 0:
            raise SpireError(f"entry update failed: {cp.stderr.strip()}")
        return True
