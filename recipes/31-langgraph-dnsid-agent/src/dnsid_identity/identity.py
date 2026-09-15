"""IdentityBundle: a loaded DNSid identity plus its signing profile."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, Literal

from dnsid import IdentityManager

if TYPE_CHECKING:  # pragma: no cover - typing only
    from dnsid.http_signatures import HttpSignatureProfile


@dataclass
class IdentityBundle:
    """A ready-to-use DNSid identity plus its (lazily built) signing profile.

    ``manager`` is the source of truth; the profile is derived from it. Build
    one with :func:`load_identity` rather than constructing it directly.
    """

    manager: IdentityManager

    @property
    def domain(self) -> str:
        return self.manager.local_domain

    @cached_property
    def http_sig(self) -> "HttpSignatureProfile":
        from dnsid.http_signatures import HttpSignatureProfile

        return HttpSignatureProfile.from_identity_manager(self.manager)


def load_identity(
    *,
    source: Literal["env", "manager"] = "env",
    manager: IdentityManager | None = None,
) -> IdentityBundle:
    """Load the local agent's DNSid identity.

    - ``source="env"`` — read ``DNSID_*`` environment variables + key store.
      Under `dnsid testnet run` this recipe builds the manager through
      lifecycle.load_identity() instead, which also wires the C2SP log
      registry and the testnet transport; prefer ``source="manager"`` there.
    - ``source="manager"`` — wrap an ``IdentityManager`` you already built.
    """
    if source == "manager":
        if manager is None:
            raise ValueError("source='manager' requires manager=")
        return IdentityBundle(manager=manager)

    if source == "env":
        from dnsid import identity_manager_from_environment

        return IdentityBundle(manager=identity_manager_from_environment())

    raise ValueError(f"unknown source: {source!r}")
