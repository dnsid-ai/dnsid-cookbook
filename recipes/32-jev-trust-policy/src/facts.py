"""Build a counterparty fact sheet from SDK-verified DNSid evidence.

Code computes ages, domain relationships, key history and Unicode signals.
Only the counterparty section goes to the model; history and operation impact
stay in code. Nothing in the sheet is a counterparty-authored description.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from confusable_homoglyphs import confusables

try:
    import idna  # installed with dnsid; optional so eval and tests run without the SDK
except ImportError:  # pragma: no cover
    idna = None

log = logging.getLogger("counterparty-trust")

ENTITY_HISTORY_UNKNOWN = "unknown: no entity-level history index is available yet"
HISTORY_UNAVAILABLE = "unavailable: the verified lifecycle could not be read"


@dataclass(frozen=True)
class Interaction:
    """What we are about to do with the counterparty. Always from our own tables."""

    direction: str  # "inbound": it is calling us. "outbound": we are calling it.
    operation: str  # plain description, e.g. "issue a refund to a customer"
    impact: str  # "none", "low", "moves money", "shares personal data", ...


@dataclass(frozen=True)
class FactSettings:
    new_agent_days: int = 30
    recent_rotation_days: int = 7

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in (self.new_agent_days, self.recent_rotation_days)):
            raise ValueError("fact age thresholds must be positive integer days")


@dataclass(frozen=True)
class History:
    issued_at: dt.datetime
    key_introduced_at: dt.datetime
    key_introduced_by: str  # "issuance", "key rotation" or "migration"
    rotations: int
    events: int
    fingerprint: str  # changes whenever the lifecycle changes; part of the cache key


def relationship(fqdn: str, gi: str) -> str:
    if fqdn == gi:
        return "self-accounted: the agent's own domain is its accountable entity"
    if fqdn.endswith("." + gi):
        return "hosted: the agent's name is a subdomain of its accountable entity's domain"
    return "delegated: a separate organization is accountable, bound by a bilateral ISSUANCE event"


def unicode_name(fqdn: str) -> str:
    if "xn--" not in fqdn:
        return fqdn
    try:
        return idna.decode(fqdn) if idna else fqdn.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return fqdn


def name_signals(fqdn: str) -> dict[str, Any]:
    name = unicode_name(fqdn)
    # ponytail: ASCII-target confusables only; preserve unmapped characters, use
    # a full UTS #39 implementation if cross-script comparisons become policy.
    skeleton = "".join(
        next((h["c"] for h in confusables.confusables_data.get(c, [])
              if h["c"].isascii() and all(x.isalnum() or x in ".-" for x in h["c"])), c)
        if not c.isascii() else c
        for c in name
    )
    return {"agent_name_unicode": name, "name_skeleton": skeleton,
            "mixed_script": bool(confusables.is_mixed_script(name))}


# --- lifecycle history ----------------------------------------------------

_KEY_EVENTS = {"ISSUANCE": "issuance", "KEYROTATION": "key rotation", "MIGRATION": "migration"}


def _kind(event: Any) -> str:
    raw = getattr(event, "event_type", None) or type(event).__name__
    raw = getattr(raw, "value", raw)  # enums
    return str(raw).upper().replace("_", "").removesuffix("EVENT")


def _when(event: Any) -> dt.datetime:
    ts = event.timestamp
    if isinstance(ts, (int, float)):
        ts = dt.datetime.fromtimestamp(ts / 1000 if ts > 1e11 else ts, dt.UTC)
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.UTC)


def summarise(events: list[Any]) -> History:
    """Summarise verified lifecycle events (log order) for the fact sheet."""
    kinds = [_kind(e) for e in events]
    if not kinds or kinds[0] not in ("ISSUANCE", "MIGRATION"):
        raise ValueError("lifecycle does not start with ISSUANCE or MIGRATION")
    times = [_when(e) for e in events]
    key_at = max(i for i, k in enumerate(kinds) if k in _KEY_EVENTS)
    digest = hashlib.sha256("|".join(f"{k}@{t.isoformat()}" for k, t in zip(kinds, times)).encode())
    return History(
        issued_at=times[0],
        key_introduced_at=times[key_at],
        key_introduced_by=_KEY_EVENTS[kinds[key_at]],
        rotations=kinds.count("KEYROTATION"),
        events=len(events),
        fingerprint=digest.hexdigest()[:16],
    )


def read_history(verified: Any) -> History | None:
    """Read the verified lifecycle behind a verify_domain result, or None.

    dnsid-py 0.23.1 exposes this only through the C2SP reader attached to the
    result. Any failure here yields None, which
    the evaluator treats as "no track record": it can only reduce trust.
    """
    rebuild = getattr(getattr(verified, "log_reader", None), "rebuild_history", None)
    if rebuild is None:
        log.warning("no lifecycle reader on verification result for %s", verified.domain)
        return None
    try:
        return summarise(list(rebuild(verified.domain)))
    except Exception as exc:  # noqa: BLE001 - fail toward less trust, never more
        log.warning("lifecycle history unavailable for %s: %s", verified.domain, exc)
        return None


# --- fact sheet -----------------------------------------------------------


def _days(since: dt.datetime, now: dt.datetime) -> float:
    return (now - since).total_seconds() / 86400


def _history_facts(h: History, now: dt.datetime, s: FactSettings) -> dict[str, Any]:
    age = _days(h.issued_at, now)
    if age < s.new_agent_days:
        label = f"new: issued less than {s.new_agent_days} days ago"
    elif age < 365:
        label = f"established: issued more than {s.new_agent_days} days but less than a year ago"
    else:
        label = "long-standing: issued more than a year ago"
    if h.key_introduced_by == "issuance":
        key = "unchanged since issuance"
    else:
        key_age = _days(h.key_introduced_at, now)
        key = f"introduced by {h.key_introduced_by} {key_age:.1f} days ago"
        if key_age < s.recent_rotation_days:
            key += f" (recent: within {s.recent_rotation_days} days)"
    return {
        "identity_age_days": round(age, 1),
        "is_new": age < s.new_agent_days,
        "recent_key_rotation": h.key_introduced_by == "key rotation" and
            _days(h.key_introduced_at, now) < s.recent_rotation_days,
        "identity_age": label,
        "current_key": key,
        "key_rotations": h.rotations,
        "lifecycle_events": h.events,
    }


def build_facts(
    *,
    domain: str,
    gi: str,
    dnssec: str,
    history: History | None,
    interaction: Interaction,
    settings: FactSettings,
    entity_history: Any = ENTITY_HISTORY_UNKNOWN,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.UTC)
    counterparty = {
        "agent_name": domain,
        "accountable_entity": gi,
        "relationship": relationship(domain, gi),
        "dnssec": dnssec,
        **name_signals(domain),
    }
    return {
        "counterparty": counterparty,
        "agent_history": _history_facts(history, now, settings) if history else HISTORY_UNAVAILABLE,
        "accountable_entity_history": entity_history,
        "interaction": dataclasses.asdict(interaction),
    }


def facts_from_verified(
    verified: Any, history: History | None, interaction: Interaction, settings: FactSettings
) -> dict[str, Any]:
    """Only SDK-verified fields go in: domain, gi and DNSSEC state."""
    return build_facts(
        domain=verified.domain,
        gi=verified.record.gi,
        dnssec=verified.dnssec_state.name,
        history=history,
        interaction=interaction,
        settings=settings,
    )
