"""Facts from DNSid-verified evidence. Policy thresholds are applied in trust.py."""

import datetime as dt
import logging

import idna
from confusable_homoglyphs import confusables
from dnsid.models import VerifiedDomain

log = logging.getLogger("counterparty-trust")
KEY_EVENTS = {"ISSUANCE": "issuance", "KEY_ROTATION": "key rotation", "MIGRATION": "migration"}


def name_signals(domain: str) -> dict:
    try:
        name = idna.decode(domain)
    except idna.IDNAError:
        name = domain
    # ponytail: ASCII-target confusables only; preserve unmapped characters.
    # Use full UTS #39 if cross-script comparisons become policy.
    skeleton = "".join(
        next((h["c"] for h in confusables.confusables_data.get(c, [])
              if h["c"].isascii() and all(x.isalnum() or x in ".-" for x in h["c"])), c)
        if not c.isascii() else c
        for c in name
    )
    return {"agent_name_unicode": name, "name_skeleton": skeleton,
            "mixed_script": bool(confusables.is_mixed_script(name))}


def counterparty(domain: str, gi: str, dnssec: str) -> dict:
    if domain == gi:
        relationship = "self-accounted: the agent's own domain is its accountable entity"
    elif domain.endswith("." + gi):
        relationship = "hosted: the agent's name is a subdomain of its accountable entity's domain"
    else:
        relationship = "delegated: a separate organization is accountable, bound by a bilateral ISSUANCE event"
    return {"agent_name": domain, "accountable_entity": gi, "relationship": relationship,
            "dnssec": dnssec, **name_signals(domain)}


def history_facts(events: list, now: dt.datetime) -> dict:
    """The pinned SDK supplies typed events with datetime timestamps, in log order."""
    if not events or events[0].event_type not in ("ISSUANCE", "MIGRATION"):
        raise ValueError("lifecycle must start with ISSUANCE or MIGRATION")
    key = next(e for e in reversed(events) if e.event_type in KEY_EVENTS)
    return {"identity_age_days": (now - events[0].timestamp).total_seconds() / 86400,
            "key_age_days": (now - key.timestamp).total_seconds() / 86400,
            "key_event": KEY_EVENTS[key.event_type]}


def facts_from_verified(verified: VerifiedDomain) -> dict:
    try:
        events = verified.log_reader.rebuild_history(verified.domain)
        history = history_facts(events, dt.datetime.now(dt.UTC))
    except Exception as exc:  # fail toward less trust if the lifecycle cannot be read
        log.warning("lifecycle unavailable for %s: %s", verified.domain, exc)
        history = None
    return {"counterparty": counterparty(verified.domain, verified.record.gi, verified.dnssec_state.name),
            "agent_history": history,
            # The live registry does not yet provide an entity-level history index.
            "accountable_entity_history": None}
