"""Identity lifecycle: environment config, C2SP log trust, registration, publication.

Everything here happens before the agent exchanges a single A2A message. It
turns the DNSID_* environment injected by `dnsid testnet run` into a usable,
published identity:

  load config from env -> register with the registry -> answer the challenge
  by signing a nonce -> publish -> the _dnsid record and JWKS go live.

Policy trust rule (normative): the C2SP policy URL comes only from the
independently supplied DNSID_LOG_POLICY_URL. It is never derived from
DNSID_LOG_REF, the log prefix, or any other log-provided data — a log that
could name its own policy could vouch for itself.
"""

from __future__ import annotations

import asyncio
import base64
import os
from collections.abc import Mapping
from urllib.parse import urlsplit

from dnsid import (
    IdentityManager,
    IdentityManagerDependencies,
    LocalKeyProvider,
    RegistryClient,
    config_from_environment,
)
from dnsid.c2sp_tlog import (
    C2spTlogVerificationOptions,
    SafeC2spResourceFetcher,
    create_c2sp_tlog_verification_registry,
    parse_c2sp_tlog_lr,
)
from dnsid.models import (
    AgentRegistrationInput,
    RegistryAgentStatus,
    TransportConfig,
)
from dnsid.registry import LogRegistry


class PollAbortError(RuntimeError):
    """Raised inside a poll callback to stop retrying immediately."""


def required_log_policy_url(environment: Mapping[str, str]) -> str:
    """Return the independently supplied testnet C2SP policy URL."""
    policy_url = environment.get("DNSID_LOG_POLICY_URL", "").strip()
    if not policy_url:
        raise RuntimeError("DNSID_LOG_POLICY_URL is required; run with `dnsid testnet run`")
    return policy_url


def make_log_registry(
    log_ref: str, policy_url: str, transport_config: TransportConfig
) -> LogRegistry | None:
    """Register a c2sp-tlog reader using independently trusted testnet policy.

    The policy URL comes from trusted testnet configuration, independently of
    the log reference. The transport routes through the testnet DNS server and
    CA bundle. Returns None when the log_ref is not a c2sp-tlog reference.
    """
    if not log_ref.startswith("c2sp-tlog:"):
        return None
    parsed = parse_c2sp_tlog_lr(log_ref)
    fetcher = SafeC2spResourceFetcher(
        transport_config=transport_config,
        allow_loopback_host=(
            urlsplit(policy_url).hostname if parsed.scope == "testnet" else None
        ),
    )
    return create_c2sp_tlog_verification_registry(
        C2spTlogVerificationOptions(
            policy_url=policy_url,
            resource_fetcher=fetcher,
            max_clock_skew_ms=30_000,
            checkpoint_freshness_ms=5 * 60_000,
        )
    )


async def poll(label: str, fn) -> None:
    """Retry an async *fn* up to 60 times at 500 ms intervals."""
    last_exc: BaseException = RuntimeError("no attempts made")
    for _ in range(60):
        try:
            await fn()
            return
        except PollAbortError:
            raise
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.5)
    raise RuntimeError(f"{label} failed: {last_exc}")


class AgentIdentity:
    """A fully wired identity: config, keys, IdentityManager, registry client."""

    def __init__(
        self,
        idm: IdentityManager,
        key_provider: LocalKeyProvider,
        registry: RegistryClient,
        agent_port: int,
        public_url: str | None,
        agent_name: str | None,
    ) -> None:
        self.idm = idm
        self.key_provider = key_provider
        self.registry = registry
        self.agent_port = agent_port
        self.public_url = public_url
        self.agent_name = agent_name

    @property
    def domain(self) -> str:
        return self.idm.local_domain


def load_identity() -> AgentIdentity:
    """Build an AgentIdentity from the DNSID_* environment.

    Requires the process to run under `dnsid testnet run`, which injects DNS
    routing (DNSID_DNS_SERVER), TLS trust (DNSID_CA_BUNDLE), the registry
    credential (DNSID_API_KEY), the identity directory (DNSID_CONFIG_DIR),
    and the independently trusted policy location (DNSID_LOG_POLICY_URL).
    """
    env = dict(os.environ)

    result = config_from_environment(env, require=["registry_url", "agent_port"])
    protocol_config = result.config.identity
    transport_config = result.config.transport
    registry_config = result.registry_config
    policy_url = required_log_policy_url(env)

    # The CLI testnet resolves every name under the governance domain (this
    # agent's endpoints and every peer's) to the host's loopback proxy, which
    # the SDK's SSRF guard would otherwise block. A leading-dot entry allows
    # that zone only; production verifiers keep this empty.
    transport_config.private_address_hosts = frozenset({"." + protocol_config.governance_id})

    # Registry mutation calls (register/verify/publish) require a session
    # credential. `dnsid testnet run` injects DNSID_API_KEY; DNSID_REGISTRY_API_KEY
    # is accepted as a manual override. Fail fast before starting the server
    # rather than surfacing an HTTP 401 partway through registration.
    registry_api_key = (env.get("DNSID_API_KEY") or env.get("DNSID_REGISTRY_API_KEY") or "").strip()
    if not registry_api_key:
        raise SystemExit(
            "DNSID_API_KEY (or DNSID_REGISTRY_API_KEY) is required to register with "
            "the registry. Run via `dnsid testnet run` (see the recipe README)."
        )

    # Set capabilities_url to point at the agent card endpoint.
    public_url = result.public_url or f"https://{protocol_config.domain}"
    if not protocol_config.capabilities_url:
        protocol_config.capabilities_url = f"{public_url.rstrip('/')}/.well-known/agent-card.json"

    # The identity directory provisioned by `dnsid testnet run`
    # (DNSID_CONFIG_DIR): its private.jwk carries the RFC 7638 thumbprint kid
    # the registry requires.
    config_dir = (env.get("DNSID_CONFIG_DIR") or "").strip()
    if not config_dir:
        raise SystemExit(
            "DNSID_CONFIG_DIR is not set. Run via `dnsid testnet run <name> -- ...` "
            "so the provisioned identity directory is injected."
        )
    key_provider = LocalKeyProvider.from_cli_directory(config_dir)

    log_registry = make_log_registry(protocol_config.log_ref, policy_url, transport_config)
    idm = IdentityManager(
        result.config,
        key_provider,
        deps=IdentityManagerDependencies(log_registry=log_registry),
    )

    registry = RegistryClient(registry_config.registry_url, api_key=registry_api_key)
    return AgentIdentity(
        idm,
        key_provider,
        registry,
        result.agent_port,
        result.public_url,
        result.agent_name,
    )


async def _verify_with_challenge(
    key_provider: LocalKeyProvider,
    registry: RegistryClient,
    domain: str,
    status: RegistryAgentStatus,
) -> None:
    """Drive the registry VERIFICATION handshake.

    Request verification, wait for the challenge nonce on the status document,
    sign the decoded nonce bytes with the active key, submit the signature,
    then wait for the agent to reach VERIFIED.
    """
    if status.registry_status != "VERIFICATION":
        await asyncio.to_thread(registry.verify_agent, domain)

    nonce = ""

    async def _await_challenge() -> None:
        nonlocal nonce
        current = await asyncio.to_thread(registry.get_agent_status, domain)
        if current is None:
            raise RuntimeError("agent not found in registry")
        if current.failed or current.terminal:
            raise PollAbortError(f"registry status is {current.registry_status}")
        raw_nonce = current.raw.get("challenge")
        if not isinstance(raw_nonce, str) or not raw_nonce:
            raise RuntimeError(f"no challenge yet (status {current.registry_status})")
        nonce = raw_nonce

    await poll(f"registry challenge {domain}", _await_challenge)

    padding = "=" * (-len(nonce) % 4)
    signature = key_provider.sign(base64.urlsafe_b64decode(nonce + padding))
    await asyncio.to_thread(registry.submit_challenge_signature, domain, nonce, signature)

    async def _await_verified() -> None:
        current = await asyncio.to_thread(registry.get_agent_status, domain)
        if current is None:
            raise RuntimeError("agent not found in registry")
        if current.failed or current.terminal:
            raise PollAbortError(f"registry status is {current.registry_status}")
        if not current.ready_for_publication and not current.published:
            raise RuntimeError(f"still {current.registry_status}")

    await poll(f"registry verified {domain}", _await_verified)


async def register_and_publish(identity: AgentIdentity) -> None:
    """Register with the registry, pass the challenge, and publish the identity.

    Idempotent: an already-published identity logs `already published (READY)`
    and returns.
    """
    idm, key_provider, registry = identity.idm, identity.key_provider, identity.registry
    domain = idm.local_domain
    status = await asyncio.to_thread(registry.get_agent_status, domain)

    if status is None:
        print(f"{domain} registering with registry")
        await asyncio.to_thread(
            registry.register_agent,
            AgentRegistrationInput(
                domain=domain,
                capabilities_url=idm.config.identity.capabilities_url or "",
            ),
        )
        status = await asyncio.to_thread(registry.get_agent_status, domain)
        if status is None:
            raise RuntimeError("agent not found in registry after registration")

    if not status.published and not status.ready_for_publication:
        await _verify_with_challenge(key_provider, registry, domain, status)
        status = await asyncio.to_thread(registry.get_agent_status, domain)

    if status is not None and status.ready_for_publication:
        published = await asyncio.to_thread(idm.publish_to_registry, registry)
        print(f"{domain} published {published.owner_name}")
    else:
        print(f"{domain} already published ({status.registry_status if status else 'unknown'})")


async def await_self_resolvable(identity: AgentIdentity) -> None:
    """Wait until the agent's own freshly published record verifies end-to-end.

    The testnet DNS reloads the generated zone every two seconds; wait for
    that reload before the first self-check so an initial NXDOMAIN isn't
    cached, then retry until the record is resolvable.
    """
    await asyncio.sleep(2.5)
    await poll(
        f"self-verify {identity.domain}",
        lambda: asyncio.to_thread(identity.idm.verify_domain, identity.domain),
    )
