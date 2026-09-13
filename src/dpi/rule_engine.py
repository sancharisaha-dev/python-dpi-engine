"""Policy decision engine: pure (identity, classification) -> action logic.

This module deliberately knows nothing about threads, queues, Scapy, or
PCAP files. It is a closed, pure-function-shaped component so that:

1. It's trivial to unit test in isolation.
2. It is unambiguous where blocking decisions are made -- nowhere else in
   the codebase (and, later, no LLM component) is allowed to produce a
   PacketAction. If a future component needs to influence policy, it must
   do so by adding a Rule here, not by intercepting packets elsewhere.

Rule evaluation order is fixed and documented so results are deterministic
regardless of the order rules were added in: IP -> domain -> app -> port.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dpi.models import AppType, FiveTuple, PacketAction, TransportProtocol


class InvalidRuleError(ValueError):
    """Raised when a rule is malformed (e.g. empty domain, bad port)."""


@dataclass
class RuleEngine:
    """Holds blocking rules and evaluates them deterministically.

    Evaluation order (fixed, not configurable, so behavior is predictable):
        1. Blocked source/destination IP
        2. Blocked domain (exact or wildcard suffix)
        3. Blocked application
        4. Blocked port (source or destination)

    The first matching rule wins and evaluation stops -- we do not need
    "priority" numbers because the category order itself is the priority.
    """

    blocked_ips: set[str] = field(default_factory=set)
    blocked_domain_exact: set[str] = field(default_factory=set)
    blocked_domain_wildcards: set[str] = field(default_factory=set)
    """Stores the suffix WITHOUT the leading '*.', e.g. "*.facebook.com"
    is stored as "facebook.com"."""
    blocked_apps: set[AppType] = field(default_factory=set)
    blocked_ports: set[int] = field(default_factory=set)

    def block_ip(self, ip: str) -> None:
        if not ip or not ip.strip():
            raise InvalidRuleError("IP address must be a non-empty string")
        self.blocked_ips.add(ip.strip())

    def block_domain(self, domain_pattern: str) -> None:
        """Block a domain. Supports wildcard patterns like
        "*.facebook.com", which blocks facebook.com and any subdomain of
        it, but does NOT block "facebook.com" itself unless it is also
        added as (or matches) an exact rule -- use "facebook.com" AND
        "*.facebook.com" to cover both the apex domain and subdomains.
        """
        if not domain_pattern or not domain_pattern.strip():
            raise InvalidRuleError("domain pattern must be non-empty")

        pattern = domain_pattern.strip().lower()
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if not suffix:
                raise InvalidRuleError(f"invalid wildcard pattern: {domain_pattern!r}")
            self.blocked_domain_wildcards.add(suffix)
        else:
            self.blocked_domain_exact.add(pattern)

    def block_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            try:
                app = AppType(app)
            except ValueError as exc:
                raise InvalidRuleError(f"unknown application: {app!r}") from exc
        self.blocked_apps.add(app)

    def block_port(self, port: int) -> None:
        if not isinstance(port, int) or not (0 < port <= 65535):
            raise InvalidRuleError(f"invalid port: {port!r}")
        self.blocked_ports.add(port)

    def evaluate(
        self,
        five_tuple: FiveTuple,
        domain: str | None,
        app: AppType,
    ) -> PacketAction:
        """Return FORWARD or DROP for this flow, given its identity and the
        best-known domain/application classification for it.
        """
        if self._ip_blocked(five_tuple):
            return PacketAction.DROP

        if domain and self._domain_blocked(domain):
            return PacketAction.DROP

        if app in self.blocked_apps:
            return PacketAction.DROP

        if self._port_blocked(five_tuple):
            return PacketAction.DROP

        return PacketAction.FORWARD

    def _ip_blocked(self, five_tuple: FiveTuple) -> bool:
        return (
            five_tuple.src_ip in self.blocked_ips
            or five_tuple.dst_ip in self.blocked_ips
        )

    def _domain_blocked(self, domain: str) -> bool:
        normalized = domain.lower().strip().rstrip(".")
        if normalized in self.blocked_domain_exact:
            return True
        for suffix in self.blocked_domain_wildcards:
            if normalized == suffix or normalized.endswith("." + suffix):
                return True
        return False

    def _port_blocked(self, five_tuple: FiveTuple) -> bool:
        return (
            five_tuple.src_port in self.blocked_ports
            or five_tuple.dst_port in self.blocked_ports
        )