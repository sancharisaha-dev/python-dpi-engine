"""Core data models shared across the DPI pipeline.

These types intentionally contain no Scapy references and no I/O. Keeping
them "dumb" (pure data) means every other module can be tested without a
real packet capture, and it keeps Scapy as an implementation detail that is
confined to ``packet_parser.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class TransportProtocol(Enum):
    """Transport-layer protocol of a parsed packet."""

    TCP = "TCP"
    UDP = "UDP"
    OTHER = "OTHER"


class AppType(Enum):
    """Coarse application/service classification.

    This is intentionally a closed enum rather than a free-form string:
    the rule engine and statistics modules pattern-match against known
    members, and an open string space would let "YouTube" and "Youtube"
    silently diverge.
    """

    YOUTUBE = "YouTube"
    FACEBOOK = "Facebook"
    GITHUB = "GitHub"
    GOOGLE = "Google"
    GRAMMARLY = "Grammarly"
    UNKNOWN = "Unknown"


class PacketAction(Enum):
    """Final disposition of a packet after policy evaluation."""

    FORWARD = auto()
    DROP = auto()


class ConnectionState(Enum):
    """Lifecycle state of a tracked flow.

    This is a simplified state model for teaching purposes -- it is not a
    full TCP state machine (no SYN/FIN/RST tracking). It exists to answer
    one question cheaply: "have we already decided to block this flow?"
    """

    NEW = auto()
    ESTABLISHED = auto()
    BLOCKED = auto()
    CLOSED = auto()


@dataclass(frozen=True, slots=True)
class FiveTuple:
    """The classic 5-tuple flow identifier.

    Frozen + slotted so instances are hashable and immutable, which lets
    them be used directly as ``dict`` keys in the flow table. Note that
    (src, sport) and (dst, dport) are NOT normalized/sorted here -- a
    connection's forward and reverse directions produce two different
    FiveTuples. That is a deliberate simplification; a production DPI
    engine would typically canonicalize direction so both sides of a
    conversation map to one Connection. We call this out explicitly
    because it is a natural interview question.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: TransportProtocol

    def __str__(self) -> str:  # pragma: no cover - trivial formatting
        return (
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} ({self.protocol.value})"
        )


@dataclass(slots=True)
class ParsedPacket:
    """A packet after L3/L4 parsing, with no Scapy objects inside.

    ``payload`` holds the raw transport-layer payload bytes (may be empty).
    ``raw_length`` is the total on-wire length, kept separately from
    ``len(payload)`` for statistics purposes.
    """

    five_tuple: FiveTuple
    payload: bytes
    raw_length: int
    sequence_number: int
    """Monotonic index assigned by the packet reader, used only to preserve
    a stable ordering for statistics/debugging -- NOT a TCP sequence
    number."""


@dataclass(slots=True)
class Connection:
    """Mutable, per-flow tracking state.

    One Connection is created per FiveTuple the first time it is seen.
    Fields are updated in place by whichever fast-path worker owns this
    flow (see load_balancer.py for why exactly one worker ever touches a
    given Connection).
    """

    five_tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    packet_count: int = 0
    byte_count: int = 0
    detected_domain: Optional[str] = None
    detected_app: AppType = AppType.UNKNOWN
    last_action: Optional[PacketAction] = None
    inspected: bool = False
    """True once deep inspection has run at least once for this flow. Used
    to avoid re-running SNI/HTTP/DNS extraction on every packet of a long
    flow -- only the first few packets are usually informative."""

    def record_packet(self, raw_length: int) -> None:
        self.packet_count += 1
        self.byte_count += raw_length


@dataclass(slots=True)
class PacketJob:
    """Unit of work passed from the load balancer to a fast-path worker."""

    packet: ParsedPacket

    @property
    def five_tuple(self) -> FiveTuple:
        return self.packet.five_tuple