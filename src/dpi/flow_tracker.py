"""Flow table: dict[FiveTuple, Connection] and its lifecycle operations.

Concurrency note: FlowTracker is intentionally NOT internally thread-safe
(no locks around self._flows). This is safe only because of flow affinity
in the load balancer (see load_balancer.py) -- each fast-path worker is
given its own FlowTracker instance holding only the flows it owns, so two
threads never touch the same Connection. If this class were ever shared
across workers without that guarantee, it would need a lock (or a
concurrent map) around every read-modify-write below.
"""

from __future__ import annotations

from dpi.models import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
)


class FlowTracker:
    """Owns and mutates the flow table for a single worker's flow subset."""

    def __init__(self) -> None:
        self._flows: dict[FiveTuple, Connection] = {}

    def get_or_create(self, five_tuple: FiveTuple) -> Connection:
        """Return the existing Connection for this flow, creating a new one
        (in NEW state) if this is the first packet seen for it."""
        conn = self._flows.get(five_tuple)
        if conn is None:
            conn = Connection(five_tuple=five_tuple)
            self._flows[five_tuple] = conn
        return conn

    def get(self, five_tuple: FiveTuple) -> Connection | None:
        return self._flows.get(five_tuple)

    def record_packet(self, five_tuple: FiveTuple, raw_length: int) -> Connection:
        """Update packet/byte counters for a flow and transition it out of
        NEW into ESTABLISHED on its second packet, if not already
        BLOCKED/CLOSED."""
        conn = self.get_or_create(five_tuple)
        conn.record_packet(raw_length)

        if conn.state == ConnectionState.NEW and conn.packet_count > 1:
            conn.state = ConnectionState.ESTABLISHED

        return conn

    def apply_classification(
        self,
        five_tuple: FiveTuple,
        domain: str | None,
        app: AppType,
    ) -> Connection:
        conn = self.get_or_create(five_tuple)
        if domain is not None:
            conn.detected_domain = domain
        conn.detected_app = app
        conn.inspected = True
        return conn

    def apply_action(self, five_tuple: FiveTuple, action: PacketAction) -> Connection:
        conn = self.get_or_create(five_tuple)
        conn.last_action = action
        if action == PacketAction.DROP:
            conn.state = ConnectionState.BLOCKED
        return conn

    def is_blocked(self, five_tuple: FiveTuple) -> bool:
        """True if this flow was already decided as BLOCKED, meaning a
        fast-path worker should drop the packet immediately without
        repeating deep inspection or rule evaluation."""
        conn = self._flows.get(five_tuple)
        return conn is not None and conn.state == ConnectionState.BLOCKED

    def close(self, five_tuple: FiveTuple) -> None:
        conn = self._flows.get(five_tuple)
        if conn is not None and conn.state != ConnectionState.BLOCKED:
            conn.state = ConnectionState.CLOSED

    def all_connections(self) -> list[Connection]:
        return list(self._flows.values())

    def __len__(self) -> int:
        return len(self._flows)