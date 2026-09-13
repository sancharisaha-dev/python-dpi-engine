"""Aggregate statistics for a completed DPI run.

Designed to be trivially serializable (to_dict() returns only primitives/
nested dicts) so a future JSON API layer can call json.dumps(stats.to_dict())
directly without any adapter code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dpi.fast_path import WorkerStats
from dpi.models import AppType


@dataclass
class Statistics:
    total_packets: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    unsupported_packets: int = 0
    """Raw frames the parser rejected (no IPv4, or no TCP/UDP, or
    malformed) -- counted independently of total_packets below. See
    raw_frame_count for the true grand total across the whole capture."""
    connection_count: int = 0
    detected_domains: set[str] = field(default_factory=set)
    app_counts: dict[AppType, int] = field(default_factory=dict)
    rule_drop_count: int = 0
    per_worker: list[WorkerStats] = field(default_factory=list)

    @property
    def raw_frame_count(self) -> int:
        """Total frames read from the capture file, supported + unsupported.

        NOTE: total_packets alone is NOT the capture's total frame count --
        it only counts packets that were successfully parsed as IPv4
        TCP/UDP and reached a fast-path worker. A capture containing ARP,
        IPv6, or other non-IPv4-TCP/UDP traffic will show
        raw_frame_count > total_packets, and that gap is exactly
        unsupported_packets. This property exists so callers never have to
        manually add the two counters themselves (or misinterpret
        total_packets as the whole file).
        """
        return self.total_packets + self.unsupported_packets

    def record_transport(self, is_tcp: bool) -> None:
        if is_tcp:
            self.tcp_packets += 1
        else:
            self.udp_packets += 1

    def record_domain(self, domain: str | None) -> None:
        if domain:
            self.detected_domains.add(domain)

    def record_app(self, app: AppType) -> None:
        self.app_counts[app] = self.app_counts.get(app, 0) + 1

    def merge_worker_stats(self, worker_stats: WorkerStats) -> None:
        self.per_worker.append(worker_stats)
        self.total_packets += worker_stats.packets_processed
        self.forwarded_packets += worker_stats.packets_forwarded
        self.dropped_packets += worker_stats.packets_dropped
        self.rule_drop_count += worker_stats.packets_dropped

    def to_dict(self) -> dict:
        return {
            "raw_frame_count": self.raw_frame_count,
            "total_packets": self.total_packets,
            "forwarded_packets": self.forwarded_packets,
            "dropped_packets": self.dropped_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "unsupported_packets": self.unsupported_packets,
            "connection_count": self.connection_count,
            "detected_domains": sorted(self.detected_domains),
            "app_counts": {app.value: count for app, count in self.app_counts.items()},
            "rule_drop_count": self.rule_drop_count,
            "per_worker": [
                {
                    "worker_id": w.worker_id,
                    "packets_processed": w.packets_processed,
                    "packets_forwarded": w.packets_forwarded,
                    "packets_dropped": w.packets_dropped,
                }
                for w in self.per_worker
            ],
        }

    def print_report(self) -> None:
        print("=== DPI Engine Report ===")
        print(f"Raw frames read (capture total): {self.raw_frame_count}")
        print(f"  Parsed as IPv4 TCP/UDP:         {self.total_packets}")
        print(f"  Unsupported/skipped:            {self.unsupported_packets}")
        print(f"    (non-IPv4, non-TCP/UDP, or malformed -- not an error)")
        print(f"Of the {self.total_packets} parsed packets:")
        print(f"  Forwarded:          {self.forwarded_packets}")
        print(f"  Dropped:            {self.dropped_packets}")
        print(f"  TCP / UDP:          {self.tcp_packets} / {self.udp_packets}")
        print(f"Connections tracked:  {self.connection_count}")
        print(f"Detected domains:     {sorted(self.detected_domains)}")
        print("Application counts:")
        for app, count in self.app_counts.items():
            print(f"  {app.value}: {count}")
        print("Per-worker stats:")
        for w in self.per_worker:
            print(
                f"  worker {w.worker_id}: processed={w.packets_processed} "
                f"forwarded={w.packets_forwarded} dropped={w.packets_dropped}"
            )