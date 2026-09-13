"""Fast-path worker: the per-thread packet processing pipeline.

Each FastPathWorker is intended to be run in its own thread, consuming
PacketJobs from a single dedicated queue.Queue (see load_balancer.py for
how jobs are routed there). Because of flow affinity, a given worker only
ever sees packets for flows whose stable_hash(five_tuple) % num_workers
equals this worker's id -- so its private FlowTracker never needs a lock.

Processing steps per packet, matching the pipeline spec:
    1. receive a PacketJob
    2. check flow state
    3. if already BLOCKED, drop immediately without repeating inspection
    4. otherwise perform deep inspection (SNI / HTTP Host / DNS)
    5. classify domain -> application
    6. evaluate rules
    7. update flow state
    8. return FORWARD or DROP
"""

from __future__ import annotations

import queue
from dataclasses import dataclass, field

from dpi.classifier import DomainClassifier
from dpi.flow_tracker import FlowTracker
from dpi.models import AppType, PacketAction, PacketJob, ParsedPacket
from dpi.rule_engine import RuleEngine
from dpi.sni_extractor import extract_dns_query, extract_http_host, extract_sni


@dataclass
class WorkerStats:
    """Per-worker statistics, merged into global stats after processing.
    Keeping these local (not shared/locked) is the other half of the
    lock-free design enabled by flow affinity."""

    worker_id: int
    packets_processed: int = 0
    packets_forwarded: int = 0
    packets_dropped: int = 0


@dataclass
class FastPathWorker:
    """Processes PacketJobs for a single worker's flow subset."""

    worker_id: int
    job_queue: "queue.Queue"
    rule_engine: RuleEngine
    classifier: DomainClassifier = field(default_factory=DomainClassifier)
    flow_tracker: FlowTracker = field(default_factory=FlowTracker)
    stats: WorkerStats = field(init=False)
    forwarded_sequence_numbers: list[int] = field(default_factory=list)
    """Sequence numbers (from ParsedPacket) of packets this worker decided
    to FORWARD. The engine uses these to know which original packets to
    write to the filtered output PCAP."""

    def __post_init__(self) -> None:
        self.stats = WorkerStats(worker_id=self.worker_id)

    def run(self) -> None:
        """Consume jobs until the sentinel (None) is received."""
        while True:
            job = self.job_queue.get()
            if job is None:
                break
            self.process_job(job)

    def process_job(self, job: PacketJob) -> PacketAction:
        packet = job.packet
        five_tuple = packet.five_tuple

        # Step 2 + 3: fast rejection of already-blocked flows.
        if self.flow_tracker.is_blocked(five_tuple):
            self.flow_tracker.record_packet(five_tuple, packet.raw_length)
            self._record_result(PacketAction.DROP)
            return PacketAction.DROP

        conn = self.flow_tracker.record_packet(five_tuple, packet.raw_length)

        # Step 4 + 5: deep inspection + classification, but only until we
        # have found a domain for this flow once -- re-parsing every
        # packet of a long-lived flow for SNI/HTTP/DNS would be wasted
        # work, since the identifying handshake/request typically only
        # appears in the first one or two packets.
        if not conn.inspected:
            domain = self._extract_domain(packet)
            app = self.classifier.classify(domain)
            self.flow_tracker.apply_classification(five_tuple, domain, app)
        else:
            domain = conn.detected_domain
            app = conn.detected_app

        # Step 6: policy decision (the ONLY place FORWARD/DROP is decided).
        action = self.rule_engine.evaluate(five_tuple, domain, app)

        # Step 7: persist the decision on the flow.
        self.flow_tracker.apply_action(five_tuple, action)

        # Step 8
        self._record_result(action)
        if action == PacketAction.FORWARD:
            self.forwarded_sequence_numbers.append(packet.sequence_number)
        return action

    def _extract_domain(self, packet: ParsedPacket) -> str | None:
        """Try each deep-inspection technique in turn. These are mutually
        exclusive in practice (a given payload is TLS, HTTP, or DNS -- not
        more than one), so the first non-None result wins."""
        sni = extract_sni(packet.payload)
        if sni:
            return sni

        host = extract_http_host(packet.payload)
        if host:
            return host

        dns_name = extract_dns_query(packet.payload)
        if dns_name:
            return dns_name

        return None

    def _record_result(self, action: PacketAction) -> None:
        self.stats.packets_processed += 1
        if action == PacketAction.FORWARD:
            self.stats.packets_forwarded += 1
        else:
            self.stats.packets_dropped += 1