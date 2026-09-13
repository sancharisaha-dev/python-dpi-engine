"""High-level orchestration: PCAP in, filtered PCAP + statistics out.

This is the only module that wires together I/O (PCAP reading/writing),
concurrency (threads + queues), and the pure logic modules (parser,
classifier, rule engine). Everything it calls is independently unit
tested; this module's own tests are necessarily more end-to-end.
"""

from __future__ import annotations

import threading
from pathlib import Path

from scapy.utils import PcapReader, wrpcap

from dpi.classifier import DomainClassifier
from dpi.fast_path import FastPathWorker
from dpi.load_balancer import LoadBalancer
from dpi.models import AppType, PacketJob, TransportProtocol
from dpi.packet_parser import try_parse_packet
from dpi.rule_engine import RuleEngine
from dpi.statistics import Statistics


class DPIEngine:
    """Top-level API for configuring rules and processing a PCAP file.

    Example:
        engine = DPIEngine(num_workers=4)
        engine.block_domain("*.facebook.com")
        engine.block_app("YouTube")
        engine.block_ip("1.2.3.4")

        report = engine.process_file("input.pcap", "filtered.pcap")
        engine.print_report()
    """

    def __init__(self, num_workers: int = 4) -> None:
        if num_workers < 1:
            raise ValueError("num_workers must be >= 1")
        self.num_workers = num_workers
        self.rule_engine = RuleEngine()
        self.classifier = DomainClassifier()
        self.statistics = Statistics()

    # -- Rule configuration (delegates straight to RuleEngine) ----------

    def block_ip(self, ip: str) -> None:
        self.rule_engine.block_ip(ip)

    def block_domain(self, domain_pattern: str) -> None:
        self.rule_engine.block_domain(domain_pattern)

    def block_app(self, app: AppType | str) -> None:
        self.rule_engine.block_app(app)

    def block_port(self, port: int) -> None:
        self.rule_engine.block_port(port)

    # -- Processing -------------------------------------------------------

    def process_file(self, input_path: str | Path, output_path: str | Path) -> Statistics:
        """Read `input_path`, apply configured rules, write forwarded
        packets to `output_path`, and return run statistics.

        Raises:
            FileNotFoundError: if input_path does not exist.
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {input_path}")

        self.statistics = Statistics()

        load_balancer = LoadBalancer(num_workers=self.num_workers)
        workers = [
            FastPathWorker(
                worker_id=i,
                job_queue=load_balancer.queues[i],
                rule_engine=self.rule_engine,
                classifier=self.classifier,
            )
            for i in range(self.num_workers)
        ]

        raw_packets_by_sequence: dict[int, object] = {}

        # --- Producer: read + parse + dispatch ---
        with PcapReader(str(input_path)) as reader:
            for raw_packet in reader:
                parsed = try_parse_packet(raw_packet)
                if parsed is None:
                    self.statistics.unsupported_packets += 1
                    continue

                raw_packets_by_sequence[parsed.sequence_number] = raw_packet
                self.statistics.record_transport(
                    is_tcp=parsed.five_tuple.protocol == TransportProtocol.TCP
                )

                job = PacketJob(packet=parsed)
                load_balancer.dispatch(job)

        load_balancer.shutdown()

        # --- Consumers: run each worker's queue-drain loop on its own
        # thread. Threads (not processes) are appropriate here: this is an
        # I/O- and syscall-light, CPU-bound-per-packet workload, and using
        # threads keeps the flow-affinity/shared-queue design simple. Note
        # that CPython's GIL means these threads do not achieve true
        # parallel CPU execution for pure-Python packet processing --
        # multithreading here is primarily an architectural/concurrency
        # exercise (matching a real DPI engine's worker-pool shape), not
        # automatically a wall-clock speedup. A production system doing
        # CPU-heavy inspection would use multiprocessing or a
        # native-code extension for real parallelism. ---
        threads = [threading.Thread(target=w.run) for w in workers]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # --- Merge results ---
        forwarded_sequences: set[int] = set()
        connection_count = 0
        for worker in workers:
            self.statistics.merge_worker_stats(worker.stats)
            forwarded_sequences.update(worker.forwarded_sequence_numbers)
            connection_count += len(worker.flow_tracker)
            for conn in worker.flow_tracker.all_connections():
                self.statistics.record_domain(conn.detected_domain)
                self.statistics.record_app(conn.detected_app)

        self.statistics.connection_count = connection_count

        forwarded_packets = [
            raw_packets_by_sequence[seq]
            for seq in sorted(forwarded_sequences)
            if seq in raw_packets_by_sequence
        ]
        wrpcap(str(output_path), forwarded_packets)

        return self.statistics

    def print_report(self) -> None:
        self.statistics.print_report()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python -m dpi.dpi_engine <input.pcap> <output.pcap>")
        sys.exit(1)

    engine = DPIEngine(num_workers=4)
    engine.block_domain("blocked-demo.com")
    engine.block_domain("*.facebook.com")
    engine.block_app("YouTube")
    result = engine.process_file(sys.argv[1], sys.argv[2])
    engine.print_report()