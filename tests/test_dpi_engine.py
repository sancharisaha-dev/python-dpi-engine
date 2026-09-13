"""End-to-end test: build an in-memory PCAP, run the full DPIEngine
pipeline against it, and assert both FORWARD and DROP outcomes occur."""

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap

from dpi.dpi_engine import DPIEngine
from dpi.models import PacketAction


def _http_request(host: str) -> bytes:
    return f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")


@pytest.fixture()
def demo_pcap(tmp_path):
    packets = [
        IP(src="10.0.0.5", dst="93.184.216.10")
        / TCP(sport=51000, dport=80, flags="PA")
        / Raw(load=_http_request("blocked-demo.com")),
        IP(src="10.0.0.5", dst="93.184.216.20")
        / TCP(sport=51050, dport=80, flags="PA")
        / Raw(load=_http_request("example.com")),
        IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="allowed-demo.org")),
    ]
    path = tmp_path / "demo.pcap"
    wrpcap(str(path), packets)
    return path


def test_process_file_produces_both_forward_and_drop(demo_pcap, tmp_path):
    engine = DPIEngine(num_workers=2)
    engine.block_domain("blocked-demo.com")

    output_path = tmp_path / "filtered.pcap"
    stats = engine.process_file(demo_pcap, output_path)

    assert stats.total_packets == 3
    assert stats.dropped_packets >= 1
    assert stats.forwarded_packets >= 1
    assert "blocked-demo.com" in stats.detected_domains
    assert "example.com" in stats.detected_domains


def test_process_file_writes_only_forwarded_packets_to_output(demo_pcap, tmp_path):
    engine = DPIEngine(num_workers=2)
    engine.block_domain("blocked-demo.com")

    output_path = tmp_path / "filtered.pcap"
    engine.process_file(demo_pcap, output_path)

    output_packets = rdpcap(str(output_path))
    # The blocked-demo.com packet must not survive to the output file.
    for pkt in output_packets:
        assert b"blocked-demo.com" not in bytes(pkt)


def test_process_file_missing_input_raises(tmp_path):
    engine = DPIEngine(num_workers=2)
    with pytest.raises(FileNotFoundError):
        engine.process_file(tmp_path / "does-not-exist.pcap", tmp_path / "out.pcap")


def test_process_file_empty_pcap_produces_zero_stats(tmp_path):
    empty_path = tmp_path / "empty.pcap"
    wrpcap(str(empty_path), [])

    engine = DPIEngine(num_workers=2)
    output_path = tmp_path / "filtered.pcap"
    stats = engine.process_file(empty_path, output_path)

    assert stats.total_packets == 0
    assert stats.forwarded_packets == 0
    assert stats.dropped_packets == 0


def test_process_file_skips_unsupported_packets(tmp_path):
    from scapy.layers.l2 import ARP, Ether

    packets = [Ether() / ARP()]
    input_path = tmp_path / "arp_only.pcap"
    wrpcap(str(input_path), packets)

    engine = DPIEngine(num_workers=2)
    output_path = tmp_path / "filtered.pcap"
    stats = engine.process_file(input_path, output_path)

    assert stats.unsupported_packets == 1
    assert stats.total_packets == 0


def test_block_ip_end_to_end(demo_pcap, tmp_path):
    engine = DPIEngine(num_workers=2)
    engine.block_ip("93.184.216.10")  # the blocked-demo.com server IP

    output_path = tmp_path / "filtered.pcap"
    stats = engine.process_file(demo_pcap, output_path)

    assert stats.dropped_packets >= 1
    assert stats.forwarded_packets >= 1


def test_repeated_processing_resets_statistics(demo_pcap, tmp_path):
    engine = DPIEngine(num_workers=2)
    engine.block_domain("blocked-demo.com")
    output_path = tmp_path / "filtered.pcap"

    stats_a = engine.process_file(demo_pcap, output_path)
    stats_b = engine.process_file(demo_pcap, output_path)

    assert stats_a.total_packets == stats_b.total_packets