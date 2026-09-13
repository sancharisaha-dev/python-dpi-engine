"""Generate a small, deterministic demo PCAP for exercising the DPI engine.

Contains:
  - A TCP flow carrying an HTTP request with a "Host: blocked-demo.com"
    header (intended to be blocked by a domain rule in the demo).
  - A second TCP flow carrying an HTTP request with "Host: example.com"
    (intended to be forwarded).
  - A UDP flow: a DNS query for "allowed-demo.org" (intended to be
    forwarded).

This deliberately produces BOTH a DROP and a FORWARD outcome when run
against the demo rules in the README, so the demo is meaningful rather
than trivially "everything passes."
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "demo.pcap"


def _http_request(host: str) -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-demo\r\n\r\n"
    ).encode("ascii")


def build_demo_packets() -> list:
    packets = []

    # --- Flow 1 (TCP): HTTP request to a domain we will block in the demo.
    blocked_request = (
        IP(src="10.0.0.5", dst="93.184.216.10")
        / TCP(sport=51000, dport=80, flags="PA", seq=1)
        / Raw(load=_http_request("blocked-demo.com"))
    )
    packets.append(blocked_request)

    # --- Flow 2 (TCP): HTTP request to a domain we will NOT block.
    allowed_request = (
        IP(src="10.0.0.5", dst="93.184.216.20")
        / TCP(sport=51050, dport=80, flags="PA", seq=1)
        / Raw(load=_http_request("example.com"))
    )
    packets.append(allowed_request)

    # --- Flow 3 (UDP): a DNS query, forwarded (not blocked in the demo).
    dns_query = (
        IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="allowed-demo.org"))
    )
    packets.append(dns_query)

    return packets


def main() -> None:
    packets = build_demo_packets()
    wrpcap(str(OUTPUT_PATH), packets)
    print(f"Wrote {len(packets)} packets to {OUTPUT_PATH}")
    print("Flows included:")
    print("  1. TCP HTTP request, Host: blocked-demo.com  (will be DROPPED by demo rules)")
    print("  2. TCP HTTP request, Host: example.com        (will be FORWARDED)")
    print("  3. UDP DNS query for allowed-demo.org         (will be FORWARDED)")


if __name__ == "__main__":
    main()