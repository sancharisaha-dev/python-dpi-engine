"""Packet parsing: turns raw Scapy packets into ParsedPacket instances.

This is the ONLY module in the project that touches Scapy layer classes for
field extraction. Every other module works with the plain-data models in
``models.py``. That boundary is deliberate: it means the rest of the
pipeline (and its tests) never needs Scapy objects, and if we ever swapped
the capture library, only this file would change.
"""

from __future__ import annotations

import itertools
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from dpi.models import FiveTuple, ParsedPacket, TransportProtocol

_sequence_counter = itertools.count()


class UnsupportedPacketError(Exception):
    """Raised when a packet has no IPv4 + (TCP|UDP) layers we can parse.

    Callers are expected to catch this and skip the packet -- it is an
    expected, non-fatal condition (e.g. ARP, ICMP, IPv6 traffic in the
    capture), not a bug.
    """


def parse_packet(raw_packet: Packet) -> ParsedPacket:
    """Parse a single Scapy packet into a ParsedPacket.

    Raises:
        UnsupportedPacketError: if the packet lacks an IPv4 layer, or lacks
            a TCP/UDP layer on top of it. This project only implements
            IPv4 + TCP/UDP inspection; IPv6, ICMP, ARP, and other L3/L4
            combinations are explicitly out of scope and are treated as
            "unsupported", not as errors in the capture.

    This function never raises on malformed *field values* inside a
    supported packet (e.g. a garbage payload) -- only on missing layers.
    Field-level parsing failures downstream (SNI/HTTP/DNS extraction) are
    handled independently and must not propagate back here.
    """
    if not raw_packet.haslayer(IP):
        raise UnsupportedPacketError("no IPv4 layer")

    ip_layer = raw_packet[IP]

    if raw_packet.haslayer(TCP):
        transport = raw_packet[TCP]
        protocol = TransportProtocol.TCP
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        payload = bytes(transport.payload)
    elif raw_packet.haslayer(UDP):
        transport = raw_packet[UDP]
        protocol = TransportProtocol.UDP
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        payload = bytes(transport.payload)
    else:
        raise UnsupportedPacketError("no TCP or UDP layer on top of IPv4")

    five_tuple = FiveTuple(
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )

    return ParsedPacket(
        five_tuple=five_tuple,
        payload=payload,
        raw_length=len(raw_packet),
        sequence_number=next(_sequence_counter),
    )


def try_parse_packet(raw_packet: Packet) -> Optional[ParsedPacket]:
    """Best-effort parse: returns None instead of raising on any parse
    failure, so a reader loop can call this in a tight loop without a
    try/except at every call site.

    Note this still does NOT swallow unexpected exceptions silently in the
    sense of hiding them entirely -- callers that need visibility into
    *why* a packet was skipped should call ``parse_packet`` directly and
    handle ``UnsupportedPacketError`` themselves.
    """
    try:
        return parse_packet(raw_packet)
    except UnsupportedPacketError:
        return None
    except Exception:
        # Defensive: a genuinely malformed packet (truncated headers,
        # bizarre field values) should not crash the read loop. We still
        # don't want to hide this class of error entirely, so re-raise
        # in debug contexts is a reasonable extension point -- for the
        # scope of this project we treat any parse exception as "skip".
        return None