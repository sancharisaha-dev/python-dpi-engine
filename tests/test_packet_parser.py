"""Tests for packet_parser.py, built entirely from in-memory Scapy packets
(no live network, no PCAP file needed)."""

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from dpi.models import TransportProtocol
from dpi.packet_parser import (
    UnsupportedPacketError,
    parse_packet,
    try_parse_packet,
)


def _tcp_packet(payload: bytes = b"") -> object:
    pkt = IP(src="10.0.0.1", dst="93.184.216.34") / TCP(
        sport=51000, dport=443
    )
    if payload:
        pkt = pkt / payload
    return pkt


def _udp_packet(payload: bytes = b"") -> object:
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    if payload:
        pkt = pkt / payload
    return pkt


def test_parse_tcp_packet_extracts_five_tuple():
    parsed = parse_packet(_tcp_packet())
    ft = parsed.five_tuple
    assert ft.src_ip == "10.0.0.1"
    assert ft.dst_ip == "93.184.216.34"
    assert ft.src_port == 51000
    assert ft.dst_port == 443
    assert ft.protocol == TransportProtocol.TCP


def test_parse_udp_packet_extracts_five_tuple():
    parsed = parse_packet(_udp_packet())
    ft = parsed.five_tuple
    assert ft.protocol == TransportProtocol.UDP
    assert ft.dst_port == 53


def test_parse_tcp_packet_extracts_payload():
    parsed = parse_packet(_tcp_packet(payload=b"hello-world"))
    assert parsed.payload == b"hello-world"


def test_parse_packet_without_ip_layer_raises():
    non_ip_packet = Ether()
    with pytest.raises(UnsupportedPacketError):
        parse_packet(non_ip_packet)


def test_parse_packet_ip_without_tcp_or_udp_raises():
    ip_only = IP(src="10.0.0.1", dst="10.0.0.2")
    with pytest.raises(UnsupportedPacketError):
        parse_packet(ip_only)


def test_try_parse_packet_returns_none_for_unsupported():
    assert try_parse_packet(Ether()) is None


def test_try_parse_packet_returns_parsed_for_supported():
    result = try_parse_packet(_tcp_packet())
    assert result is not None
    assert result.five_tuple.protocol == TransportProtocol.TCP


def test_sequence_numbers_increase_monotonically():
    a = parse_packet(_tcp_packet())
    b = parse_packet(_tcp_packet())
    assert b.sequence_number > a.sequence_number