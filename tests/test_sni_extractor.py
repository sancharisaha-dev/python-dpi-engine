"""Tests for SNI/HTTP Host/DNS extraction, and the domain classifier."""

import struct

from scapy.layers.dns import DNS, DNSQR

from dpi.classifier import DomainClassifier
from dpi.models import AppType
from dpi.sni_extractor import (
    extract_dns_query,
    extract_http_host,
    extract_sni,
)


def _build_client_hello(sni_hostname: str) -> bytes:
    """Hand-build a minimal, valid-enough TLS ClientHello record containing
    a server_name extension, so we can test the parser without needing a
    real network capture."""
    hostname_bytes = sni_hostname.encode("ascii")

    # server_name entry: type(1) + length(2) + name
    sni_entry = struct.pack("!B", 0x00) + struct.pack(
        "!H", len(hostname_bytes)
    ) + hostname_bytes
    # server_name_list: length(2) + entries
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    # extension: type(2) + length(2) + body
    sni_extension = (
        struct.pack("!H", 0x0000) + struct.pack("!H", len(sni_list)) + sni_list
    )

    extensions = sni_extension
    extensions_block = struct.pack("!H", len(extensions)) + extensions

    session_id = b""
    cipher_suites = struct.pack("!H", 0x1301)  # one cipher suite
    compression_methods = b"\x00"

    handshake_body = (
        struct.pack("!H", 0x0303)  # client_version (TLS 1.2 record)
        + (b"\x00" * 32)  # random
        + struct.pack("!B", len(session_id)) + session_id
        + struct.pack("!H", len(cipher_suites)) + cipher_suites
        + struct.pack("!B", len(compression_methods)) + compression_methods
        + extensions_block
    )

    handshake_header = struct.pack("!B", 0x01) + (
        len(handshake_body).to_bytes(3, "big")
    )
    handshake_msg = handshake_header + handshake_body

    record_header = (
        struct.pack("!B", 0x16)  # handshake content type
        + struct.pack("!H", 0x0303)  # record version
        + struct.pack("!H", len(handshake_msg))
    )
    return record_header + handshake_msg


def test_extract_sni_from_valid_client_hello():
    payload = _build_client_hello("example.com")
    assert extract_sni(payload) == "example.com"


def test_extract_sni_returns_none_for_non_tls_payload():
    assert extract_sni(b"not a tls record at all") is None


def test_extract_sni_returns_none_for_truncated_payload():
    payload = _build_client_hello("example.com")
    assert extract_sni(payload[:10]) is None


def test_extract_http_host_finds_host_header():
    request = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"User-Agent: test\r\n\r\n"
    )
    assert extract_http_host(request) == "www.example.com"


def test_extract_http_host_returns_none_when_absent():
    request = b"GET /index.html HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
    assert extract_http_host(request) is None


def test_extract_http_host_returns_none_for_non_http_binary_payload():
    assert extract_http_host(b"\x00\x01\x02\xff\xfe") is None


def test_extract_dns_query_finds_qname():
    dns_pkt = DNS(rd=1, qd=DNSQR(qname="example.com"))
    payload = bytes(dns_pkt)
    assert extract_dns_query(payload) == "example.com"


def test_extract_dns_query_returns_none_for_non_dns_payload():
    assert extract_dns_query(b"not dns") is None


def test_classifier_matches_known_domain_exact():
    classifier = DomainClassifier()
    assert classifier.classify("youtube.com") == AppType.YOUTUBE


def test_classifier_matches_known_domain_subdomain():
    classifier = DomainClassifier()
    assert classifier.classify("m.youtube.com") == AppType.YOUTUBE
    assert classifier.classify("www.facebook.com") == AppType.FACEBOOK


def test_classifier_returns_unknown_for_unrecognized_domain():
    classifier = DomainClassifier()
    assert classifier.classify("some-random-site.org") == AppType.UNKNOWN


def test_classifier_returns_unknown_for_none_domain():
    classifier = DomainClassifier()
    assert classifier.classify(None) == AppType.UNKNOWN


def test_classifier_register_adds_new_mapping():
    classifier = DomainClassifier()
    classifier.register("example.com", AppType.GOOGLE)
    assert classifier.classify("example.com") == AppType.GOOGLE