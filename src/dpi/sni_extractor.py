"""Domain extraction from plaintext protocol metadata.

IMPORTANT LIMITATIONS (read before using this module's output as ground
truth):

- TLS SNI extraction reads the *unencrypted* ClientHello handshake message.
  This is standard, well-documented DPI behavior -- it is NOT decryption of
  HTTPS traffic, and this module never claims to decrypt anything.
- SNI is not guaranteed to be present. Encrypted Client Hello (ECH) hides
  the real SNI inside an encrypted inner ClientHello; some clients omit
  SNI; some connections are made directly to an IP with no hostname at
  all. Absence of an extracted SNI means "not observable here", not "no
  domain involved."
- HTTP Host extraction only works on plaintext HTTP/1.x requests. It will
  never see anything for HTTPS traffic.
- DNS query extraction only sees plaintext DNS-over-UDP/53. DNS-over-HTTPS
  (DoH) and DNS-over-TLS (DoT) are opaque to this technique.
- An IP address does not uniquely identify a domain: many domains share an
  IP behind a CDN or load balancer, and one domain can resolve to many IPs.
  Domain identification here relies on SNI/Host/DNS content, not on IP
  address alone.
"""

from __future__ import annotations

import re
import struct
from typing import Optional

from scapy.layers.dns import DNS
from scapy.packet import Raw

_TLS_HANDSHAKE_CONTENT_TYPE = 0x16
_TLS_CLIENT_HELLO_HANDSHAKE_TYPE = 0x01
_TLS_EXTENSION_SERVER_NAME = 0x0000
_SNI_HOST_NAME_TYPE = 0x00

_MAX_HOSTNAME_LENGTH = 253
_MIN_HOSTNAME_LENGTH = 4  # shortest plausible "a.bc" style hostname

# One or more dot-separated labels, each 1-63 chars, alphanumeric with
# internal hyphens only (no leading/trailing hyphen per label). Requires
# at least one dot, since a lone label is not a meaningful domain in this
# project's context and is far more likely to be misparsed noise.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _looks_like_hostname(candidate: str) -> bool:
    """Reject decoded byte strings that happen to be valid ASCII but are
    not plausible hostnames.

    This guards against a real failure mode: encrypted TLS application
    data or unrelated binary payloads can coincidentally decode as ASCII
    (control characters are still valid ASCII bytes), which would
    otherwise be misreported as a "detected domain". A successful ASCII
    decode is necessary but not sufficient evidence of a real hostname.
    """
    if not (_MIN_HOSTNAME_LENGTH <= len(candidate) <= _MAX_HOSTNAME_LENGTH):
        return False
    return bool(_HOSTNAME_RE.match(candidate))


def extract_sni(payload: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello, if present.

    Returns None if the payload is not a TLS ClientHello, is truncated, or
    contains no server_name extension (including the ECH case, where the
    real hostname is encrypted and unavailable to this parser).
    """
    try:
        return _parse_client_hello_sni(payload)
    except (IndexError, struct.error):
        # Truncated or malformed handshake bytes -- treat as "no SNI
        # observed" rather than propagating a parsing exception. A single
        # oddly-fragmented ClientHello should not crash the pipeline.
        return None


def _parse_client_hello_sni(payload: bytes) -> Optional[str]:
    if len(payload) < 5:
        return None

    # TLS record header: content type (1) + version (2) + length (2)
    content_type = payload[0]
    if content_type != _TLS_HANDSHAKE_CONTENT_TYPE:
        return None

    record_body = payload[5:]
    if len(record_body) < 4:
        return None

    # Handshake header: msg type (1) + length (3)
    handshake_type = record_body[0]
    if handshake_type != _TLS_CLIENT_HELLO_HANDSHAKE_TYPE:
        return None

    pos = 4  # skip handshake type + 3-byte length
    pos += 2  # client_version
    pos += 32  # random
    if pos >= len(record_body):
        return None

    session_id_len = record_body[pos]
    pos += 1 + session_id_len

    if pos + 2 > len(record_body):
        return None
    cipher_suites_len = struct.unpack("!H", record_body[pos:pos + 2])[0]
    pos += 2 + cipher_suites_len

    if pos + 1 > len(record_body):
        return None
    compression_len = record_body[pos]
    pos += 1 + compression_len

    if pos + 2 > len(record_body):
        return None
    extensions_len = struct.unpack("!H", record_body[pos:pos + 2])[0]
    pos += 2
    extensions_end = pos + extensions_len

    while pos + 4 <= min(extensions_end, len(record_body)):
        ext_type = struct.unpack("!H", record_body[pos:pos + 2])[0]
        ext_len = struct.unpack("!H", record_body[pos + 2:pos + 4])[0]
        ext_body = record_body[pos + 4:pos + 4 + ext_len]

        if ext_type == _TLS_EXTENSION_SERVER_NAME:
            hostname = _parse_server_name_extension(ext_body)
            if hostname is not None:
                return hostname

        pos += 4 + ext_len

    return None


def _parse_server_name_extension(ext_body: bytes) -> Optional[str]:
    if len(ext_body) < 2:
        return None
    # server_name_list length (2 bytes), then entries of
    # [type(1) + length(2) + name(length)]
    list_pos = 2
    while list_pos + 3 <= len(ext_body):
        name_type = ext_body[list_pos]
        name_len = struct.unpack(
            "!H", ext_body[list_pos + 1:list_pos + 3]
        )[0]
        name_bytes = ext_body[list_pos + 3:list_pos + 3 + name_len]
        if name_type == _SNI_HOST_NAME_TYPE and name_bytes:
            try:
                candidate = name_bytes.decode("ascii")
            except UnicodeDecodeError:
                return None
            # A successful ASCII decode alone is not enough evidence: this
            # extension slot can be reached by walking into non-SNI bytes
            # (e.g. adjacent extensions or, for malformed/edge-case input,
            # encrypted data), and control characters still decode as
            # valid ASCII. Require it to actually look like a hostname.
            return candidate if _looks_like_hostname(candidate) else None
        list_pos += 3 + name_len
    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """Extract the Host header from a plaintext HTTP/1.x request.

    Only ever sees anything for unencrypted HTTP traffic -- HTTPS Host
    information is not observable this way (see module docstring).
    """
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None

    if "\r\n" not in text:
        return None

    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            candidate = line.split(":", 1)[1].strip()
            # Guard against non-HTTP payloads that coincidentally contain
            # "\r\n" and a line starting with "host:" (rare, but binary
            # data is not excluded from producing that byte sequence).
            return candidate if _looks_like_hostname(candidate) else None
    return None


def extract_dns_query(payload: bytes) -> Optional[str]:
    """Extract the first queried name from a plaintext DNS message.

    Returns None if the payload does not parse as DNS or has no question
    records. Only sees plaintext DNS-over-UDP/53; DoH/DoT are opaque here.
    """
    try:
        dns_packet = DNS(payload)
    except Exception:
        return None

    if dns_packet.haslayer(Raw) and not getattr(dns_packet, "qd", None):
        # Scapy dissected it as raw bytes, not as DNS -- not a DNS message.
        return None

    if not dns_packet.qd or dns_packet.qdcount == 0:
        return None

    try:
        qname = dns_packet.qd[0].qname
    except (IndexError, AttributeError):
        return None

    if qname is None:
        return None

    name = qname.decode("ascii", errors="ignore") if isinstance(qname, bytes) else str(qname)
    name = name.rstrip(".")
    return name if _looks_like_hostname(name) else None