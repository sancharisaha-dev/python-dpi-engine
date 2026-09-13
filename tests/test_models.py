"""Tests for core models -- mainly FiveTuple hashability/equality, since
everything downstream (flow table, load balancer) depends on it behaving
correctly as a dict key."""

from dpi.models import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
    ParsedPacket,
    TransportProtocol,
)


def make_five_tuple(sport: int = 1111) -> FiveTuple:
    return FiveTuple(
        src_ip="10.0.0.1",
        dst_ip="93.184.216.34",
        src_port=sport,
        dst_port=443,
        protocol=TransportProtocol.TCP,
    )


def test_five_tuple_equality():
    a = make_five_tuple()
    b = make_five_tuple()
    assert a == b


def test_five_tuple_inequality_on_any_field():
    base = make_five_tuple()
    assert base != make_five_tuple(sport=2222)
    assert base != FiveTuple(
        base.src_ip, base.dst_ip, base.src_port, base.dst_port,
        TransportProtocol.UDP,
    )


def test_five_tuple_hashable_and_usable_as_dict_key():
    table: dict[FiveTuple, str] = {}
    ft = make_five_tuple()
    table[ft] = "flow-A"

    # An equal-but-distinct instance must retrieve the same entry.
    same_ft = make_five_tuple()
    assert table[same_ft] == "flow-A"
    assert len({make_five_tuple(), make_five_tuple()}) == 1


def test_five_tuple_is_immutable():
    ft = make_five_tuple()
    try:
        ft.src_port = 9999  # type: ignore[misc]
        assert False, "FiveTuple should be frozen"
    except AttributeError:
        pass


def test_connection_record_packet_updates_counters():
    conn = Connection(five_tuple=make_five_tuple())
    conn.record_packet(raw_length=100)
    conn.record_packet(raw_length=50)
    assert conn.packet_count == 2
    assert conn.byte_count == 150


def test_connection_defaults():
    conn = Connection(five_tuple=make_five_tuple())
    assert conn.state == ConnectionState.NEW
    assert conn.detected_app == AppType.UNKNOWN
    assert conn.last_action is None
    assert conn.inspected is False


def test_parsed_packet_holds_no_scapy_objects():
    pkt = ParsedPacket(
        five_tuple=make_five_tuple(),
        payload=b"hello",
        raw_length=64,
        sequence_number=0,
    )
    assert isinstance(pkt.payload, bytes)
    assert pkt.raw_length == 64