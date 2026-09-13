from dpi.flow_tracker import FlowTracker
from dpi.models import AppType, ConnectionState, FiveTuple, PacketAction, TransportProtocol


def ft():
    return FiveTuple("10.0.0.1", "93.184.216.34", 1111, 443, TransportProtocol.TCP)


def test_get_or_create_creates_new_connection_in_new_state():
    tracker = FlowTracker()
    conn = tracker.get_or_create(ft())
    assert conn.state == ConnectionState.NEW
    assert len(tracker) == 1


def test_get_or_create_returns_same_connection_for_same_flow():
    tracker = FlowTracker()
    conn_a = tracker.get_or_create(ft())
    conn_b = tracker.get_or_create(ft())
    assert conn_a is conn_b


def test_record_packet_updates_counters_and_transitions_state():
    tracker = FlowTracker()
    five_tuple = ft()
    tracker.record_packet(five_tuple, raw_length=100)
    conn = tracker.get(five_tuple)
    assert conn.packet_count == 1
    assert conn.state == ConnectionState.NEW

    tracker.record_packet(five_tuple, raw_length=50)
    conn = tracker.get(five_tuple)
    assert conn.packet_count == 2
    assert conn.byte_count == 150
    assert conn.state == ConnectionState.ESTABLISHED


def test_apply_classification_sets_domain_and_app():
    tracker = FlowTracker()
    five_tuple = ft()
    tracker.apply_classification(five_tuple, domain="youtube.com", app=AppType.YOUTUBE)
    conn = tracker.get(five_tuple)
    assert conn.detected_domain == "youtube.com"
    assert conn.detected_app == AppType.YOUTUBE
    assert conn.inspected is True


def test_apply_action_drop_transitions_to_blocked():
    tracker = FlowTracker()
    five_tuple = ft()
    tracker.apply_action(five_tuple, PacketAction.DROP)
    conn = tracker.get(five_tuple)
    assert conn.state == ConnectionState.BLOCKED
    assert conn.last_action == PacketAction.DROP


def test_apply_action_forward_does_not_block():
    tracker = FlowTracker()
    five_tuple = ft()
    tracker.apply_action(five_tuple, PacketAction.FORWARD)
    conn = tracker.get(five_tuple)
    assert conn.state != ConnectionState.BLOCKED


def test_is_blocked_true_only_after_drop():
    tracker = FlowTracker()
    five_tuple = ft()
    assert tracker.is_blocked(five_tuple) is False
    tracker.apply_action(five_tuple, PacketAction.DROP)
    assert tracker.is_blocked(five_tuple) is True


def test_is_blocked_false_for_unknown_flow():
    tracker = FlowTracker()
    assert tracker.is_blocked(ft()) is False


def test_close_sets_closed_unless_blocked():
    tracker = FlowTracker()
    five_tuple = ft()
    tracker.get_or_create(five_tuple)
    tracker.close(five_tuple)
    assert tracker.get(five_tuple).state == ConnectionState.CLOSED


def test_close_does_not_override_blocked():
    tracker = FlowTracker()
    five_tuple = ft()
    tracker.apply_action(five_tuple, PacketAction.DROP)
    tracker.close(five_tuple)
    assert tracker.get(five_tuple).state == ConnectionState.BLOCKED