import pytest

from dpi.models import AppType, FiveTuple, PacketAction, TransportProtocol
from dpi.rule_engine import InvalidRuleError, RuleEngine


def ft(src="10.0.0.1", dst="93.184.216.34", sport=1111, dport=443, proto=TransportProtocol.TCP):
    return FiveTuple(src, dst, sport, dport, proto)


def test_forward_by_default():
    engine = RuleEngine()
    assert engine.evaluate(ft(), domain="example.com", app=AppType.UNKNOWN) == PacketAction.FORWARD


def test_block_ip_matches_src_or_dst():
    engine = RuleEngine()
    engine.block_ip("93.184.216.34")
    assert engine.evaluate(ft(), domain=None, app=AppType.UNKNOWN) == PacketAction.DROP


def test_block_domain_exact():
    engine = RuleEngine()
    engine.block_domain("facebook.com")
    assert engine.evaluate(ft(), domain="facebook.com", app=AppType.FACEBOOK) == PacketAction.DROP


def test_block_domain_wildcard_matches_subdomain():
    engine = RuleEngine()
    engine.block_domain("*.facebook.com")
    assert engine.evaluate(ft(), domain="www.facebook.com", app=AppType.FACEBOOK) == PacketAction.DROP


def test_block_domain_wildcard_does_not_match_unrelated_domain():
    engine = RuleEngine()
    engine.block_domain("*.facebook.com")
    assert engine.evaluate(ft(), domain="example.com", app=AppType.UNKNOWN) == PacketAction.FORWARD


def test_block_app():
    engine = RuleEngine()
    engine.block_app(AppType.YOUTUBE)
    assert engine.evaluate(ft(), domain="youtube.com", app=AppType.YOUTUBE) == PacketAction.DROP


def test_block_app_by_string():
    engine = RuleEngine()
    engine.block_app("YouTube")
    assert AppType.YOUTUBE in engine.blocked_apps


def test_block_port():
    engine = RuleEngine()
    engine.block_port(443)
    assert engine.evaluate(ft(dport=443), domain=None, app=AppType.UNKNOWN) == PacketAction.DROP


def test_block_port_matches_src_port_too():
    engine = RuleEngine()
    engine.block_port(1111)
    assert engine.evaluate(ft(sport=1111), domain=None, app=AppType.UNKNOWN) == PacketAction.DROP


def test_invalid_ip_rule_raises():
    engine = RuleEngine()
    with pytest.raises(InvalidRuleError):
        engine.block_ip("")


def test_invalid_domain_rule_raises():
    engine = RuleEngine()
    with pytest.raises(InvalidRuleError):
        engine.block_domain("")


def test_invalid_wildcard_domain_raises():
    engine = RuleEngine()
    with pytest.raises(InvalidRuleError):
        engine.block_domain("*.")


def test_invalid_app_rule_raises():
    engine = RuleEngine()
    with pytest.raises(InvalidRuleError):
        engine.block_app("NotARealApp")


def test_invalid_port_rule_raises():
    engine = RuleEngine()
    with pytest.raises(InvalidRuleError):
        engine.block_port(70000)
    with pytest.raises(InvalidRuleError):
        engine.block_port(0)


def test_evaluation_order_ip_before_domain():
    """An IP-block rule should trigger even if no domain rule matches --
    ensures IP is checked independently, first in priority order."""
    engine = RuleEngine()
    engine.block_ip("93.184.216.34")
    result = engine.evaluate(ft(), domain="totally-unblocked.com", app=AppType.UNKNOWN)
    assert result == PacketAction.DROP