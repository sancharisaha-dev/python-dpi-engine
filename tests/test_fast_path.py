import queue

from dpi.classifier import DomainClassifier
from dpi.fast_path import FastPathWorker
from dpi.models import (
    AppType,
    FiveTuple,
    PacketAction,
    PacketJob,
    ParsedPacket,
    TransportProtocol,
)
from dpi.rule_engine import RuleEngine
from dpi.sni_extractor import extract_sni

from tests.test_sni_extractor import _build_client_hello


def ft():
    return FiveTuple("10.0.0.1", "93.184.216.34", 1111, 443, TransportProtocol.TCP)


def make_worker(rule_engine=None):
    return FastPathWorker(
        worker_id=0,
        job_queue=queue.Queue(),
        rule_engine=rule_engine or RuleEngine(),
        classifier=DomainClassifier(),
    )


def job_with_payload(payload: bytes, five_tuple=None, seq=0):
    five_tuple = five_tuple or ft()
    packet = ParsedPacket(
        five_tuple=five_tuple, payload=payload, raw_length=100, sequence_number=seq
    )
    return PacketJob(packet=packet)


def test_forwards_unclassified_traffic_by_default():
    worker = make_worker()
    action = worker.process_job(job_with_payload(b""))
    assert action == PacketAction.FORWARD


def test_extracts_sni_and_classifies_and_blocks():
    rule_engine = RuleEngine()
    rule_engine.block_domain("*.youtube.com")
    worker = make_worker(rule_engine)

    payload = _build_client_hello("m.youtube.com")
    action = worker.process_job(job_with_payload(payload))

    assert action == PacketAction.DROP
    conn = worker.flow_tracker.get(ft())
    assert conn.detected_domain == "m.youtube.com"
    assert conn.detected_app == AppType.YOUTUBE


def test_already_blocked_flow_drops_without_reinspection():
    rule_engine = RuleEngine()
    rule_engine.block_domain("*.youtube.com")
    worker = make_worker(rule_engine)

    payload = _build_client_hello("m.youtube.com")
    worker.process_job(job_with_payload(payload, seq=0))

    # Second packet on the same flow has NO identifying payload at all --
    # if the worker tried to re-inspect, it would find no domain and might
    # forward. Instead it must short-circuit on the already-BLOCKED state.
    second_action = worker.process_job(job_with_payload(b"", seq=1))
    assert second_action == PacketAction.DROP


def test_forwarded_sequence_numbers_recorded():
    worker = make_worker()
    worker.process_job(job_with_payload(b"", seq=42))
    assert 42 in worker.forwarded_sequence_numbers


def test_dropped_packets_not_in_forwarded_sequence_numbers():
    rule_engine = RuleEngine()
    rule_engine.block_ip("93.184.216.34")
    worker = make_worker(rule_engine)
    worker.process_job(job_with_payload(b"", seq=7))
    assert 7 not in worker.forwarded_sequence_numbers


def test_worker_stats_track_forward_and_drop_counts():
    rule_engine = RuleEngine()
    rule_engine.block_port(443)
    worker = make_worker(rule_engine)
    worker.process_job(job_with_payload(b"", seq=1))
    worker.process_job(job_with_payload(b"", seq=2))
    assert worker.stats.packets_processed == 2
    assert worker.stats.packets_dropped == 2
    assert worker.stats.packets_forwarded == 0


def test_run_processes_until_sentinel():
    worker = make_worker()
    worker.job_queue.put(job_with_payload(b"", seq=1))
    worker.job_queue.put(job_with_payload(b"", seq=2))
    worker.job_queue.put(None)
    worker.run()
    assert worker.stats.packets_processed == 2