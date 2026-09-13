from dpi.load_balancer import LoadBalancer, stable_hash
from dpi.models import FiveTuple, ParsedPacket, PacketJob, TransportProtocol


def ft(sport=1111):
    return FiveTuple("10.0.0.1", "93.184.216.34", sport, 443, TransportProtocol.TCP)


def job_for(five_tuple):
    packet = ParsedPacket(
        five_tuple=five_tuple, payload=b"", raw_length=60, sequence_number=0
    )
    return PacketJob(packet=packet)


def test_stable_hash_is_deterministic_across_calls():
    five_tuple = ft()
    assert stable_hash(five_tuple) == stable_hash(five_tuple)


def test_same_flow_always_maps_to_same_worker():
    lb = LoadBalancer(num_workers=4)
    five_tuple = ft()
    ids = {lb.worker_id_for(five_tuple) for _ in range(20)}
    assert len(ids) == 1


def test_dispatch_puts_job_on_correct_worker_queue():
    lb = LoadBalancer(num_workers=4)
    five_tuple = ft()
    job = job_for(five_tuple)
    worker_id = lb.dispatch(job)
    assert lb.queues[worker_id].get_nowait() is job


def test_different_flows_can_map_to_different_workers():
    lb = LoadBalancer(num_workers=8)
    worker_ids = {lb.worker_id_for(ft(sport=p)) for p in range(1000, 1050)}
    # Not a strict requirement of correctness, but with 50 distinct flows
    # across 8 workers we should see more than one worker used.
    assert len(worker_ids) > 1


def test_shutdown_pushes_sentinel_to_every_queue():
    lb = LoadBalancer(num_workers=3)
    lb.shutdown()
    for q in lb.queues:
        assert q.get_nowait() is None


def test_invalid_worker_count_raises():
    try:
        LoadBalancer(num_workers=0)
        assert False, "expected ValueError"
    except ValueError:
        pass