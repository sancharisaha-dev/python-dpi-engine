"""Deterministic load balancing across fast-path workers via flow affinity.

Why flow affinity matters (interview-ready explanation):

Each fast-path worker owns a private FlowTracker holding only the flows
routed to it. Because worker selection is a pure, deterministic function of
the FiveTuple, every packet belonging to the same flow is guaranteed to
land on the same worker for the lifetime of that flow. That means:

  - No two threads ever read or write the same Connection object, so the
    flow table needs NO locks, despite being mutated concurrently overall.
  - Only truly global state (aggregate statistics, the output packet
    queue) needs synchronization, and that's handled by queue.Queue,
    which is internally lock-protected.

This is a common real-world DPI/load-balancer pattern (matches how RSS/RPS
hashing and many hardware NICs pin flows to CPU cores for the same reason).

We deliberately do NOT use Python's builtin hash() for this, because
str/bytes hashing in CPython is randomized per-process via PYTHONHASHSEED
(for security, to prevent hash-flooding attacks). That randomization would
break our requirement that the same flow maps to the same worker
consistently -- it would even differ between two runs of the same program.
Instead we use hashlib.blake2b, which is stable across runs and processes.
"""

from __future__ import annotations

import hashlib
import queue
from dataclasses import dataclass, field

from dpi.models import FiveTuple, PacketJob


def stable_hash(five_tuple: FiveTuple) -> int:
    """A hash of a FiveTuple that is stable across processes and runs
    (unlike Python's built-in hash() for strings, which is randomized per
    process). Used purely for worker selection, not as the FiveTuple's
    __hash__ (that one is derived automatically from the frozen dataclass
    fields and is used for the flow table dict)."""
    canonical = "|".join(
        [
            five_tuple.src_ip,
            five_tuple.dst_ip,
            str(five_tuple.src_port),
            str(five_tuple.dst_port),
            five_tuple.protocol.value,
        ]
    ).encode("utf-8")
    digest = hashlib.blake2b(canonical, digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big")


@dataclass
class LoadBalancer:
    """Routes PacketJobs to worker queues using deterministic flow affinity.

    worker_id = stable_hash(five_tuple) % num_workers

    The same flow always maps to the same worker_id, for as long as
    num_workers does not change mid-run (changing worker count would
    naturally reshuffle flow->worker assignment, same as resizing a
    consistent-hash ring without the "consistent" part -- a known
    trade-off, not a bug).
    """

    num_workers: int
    queues: list[queue.Queue] = field(init=False)

    def __post_init__(self) -> None:
        if self.num_workers < 1:
            raise ValueError("num_workers must be >= 1")
        self.queues = [queue.Queue() for _ in range(self.num_workers)]

    def worker_id_for(self, five_tuple: FiveTuple) -> int:
        return stable_hash(five_tuple) % self.num_workers

    def dispatch(self, job: PacketJob) -> int:
        """Route a job to its worker's queue. Returns the worker_id it was
        sent to (useful for statistics/logging)."""
        worker_id = self.worker_id_for(job.five_tuple)
        self.queues[worker_id].put(job)
        return worker_id

    def shutdown(self) -> None:
        """Push a sentinel (None) onto every worker queue so each worker's
        consume loop can exit cleanly once it drains remaining jobs.
        Using None as a sentinel is safe here because a real PacketJob is
        never None -- workers check `if job is None: break` before doing
        any further processing."""
        for q in self.queues:
            q.put(None)