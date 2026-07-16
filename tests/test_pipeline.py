"""Pipeline primitive tests: the bounded drop-queue and the single batched DB writer.

Two invariants matter here and both are load-bearing:

  * The sniffer must NEVER block. On overflow we drop and count. A blocked sniffer
    stops seeing all traffic, which is worse than losing some -- and an uncounted
    drop is indistinguishable from working correctly.
  * The DB writer must actually commit what it accepts, in batches.
"""
import os
import sqlite3
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import (BatchedDBWriter, DropCounterQueue,  # noqa: E402
                      RateTracker, ShardedCaptureQueue)


# --------------------------------------------------------------------------
# bounded capture queue
# --------------------------------------------------------------------------
def test_offer_drops_and_counts_on_overflow():
    q = DropCounterQueue(maxsize=3)
    accepted = [q.offer(i) for i in range(5)]

    assert accepted == [True, True, True, False, False]
    assert q.dropped == 2
    assert q.offered == 5
    assert q.qsize() == 3


def test_offer_never_blocks_when_full():
    """The critical property: a full queue must not stall the caller."""
    q = DropCounterQueue(maxsize=1)
    q.offer("fills it")

    t0 = time.perf_counter()
    for _ in range(2000):
        assert q.offer("dropped") is False
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.0, f"offer() blocked on a full queue ({elapsed:.2f}s)"
    assert q.dropped == 2000


def test_no_drops_below_capacity():
    q = DropCounterQueue(maxsize=100)
    for i in range(100):
        assert q.offer(i) is True
    assert q.dropped == 0
    assert q.stats() == {"offered": 100, "dropped": 0, "queued": 100}


def test_drained_queue_accepts_again():
    """Overflow is transient: once consumers catch up, capture resumes."""
    q = DropCounterQueue(maxsize=2)
    q.offer(1); q.offer(2)
    assert q.offer(3) is False

    assert q.get() == 1
    q.task_done()
    assert q.offer(4) is True
    assert q.dropped == 1


def test_put_blocking_applies_backpressure_for_file_replay():
    """Replay is lossless: a pcap producer waits rather than dropping."""
    q = DropCounterQueue(maxsize=1)
    q.put_blocking("first")
    done = threading.Event()

    def producer():
        q.put_blocking("second")     # must wait for space
        done.set()

    t = threading.Thread(target=producer, daemon=True)
    t.start()
    assert not done.wait(0.2), "put_blocking should have waited on a full queue"

    q.get(); q.task_done()
    assert done.wait(2.0), "put_blocking never completed after space freed"
    assert q.dropped == 0
    t.join(1.0)


def test_put_blocking_counts_toward_offered():
    """`offered` drives packets/sec and the /stats header. Counting only offer()
    made pcap replay -- the demo path -- report 0 packets captured while hundreds
    flowed through it."""
    q = DropCounterQueue(maxsize=10)
    for i in range(5):
        q.put_blocking(i)
    assert q.offered == 5
    assert q.stats() == {"offered": 5, "dropped": 0, "queued": 5}

    q.offer("live")
    assert q.offered == 6, "offer() and put_blocking() must count the same way"


# --------------------------------------------------------------------------
# flow-key sharding
#
# The invariant: all packets of one flow reach the SAME shard, in order. Flow
# tracking is order-dependent, so violating this fragments flows and reverses
# their direction -- which is exactly what the shared-tracker design did.
# --------------------------------------------------------------------------
def test_same_key_always_routes_to_the_same_shard():
    q = ShardedCaptureQueue(shards=8, total_maxsize=800)
    key = (("1.1.1.1", 4000), ("2.2.2.2", 80), 6)
    assert len({q.index_for(key) for _ in range(100)}) == 1


def test_a_flows_packets_stay_in_order_within_its_shard():
    """FIFO per shard is what preserves within-flow packet order."""
    q = ShardedCaptureQueue(shards=4, total_maxsize=400)
    key = (("1.1.1.1", 4000), ("2.2.2.2", 80), 6)
    for i in range(20):
        q.put_blocking(key, i)

    shard = q.queue(q.index_for(key))
    assert [shard.get() for _ in range(20)] == list(range(20))


def test_both_directions_of_a_flow_share_a_shard():
    """The canonical key is direction-independent; if A->B and B->A split across
    shards, two workers would each see half a conversation."""
    q = ShardedCaptureQueue(shards=8, total_maxsize=800)
    # What flow_tracker.canonical_key produces for either direction.
    key = (("1.1.1.1", 4000), ("2.2.2.2", 80), 6)
    assert q.index_for(key) == q.index_for(key)

    q.put_blocking(key, "forward")
    q.put_blocking(key, "backward")
    shard = q.queue(q.index_for(key))
    assert shard.qsize() == 2, "both directions must land in one shard"


def test_distinct_flows_spread_across_shards():
    """Sharding must actually parallelise; everything on one worker would be a
    correct but pointless pipeline."""
    q = ShardedCaptureQueue(shards=8, total_maxsize=8000)
    keys = [(("10.0.0.%d" % i, 4000 + i), ("2.2.2.2", 80), 6) for i in range(200)]
    used = {q.index_for(k) for k in keys}
    assert len(used) == 8, f"200 flows only reached {len(used)} of 8 shards"


def test_total_capacity_is_split_not_multiplied():
    """The memory bound must match the single-queue design it replaced."""
    q = ShardedCaptureQueue(shards=4, total_maxsize=400)
    for i in range(4):
        assert q.queue(i)._q.maxsize == 100


def test_offer_drops_and_counts_per_shard_without_blocking():
    q = ShardedCaptureQueue(shards=2, total_maxsize=4)      # 2 slots per shard
    key = (("1.1.1.1", 4000), ("2.2.2.2", 80), 6)
    accepted = [q.offer(key, i) for i in range(5)]

    assert accepted == [True, True, False, False, False]
    assert q.dropped == 3
    assert q.offered == 5
    stats = q.stats()
    assert stats["dropped"] == 3 and stats["offered"] == 5
    assert len(stats["shards"]) == 2
    assert sum(s["dropped"] for s in stats["shards"]) == 3


def test_stats_aggregate_across_shards():
    q = ShardedCaptureQueue(shards=4, total_maxsize=400)
    for i in range(40):
        q.put_blocking((("10.0.0.%d" % i, i), ("2.2.2.2", 80), 6), i)
    q.count_ignored()
    q.count_ignored()

    s = q.stats()
    assert s["offered"] == 40
    assert s["queued"] == 40 == q.qsize()
    assert s["dropped"] == 0
    assert s["ignored"] == 2, "non-flow packets are counted, not silently vanished"


def test_join_waits_for_every_shard():
    q = ShardedCaptureQueue(shards=3, total_maxsize=300)
    for i in range(9):
        q.put_blocking((("10.0.0.%d" % i, i), ("2.2.2.2", 80), 6), i)

    done = threading.Event()
    threading.Thread(target=lambda: (q.join(), done.set()), daemon=True).start()
    assert not done.wait(0.2), "join() returned with work outstanding"

    for i in range(q.shards):
        shard = q.queue(i)
        while shard.qsize():
            shard.get()
            shard.task_done()
    assert done.wait(2.0), "join() never returned after all shards drained"


def test_shard_count_must_be_positive():
    with pytest.raises(ValueError):
        ShardedCaptureQueue(shards=0, total_maxsize=100)


# --------------------------------------------------------------------------
# packets/sec sampler
# --------------------------------------------------------------------------
class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_rate_is_measured_over_the_sampling_window():
    """100 packets per tick over 5 ticks of 1s => 100/sec."""
    clock = FakeClock()
    counter = {"n": 0}
    r = RateTracker(lambda: counter["n"], interval=1.0, window=30.0, clock=clock)

    for _ in range(5):
        r.sample()
        counter["n"] += 100
        clock.advance(1.0)
    r.sample()

    assert r.rate() == pytest.approx(100.0)


def test_rate_is_zero_until_two_samples_exist():
    """One data point is not a rate; refuse to guess."""
    clock = FakeClock()
    r = RateTracker(lambda: 500, interval=1.0, window=30.0, clock=clock)
    assert r.rate() == 0.0
    r.sample()
    assert r.rate() == 0.0, "a single sample cannot imply a rate"


def test_rate_does_not_depend_on_who_reads_it():
    """The whole reason this is a sampler thread: /stats may be polled by any
    number of dashboards at any interval, and the packet rate must not change
    because someone opened a second browser tab."""
    clock = FakeClock()
    counter = {"n": 0}
    r = RateTracker(lambda: counter["n"], interval=1.0, window=30.0, clock=clock)

    for _ in range(4):
        r.sample()
        counter["n"] += 50
        clock.advance(1.0)
    r.sample()

    assert r.rate() == r.rate() == pytest.approx(50.0), "reading changed the value"


def test_rate_window_is_bounded():
    """Samples must not accumulate forever in a long-running process."""
    clock = FakeClock()
    r = RateTracker(lambda: 1, interval=1.0, window=10.0, clock=clock)
    for _ in range(1000):
        r.sample()
        clock.advance(1.0)
    assert len(r._samples) <= 12


def test_rate_falls_back_to_zero_on_a_stalled_clock():
    clock = FakeClock()
    r = RateTracker(lambda: 7, interval=1.0, window=30.0, clock=clock)
    r.sample()
    r.sample()                      # same instant, no elapsed time
    assert r.rate() == 0.0, "a zero-length window must not divide by zero"


def test_rate_thread_samples_on_its_own():
    counter = {"n": 0}
    r = RateTracker(lambda: counter["n"], interval=0.02, window=5.0)
    r.start()
    try:
        deadline = time.time() + 2
        while time.time() < deadline and len(r._samples) < 3:
            counter["n"] += 10
            time.sleep(0.01)
        assert len(r._samples) >= 3, "sampler thread never sampled"
        assert r.rate() > 0
    finally:
        r.stop()
        r.join(1.0)


# --------------------------------------------------------------------------
# single batched DB writer
# --------------------------------------------------------------------------
INSERT = "INSERT INTO t (v) VALUES (?)"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "w.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)")
    conn.execute("CREATE TABLE t2 (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)")
    conn.commit()
    conn.close()
    return path


def _rows(path, table="t"):
    conn = sqlite3.connect(path)
    try:
        return [r[0] for r in conn.execute(f"SELECT v FROM {table} ORDER BY id")]
    finally:
        conn.close()


def test_writer_flushes_everything_submitted(db):
    w = BatchedDBWriter(db, batch_size=10, flush_interval=0.05)
    w.start()
    try:
        for i in range(250):
            assert w.submit(INSERT, (f"v{i}",)) is True
        assert w.drain(timeout=10) is True
        assert _rows(db) == [f"v{i}" for i in range(250)]
        assert w.stats()["written"] == 250
    finally:
        w.stop()


def test_writer_batches_rather_than_committing_per_row(db):
    """250 rows at batch_size=50 must not become 250 commits."""
    w = BatchedDBWriter(db, batch_size=50, flush_interval=5.0)
    w.start()
    try:
        for i in range(250):
            w.submit(INSERT, (f"v{i}",))
        assert w.drain(timeout=10) is True
        batches = w.stats()["batches"]
        assert len(_rows(db)) == 250
        assert batches <= 10, f"expected batching, got {batches} batches for 250 rows"
    finally:
        w.stop()


def test_writer_flushes_partial_batch_on_time_trigger(db):
    """A trickle must not sit in the queue forever waiting for a full batch."""
    w = BatchedDBWriter(db, batch_size=1000, flush_interval=0.1)
    w.start()
    try:
        w.submit(INSERT, ("lonely",))
        deadline = time.time() + 5
        while time.time() < deadline and not _rows(db):
            time.sleep(0.02)
        assert _rows(db) == ["lonely"], "partial batch was not time-flushed"
    finally:
        w.stop()


def test_writer_groups_multiple_statements_in_one_batch(db):
    w = BatchedDBWriter(db, batch_size=100, flush_interval=0.05)
    w.start()
    try:
        for i in range(20):
            w.submit(INSERT, (f"a{i}",))
            w.submit("INSERT INTO t2 (v) VALUES (?)", (f"b{i}",))
        assert w.drain(timeout=10) is True
        assert _rows(db, "t") == [f"a{i}" for i in range(20)]
        assert _rows(db, "t2") == [f"b{i}" for i in range(20)]
    finally:
        w.stop()


def test_writer_enables_wal(db):
    w = BatchedDBWriter(db, batch_size=5, flush_interval=0.05)
    w.start()
    try:
        w.submit(INSERT, ("x",))
        w.drain(timeout=10)
        conn = sqlite3.connect(db)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode.lower() == "wal"
    finally:
        w.stop()


def test_writer_drops_and_counts_when_queue_full(db):
    """A stalled disk must not back-pressure into the enrichment workers."""
    w = BatchedDBWriter(db, batch_size=10, flush_interval=0.05, maxsize=5)
    # deliberately NOT started: nothing drains, so the queue fills
    accepted = [w.submit(INSERT, (str(i),)) for i in range(20)]
    assert accepted[:5] == [True] * 5
    assert all(a is False for a in accepted[5:])
    assert w.stats()["dropped"] == 15


def test_concurrent_producers_all_land(db):
    """Many workers submit; exactly one thread writes; nothing is lost."""
    w = BatchedDBWriter(db, batch_size=32, flush_interval=0.05)
    w.start()
    try:
        def produce(n):
            for i in range(50):
                w.submit(INSERT, (f"t{n}-{i}",))

        threads = [threading.Thread(target=produce, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert w.drain(timeout=10) is True
        assert len(_rows(db)) == 400
    finally:
        w.stop()
