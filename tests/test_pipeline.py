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

from pipeline import BatchedDBWriter, DropCounterQueue  # noqa: E402


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
