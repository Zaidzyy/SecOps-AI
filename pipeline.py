"""Ingestion pipeline primitives: a bounded drop-queue and a single batched DB writer.

    sniff thread (capture ONLY)
      -> capture_queue (bounded; DROP + count on overflow, never blocks)
        -> N enrichment workers (geo/reputation via TTL cache, flow tracking, classify)
          -> write_queue
            -> ONE DB-writer thread (batched inserts, one connection, WAL)

Two rules drive this design:

1. The sniffer must never block. If the capture queue is full we drop the packet
   and increment a counter. A blocked sniffer stops seeing *all* traffic, which is
   worse than losing some of it -- and the drop counter makes the loss visible
   instead of silent.

2. Exactly one thread writes to SQLite. SQLite serializes writes anyway, so
   multiple writer threads would only trade I/O-blocking for lock-blocking. One
   thread draining a queue in batches removes contention and amortizes commits.

Both classes are plain threading primitives with no app imports, so they are
testable on their own.
"""
from __future__ import annotations

import queue
import sqlite3
import threading
import time
from collections import defaultdict, deque

import config


class DropCounterQueue:
    """Bounded queue that drops (and counts) instead of blocking the producer.

    `offer()` is the sniffer's entry point: it never blocks. `put_blocking()`
    exists for file replay, where the producer is a pcap rather than live traffic
    -- there is no traffic to miss, so applying backpressure is correct and keeps
    replay lossless.
    """

    def __init__(self, maxsize: int):
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._dropped = 0
        self._offered = 0
        self._lock = threading.Lock()

    def offer(self, item) -> bool:
        """Never blocks. Returns False and counts a drop if the queue is full."""
        with self._lock:
            self._offered += 1
        try:
            self._q.put_nowait(item)
            return True
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False

    def put_blocking(self, item, timeout: float | None = None) -> None:
        # Counts toward `offered` exactly like offer() does: `offered` means
        # "packets this queue accepted", and it feeds packets/sec and the /stats
        # header. Counting only the offer() path made replay -- which is the whole
        # demo path -- report 0 packets captured while 264 flowed through it.
        with self._lock:
            self._offered += 1
        self._q.put(item, timeout=timeout)

    def get(self, timeout: float | None = None):
        return self._q.get(timeout=timeout)

    def task_done(self) -> None:
        self._q.task_done()

    def join(self) -> None:
        self._q.join()

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def offered(self) -> int:
        with self._lock:
            return self._offered

    def qsize(self) -> int:
        return self._q.qsize()

    def stats(self) -> dict:
        with self._lock:
            return {"offered": self._offered, "dropped": self._dropped,
                    "queued": self._q.qsize()}


class RateTracker(threading.Thread):
    """Samples a monotonically-increasing counter on a fixed interval and reports
    its rate of change over a trailing window.

    This is a thread rather than "remember the last value the caller saw" on
    purpose: /stats is polled by however many dashboards happen to be open, at
    whatever interval they like, and a rate computed from the gap between reads
    would change meaning with the number of viewers -- two browsers would each
    see roughly half the true packet rate. Sampling on our own clock makes
    packets/sec a property of the traffic instead of a property of the audience.
    """

    def __init__(self, source, interval: float = config.RATE_SAMPLE_INTERVAL_S,
                 window: float = config.RATE_WINDOW_S, clock=time.monotonic):
        super().__init__(name="rate-tracker", daemon=True)
        self._source = source
        self._interval = interval
        self._clock = clock
        # +2: enough samples to always span the full window, never unbounded.
        self._samples: deque = deque(maxlen=int(window / max(interval, 0.001)) + 2)
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()

    def sample(self) -> None:
        with self._lock:
            self._samples.append((self._clock(), self._source()))

    def rate(self) -> float:
        """Units per second across the trailing window, 0.0 until two samples
        exist (we refuse to guess a rate from a single point)."""
        with self._lock:
            if len(self._samples) < 2:
                return 0.0
            (t0, c0), (t1, c1) = self._samples[0], self._samples[-1]
        dt = t1 - t0
        if dt <= 0:
            return 0.0
        return max(0.0, (c1 - c0) / dt)

    def run(self) -> None:
        self.sample()
        while not self._stop_evt.wait(self._interval):
            self.sample()

    def stop(self) -> None:
        self._stop_evt.set()


_STOP = object()
_FLUSH = object()


class BatchedDBWriter(threading.Thread):
    """The ONLY thread that writes to SQLite.

    Drains a queue of (sql, params) and flushes them with executemany, grouped by
    statement, when either DB_BATCH_SIZE rows are pending or DB_FLUSH_INTERVAL_S
    has elapsed. Uses one long-lived connection in WAL mode so dashboard reads
    never block behind a write.
    """

    def __init__(self, db_path: str,
                 batch_size: int = config.DB_BATCH_SIZE,
                 flush_interval: float = config.DB_FLUSH_INTERVAL_S,
                 maxsize: int = config.WRITE_QUEUE_MAX):
        super().__init__(name="db-writer", daemon=True)
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()
        self._stats = {"written": 0, "batches": 0, "dropped": 0, "errors": 0}
        self._conn: sqlite3.Connection | None = None

    # -- producer side -----------------------------------------------------
    def submit(self, sql: str, params: tuple) -> bool:
        """Queue one row. Never blocks; drops + counts if the queue is full so a
        stalled disk can't back-pressure into the enrichment workers."""
        try:
            self._q.put_nowait((sql, params))
            return True
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1
            return False

    # -- consumer side -----------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        # WAL: readers (Flask routes) never block behind this writer, and the
        # writer never blocks behind readers.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def run(self) -> None:
        self._conn = self._connect()
        batch: list[tuple] = []
        deadline = time.monotonic() + self.flush_interval
        while True:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                item = self._q.get(timeout=timeout)
            except queue.Empty:
                item = None
            else:
                if item is _STOP:
                    self._flush(batch)
                    batch = []
                    self._q.task_done()
                    break
                if isinstance(item, tuple) and item and item[0] is _FLUSH:
                    # Flush barrier: commit everything queued before it, THEN
                    # signal. drain() relies on this to be race-free -- waiting on
                    # queue.join() alone would return before the final partial
                    # batch had been committed.
                    self._flush(batch)
                    batch = []
                    deadline = time.monotonic() + self.flush_interval
                    item[1].set()
                    self._q.task_done()
                    continue
                batch.append(item)
                self._q.task_done()

            if len(batch) >= self.batch_size or (batch and time.monotonic() >= deadline):
                self._flush(batch)
                batch = []
                deadline = time.monotonic() + self.flush_interval
            elif item is None:
                deadline = time.monotonic() + self.flush_interval
        if self._conn is not None:
            self._conn.close()

    def _flush(self, batch: list[tuple]) -> None:
        if not batch:
            return
        groups: dict[str, list[tuple]] = defaultdict(list)
        for sql, params in batch:
            groups[sql].append(params)
        try:
            for sql, rows in groups.items():
                self._conn.executemany(sql, rows)
            self._conn.commit()
            with self._lock:
                self._stats["written"] += len(batch)
                self._stats["batches"] += 1
        except Exception as e:                      # pragma: no cover - defensive
            with self._lock:
                self._stats["errors"] += 1
            print(f"[ERROR] DB writer batch failed ({len(batch)} rows, continuing): {e}")

    # -- lifecycle ---------------------------------------------------------
    def drain(self, timeout: float = 30.0) -> bool:
        """Block until everything queued so far is committed. Returns True if the
        flush completed within `timeout`.

        Used by replay and tests so writes are observable at a known point; the
        live path never needs it. Implemented as a barrier rather than
        queue.join() because task_done() fires when a row is dequeued, which is
        before it is committed.
        """
        if not self.is_alive():
            return False
        done = threading.Event()
        self._q.put((_FLUSH, done))
        return done.wait(timeout)

    def stop(self, timeout: float = 5.0) -> None:
        self._q.put(_STOP)
        self.join(timeout=timeout)

    def stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
        s["queued"] = self._q.qsize()
        return s
