"""
nas_logger.py - write EdgeGuard records to the classroom NAS MariaDB (Socket 7).

Runs in a background thread so a slow or unreachable NAS never blocks the caller.
  - Telemetry is batched and written every 10 s (FR-5.2)
  - Security events / quarantine actions trigger an immediate write (< 2 s, FR-5.3, FR-5.4)
  - While the NAS is down, up to 10,000 records are buffered and written
    in order once it comes back (FR-5.6)

Self-test (from the repo root):  python3 -m hmi.nas_logger
"""
import collections
import json
import threading
import time
import uuid

import pymysql

from common import config

TELEMETRY_FLUSH_S = 10.0
RETRY_S = 5.0
MAX_BUFFER = 10_000

TELEMETRY_SQL = (
    "INSERT INTO telemetry (node, seq, edge_ts, hmi_rx_ts, temp_c, humidity, pressure_hpa) "
    "VALUES (%s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s), %s, %s, %s)"
)
EVENT_SQL = (
    "INSERT INTO security_events "
    "(event_uid, event_type, node, src_ip, src_port, edge_ts, hmi_rx_ts, details) "
    "VALUES (%s, %s, %s, %s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s), %s)"
)
ACTION_SQL = (
    "INSERT INTO quarantine_actions "
    "(order_id, action, target_ip, reason, trigger_event_uid, status, detail, ordered_at, confirmed_at) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s))"
)

CONNECTION_ERRORS = (pymysql.err.OperationalError, pymysql.err.InterfaceError)


class NasLogger:
    def __init__(self):
        self.buffer = collections.deque()      # (sql, params) in arrival order
        self.lock = threading.Lock()           # guards self.buffer
        self.urgent = threading.Event()        # set when an event/action is waiting
        self.stop_flag = threading.Event()
        self.conn = None
        self.next_retry = 0.0
        self.written = 0
        self.dropped = 0
        self.thread = threading.Thread(target=self._run, name="nas_logger", daemon=True)

    # ---- Public API (safe to call from any thread, never blocks) ----

    def start(self):
        self.thread.start()

    def stop(self):
        """Write whatever is buffered, then shut the thread down."""
        self.stop_flag.set()
        self.urgent.set()
        self.thread.join(timeout=10)

    def log_telemetry(self, r):
        params = (r["node"], r["seq"], r["ts"], r["rx_ts"],
                  r["temp_c"], r["humidity"], r["pressure_hpa"])
        self._add(TELEMETRY_SQL, params, urgent=False)

    def log_event(self, event_type, node, rx_ts, edge_ts=None,
                  src_ip=None, src_port=None, details=None, event_uid=None):
        """Log a security event. Returns its event_uid so a quarantine can reference it."""
        event_uid = event_uid or str(uuid.uuid4())
        details_json = json.dumps(details) if details is not None else None
        params = (event_uid, event_type, node, src_ip, src_port, edge_ts, rx_ts, details_json)
        self._add(EVENT_SQL, params, urgent=True)
        return event_uid

    def log_action(self, order_id, action, target_ip, reason, status, detail,
                   ordered_at, confirmed_at, trigger_event_uid=None):
        params = (order_id, action, target_ip, reason, trigger_event_uid,
                  status, detail, ordered_at, confirmed_at)
        self._add(ACTION_SQL, params, urgent=True)

    def stats(self):
        with self.lock:
            buffered = len(self.buffer)
        return {"connected": self.conn is not None, "buffered": buffered,
                "written": self.written, "dropped": self.dropped}

    # ---- Internals (writer thread only) ----

    def _add(self, sql, params, urgent):
        with self.lock:
            if len(self.buffer) >= MAX_BUFFER:
                self.buffer.popleft()          # full: drop the oldest record
                self.dropped += 1
            self.buffer.append((sql, params))
        if urgent:
            self.urgent.set()                  # wake the writer thread now

    def _requeue(self, items):
        """Put unwritten records back at the front, keeping their order."""
        with self.lock:
            self.buffer.extendleft(reversed(items))
            while len(self.buffer) > MAX_BUFFER:
                self.buffer.popleft()
                self.dropped += 1

    def _run(self):
        next_flush = time.monotonic() + TELEMETRY_FLUSH_S
        while True:
            self.urgent.wait(timeout=1.0)      # wake on urgent records or every 1 s
            stopping = self.stop_flag.is_set()
            now = time.monotonic()
            if self.urgent.is_set() or now >= next_flush or stopping:
                self.urgent.clear()
                self._flush()
                if now >= next_flush:
                    next_flush = now + TELEMETRY_FLUSH_S
            if stopping:
                break
        if self.buffer:
            print(f"[nas] shutting down with {len(self.buffer)} unwritten record(s)")
        self._disconnect()

    def _ensure_connected(self):
        if self.conn is not None:
            return True
        if time.monotonic() < self.next_retry:
            return False
        try:
            self.conn = pymysql.connect(
                host=config.get("NAS_IP"),
                port=config.get_int("NAS_PORT", 3306),
                user=config.get("NAS_DB_USER"),
                password=config.get("NAS_DB_PASSWORD"),
                database=config.get("NAS_DB_NAME"),
                connect_timeout=3, read_timeout=5, write_timeout=5,
            )
            print(f"[nas] connected to {config.get('NAS_IP')}")
            return True
        except pymysql.MySQLError as e:
            self.next_retry = time.monotonic() + RETRY_S
            print(f"[nas] cannot connect ({e}); {len(self.buffer)} record(s) buffered, "
                  f"retrying in {RETRY_S:.0f} s")
            return False

    def _disconnect(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass                           # it may already be dead
            self.conn = None

    def _flush(self):
        if not self._ensure_connected():
            return
        with self.lock:
            batch = list(self.buffer)
            self.buffer.clear()
        if not batch:
            return
        try:
            with self.conn.cursor() as cur:
                for sql, params in batch:
                    cur.execute(sql, params)
            self.conn.commit()                 # one transaction for the whole batch
            self.written += len(batch)
        except CONNECTION_ERRORS as e:
            print(f"[nas] connection lost ({e}); keeping {len(batch)} record(s) for retry")
            self._disconnect()
            self._requeue(batch)
        except pymysql.MySQLError as e:
            print(f"[nas] batch rejected ({e}); retrying records one at a time")
            self.conn.rollback()
            self._write_one_by_one(batch)

    def _write_one_by_one(self, batch):
        """Isolate a bad record so it can't block everything behind it."""
        for i, (sql, params) in enumerate(batch):
            try:
                with self.conn.cursor() as cur:
                    cur.execute(sql, params)
                self.conn.commit()
                self.written += 1
            except CONNECTION_ERRORS as e:
                print(f"[nas] connection lost ({e}); keeping {len(batch) - i} record(s)")
                self._disconnect()
                self._requeue(batch[i:])
                return
            except pymysql.MySQLError as e:
                self.conn.rollback()
                self.dropped += 1
                print(f"[nas] dropped bad record ({e}): {params}")


if __name__ == "__main__":
    nas = NasLogger()
    nas.start()
    now = time.time()
    nas.log_telemetry({"node": "selftest", "seq": 1, "ts": now - 0.008, "rx_ts": now,
                       "temp_c": 23.4, "humidity": 41.2, "pressure_hpa": 1012.8})
    uid = nas.log_event("operator_ack", "selftest", rx_ts=now,
                        details={"note": "nas_logger self-test"})
    time.sleep(3)
    nas.stop()
    print(f"[nas] self-test done: {nas.stats()}  event_uid={uid}")
