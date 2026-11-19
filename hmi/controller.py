"""
controller.py - EdgeGuard quarantine controller (HMI Pi, runs in Docker)

  S3  TCP :5020  server  <- Sense HAT event_reporter (security events)
  S4  TCP :5030  client  -> Sense HAT enforcement_agent (quarantine/release orders)
  S8  TCP :5070  server  <- dashboard, localhost only (live updates + release requests)
  S7  NasLogger          -> NAS (security_events, quarantine_actions)

Policy (FR-3.7): quarantine after 1 canary_hit, or after UNAUTH_CMD_LIMIT
unauthorized_command events from the same IP within UNAUTH_WINDOW_S seconds.
This is the only place quarantine decisions are made (FR-2.2).

Run (repo root):  python3 -m hmi.controller
"""
import collections
import functools
import ipaddress
import json
import selectors
import socket
import time
import uuid
from pathlib import Path

from common import config
from common.messages import NUMBER, decode_json, encode_line, require_fields
from hmi.nas_logger import NasLogger

# ---- Settings (common/config.env; env vars override, e.g. in docker-compose.yml) ----
SENSEHAT_IP = config.get("SENSEHAT_IP")
EVENT_PORT = config.get_int("EVENT_PORT", 5020)
ENFORCE_PORT = config.get_int("ENFORCE_PORT", 5030)
CONTROL_PORT = config.get_int("CONTROL_PORT", 5070)
CONTROL_BIND = config.get("CONTROL_BIND", "127.0.0.1")    # set to 0.0.0.0 inside Docker
EVENT_SOURCES = {ip.strip() for ip in config.get("EVENT_SOURCES", SENSEHAT_IP).split(",")}
SUBNET = ipaddress.ip_network(config.get("CLASSROOM_SUBNET"), strict=False)
ALLOWLIST = {ip for ip in (config.get("HMI_IP"), SENSEHAT_IP,
                           config.get("MGMT_HOST_IP", ""), config.get("GATEWAY_IP", "")) if ip}
UNAUTH_LIMIT = config.get_int("UNAUTH_CMD_LIMIT", 3)
UNAUTH_WINDOW_S = config.get_float("UNAUTH_WINDOW_S", 60)
STATE_FILE = Path(config.get("CONTROLLER_STATE_FILE", "data/controller_state.json"))
RETRY_S = 2.0
MAX_LINE = 4096
RECENT_EVENTS = 50

SECURITY_EVENT_FIELDS = {
    "type": str, "event": str, "node": str, "ts": NUMBER,
    "src_ip": str, "src_port": int, "details": dict,
}
EVENT_TYPES = {"canary_hit", "unauthorized_command"}


def parse_security_event(line):
    """One line of bytes -> validated security_event dict, or raise ValueError."""
    msg = decode_json(line)
    require_fields(msg, SECURITY_EVENT_FIELDS)
    if msg["type"] != "security_event":
        raise ValueError(f"unexpected type {msg['type']!r}")
    if msg["event"] not in EVENT_TYPES:
        raise ValueError(f"unknown event {msg['event']!r}")
    try:
        ipaddress.ip_address(msg["src_ip"])          # it may end up in a firewall rule
    except ValueError:
        raise ValueError(f"src_ip {msg['src_ip']!r} is not a valid IP address")
    return msg


class LineConn:
    """One TCP connection carrying newline-delimited JSON (used for S3, S4 and S8)."""

    def __init__(self, sock, name):
        self.sock = sock
        self.name = name
        self.buf = bytearray()

    def read_lines(self):
        """Complete lines received so far, or None if the connection is finished."""
        try:
            data = self.sock.recv(4096)
        except OSError:
            return None
        if not data:                                  # b"" = the peer closed
            return None
        self.buf += data
        *lines, self.buf = self.buf.split(b"\n")       # framing: keep the partial line
        if len(self.buf) > MAX_LINE:
            return None
        return [line for line in lines if line.strip()]

    def send(self, msg):
        try:
            self.sock.sendall(encode_line(msg))
            return True
        except OSError:
            return False


class Controller:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.nas = NasLogger()
        self.quarantined = {}          # ip -> {reason, since, order_id, event_uid}
        self.strikes = collections.defaultdict(collections.deque)   # ip -> times of unauthorized cmds
        self.recent = collections.deque(maxlen=RECENT_EVENTS)       # replayed to new dashboards
        self.pending = {}              # order_id -> {order, event_uid, ordered_at, sent}
        self.enforcer = None           # LineConn to the enforcement agent (S4)
        self.next_connect = 0.0
        self.dashboards = set()        # LineConns on S8
        self.stats = {"s3_clients": 0, "events": 0, "malformed": 0, "refused": 0,
                      "orders_sent": 0, "results": 0}
        self.load_state()

    # ---- Saved state: the quarantine list survives a controller restart ----

    def load_state(self):
        try:
            self.quarantined = json.loads(STATE_FILE.read_text())
            print(f"[controller] restored {len(self.quarantined)} quarantine(s) from {STATE_FILE}")
        except FileNotFoundError:
            pass
        except ValueError as e:
            print(f"[controller] ignoring unreadable {STATE_FILE}: {e}")

    def save_state(self):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.quarantined))
        tmp.replace(STATE_FILE)                        # atomic: never a half-written file

    # ---- Connection plumbing shared by S3, S4 and S8 ----

    def listen(self, host, port, on_accept, label):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen()
        srv.setblocking(False)
        self.sel.register(srv, selectors.EVENT_READ, on_accept)
        print(f"[controller] {label} listening on TCP {host}:{port}")

    def register_conn(self, sock, name, on_line, on_close):
        sock.settimeout(1.0)                           # sendall can never hang the loop
        conn = LineConn(sock, name)
        handler = functools.partial(self.on_readable, conn, on_line, on_close)
        self.sel.register(sock, selectors.EVENT_READ, handler)
        return conn

    def on_readable(self, conn, on_line, on_close, _sock):
        lines = conn.read_lines()
        if lines is None:
            self.close_conn(conn)
            on_close(conn)
            return
        for line in lines:
            on_line(conn, line)

    def close_conn(self, conn):
        try:
            self.sel.unregister(conn.sock)
        except (KeyError, ValueError):
            pass
        conn.sock.close()

    # ---- S3: security events from the Sense HAT Pi ----

    def on_s3_accept(self, srv):
        sock, (ip, port) = srv.accept()
        if ip not in EVENT_SOURCES:
            self.stats["refused"] += 1
            print(f"[S3] REFUSED {ip}:{port} (not an allowed event source)")
            sock.close()
            return
        conn = self.register_conn(sock, f"{ip}:{port}", self.on_s3_line, self.on_s3_closed)
        self.stats["s3_clients"] += 1
        print(f"[S3] event reporter connected from {conn.name}")

    def on_s3_closed(self, conn):
        self.stats["s3_clients"] -= 1
        print(f"[S3] {conn.name} disconnected")

    def on_s3_line(self, conn, line):
        rx_ts = time.time()
        try:
            ev = parse_security_event(line)
        except ValueError as e:
            self.stats["malformed"] += 1
            print(f"[S3] rejected message from {conn.name}: {e}")
            return

        self.stats["events"] += 1
        ev["rx_ts"] = rx_ts
        ev["event_uid"] = self.nas.log_event(                    # FR-5.3
            ev["event"], ev["node"], rx_ts, edge_ts=ev["ts"],
            src_ip=ev["src_ip"], src_port=ev["src_port"], details=ev["details"])
        print(f"[S3] {ev['event']} from {ev['src_ip']}:{ev['src_port']}")
        self.recent.append(ev)
        self.broadcast({"kind": "security_event", **ev})
        self.apply_policy(ev)

    # ---- Detection policy (FR-3.7) ----

    def apply_policy(self, ev):
        ip = ev["src_ip"]
        if ip in self.quarantined or self.order_pending_for(ip):
            return                                     # already handled

        if ev["event"] == "canary_hit":                # 1 canary hit = quarantine
            self.quarantine(ip, "canary_hit", ev["event_uid"])
            return

        strikes = self.strikes[ip]                     # sliding 60 s window
        strikes.append(ev["rx_ts"])
        while strikes and ev["rx_ts"] - strikes[0] > UNAUTH_WINDOW_S:
            strikes.popleft()
        print(f"[policy] {ip}: {len(strikes)}/{UNAUTH_LIMIT} unauthorized commands "
              f"in {UNAUTH_WINDOW_S:.0f} s")
        if len(strikes) >= UNAUTH_LIMIT:
            strikes.clear()
            self.quarantine(ip, "unauthorized_commands", ev["event_uid"])

    def order_pending_for(self, ip):
        return any(p["order"]["target_ip"] == ip and p["order"]["action"] == "quarantine"
                   for p in self.pending.values())

    def quarantine(self, ip, reason, event_uid):
        addr = ipaddress.ip_address(ip)
        if ip in ALLOWLIST or addr.is_loopback:
            print(f"[policy] NOT quarantining {ip}: allowlisted (FR-2.4)")
            return
        if addr not in SUBNET:
            print(f"[policy] NOT quarantining {ip}: outside {SUBNET} (NFR-4.4)")
            return
        self.send_order("quarantine", ip, reason, event_uid)

    # ---- S4: orders to the enforcement agent ----

    def send_order(self, action, ip, reason, event_uid=None):
        order = {"type": "order", "order_id": "q-" + uuid.uuid4().hex[:10],
                 "action": action, "target_ip": ip, "reason": reason}
        self.pending[order["order_id"]] = {"order": order, "event_uid": event_uid,
                                           "ordered_at": time.time(), "sent": False}
        print(f"[S4] {action.upper()} {ip} ({reason}) -> order {order['order_id']}")
        self.flush_orders()

    def flush_orders(self):
        """Send any orders not yet sent. Called on every new order and every loop pass."""
        unsent = [p for p in self.pending.values() if not p["sent"]]
        if not unsent or not self.ensure_enforcer():
            return
        for p in unsent:
            if not self.enforcer.send(p["order"]):
                self.close_conn(self.enforcer)
                self.on_s4_closed(self.enforcer)
                return
            p["sent"] = True
            self.stats["orders_sent"] += 1

    def ensure_enforcer(self):
        if self.enforcer:
            return True
        if time.monotonic() < self.next_connect:
            return False
        try:
            sock = socket.create_connection((SENSEHAT_IP, ENFORCE_PORT), timeout=1.0)
        except OSError as e:
            self.next_connect = time.monotonic() + RETRY_S
            print(f"[S4] enforcement agent {SENSEHAT_IP}:{ENFORCE_PORT} unreachable ({e}); "
                  f"{len(self.pending)} order(s) waiting, retrying in {RETRY_S:.0f} s")
            return False
        self.enforcer = self.register_conn(sock, f"{SENSEHAT_IP}:{ENFORCE_PORT}",
                                           self.on_s4_line, self.on_s4_closed)
        print(f"[S4] connected to enforcement agent {self.enforcer.name}")
        return True

    def on_s4_closed(self, conn):
        print(f"[S4] connection to enforcement agent closed; will resend unconfirmed orders")
        self.enforcer = None
        self.next_connect = time.monotonic() + RETRY_S
        for p in self.pending.values():
            p["sent"] = False          # resend on reconnect; the agent handles repeats safely

    def on_s4_line(self, conn, line):
        try:
            res = decode_json(line)
        except ValueError as e:
            print(f"[S4] unreadable reply from agent: {e}")
            return
        p = self.pending.pop(res.get("order_id"), None)     # order_id may be null
        if p is None:
            print(f"[S4] result for unknown order: {res}")
            return

        self.stats["results"] += 1
        order = p["order"]
        ip, action = order["target_ip"], order["action"]
        status = res.get("status") if res.get("status") in ("applied", "refused", "error") else "error"
        detail = str(res.get("detail", ""))[:255]
        print(f"[S4] {order['order_id']} {action} {ip}: {status} - {detail}")

        self.nas.log_action(order["order_id"], action, ip, order["reason"], status, detail,
                            p["ordered_at"], time.time(), trigger_event_uid=p["event_uid"])  # FR-5.4
        if status == "applied":
            if action == "quarantine":
                self.quarantined[ip] = {"reason": order["reason"], "since": time.time(),
                                        "order_id": order["order_id"], "event_uid": p["event_uid"]}
            else:
                self.quarantined.pop(ip, None)
            self.save_state()

        self.broadcast({"kind": "order_result", "order_id": order["order_id"], "action": action,
                        "target_ip": ip, "status": status, "detail": detail})
        self.broadcast({"kind": "quarantine", "quarantined": self.quarantine_list()})

    # ---- S8: dashboard channel (localhost only) ----

    def on_s8_accept(self, srv):
        sock, (ip, port) = srv.accept()
        conn = self.register_conn(sock, f"dashboard {ip}:{port}", self.on_s8_line, self.on_s8_closed)
        self.dashboards.add(conn)
        conn.send({"kind": "snapshot", "quarantined": self.quarantine_list(),
                   "events": list(self.recent)})
        print(f"[S8] {conn.name} connected")

    def on_s8_closed(self, conn):
        self.dashboards.discard(conn)
        print(f"[S8] {conn.name} disconnected")

    def on_s8_line(self, conn, line):
        try:
            msg = decode_json(line)
            ip = str(ipaddress.ip_address(msg.get("target_ip")))
        except (ValueError, TypeError):
            print(f"[S8] ignored bad request from {conn.name}")
            return
        if msg.get("kind") == "release":
            print(f"[S8] operator requested release of {ip}")
            self.send_order("release", ip, "operator_release")

    def broadcast(self, msg):
        for conn in list(self.dashboards):
            if not conn.send(msg):
                self.close_conn(conn)
                self.dashboards.discard(conn)

    def quarantine_list(self):
        return [{"ip": ip, **info} for ip, info in sorted(self.quarantined.items())]

    def status_msg(self):
        return {"kind": "controller_status", "s4_connected": self.enforcer is not None,
                "pending_orders": len(self.pending), "dashboards": len(self.dashboards),
                "stats": self.stats, "nas": self.nas.stats()}

    # ---- Main loop ----

    def run(self):
        self.nas.start()
        self.listen("0.0.0.0", EVENT_PORT, self.on_s3_accept, "S3 security events")
        self.listen(CONTROL_BIND, CONTROL_PORT, self.on_s8_accept, "S8 dashboard channel")
        print(f"[controller] event sources {sorted(EVENT_SOURCES)}; allowlist {sorted(ALLOWLIST)}; "
              f"subnet {SUBNET}; policy 1 canary hit or {UNAUTH_LIMIT} unauthorized in "
              f"{UNAUTH_WINDOW_S:.0f} s")
        next_status = 0.0
        try:
            while True:
                for key, _mask in self.sel.select(timeout=1.0):
                    key.data(key.fileobj)
                self.flush_orders()                    # retries S4 while orders are waiting
                if time.monotonic() >= next_status:
                    self.broadcast(self.status_msg())  # feeds the socket status panel
                    next_status = time.monotonic() + 1.0
        except KeyboardInterrupt:
            print(f"\n[controller] shutting down. stats: {self.stats}")
        finally:
            self.nas.stop()
            for key in list(self.sel.get_map().values()):
                key.fileobj.close()
            self.sel.close()


if __name__ == "__main__":
    Controller().run()
