"""
hmi_ingest.py - HMI Pi ingest service

Step 3: Listen on two UDP sockets at once using selectors:
  Socket 1 (UDP 5005) - telemetry readings
  Socket 5 (UDP 5040) - heartbeats, joystick presses, tamper events
and track whether the Sense HAT Pi is online.
"""
import json
import selectors
import socket
import time

BIND_HOST = "0.0.0.0"
TELEMETRY_PORT = 5005      # Socket 1
EDGE_EVENT_PORT = 5040     # Socket 5
MAX_DATAGRAM = 4096
OFFLINE_AFTER_S = 6.0      # FR-4.3: offline within 6 s of heartbeats stopping

NUMBER = (int, float)

# ---- Message formats (the contract with Cameron -> common/protocol.md) ----

TELEMETRY_FIELDS = {
    "node": str,
    "seq": int,
    "ts": NUMBER,
    "temp_c": NUMBER,
    "humidity": NUMBER,
    "pressure_hpa": NUMBER,
}

# Socket 5 carries three message types, told apart by the "type" field.
EDGE_EVENT_FIELDS = {
    "heartbeat": {"node": str, "ts": NUMBER, "uptime_s": NUMBER, "quarantine_count": int},
    "joystick":  {"node": str, "ts": NUMBER, "direction": str, "action": str},
    "tamper":    {"node": str, "ts": NUMBER, "accel_g": NUMBER},
}


# ---- Parsing / validation ----

def decode_json(data):
    """Bytes -> dict, or raise ValueError."""
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"not valid JSON: {e}")
    if not isinstance(msg, dict):
        raise ValueError("JSON is not an object")
    return msg


def require_fields(msg, fields):
    """Raise ValueError if msg is missing a field or a field has the wrong type."""
    for field, allowed in fields.items():
        if field not in msg:
            raise ValueError(f"missing field '{field}'")
        # bool is a subclass of int in Python, so reject it explicitly
        if isinstance(msg[field], bool) or not isinstance(msg[field], allowed):
            raise ValueError(f"field '{field}' has the wrong type")


def parse_telemetry(data):
    msg = decode_json(data)
    require_fields(msg, TELEMETRY_FIELDS)
    return msg


def parse_edge_event(data):
    msg = decode_json(data)
    msg_type = msg.get("type")
    if msg_type not in EDGE_EVENT_FIELDS:
        raise ValueError(f"unknown message type {msg_type!r}")
    require_fields(msg, EDGE_EVENT_FIELDS[msg_type])
    return msg


def check_sequence(seq, stats):
    """Compare seq to the last one seen and count any lost datagrams."""
    last = stats["last_seq"]
    if last is not None:
        if seq > last + 1:
            missed = seq - last - 1
            stats["lost"] += missed
            print(f"[S1] WARNING: {missed} datagram(s) lost (seq {last} -> {seq})")
        elif seq <= last:
            print(f"[S1] sequence restarted or out of order ({last} -> {seq}), resyncing")
    stats["last_seq"] = seq


# ---- The service ----

class Ingest:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.s1_stats = {"received": 0, "malformed": 0, "lost": 0, "last_seq": None}
        self.s5_stats = {"received": 0, "malformed": 0}
        self.last_heartbeat = None   # HMI clock time of the last heartbeat
        self.edge_online = False

    def open_udp(self, port, handler):
        """Bind a UDP socket and register it so select() calls handler when data arrives."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((BIND_HOST, port))
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, handler)
        print(f"[ingest] listening on UDP {BIND_HOST}:{port}")
        return sock

    def on_telemetry(self, sock):
        """Socket 1: one sensor reading per datagram."""
        data, (ip, port) = sock.recvfrom(MAX_DATAGRAM)
        rx_ts = time.time()
        try:
            reading = parse_telemetry(data)
        except ValueError as e:
            self.s1_stats["malformed"] += 1
            print(f"[S1] rejected datagram from {ip}:{port}: {e}")
            return

        reading["rx_ts"] = rx_ts
        self.s1_stats["received"] += 1
        check_sequence(reading["seq"], self.s1_stats)

        delay_ms = (rx_ts - reading["ts"]) * 1000
        print(f"[S1] #{reading['seq']} from {ip}: "
              f"{reading['temp_c']:.1f} C  "
              f"{reading['humidity']:.1f} %  "
              f"{reading['pressure_hpa']:.1f} hPa  "
              f"(delay {delay_ms:.0f} ms)")

    def on_edge_event(self, sock):
        """Socket 5: heartbeat, joystick, or tamper message."""
        data, (ip, port) = sock.recvfrom(MAX_DATAGRAM)
        rx_ts = time.time()
        try:
            event = parse_edge_event(data)
        except ValueError as e:
            self.s5_stats["malformed"] += 1
            print(f"[S5] rejected datagram from {ip}:{port}: {e}")
            return

        self.s5_stats["received"] += 1
        event["rx_ts"] = rx_ts

        if event["type"] == "heartbeat":
            self.last_heartbeat = rx_ts
            if not self.edge_online:
                self.edge_online = True
                print(f"[S5] edge node ONLINE ({ip}), "
                      f"uptime {event['uptime_s']:.0f} s, "
                      f"{event['quarantine_count']} active quarantine(s)")
        elif event["type"] == "joystick":
            print(f"[S5] joystick {event['direction']} {event['action']}")
        elif event["type"] == "tamper":
            print(f"[S5] TAMPER detected: {event['accel_g']:.2f} g")

    def check_edge_online(self):
        """Mark the edge node offline if heartbeats have stopped."""
        if self.edge_online and time.time() - self.last_heartbeat > OFFLINE_AFTER_S:
            self.edge_online = False
            print(f"[S5] edge node OFFLINE (no heartbeat for {OFFLINE_AFTER_S:.0f} s)")

    def run(self):
        s1 = self.open_udp(TELEMETRY_PORT, self.on_telemetry)
        s5 = self.open_udp(EDGE_EVENT_PORT, self.on_edge_event)
        try:
            while True:
                # Wait up to 1 s for either socket to have data
                for key, _mask in self.sel.select(timeout=1.0):
                    handler = key.data       # the function we registered
                    handler(key.fileobj)     # key.fileobj is the socket
                self.check_edge_online()     # runs at least once per second
        except KeyboardInterrupt:
            print(f"\n[ingest] shutting down")
            print(f"  S1 stats: {self.s1_stats}")
            print(f"  S5 stats: {self.s5_stats}")
        finally:
            for sock in (s1, s5):
                self.sel.unregister(sock)
                sock.close()
            self.sel.close()


if __name__ == "__main__":
    Ingest().run()
