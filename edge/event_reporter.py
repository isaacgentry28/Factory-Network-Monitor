"""
event_reporter.py - Socket 3 client (TCP -> HMI controller :5020)

Collects security events from the other edge components and forwards them to
the quarantine controller over one persistent TCP connection (FR-2.3).

  canary_listener  --\
  command_service  ---+-> UDP 127.0.0.1:5050 -> event_reporter -> TCP HMI:5020 (S3)
  enforcement_agent --/

- Reconnects every 2 s if the controller isn't up or the connection drops (NFR-6.3).
- Buffers up to 1000 events while disconnected and sends them in order once
  the connection is back, so nothing detected during an outage is lost.
- The controller never replies on S3 (protocol.md); if it sends anything we
  ignore it, and an empty read means it closed the connection.

Run (repo root):  python3 -m edge.event_reporter
Test without the HMI:  nc -lk 5020  on another machine, and HMI_IP=<that IP>
"""
import collections
import json
import selectors
import socket
import time

from common import config
from edge import edgelib
from edge.edgelib import log

C = "reporter"
HMI_IP = edgelib.HMI_IP
EVENT_PORT = config.get_int("EVENT_PORT")
MAX_BUFFER = 1000
VALID_EVENTS = {"canary_hit", "unauthorized_command"}


def valid(msg):
    return (isinstance(msg, dict)
            and msg.get("type") == "security_event"
            and msg.get("event") in VALID_EVENTS
            and isinstance(msg.get("src_ip"), str)
            and isinstance(msg.get("src_port"), int))


class Reporter:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.queue = collections.deque(maxlen=MAX_BUFFER)   # oldest dropped if full
        self.tcp = None
        self.next_connect = 0.0
        self.sent = 0

        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", edgelib.EVENT_RELAY_PORT))     # local only
        self.udp.setblocking(False)
        self.sel.register(self.udp, selectors.EVENT_READ, "udp")
        log(C, f"collecting events on UDP 127.0.0.1:{edgelib.EVENT_RELAY_PORT}")

    # ---- S3 connection ----

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(edgelib.RETRY_S)
        try:
            sock.connect((HMI_IP, EVENT_PORT))
        except OSError as e:
            sock.close()
            self.next_connect = time.time() + edgelib.RETRY_S
            if self.next_connect - self.last_warn > 30:     # don't spam the journal
                log(C, f"controller {HMI_IP}:{EVENT_PORT} not reachable ({e}); retrying every "
                       f"{edgelib.RETRY_S:.0f} s, {len(self.queue)} event(s) buffered")
                self.last_warn = self.next_connect
            return
        self.tcp = sock
        self.sel.register(sock, selectors.EVENT_READ, "tcp")
        log(C, f"connected to controller {HMI_IP}:{EVENT_PORT}")

    last_warn = 0.0

    def disconnect(self, why):
        if self.tcp:
            self.sel.unregister(self.tcp)
            self.tcp.close()
            self.tcp = None
            log(C, f"lost controller connection ({why}); reconnecting")
        self.next_connect = time.time() + edgelib.RETRY_S

    def flush(self):
        while self.queue and self.tcp:
            msg = self.queue[0]
            try:
                edgelib.send_json_line(self.tcp, msg)
            except OSError as e:
                self.disconnect(e)
                return
            self.queue.popleft()
            self.sent += 1
            log(C, f"-> S3 {msg['event']} from {msg['src_ip']}:{msg['src_port']}")

    # ---- Main loop ----

    def on_udp(self):
        data, _addr = self.udp.recvfrom(4096)
        try:
            msg = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            msg = None
        if not valid(msg):
            log(C, f"ignored malformed local event: {data[:100]!r}")
            return
        if len(self.queue) == MAX_BUFFER:
            log(C, "WARNING: buffer full, dropping oldest event")
        self.queue.append(msg)

    def on_tcp(self):
        try:
            data = self.tcp.recv(4096)
        except OSError as e:
            self.disconnect(e)
            return
        if not data:
            self.disconnect("controller closed the connection")

    def run(self):
        try:
            while True:
                if self.tcp is None and time.time() >= self.next_connect:
                    self.connect()
                for key, _ in self.sel.select(timeout=0.5):
                    if key.data == "udp":
                        self.on_udp()
                    elif key.data == "tcp" and self.tcp:
                        self.on_tcp()
                self.flush()
        except KeyboardInterrupt:
            log(C, f"stopped; sent {self.sent}, {len(self.queue)} still buffered")
        finally:
            if self.tcp:
                self.tcp.close()
            self.udp.close()


if __name__ == "__main__":
    Reporter().run()