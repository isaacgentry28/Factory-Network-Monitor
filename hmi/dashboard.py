"""
dashboard.py - EdgeGuard HMI touchscreen dashboard (Tkinter, full screen)

Inputs:
  UDP 127.0.0.1:5075  <- hmi_ingest: telemetry, edge_event (tamper/joystick), edge_status
  TCP 127.0.0.1:5070  <-> controller (S8): security events, quarantine list, order results,
                          controller status; we send release requests back
Shows (FR-4.1 - 4.9): live readings, edge online/offline with heartbeat age, a security
banner matching the Sense HAT LED, a scrolling event feed, and the quarantine list with
a Release button per host.

Run (repo root):  python3 -m hmi.dashboard          (add --windowed to test on a laptop)
"""
import json
import socket
import sys
import time
import tkinter as tk

from common import config
from common.messages import decode_json, encode_line

RELAY_ADDR = ("127.0.0.1", config.get_int("DASH_RELAY_PORT", 5075))
CONTROL_ADDR = ("127.0.0.1", config.get_int("CONTROL_PORT", 5070))
MAX_DATAGRAM = 4096
POLL_MS = 100            # check both sockets 10x per second (events show in < 500 ms, FR-4.5)
INGEST_SILENT_S = 3.0
RECONNECT_S = 2.0
MAX_FEED = 100

FONT = "Helvetica"
MONO = "DejaVu Sans Mono"
BG = "#1e1e1e"
TILE = "#2b2b2b"
FG = "#f0f0f0"
DIM = "#757575"
GREEN = "#2e7d32"
AMBER = "#ef6c00"
RED = "#c62828"
GREY = "#616161"
FEED_COLORS = {"info": FG, "ok": "#81c784", "warn": "#ffb74d", "alert": "#ef5350"}
EVENT_LABELS = {"canary_hit": "CANARY HIT", "unauthorized_command": "UNAUTHORIZED CMD"}


class Dashboard:
    def __init__(self, root):
        self.root = root
        root.title("EdgeGuard HMI")
        root.configure(bg=BG)
        if "--windowed" in sys.argv:
            root.geometry("800x480")              # normal window for testing
        else:
            root.attributes("-fullscreen", True)  # full screen on the Pi touchscreen
        root.bind("<Escape>", lambda e: root.destroy())

        # UDP relay from hmi_ingest
        self.relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.relay.bind(RELAY_ADDR)
        self.relay.setblocking(False)

        # S8 connection to the controller (made in poll, retried every 2 s)
        self.ctrl = None
        self.ctrl_buf = bytearray()
        self.next_ctrl_try = 0.0

        # State shown on screen
        self.last_status_rx = None       # when hmi_ingest last sent edge_status
        self.edge_online = False
        self.last_heartbeat = None       # HMI clock time of the last heartbeat
        self.ingest_stats = None
        self.controller_status = None
        self.quarantined = []
        self.alert = None                # e.g. "TAMPER 2.31 g", cleared by the joystick
        self.seen_events = set()         # event_uids already in the feed

        self.build_ui()
        self.root.after(POLL_MS, self.poll)

    # ---- Layout ----

    def build_ui(self):
        self.banner = tk.Label(self.root, text="STARTING...", font=(FONT, 22, "bold"),
                               fg="white", bg=GREY, pady=12)
        self.banner.pack(fill="x")

        self.edge_label = tk.Label(self.root, text="", font=(FONT, 14), fg=DIM, bg=BG, anchor="w")
        self.edge_label.pack(fill="x", padx=16, pady=(6, 0))

        tiles = tk.Frame(self.root, bg=BG)
        tiles.pack(fill="x", padx=10, pady=8)
        self.temp_value = self.make_tile(tiles, "Temperature", 0)
        self.hum_value = self.make_tile(tiles, "Humidity", 1)
        self.pres_value = self.make_tile(tiles, "Pressure", 2)

        # Footer is packed BEFORE the bottom area so it always keeps its space
        self.info_label = tk.Label(self.root, text="", font=(FONT, 12), fg=DIM, bg=BG, anchor="w")
        self.info_label.pack(side="bottom", fill="x", padx=16, pady=(0, 6))

        bottom = tk.Frame(self.root, bg=BG)
        bottom.pack(expand=True, fill="both", padx=10, pady=(0, 6))
        bottom.columnconfigure(0, weight=3)          # event feed gets 3/5 of the width
        bottom.columnconfigure(1, weight=2)          # quarantine list gets 2/5
        bottom.rowconfigure(0, weight=1)

        feed_box = tk.Frame(bottom, bg=TILE, padx=8, pady=6)
        feed_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tk.Label(feed_box, text="Security events", font=(FONT, 14, "bold"),
                 fg=FG, bg=TILE, anchor="w").pack(fill="x")
        self.feed = tk.Listbox(feed_box, font=(MONO, 12), bg=BG, fg=FG, borderwidth=0,
                               highlightthickness=0, activestyle="none",
                               selectbackground=BG, selectforeground=FG)
        self.feed.pack(expand=True, fill="both")

        q_box = tk.Frame(bottom, bg=TILE, padx=8, pady=6)
        q_box.grid(row=0, column=1, sticky="nsew")
        tk.Label(q_box, text="Quarantined hosts", font=(FONT, 14, "bold"),
                 fg=FG, bg=TILE, anchor="w").pack(fill="x")
        self.q_rows = tk.Frame(q_box, bg=TILE)
        self.q_rows.pack(expand=True, fill="both")
        self.show_quarantine([])

    def make_tile(self, parent, title, column):
        """One box with a title and a big value. Returns the value label."""
        frame = tk.Frame(parent, bg=TILE, padx=10, pady=8)
        frame.grid(row=0, column=column, sticky="nsew", padx=4)
        parent.columnconfigure(column, weight=1)
        tk.Label(frame, text=title, font=(FONT, 14), fg=FG, bg=TILE).pack()
        value = tk.Label(frame, text="--", font=(FONT, 34, "bold"), fg=FG, bg=TILE)
        value.pack()
        return value

    # ---- Main loop (Tk calls this every POLL_MS) ----

    def poll(self):
        try:
            self.read_relay()
            self.connect_controller()
            self.read_controller()
            self.update_edge_line()
            self.update_banner()
            self.update_footer()
        except Exception as e:                     # the screen must never stop updating
            print(f"[dashboard] error: {e!r}", flush=True)
        finally:
            self.root.after(POLL_MS, self.poll)

    # ---- UDP relay from hmi_ingest ----

    def read_relay(self):
        while True:
            try:
                data, _addr = self.relay.recvfrom(MAX_DATAGRAM)
            except BlockingIOError:
                return                              # nothing left to read
            try:
                self.handle_relay(json.loads(data.decode("utf-8")))
            except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError) as e:
                print(f"[dashboard] skipped bad relay message: {e}", flush=True)

    def handle_relay(self, msg):
        kind = msg.get("kind")
        if kind == "telemetry":
            self.temp_value.config(text=f"{msg['temp_c']:.1f} °C")
            self.hum_value.config(text=f"{msg['humidity']:.1f} %")
            self.pres_value.config(text=f"{msg['pressure_hpa']:.1f} hPa")
        elif kind == "edge_status":
            self.last_status_rx = time.monotonic()
            self.edge_online = msg["online"]
            self.last_heartbeat = msg["last_heartbeat"]
            self.ingest_stats = msg
            color = FG if self.edge_online else DIM   # dim stale readings when offline
            for label in (self.temp_value, self.hum_value, self.pres_value):
                label.config(fg=color)
        elif kind == "edge_event":
            if msg["type"] == "tamper":
                self.alert = f"TAMPER {msg['accel_g']:.2f} g"
                self.add_feed(f"TAMPER detected ({msg['accel_g']:.2f} g)", "warn", msg.get("rx_ts"))
            elif msg["type"] == "joystick" and msg["direction"] == "middle" and msg["action"] == "pressed":
                self.alert = None
                self.add_feed("Operator acknowledged alerts (joystick)", "ok", msg.get("rx_ts"))

    # ---- S8: connection to the controller ----

    def connect_controller(self):
        """(Re)connect to the controller, at most once every RECONNECT_S."""
        if self.ctrl is not None or time.monotonic() < self.next_ctrl_try:
            return
        try:
            sock = socket.create_connection(CONTROL_ADDR, timeout=0.3)
        except OSError:
            self.next_ctrl_try = time.monotonic() + RECONNECT_S
            return
        sock.setblocking(False)
        self.ctrl = sock
        self.ctrl_buf = bytearray()
        self.add_feed("Connected to controller", "ok")

    def read_controller(self):
        while self.ctrl is not None:
            try:
                data = self.ctrl.recv(65536)
            except BlockingIOError:
                return                              # nothing waiting right now
            except OSError:
                data = b""
            if not data:                            # controller closed or crashed
                self.drop_controller("Lost connection to controller")
                return
            self.ctrl_buf += data
            *lines, self.ctrl_buf = self.ctrl_buf.split(b"\n")
            for line in lines:
                if line.strip():
                    try:
                        self.handle_controller(decode_json(line))
                    except (ValueError, KeyError, TypeError) as e:
                        print(f"[dashboard] skipped bad controller message: {e}", flush=True)

    def drop_controller(self, why):
        if self.ctrl is not None:
            self.ctrl.close()
        self.ctrl = None
        self.controller_status = None
        self.next_ctrl_try = time.monotonic() + RECONNECT_S
        self.add_feed(why, "warn")

    def send_controller(self, msg):
        if self.ctrl is None:
            self.add_feed("Controller not connected - request not sent", "warn")
            return False
        try:
            self.ctrl.sendall(encode_line(msg))
            return True
        except OSError:
            self.drop_controller("Lost connection to controller")
            return False

    def handle_controller(self, msg):
        kind = msg.get("kind")
        if kind == "snapshot":                      # sent once, right after we connect
            for ev in msg["events"]:
                self.feed_security_event(ev)
            self.show_quarantine(msg["quarantined"])
        elif kind == "security_event":
            self.feed_security_event(msg)
        elif kind == "order_result":
            ip = msg["target_ip"]
            if msg["status"] == "applied" and msg["action"] == "quarantine":
                self.add_feed(f"QUARANTINED {ip}", "alert")
            elif msg["status"] == "applied":
                self.add_feed(f"RELEASED {ip}", "ok")
            else:
                self.add_feed(f"{msg['action']} {ip} {msg['status']}: {msg['detail']}", "warn")
        elif kind == "quarantine":
            self.show_quarantine(msg["quarantined"])
        elif kind == "controller_status":
            self.controller_status = msg

    # ---- Event feed ----

    def feed_security_event(self, ev):
        uid = ev.get("event_uid")
        if uid in self.seen_events:                 # skip repeats after a reconnect
            return
        self.seen_events.add(uid)
        label = EVENT_LABELS.get(ev["event"], ev["event"])
        self.add_feed(f"{label} from {ev['src_ip']}:{ev['src_port']}", "alert", ev.get("rx_ts"))

    def add_feed(self, text, level, ts=None):
        stamp = time.strftime("%H:%M:%S", time.localtime(ts or time.time()))
        self.feed.insert(0, f"{stamp}  {text}")     # newest at the top
        self.feed.itemconfig(0, fg=FEED_COLORS[level])
        if self.feed.size() > MAX_FEED:
            self.feed.delete(MAX_FEED, "end")

    # ---- Quarantine list with Release buttons ----

    def show_quarantine(self, hosts):
        self.quarantined = hosts
        for child in self.q_rows.winfo_children():
            child.destroy()
        if not hosts:
            tk.Label(self.q_rows, text="No hosts quarantined", font=(FONT, 14),
                     fg=DIM, bg=TILE).pack(pady=12)
        for host in hosts:
            row = tk.Frame(self.q_rows, bg=TILE)
            row.pack(fill="x", pady=4)
            since = time.strftime("%H:%M:%S", time.localtime(host.get("since") or time.time()))
            tk.Label(row, text=f"{host['ip']}\n{host.get('reason', '')} · since {since}",
                     font=(FONT, 13), fg=FG, bg=TILE, justify="left",
                     anchor="w").pack(side="left", fill="x", expand=True)
            tk.Button(row, text="Release", font=(FONT, 16, "bold"), width=7,
                      bg=RED, fg="white", activebackground="#8e0000", activeforeground="white",
                      command=lambda ip=host["ip"]: self.release(ip)
                      ).pack(side="right", ipady=10, padx=4)   # >= 48 px for a finger (FR-4.9)

    def release(self, ip):
        if self.send_controller({"kind": "release", "target_ip": ip}):
            self.add_feed(f"Release requested for {ip}", "info")

    # ---- Status lines (refreshed every poll) ----

    def update_banner(self):
        """Same priority as the Sense HAT LED: red > amber > green (FR-4.8)."""
        if self.ctrl is None:
            text, color = "CONTROLLER NOT CONNECTED", GREY
        elif self.quarantined:
            n = len(self.quarantined)
            text, color = f"QUARANTINE ACTIVE - {n} host{'s' if n != 1 else ''} blocked", RED
        elif self.alert:
            text, color = f"ALERT - {self.alert} - press joystick to acknowledge", AMBER
        else:
            text, color = "NORMAL", GREEN
        self.banner.config(text=text, bg=color)

    def update_edge_line(self):
        """Edge online/offline and time since the last heartbeat (FR-4.3)."""
        if self.last_status_rx is None:
            text, color = "Edge node: waiting for hmi_ingest...", DIM
        elif time.monotonic() - self.last_status_rx > INGEST_SILENT_S:
            text, color = "Edge node: UNKNOWN - no data from hmi_ingest", FEED_COLORS["warn"]
        elif self.edge_online:
            age = time.time() - self.last_heartbeat
            text, color = f"Edge node ONLINE · last heartbeat {age:.1f} s ago", FEED_COLORS["ok"]
        elif self.last_heartbeat:
            age = time.time() - self.last_heartbeat
            text, color = f"Edge node OFFLINE · no heartbeat for {age:.0f} s", FEED_COLORS["alert"]
        else:
            text, color = "Edge node OFFLINE · no heartbeat yet", FEED_COLORS["alert"]
        self.edge_label.config(text=text, fg=color)

    def update_footer(self):
        parts = []
        if self.ingest_stats:
            s1, s5 = self.ingest_stats["s1"], self.ingest_stats["s5"]
            parts.append(f"S1 rx {s1['received']} lost {s1['lost']} bad {s1['malformed']}")
            parts.append(f"S5 rx {s5['received']}")
        if self.controller_status:
            st = self.controller_status
            parts.append(f"S3 clients {st['stats']['s3_clients']} events {st['stats']['events']}")
            parts.append(f"S4 {'connected' if st['s4_connected'] else 'idle'}")
            parts.append(f"NAS {'up' if st['nas']['connected'] else 'DOWN'}")
        self.info_label.config(text="   |   ".join(parts))


def main():
    root = tk.Tk()
    app = Dashboard(root)
    try:
        root.mainloop()
    finally:
        app.relay.close()
        if app.ctrl is not None:
            app.ctrl.close()


if __name__ == "__main__":
    main()
