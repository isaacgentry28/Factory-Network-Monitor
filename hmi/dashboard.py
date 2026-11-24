"""
dashboard.py - EdgeGuard HMI touchscreen dashboard (Tkinter, full screen)

  UDP 127.0.0.1:5075  <- hmi_ingest: telemetry, edge_event (tamper/joystick), edge_status
  TCP 127.0.0.1:5070  <-> controller (S8): events, quarantine list, order results, status;
                          we send release requests
  TCP SenseHAT:5010   -> command service (S2): LED commands from the buttons; acks come back

Always visible: security banner (matches the Sense HAT LED), edge status, readings,
quarantine list with Release buttons. Tabs: Events (FR-4.5), Commands (FR-4.7), Sockets (FR-4.4).

Run (repo root):  python3 -m hmi.dashboard          (add --windowed to test on a laptop)
"""
import json
import socket
import sys
import time
import tkinter as tk

from common import config
from common.messages import decode_json, encode_line

RELAY_PORT = config.get_int("DASH_RELAY_PORT", 5075)
CONTROL_PORT = config.get_int("CONTROL_PORT", 5070)
SENSEHAT_IP = config.get("SENSEHAT_IP")
COMMAND_PORT = config.get_int("COMMAND_PORT", 5010)
MAX_DATAGRAM = 4096
POLL_MS = 100            # check every socket 10x per second (events show in < 500 ms, FR-4.5)
INGEST_SILENT_S = 3.0
RECEIVING_S = 3.0        # a stream counts as "receiving" if data arrived this recently
RECONNECT_S = 2.0
ACK_TIMEOUT_S = 3.0
MAX_FEED = 100

FONT = "Helvetica"
MONO = "DejaVu Sans Mono"
BG = "#1e1e1e"
TILE = "#2b2b2b"
TAB_ON = "#424242"
FG = "#f0f0f0"
DIM = "#757575"
GREEN = "#2e7d32"
AMBER = "#ef6c00"
RED = "#c62828"
GREY = "#616161"
FEED_COLORS = {"info": FG, "ok": "#81c784", "warn": "#ffb74d", "alert": "#ef5350"}
STATE_COLORS = {"ok": "#81c784", "idle": FG, "bad": "#ef5350"}
EVENT_LABELS = {"canary_hit": "CANARY HIT", "unauthorized_command": "UNAUTHORIZED CMD"}

COMMANDS = [   # (button text, S2 command fields) - patterns come from Cameron's led_status.py
    ("Test pattern", {"command": "led_pattern", "pattern": "test"}),
    ("Checker", {"command": "led_pattern", "pattern": "checker"}),
    ("Blue", {"command": "led_pattern", "pattern": "blue"}),
    ("Clear LED", {"command": "led_clear"}),
]

SOCKET_ROWS = [   # (key, name, transport, port) for the Sockets tab (FR-4.4)
    ("s1", "S1 telemetry", "UDP", config.get("TELEMETRY_PORT", 5005)),
    ("s2", "S2 commands", "TCP", str(COMMAND_PORT)),
    ("s3", "S3 sec. events", "TCP", config.get("EVENT_PORT", 5020)),
    ("s4", "S4 quarantine", "TCP", config.get("ENFORCE_PORT", 5030)),
    ("s5", "S5 heartbeat", "UDP", config.get("EDGE_EVENT_PORT", 5040)),
    ("s6", "S6 canary", "TCP", config.get("CANARY_PORT", 5060)),
    ("s7", "S7 NAS log", "TCP", config.get("NAS_PORT", 3306)),
    ("s8", "S8 dashboard", "TCP", str(CONTROL_PORT)),
    ("relay", "Ingest relay", "UDP", str(RELAY_PORT)),
]


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
        self.relay.bind(("127.0.0.1", RELAY_PORT))
        self.relay.setblocking(False)

        # S8 to the controller (connected in poll, retried every 2 s)
        self.ctrl = None
        self.ctrl_buf = bytearray()
        self.next_ctrl_try = 0.0

        # S2 to the Sense HAT command service (opened on the first button press)
        self.cmd = None
        self.cmd_buf = bytearray()
        self.cmd_seq = 0
        self.cmd_pending = {}            # request_id -> (button text, monotonic time sent)

        # State shown on screen
        self.last_status_rx = None       # when hmi_ingest last sent edge_status
        self.last_telemetry = None       # when the last S1 reading arrived
        self.edge_online = False
        self.last_heartbeat = None       # HMI clock time of the last heartbeat
        self.ingest_stats = None
        self.controller_status = None
        self.quarantined = []
        self.alert = None                # e.g. "TAMPER 2.31 g", cleared by the joystick
        self.seen_events = set()         # event_uids already in the feed
        self.counts = {"relay": 0, "s8": 0, "s2_sent": 0, "s2_acks": 0, "canary": 0}

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

        bottom = tk.Frame(self.root, bg=BG)
        bottom.pack(expand=True, fill="both", padx=10, pady=(0, 8))
        bottom.columnconfigure(0, weight=3)          # tabs get 3/5 of the width
        bottom.columnconfigure(1, weight=2)          # quarantine list gets 2/5
        bottom.rowconfigure(0, weight=1)

        # Left: tab bar + three pages stacked in the same spot
        left = tk.Frame(bottom, bg=TILE, padx=8, pady=6)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        tabbar = tk.Frame(left, bg=TILE)
        tabbar.pack(fill="x")
        pages = tk.Frame(left, bg=TILE)
        pages.pack(expand=True, fill="both", pady=(6, 0))
        pages.rowconfigure(0, weight=1)
        pages.columnconfigure(0, weight=1)

        self.pages = {}
        self.tab_buttons = {}
        for name, builder in (("Events", self.build_events_page),
                              ("Commands", self.build_commands_page),
                              ("Sockets", self.build_sockets_page)):
            page = tk.Frame(pages, bg=TILE)
            page.grid(row=0, column=0, sticky="nsew")    # all pages share one cell
            builder(page)
            self.pages[name] = page
            btn = tk.Button(tabbar, text=name, font=(FONT, 14, "bold"), width=9, relief="flat",
                            fg=FG, bg=TILE, activebackground=TAB_ON, activeforeground=FG,
                            command=lambda n=name: self.show_page(n))
            btn.pack(side="left", ipady=8, padx=(0, 4))  # ~48 px tall (FR-4.9)
            self.tab_buttons[name] = btn
        self.show_page("Events")

        # Right: quarantine list
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

    def build_events_page(self, page):
        self.feed = tk.Listbox(page, font=(MONO, 12), bg=BG, fg=FG, borderwidth=0,
                               highlightthickness=0, activestyle="none",
                               selectbackground=BG, selectforeground=FG)
        self.feed.pack(expand=True, fill="both")

    def build_commands_page(self, page):
        grid = tk.Frame(page, bg=TILE)
        grid.pack(fill="x")
        for i, (text, fields) in enumerate(COMMANDS):
            tk.Button(grid, text=text, font=(FONT, 15, "bold"), bg=GREY, fg="white",
                      activebackground=TAB_ON, activeforeground="white",
                      command=lambda t=text, f=fields: self.send_command(t, f)
                      ).grid(row=i // 2, column=i % 2, sticky="ew", padx=4, pady=4, ipady=10)
            grid.columnconfigure(i % 2, weight=1)
        self.cmd_result = tk.Label(page, text=f"Commands go to {SENSEHAT_IP}:{COMMAND_PORT} (S2)",
                                   font=(FONT, 13), fg=DIM, bg=TILE, anchor="w", justify="left")
        self.cmd_result.pack(fill="x", pady=(8, 0))

    def build_sockets_page(self, page):
        for col, heading in enumerate(("Socket", "Proto", "Port", "State", "Messages")):
            tk.Label(page, text=heading, font=(FONT, 12, "bold"), fg=DIM, bg=TILE,
                     anchor="w").grid(row=0, column=col, sticky="w", padx=4)
        self.socket_cells = {}
        for row, (key, name, proto, port) in enumerate(SOCKET_ROWS, start=1):
            for col, text in enumerate((name, proto, port)):
                tk.Label(page, text=text, font=(FONT, 12), fg=FG, bg=TILE,
                         anchor="w").grid(row=row, column=col, sticky="w", padx=4)
            state = tk.Label(page, text="-", font=(FONT, 12, "bold"), fg=DIM, bg=TILE, anchor="w")
            state.grid(row=row, column=3, sticky="w", padx=4)
            msgs = tk.Label(page, text="-", font=(FONT, 12), fg=FG, bg=TILE, anchor="w")
            msgs.grid(row=row, column=4, sticky="w", padx=4)
            self.socket_cells[key] = (state, msgs)
        page.columnconfigure(4, weight=1)

    def show_page(self, name):
        self.pages[name].tkraise()                   # bring this page to the front
        for tab, btn in self.tab_buttons.items():
            btn.config(bg=TAB_ON if tab == name else TILE)
        self.current_page = name

    # ---- Main loop (Tk calls this every POLL_MS) ----

    def poll(self):
        try:
            self.read_relay()
            self.connect_controller()
            self.read_controller()
            self.read_commands()
            self.check_command_timeouts()
            self.update_edge_line()
            self.update_banner()
            if self.current_page == "Sockets":
                self.update_sockets()
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
                return
            self.counts["relay"] += 1
            try:
                self.handle_relay(json.loads(data.decode("utf-8")))
            except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError) as e:
                print(f"[dashboard] skipped bad relay message: {e}", flush=True)

    def handle_relay(self, msg):
        kind = msg.get("kind")
        if kind == "telemetry":
            self.last_telemetry = time.monotonic()
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

    # ---- S8: controller ----

    def connect_controller(self):
        """(Re)connect to the controller, at most once every RECONNECT_S."""
        if self.ctrl is not None or time.monotonic() < self.next_ctrl_try:
            return
        try:
            sock = socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=0.3)
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
                return
            except OSError:
                data = b""
            if not data:
                self.drop_controller("Lost connection to controller")
                return
            self.ctrl_buf += data
            *lines, self.ctrl_buf = self.ctrl_buf.split(b"\n")
            for line in lines:
                if line.strip():
                    self.counts["s8"] += 1
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

    # ---- S2: actuator commands to the Sense HAT Pi (FR-4.7) ----

    def send_command(self, text, fields):
        if self.cmd is None:
            try:
                sock = socket.create_connection((SENSEHAT_IP, COMMAND_PORT), timeout=0.5)
            except OSError as e:
                self.cmd_result.config(text=f"{text}: command service unreachable ({e})",
                                       fg=FEED_COLORS["alert"])
                return
            sock.setblocking(False)
            self.cmd = sock
            self.cmd_buf = bytearray()
        self.cmd_seq += 1
        request_id = f"c-{self.cmd_seq:04d}"
        try:
            self.cmd.sendall(encode_line({"type": "command", "request_id": request_id, **fields}))
        except OSError:
            self.drop_commands()
            self.cmd_result.config(text=f"{text}: send failed - tap again", fg=FEED_COLORS["warn"])
            return
        self.cmd_pending[request_id] = (text, time.monotonic())
        self.counts["s2_sent"] += 1
        self.cmd_result.config(text=f"{text}: sent ({request_id}), waiting for ack...", fg=FG)

    def read_commands(self):
        while self.cmd is not None:
            try:
                data = self.cmd.recv(4096)
            except BlockingIOError:
                return
            except OSError:
                data = b""
            if not data:                            # command service closed the connection
                self.drop_commands()
                return
            self.cmd_buf += data
            *lines, self.cmd_buf = self.cmd_buf.split(b"\n")
            for line in lines:
                if line.strip():
                    try:
                        self.handle_ack(decode_json(line))
                    except (ValueError, KeyError, TypeError) as e:
                        print(f"[dashboard] skipped bad ack: {e}", flush=True)

    def handle_ack(self, ack):
        self.counts["s2_acks"] += 1
        text, sent = self.cmd_pending.pop(ack.get("request_id"), ("?", None))
        took = f" in {(time.monotonic() - sent) * 1000:.0f} ms" if sent else ""
        if ack.get("status") == "executed":
            self.cmd_result.config(text=f"{text}: EXECUTED{took}", fg=FEED_COLORS["ok"])
            self.add_feed(f"Command '{text}' executed{took}", "ok")
        else:
            reason = ack.get("reason", "no reason given")
            self.cmd_result.config(text=f"{text}: REJECTED - {reason}", fg=FEED_COLORS["alert"])
            self.add_feed(f"Command '{text}' rejected: {reason}", "warn")

    def check_command_timeouts(self):
        """No ack within 3 s: the edge is probably gone, so drop the connection."""
        now = time.monotonic()
        for text, sent in self.cmd_pending.values():
            if now - sent > ACK_TIMEOUT_S:
                self.cmd_result.config(text=f"{text}: no ack after {ACK_TIMEOUT_S:.0f} s - edge unreachable?",
                                       fg=FEED_COLORS["alert"])
                self.drop_commands()
                return

    def drop_commands(self):
        if self.cmd is not None:
            self.cmd.close()
        self.cmd = None
        self.cmd_pending.clear()

    # ---- Event feed ----

    def feed_security_event(self, ev):
        uid = ev.get("event_uid")
        if uid in self.seen_events:                 # skip repeats after a reconnect
            return
        self.seen_events.add(uid)
        if ev["event"] == "canary_hit":
            self.counts["canary"] += 1
        label = EVENT_LABELS.get(ev["event"], ev["event"])
        self.add_feed(f"{label} from {ev['src_ip']}:{ev['src_port']}", "alert", ev.get("rx_ts"))
        if self.current_page != "Events":
            self.show_page("Events")                # never hide an attack behind another tab

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

    # ---- Status (refreshed every poll) ----

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

    def socket_states(self):
        """(state text, ok/idle/bad, message count text) for every row of the Sockets tab."""
        now = time.monotonic()
        ing = self.ingest_stats or {}
        s1, s5 = ing.get("s1", {}), ing.get("s5", {})
        ctl = self.controller_status or {}
        cst = ctl.get("stats", {})
        ing_nas, ctl_nas = ing.get("nas", {}), ctl.get("nas", {})
        receiving = self.last_telemetry is not None and now - self.last_telemetry < RECEIVING_S
        relay_ok = self.last_status_rx is not None and now - self.last_status_rx < INGEST_SILENT_S
        nas_ok = ing_nas.get("connected") and ctl_nas.get("connected")
        return {
            "s1": ("receiving" if receiving else "no data", "ok" if receiving else "bad",
                   f"{s1.get('received', 0)} rx, {s1.get('lost', 0)} lost"),
            "s2": ("connected" if self.cmd else "idle (on demand)", "ok" if self.cmd else "idle",
                   f"{self.counts['s2_sent']} sent, {self.counts['s2_acks']} acks"),
            "s3": (f"connected ({cst['s3_clients']})" if cst.get("s3_clients") else "no reporter",
                   "ok" if cst.get("s3_clients") else "bad",
                   f"{cst.get('events', 0)} events"),
            "s4": ("connected" if ctl.get("s4_connected") else "idle (on demand)",
                   "ok" if ctl.get("s4_connected") else "idle",
                   f"{cst.get('orders_sent', 0)} orders, {cst.get('results', 0)} results"),
            "s5": ("receiving" if self.edge_online else "offline",
                   "ok" if self.edge_online else "bad",
                   f"{s5.get('received', 0)} rx"),
            "s6": ("on the edge", "idle", f"{self.counts['canary']} hits seen"),
            "s7": ("connected" if nas_ok else "DOWN", "ok" if nas_ok else "bad",
                   f"{ing_nas.get('written', 0) + ctl_nas.get('written', 0)} written, "
                   f"{ing_nas.get('buffered', 0) + ctl_nas.get('buffered', 0)} buffered"),
            "s8": ("connected" if self.ctrl else "DOWN", "ok" if self.ctrl else "bad",
                   f"{self.counts['s8']} msgs"),
            "relay": ("receiving" if relay_ok else "no data", "ok" if relay_ok else "bad",
                      f"{self.counts['relay']} msgs"),
        }

    def update_sockets(self):
        for key, (state_text, level, msgs) in self.socket_states().items():
            state, count = self.socket_cells[key]
            state.config(text=state_text, fg=STATE_COLORS[level])
            count.config(text=msgs)


def main():
    root = tk.Tk()
    app = Dashboard(root)
    try:
        root.mainloop()
    finally:
        app.relay.close()
        for sock in (app.ctrl, app.cmd):
            if sock is not None:
                sock.close()


if __name__ == "__main__":
    main()
