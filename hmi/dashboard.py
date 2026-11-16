"""
dashboard.py - HMI touchscreen dashboard (skeleton for M1)

Shows live sensor readings and edge online/offline status (FR-4.1 - 4.3).
Data arrives from hmi_ingest.py over UDP 127.0.0.1:5075 (see Docs/protocol.md).
"""
import json
import socket 
import time
import tkinter as tk
import sys


RELAY_ADDR = ("127.0.0.1", 5075)
MAX_DATAGRAM = 4096
POLL_MS = 100
INGEST_SILENT_S = 3.0

BG = "#1e1e1e"
TILE = "#2b2b2b"
FG = "#f0f0f0"
DIM = "#757575"
GREEN = "#2e7d32"
RED = "#c62828"
GREY = "#616161"

class Dashboard:
    def __init__(self, root):
        self.root = root
        root.title("EdgeGaurd HMI")
        root.configure(bg=BG)
        if "--windowed" in sys.argv:
            root.geometry("800x480")              # normal resizable window for testing
        else:
            root.attributes("-fullscreen", True)  # default: full-screen on the Pi touchscreen

        root.bind("<Escape>", lambda e: root.destroy())

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(RELAY_ADDR)
        self.sock.setblocking(False)
        self.last_status_rx = None

        self.build_ui()
        self.root.after(POLL_MS, self.poll)

    def build_ui(self):
        # Status banner across the top
        self.status_label = tk.Label(self.root, text="WAITING FOR DATA",
                                     font=("Helvetica", 28, "bold"),
                                     fg="white", bg=GREY, pady=20)
        self.status_label.pack(fill="x")

        # Three sensor tiles side by side
        tiles = tk.Frame(self.root, bg=BG)
        tiles.pack(expand=True, fill="both", padx=20, pady=20)
        self.temp_value = self.make_tile(tiles, "Temperature", 0)
        self.hum_value = self.make_tile(tiles, "Humidity", 1)
        self.pres_value = self.make_tile(tiles, "Pressure", 2)

        # Footer with socket stats
        self.info_label = tk.Label(self.root, text="", font=("Helvetica", 14),
                                   fg=FG, bg=BG, anchor="w")
        self.info_label.pack(fill="x", padx=20, pady=10)

    def make_tile(self, parent, title, column):
        """One box with a title and a big value. Returns the value label so we can update it."""
        frame = tk.Frame(parent, bg=TILE, padx=20, pady=20)
        frame.grid(row=0, column=column, sticky="nsew", padx=10)
        parent.columnconfigure(column, weight=1)   # tiles share the width equally
        parent.rowconfigure(0, weight=1)
        tk.Label(frame, text=title, font=("Helvetica", 20), fg=FG, bg=TILE).pack()
        value = tk.Label(frame, text="--", font=("Helvetica", 48, "bold"), fg=FG, bg=TILE)
        value.pack(expand=True)
        return value

    # ---- Receiving ----

    def poll(self):
        """Read every datagram waiting on the socket, then schedule the next poll."""
        while True:
            try:
                data, _addr = self.sock.recvfrom(MAX_DATAGRAM)
            except BlockingIOError:
                break                       # nothing left to read
            try:
                msg = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue                    # skip bad datagrams, never crash the GUI
            if isinstance(msg, dict):
                self.handle(msg)

        self.check_ingest_alive()
        self.root.after(POLL_MS, self.poll)

    def handle(self, msg):
        kind = msg.get("kind")
        if kind == "telemetry":
            self.temp_value.config(text=f"{msg['temp_c']:.1f} °C")
            self.hum_value.config(text=f"{msg['humidity']:.1f} %")
            self.pres_value.config(text=f"{msg['pressure_hpa']:.1f} hPa")
        elif kind == "edge_status":
            self.last_status_rx = time.monotonic()
            self.show_status(msg)
        # "edge_event" (joystick, tamper) gets handled in a later step

    # ---- Display ----

    def show_status(self, msg):
        online = msg["online"]
        if online:
            self.status_label.config(text="EDGE NODE ONLINE", bg=GREEN)
        else:
            self.status_label.config(text="EDGE NODE OFFLINE", bg=RED)

        # Dim the readings when the edge is offline so nobody trusts stale values
        color = FG if online else DIM
        for label in (self.temp_value, self.hum_value, self.pres_value):
            label.config(fg=color)

        s1, s5 = msg["s1"], msg["s5"]
        self.info_label.config(
            text=f"S1  received {s1['received']}   lost {s1['lost']}   malformed {s1['malformed']}"
                 f"        S5  received {s5['received']}   malformed {s5['malformed']}")

    def check_ingest_alive(self):
        """hmi_ingest sends a status every second. If it goes quiet, say so."""
        if (self.last_status_rx is not None
                and time.monotonic() - self.last_status_rx > INGEST_SILENT_S):
            self.status_label.config(text="NO DATA FROM hmi_ingest", bg=GREY)


def main():
    root = tk.Tk()
    app = Dashboard(root)
    try:
        root.mainloop()
    finally:
        app.sock.close()


if __name__ == "__main__":
    main()