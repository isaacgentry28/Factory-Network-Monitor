"""
heartbeat.py - Socket 5 sender (UDP -> HMI:5040)

One 10 Hz loop that sends three message types on the same socket (protocol.md S5):
  heartbeat  every 2 s, with uptime and the current quarantine count   (FR-4.3)
  joystick   on each press; middle press = operator acknowledgment     (FR-3.5)
  tamper     when IMU acceleration > 1.5 g, at most one per 2 s        (FR-3.3)

Tamper also turns the LED amber (FR-3.4). A middle joystick press clears
amber alerts, but never a quarantine - only a release order does that.

Run (repo root):  python3 -m edge.heartbeat
"""
import json
import socket
import time

from common import config
from edge import edgelib
from edge.edgelib import log

C = "heartbeat"
HMI_IP = edgelib.HMI_IP
EDGE_EVENT_PORT = config.get_int("EDGE_EVENT_PORT")
HEARTBEAT_EVERY_S = config.get_float("HEARTBEAT_EVERY_S", 2)
TAMPER_G_DEFAULT = config.get_float("TAMPER_G", 1.5)
TAMPER_COOLDOWN_S = 2.0
LOOP_EVERY_S = 0.1          # 10 Hz IMU sampling


def system_uptime_s():
    try:
        with open("/proc/uptime") as f:
            return round(float(f.read().split()[0]), 1)
    except OSError:
        return 0.0


def tamper_threshold():
    """The HMI can change it with a 'setpoint' command named tamper_g."""
    sp = edgelib.read_state("setpoints.json", {})
    value = sp.get("tamper_g")
    return float(value) if isinstance(value, (int, float)) else TAMPER_G_DEFAULT


class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg):
        msg = {"node": edgelib.NODE, "ts": time.time(), **msg}
        try:
            self.sock.sendto(json.dumps(msg).encode("utf-8"), (HMI_IP, EDGE_EVENT_PORT))
        except OSError as e:
            log(C, f"send failed ({e}); will retry")


def main():
    sense = edgelib.get_sensehat(C)
    tx = Sender()
    next_heartbeat = time.time()
    last_tamper = 0.0
    log(C, f"sending heartbeat/joystick/tamper to {HMI_IP}:{EDGE_EVENT_PORT}")

    try:
        while True:
            loop_start = time.time()

            # 1. Heartbeat every 2 s
            if loop_start >= next_heartbeat:
                tx.send({
                    "type": "heartbeat",
                    "uptime_s": system_uptime_s(),
                    "quarantine_count": edgelib.quarantine_count(),
                })
                next_heartbeat += HEARTBEAT_EVERY_S
                if next_heartbeat < loop_start:          # fell far behind; resync
                    next_heartbeat = loop_start + HEARTBEAT_EVERY_S

            # 2. Joystick: only "pressed" events, to keep traffic low (protocol.md allows this)
            for ev in sense.stick.get_events():
                if ev.action != "pressed":
                    continue
                tx.send({"type": "joystick", "direction": ev.direction, "action": ev.action})
                log(C, f"joystick {ev.direction} pressed")
                if ev.direction == "middle":
                    edgelib.clear_state("alert.json")    # amber -> green (red stays if quarantined)
                    log(C, "operator acknowledged alerts")

            # 3. Tamper detection at 10 Hz
            g = edgelib.accel_magnitude_g(sense.get_accelerometer_raw())
            if g > tamper_threshold() and loop_start - last_tamper >= TAMPER_COOLDOWN_S:
                last_tamper = loop_start
                tx.send({"type": "tamper", "accel_g": round(g, 2)})
                edgelib.raise_alert("tamper")
                log(C, f"TAMPER: {g:.2f} g")

            time.sleep(max(0.0, LOOP_EVERY_S - (time.time() - loop_start)))
    except KeyboardInterrupt:
        log(C, "stopped")


if __name__ == "__main__":
    main()