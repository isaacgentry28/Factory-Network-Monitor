"""
fake_edge.py - pretends to be the Sense HAT Pi so the HMI can be tested without it.

Stage 1 sends:
  Socket 1 (UDP 5005) - one telemetry reading per second
  Socket 5 (UDP 5040) - one heartbeat every 2 seconds
using the formats in Docs/protocol.md.
"""
import json
import random
import socket
import time

HMI_HOST = "127.0.0.1"     # change to "192.168.5.12" to target the real HMI Pi
TELEMETRY_PORT = 5005      # Socket 1
EDGE_EVENT_PORT = 5040     # Socket 5
TELEMETRY_EVERY_S = 1.0    # FR-3.1: 1 Hz
HEARTBEAT_EVERY_S = 2.0    # HMI marks offline after 6 s (3 missed)
NODE = "sensehat"


# ---- Message builders (field names must match hmi_ingest.py exactly) ----

def make_telemetry(seq):
    return {
        "node": NODE,
        "seq": seq,
        "ts": time.time(),
        "temp_c": round(23.0 + random.uniform(-0.5, 0.5), 2),
        "humidity": round(40.0 + random.uniform(-2.0, 2.0), 2),
        "pressure_hpa": round(1013.0 + random.uniform(-1.0, 1.0), 2),
    }


def make_heartbeat(start_time):
    return {
        "type": "heartbeat",
        "node": NODE,
        "ts": time.time(),
        "uptime_s": round(time.time() - start_time, 1),
        "quarantine_count": 0,
    }


def send(sock, msg, port):
    """dict -> JSON string -> UTF-8 bytes -> one datagram."""
    data = json.dumps(msg).encode("utf-8")
    sock.sendto(data, (HMI_HOST, port))


# ---- Main loop ----

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # no bind(): senders don't need a fixed port
    start_time = time.time()
    seq = 0
    next_telemetry = start_time    # send the first of each right away
    next_heartbeat = start_time

    print(f"[fake_edge] sending to {HMI_HOST} "
          f"(S1 UDP {TELEMETRY_PORT}, S5 UDP {EDGE_EVENT_PORT}). Ctrl+C to stop.")
    try:
        while True:
            now = time.time()

            if now >= next_telemetry:
                seq += 1
                send(sock, make_telemetry(seq), TELEMETRY_PORT)
                next_telemetry += TELEMETRY_EVERY_S    # schedule from the plan, not from "now", so it never drifts

            if now >= next_heartbeat:
                send(sock, make_heartbeat(start_time), EDGE_EVENT_PORT)
                next_heartbeat += HEARTBEAT_EVERY_S

            time.sleep(0.05)   # check the timers 20 times per second
    except KeyboardInterrupt:
        print(f"\n[fake_edge] stopped after {seq} readings")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
