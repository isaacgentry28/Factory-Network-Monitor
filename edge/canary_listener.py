"""
canary_listener.py - Socket 6 server (TCP 5060)

No legitimate client ever connects here. On every connection:
  1. record the source IP and port,
  2. close the connection without reading or replying,
  3. report a canary_hit event (-> event_reporter -> S3)      (FR-3.6)

IMPORTANT for testing: a connection only reaches accept() after a full TCP
handshake. "sudo nmap" defaults to a SYN (half-open) scan, which never
completes the handshake, so use a connect scan:
    nmap -sT -p 5060 <SenseHAT_IP>       (or nc -z <SenseHAT_IP> 5060)

Run (repo root):  python3 -m edge.canary_listener
"""
from common import config
from edge import edgelib
from edge.edgelib import log

C = "canary"
CANARY_PORT = config.get_int("CANARY_PORT")


def main():
    server = edgelib.tcp_server(edgelib.SENSEHAT_IP, CANARY_PORT, C, backlog=50)
    try:
        while True:
            conn, (ip, port) = server.accept()
            conn.close()          # never read, never reply
            log(C, f"CANARY HIT from {ip}:{port}")
            edgelib.report_event("canary_hit", ip, port, {"port": CANARY_PORT})
    except KeyboardInterrupt:
        log(C, "stopped")
    finally:
        server.close()


if __name__ == "__main__":
    main()