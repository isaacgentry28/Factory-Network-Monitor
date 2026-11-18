"""
command_service.py - Socket 2 server (TCP 5010), the protected actuator service

Executes commands only when the connection comes from the HMI Pi's IP (FR-2.5).
Message formats are in Docs/protocol.md (S2):

  request: {"type": "command", "request_id": "c-0001", "command": "led_pattern", "pattern": "test"}
           {"type": "command", "request_id": "c-0002", "command": "led_clear"}
           {"type": "command", "request_id": "c-0003", "command": "setpoint", "name": "tamper_g", "value": 2.0}
  reply:   {"type": "ack", "request_id": "c-0001", "status": "executed"}
           {"type": "ack", "request_id": "c-0009", "status": "rejected", "reason": "unknown command"}

Any other source IP: read (at most) one command, reply "rejected", close the
connection, and report an unauthorized_command event over S3 (FR-3.6).

Run (repo root):  python3 -m edge.command_service
"""
import socket
import threading
import time

from common import config
from edge import edgelib
from edge.edgelib import log
from edge.led_status import PATTERNS

C = "command"
COMMAND_PORT = config.get_int("COMMAND_PORT")
UNAUTH_READ_TIMEOUT_S = 3.0


def ack(request_id, status, reason=None):
    msg = {"type": "ack", "request_id": request_id, "status": status}
    if reason:
        msg["reason"] = reason
    return msg


def execute(msg):
    """Run one command from the HMI. Returns (status, reason)."""
    if msg.get("type") != "command":
        return "rejected", "type must be 'command'"
    cmd = msg.get("command")

    if cmd == "led_pattern":
        pattern = msg.get("pattern")
        if pattern not in PATTERNS:
            return "rejected", f"unknown pattern (use one of: {', '.join(PATTERNS)})"
        edgelib.write_state("led_pattern.json", {"pattern": pattern, "ts": time.time()})
        # Still "executed" during a quarantine; led_status just keeps red on top (FR-2.6).
        return "executed", None

    if cmd == "led_clear":
        edgelib.clear_state("led_pattern.json")
        return "executed", None

    if cmd == "setpoint":
        name, value = msg.get("name"), msg.get("value")
        if not isinstance(name, str) or isinstance(value, bool) or not isinstance(value, (int, float)):
            return "rejected", "setpoint needs a string 'name' and a number 'value'"
        sp = edgelib.read_state("setpoints.json", {})
        sp[name] = value
        edgelib.write_state("setpoints.json", sp)
        return "executed", None

    return "rejected", "unknown command"


def handle_authorized(conn, ip, port):
    """The HMI may keep one connection open and send many commands."""
    log(C, f"HMI connected from {ip}:{port}")
    for msg in edgelib.read_json_lines(conn):
        if isinstance(msg, ValueError):
            edgelib.send_json_line(conn, ack(None, "rejected", str(msg)))
            continue
        request_id = msg.get("request_id")
        status, reason = execute(msg)
        edgelib.send_json_line(conn, ack(request_id, status, reason))
        log(C, f"{request_id} {msg.get('command')}: {status}{' - ' + reason if reason else ''}")
    log(C, f"HMI {ip}:{port} disconnected")


def handle_unauthorized(conn, ip, port):
    """Read one command (if the host sends one), reject it, close, report."""
    conn.settimeout(UNAUTH_READ_TIMEOUT_S)
    details = {"service": "command_service"}
    request_id = None
    try:
        first = next(edgelib.read_json_lines(conn), None)
        if isinstance(first, dict):
            request_id = first.get("request_id")
            details["command"] = str(first.get("command"))[:64]
    except (socket.timeout, OSError):
        pass   # sent nothing, or garbage - still unauthorized
    try:
        edgelib.send_json_line(conn, ack(request_id, "rejected", "unauthorized source"))
    except OSError:
        pass
    log(C, f"REJECTED connection from unauthorized host {ip}:{port} {details}")
    edgelib.report_event("unauthorized_command", ip, port, details)


def handle(conn, ip, port):
    try:
        if ip == edgelib.HMI_IP:
            handle_authorized(conn, ip, port)
        else:
            handle_unauthorized(conn, ip, port)
    except OSError as e:
        log(C, f"connection {ip}:{port} error: {e}")
    finally:
        conn.close()


def main():
    server = edgelib.tcp_server(edgelib.SENSEHAT_IP, COMMAND_PORT, C)
    log(C, f"authorized commander: {edgelib.HMI_IP}")
    try:
        while True:
            conn, (ip, port) = server.accept()
            threading.Thread(target=handle, args=(conn, ip, port), daemon=True).start()
    except KeyboardInterrupt:
        log(C, "stopped")
    finally:
        server.close()


if __name__ == "__main__":
    main()