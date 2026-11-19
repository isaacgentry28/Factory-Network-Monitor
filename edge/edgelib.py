"""
Note: for the service files, cps-edge.target is the entire group, ensuring no commands 
are run after boot. sudo systemctl restart cps-edge.target 
will restart all seven instead of restarting each 
one by name. 
systemctl status 'cps-*' - shows whether each program is running and its last few log lines
sudo systemctl stop cps-edge.target - stops all seven. 
journalctl -u [cps-sensor] -f 
^^will follow one program's log live (ctrl c to quit)
systemctl status - useful for showing every component started automatically 
after a cold reboot! 

okay note over :)

Each edge component runs as its own process (FR-2.7), so they share
information in two simple ways:

  1. Security events -> local UDP 127.0.0.1:5050 -> event_reporter.py -> S3.
     report_event() below is the one function canary_listener.py,
     command_service.py and enforcement_agent.py call.

  2. Small JSON "state files" in EDGE_STATE_DIR (default /tmp/edgeguard):
       quarantine.json  written by enforcement_agent  (read by led_status, heartbeat)
       alert.json       written by heartbeat (tamper sets it, joystick clears it)
       led_pattern.json written by command_service    (read by led_status)
       setpoints.json   written by command_service    (read by heartbeat)

     I think Run everything from the repo root with "python3 -m edge.<name>" so that
"from common import config" works (same as the HMI side).

"""
import errno
import json
import math
import os
import random
import socket 
import time
from pathlib import Path

from common import config

NODE = "sensehat"

# ---- Settings (from common/config.env; env vars override, e.g. HMI_IP=127.0.0.1)----#

HMI_IP = config.get("HMI_IP")
SENSEHAT_IP = config.get("SENSEHAT_IP")
CLASSROOM_SUBNET = config.get("CLASSROOM_SUBNET")

#edge only settings#

EVENT_RELAY_PORT = config.get_int("EVENT_RELAY_PORT", 5050) #127.0.0.1 
STATE_DIR = Path(config.get("EDGE_STATE_DIR", "/tmp/edgeguard"))
RETRY_S = config.get_float("RETRY_S", 2) #NFR-6.3

def log(component, text):
    """Print with a component tag. system/journalctl add the timestamp!"""
    print(f"[{component}] {text}", flush=True)
    
#---Sockets---#

def bind_with_retry(sock, addr, compnent):
    """
    Bind to the Pi's eth0 IP. Right after boot, eth0 may not have its address yet, 
    so keep retrying every2 s instead of crashing.
    """
    while True:
        try:
            sock.bind(addr)
            return
        except OSError as e:
            if e.errno != errno.EADDRNOTAVAIL:
                raise
            log(compnent, f"{addr[0]} not available yet, retrying in {RETRY_S:.0f} s")
            time.sleep(RETRY_S)
            
def tcp_server(ip, port, component, backlog=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #fast restart after a crash
    bind_with_retry(sock, (ip, port), component)
    sock.listen(backlog)
    log(component, f"listening on TCP {ip}:{port}")
    return sock

def send_json_line(conn, msg):
    """TCP framing (protocal.md): one JSON object per line."""
    conn.sendall((json.dumps(msg) + "\n").encode("utf-8"))
    
def read_json_lines(conn, max_line=4096):
    """
    Generator: yields one dict per newline-terminated line from a TCP socket.
    Yields ValueError instances for lines that aren't a JSON object, so the 
    caller can reply with an error instead of crashing. 
    Stops when the peer closes the connection.
    """
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8"))
                if not isinstance(msg, dict):
                    raise ValueError("JSON is not an object")
                yield msg
            except (UnicodeDecodeError, ValueError) as e:
                yield ValueError(f"Bad Message: {e}")
        if len(buf) > max_line:
            yield ValueError("line too long")
            return
        
#---Security events + event reporter + S3 ----#
_relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def report_event(event, src_ip, src_port, details=None):
    """
    Hand a security event to event_reporter.py, which forwards is over S3. 
    if the reporter isn't running, we log and carry on.
    """
    msg = {
        "type": "security_event",
        "event": event,                 # "canary_hit" or "unauthorized_command"
        "node": NODE,
        "ts": time.time(),
        "src_ip": src_ip,
        "src_port": int(src_port),
        "details": details or {},
    }
    try:
        _relay_sock.sendto(json.dumps(msg).encode("utf-8"), ("127.0.0.1", EVENT_RELAY_PORT))
    except OSError as e:
        print(f"[edgelib] WARNING: could not hand event to event_reporter: {e}", flush=True)
    return msg


# ---- State files ----

def _ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        # Different services run as different users (the agent is root),
        # so the folder must be writable by all, like /tmp itself.
        os.chmod(STATE_DIR, 0o1777)
    except PermissionError:
        pass   # someone else created it; they already set the mode


def write_state(name, data):
    """Atomically replace STATE_DIR/name with JSON data."""
    _ensure_state_dir()
    path = STATE_DIR / name
    tmp = path.with_name(f".{name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data))
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def read_state(name, default=None):
    try:
        return json.loads((STATE_DIR / name).read_text())
    except (FileNotFoundError, ValueError):
        return default


def clear_state(name):
    try:
        (STATE_DIR / name).unlink()
    except FileNotFoundError:
        pass


def raise_alert(reason):
    """Amber LED: an alert is waiting for the operator (cleared by the joystick)."""
    write_state("alert.json", {"active": True, "reason": reason, "ts": time.time()})


def quarantine_count():
    q = read_state("quarantine.json", {})
    return len(q.get("hosts", {}))


# ---- Sense HAT access (real hardware, or a fake for testing off the Pi) ----

class _FakeStick:
    def get_events(self):
        return []


class FakeSenseHat:
    """
    Stands in for sense_hat.SenseHat when the library or board isn't there,
    so you can run and test the edge code on a laptop. Set EDGE_FAKE_HAT=1
    to force it. Shake simulation: set EDGE_FAKE_SHAKE=1 for occasional 2 g spikes.
    """
    def __init__(self):
        self.stick = _FakeStick()
        self.low_light = False
        self._last_pixels = None
        self._shake = os.environ.get("EDGE_FAKE_SHAKE") == "1"

    def get_temperature(self):
        return 23.0 + random.uniform(-0.5, 0.5)

    def get_humidity(self):
        return 40.0 + random.uniform(-2.0, 2.0)

    def get_pressure(self):
        return 1013.0 + random.uniform(-1.0, 1.0)

    def get_accelerometer_raw(self):
        if self._shake and random.random() < 0.02:
            return {"x": 1.2, "y": 1.1, "z": 1.0}
        return {"x": 0.0, "y": 0.0, "z": 1.0}

    def set_pixels(self, pixels):
        if pixels != self._last_pixels:
            self._last_pixels = pixels
            print(f"[fake-hat] LED matrix -> top-left pixel {pixels[0]}", flush=True)

    def clear(self, *args):
        self.set_pixels([(0, 0, 0)] * 64)


def get_sensehat(component):
    if os.environ.get("EDGE_FAKE_HAT") == "1":
        log(component, "using FAKE Sense HAT (EDGE_FAKE_HAT=1)")
        return FakeSenseHat()
    try:
        from sense_hat import SenseHat
        return SenseHat()
    except Exception as e:     # library missing, or not running on the Pi
        log(component, f"real Sense HAT unavailable ({e}); using FAKE Sense HAT")
        return FakeSenseHat()


def accel_magnitude_g(raw):
    return math.sqrt(raw["x"] ** 2 + raw["y"] ** 2 + raw["z"] ** 2)