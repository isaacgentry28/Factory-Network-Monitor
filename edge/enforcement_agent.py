"""
enforcement_agent.py - Socket 4 server (TCP 5030), runs as root (NFR-2.4)

Applies quarantine/release orders from the HMI quarantine controller as nftables
rules. Formats are in Docs/protocol.md (S4):

  order:  {"type": "order", "order_id": "q-0001", "action": "quarantine",
           "target_ip": "192.168.5.99", "reason": "canary_hit"}
  result: {"type": "order_result", "order_id": "q-0001", "status": "applied",
           "detail": "rule added to inet cps_quarantine"}

Safety rules:
  - Orders are accepted only from the HMI Pi's IP. Any other connection is
    closed and reported as unauthorized_command.
  - Never quarantines anything on its own; only on an order (FR-2.2).
  - Refuses targets on the allowlist: HMI Pi, this Pi, the management host,
    the gateway, loopback (FR-2.4, NFR-3.3). Also refuses targets outside
    CLASSROOM_SUBNET (NFR-4.4, double-checked here as well as on the controller).
  - Only touches its own table, inet cps_quarantine; adds/removes one
    "ip saddr X drop" rule per host and never flushes anything else (NFR-3.2).
  - Rules stay in place if the HMI goes away or this agent restarts (FR-2.8).
    On startup it re-reads the rules already in the kernel.

Emergency recovery from the Pi's local console (NFR-3.5):
    sudo nft delete table inet cps_quarantine

Run (repo root):        sudo python3 -m edge.enforcement_agent
Test without nftables:  EDGE_NFT_DRY_RUN=1 python3 -m edge.enforcement_agent
"""
import ipaddress
import os
import re
import subprocess
import sys
import threading
import time

from common import config
from edge import edgelib
from edge.edgelib import log

C = "enforce"
ENFORCE_PORT = config.get_int("ENFORCE_PORT")
TABLE = "cps_quarantine"
CHAIN = "input"
DRY_RUN = os.environ.get("EDGE_NFT_DRY_RUN") == "1"

SAFE_TEXT = re.compile(r"[^A-Za-z0-9_.:-]")
RULE_RE = re.compile(r'ip saddr ([0-9.]+) .*?drop(?: comment "([^"]*)")?\s+# handle (\d+)')


def safe(text, limit=40):
    """Keep only harmless characters, so nothing from the network ends up as nft syntax."""
    return SAFE_TEXT.sub("_", str(text))[:limit]


# ---- Allowlist ----

def default_gateway():
    """Read the gateway from 'ip route show default' if GATEWAY_IP is blank in config."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"default via ([0-9.]+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def build_allowlist():
    allow = {edgelib.HMI_IP, edgelib.SENSEHAT_IP,
             config.get("MGMT_HOST_IP", ""), config.get("GATEWAY_IP", "") or default_gateway()}
    return {ip for ip in allow if ip}


# ---- nftables ----

class Nft:
    """Thin wrapper around the nft command. In dry-run mode it only pretends."""

    def __init__(self):
        self.fake_rules = {}          # dry run: handle -> (ip, comment)
        self.next_handle = 100

    def run(self, script):
        if DRY_RUN:
            return ""
        r = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "nft failed")
        return r.stdout

    def setup(self):
        """Create our table and chain if missing. 'add' does nothing if they already exist."""
        self.run(
            f"add table inet {TABLE}\n"
            f"add chain inet {TABLE} {CHAIN} "
            "{ type filter hook input priority -10 ; policy accept ; }\n"
        )

    def list_rules(self):
        """Return {ip: (handle, comment)} for the drop rules currently in the kernel."""
        if DRY_RUN:
            return {ip: (h, c) for h, (ip, c) in self.fake_rules.items()}
        r = subprocess.run(["nft", "-a", "list", "chain", "inet", TABLE, CHAIN],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        rules = {}
        for m in RULE_RE.finditer(r.stdout):
            rules[m.group(1)] = (int(m.group(3)), m.group(2) or "")
        return rules

    def add_drop(self, ip, comment):
        if DRY_RUN:
            self.fake_rules[self.next_handle] = (ip, comment)
            self.next_handle += 1
            return
        self.run(f'add rule inet {TABLE} {CHAIN} ip saddr {ip} counter drop comment "{comment}"\n')

    def delete(self, handle):
        if DRY_RUN:
            self.fake_rules.pop(handle, None)
            return
        self.run(f"delete rule inet {TABLE} {CHAIN} handle {int(handle)}\n")


# ---- The agent ----

class Agent:
    def __init__(self):
        self.nft = Nft()
        self.lock = threading.Lock()      # one nft change at a time
        self.allowlist = build_allowlist()
        self.subnet = ipaddress.ip_network(edgelib.CLASSROOM_SUBNET, strict=False)

    def sync_state_file(self):
        """Publish the current quarantine list for led_status.py and heartbeat.py."""
        hosts = {}
        for ip, (_handle, comment) in self.nft.list_rules().items():
            parts = comment.split("|")            # "order_id|reason|since"
            hosts[ip] = {
                "order_id": parts[0] if parts else "",
                "reason": parts[1] if len(parts) > 1 else "",
                "since": float(parts[2]) if len(parts) > 2 and parts[2].replace(".", "").isdigit() else None,
            }
        edgelib.write_state("quarantine.json", {"hosts": hosts, "updated": time.time()})
        return hosts

    def check_order(self, msg):
        """Return (order_id, action, ip) or raise ValueError with the reason."""
        if msg.get("type") != "order":
            raise ValueError("type must be 'order'")
        order_id = msg.get("order_id")
        if not isinstance(order_id, str) or not order_id:
            raise ValueError("missing order_id")
        action = msg.get("action")
        if action not in ("quarantine", "release"):
            raise ValueError("action must be 'quarantine' or 'release'")
        try:
            ip = ipaddress.IPv4Address(msg.get("target_ip"))
        except (ipaddress.AddressValueError, ValueError):
            raise ValueError(f"target_ip is not an IPv4 address: {msg.get('target_ip')!r}")
        return order_id, action, ip

    def apply(self, msg):
        """Process one order. Returns the order_result message."""
        order_id = msg.get("order_id") if isinstance(msg.get("order_id"), str) else None
        try:
            order_id, action, ip = self.check_order(msg)
        except ValueError as e:
            return result(order_id, "error", str(e))
        ip_s = str(ip)

        with self.lock:
            try:
                rules = self.nft.list_rules()

                if action == "release":
                    if ip_s not in rules:
                        return result(order_id, "applied", f"{ip_s} was not quarantined")
                    self.nft.delete(rules[ip_s][0])
                    self.sync_state_file()
                    return result(order_id, "applied", f"rule for {ip_s} removed from inet {TABLE}")

                # quarantine
                if ip_s in self.allowlist or ip.is_loopback:
                    return result(order_id, "refused", f"{ip_s} is allowlisted")
                if ip not in self.subnet:
                    return result(order_id, "refused", f"{ip_s} is outside {self.subnet}")
                if ip_s in rules:
                    return result(order_id, "applied", f"{ip_s} already quarantined")
                comment = f"{safe(order_id)}|{safe(msg.get('reason', ''))}|{time.time():.0f}"
                self.nft.add_drop(ip_s, comment)
                self.sync_state_file()
                return result(order_id, "applied", f"rule added to inet {TABLE}")
            except (RuntimeError, OSError, subprocess.SubprocessError) as e:
                return result(order_id, "error", f"nft: {e}")

    def handle(self, conn, ip, port):
        try:
            if ip != edgelib.HMI_IP:
                log(C, f"REJECTED order connection from unauthorized host {ip}:{port}")
                edgelib.report_event("unauthorized_command", ip, port, {"service": "enforcement_agent"})
                return
            log(C, f"controller connected from {ip}:{port}")
            for msg in edgelib.read_json_lines(conn):
                if isinstance(msg, ValueError):
                    reply = result(None, "error", str(msg))
                else:
                    reply = self.apply(msg)
                    log(C, f"{reply['order_id']} {msg.get('action')} {msg.get('target_ip')}: "
                           f"{reply['status']} - {reply['detail']}")
                edgelib.send_json_line(conn, reply)
            log(C, f"controller {ip}:{port} disconnected (rules stay in place)")
        except OSError as e:
            log(C, f"connection {ip}:{port} error: {e}")
        finally:
            conn.close()

    def run(self):
        if DRY_RUN:
            log(C, "DRY RUN: nft commands are simulated, no firewall changes")
        elif os.geteuid() != 0:
            sys.exit(f"[{C}] must run as root to change nftables (or set EDGE_NFT_DRY_RUN=1 to test)")

        self.nft.setup()
        existing = self.sync_state_file()
        log(C, f"table inet {TABLE} ready; {len(existing)} existing quarantine(s): {sorted(existing) or 'none'}")
        log(C, f"allowlist (never quarantined): {sorted(self.allowlist)}; subnet {self.subnet}")

        server = edgelib.tcp_server(edgelib.SENSEHAT_IP, ENFORCE_PORT, C)
        try:
            while True:
                conn, (ip, port) = server.accept()
                threading.Thread(target=self.handle, args=(conn, ip, port), daemon=True).start()
        except KeyboardInterrupt:
            log(C, "stopped (quarantine rules left in place)")
        finally:
            server.close()


def result(order_id, status, detail):
    return {"type": "order_result", "order_id": order_id, "status": status, "detail": detail}


if __name__ == "__main__":
    Agent().run()