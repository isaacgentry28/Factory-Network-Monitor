# EdgeGuard: Expo Demo Commands (NFR-5.5)

Every command we run live at the Week 15 Expo, in demo order, with what it should show and which requirement it proves.

| Node | IP | Runs |
|---|---|---|
| HMI Pi | `192.168.5.12` | Docker Compose: `controller` (bridge), `ingest` and `dashboard` (host network) |
| Sense HAT Pi | `192.168.5.13` | systemd: `cps-edge.target` → `cps-sensor`, `cps-heartbeat`, `cps-led`, `cps-reporter`, `cps-canary`, `cps-command`, `cps-enforce` |
| Classroom NAS | `192.168.5.254` | MariaDB, port 3306, Table 1 database |
| Attack host | `192.168.5.x` (e.g. `.171`) | A team laptop **plugged into the table switch**. Must be on 192.168.5.0/24, or the controller correctly refuses to quarantine it (NFR-4.4) |

> **⏳ = depends on work not finished yet.** The dashboard's Release and command buttons (FR-4.6, FR-4.7) and the environmental alarm (FR-3.2) each have a command-line fallback below until they're built.

---

## 0. Pre-flight (before the audience arrives)

### One-time setup on the HMI Pi: NAS login without typing the password
Create `~/.my.cnf` on the HMI Pi. It's outside the repo, so it's never committed:
```ini
[client]
host=192.168.5.254
user=<NAS_DB_USER>
password=<NAS_DB_PASSWORD>
database=<NAS_DB_NAME>
```
```bash
chmod 600 ~/.my.cnf
mariadb -e "SELECT COUNT(*) FROM telemetry;"     # should print a number, no prompt
```

### Tools (if missing)
```bash
sudo apt install -y tcpdump ethtool nmap lsof     # on both Pis
```

### Clean starting state
**Sense HAT Pi:**
```bash
sudo nft list table inet cps_quarantine           # should show no drop rules
systemctl is-active cps-edge.target               # active
```
**HMI Pi:**
```bash
cd ~/Factory-Network-Monitor
docker compose ps                                 # controller, ingest, dashboard: all "Up"
```
**Attack host:** check it's on the classroom subnet:
```bash
ifconfig | grep "inet 192.168.5"                  # macOS
ip -br addr | grep 192.168.5                      # Linux
```

---

## 1. Cold boot in under 180 s (NFR-6.1, 6.2, 6.6)

1. Power both Pis off. Start a stopwatch and power both on.
2. **Type nothing.** Stop the clock when the dashboard shows **live readings** and **EDGE NODE ONLINE**.
3. Record the time in the README.

Prove that nothing was started by hand:
```bash
# HMI Pi
docker compose ps                                  # all three Up, restarted by Docker itself
uptime                                             # booted moments ago

# Sense HAT Pi
systemctl list-units 'cps-*' --no-pager            # all 8 units active
```

---

## 2. Socket and process audit (NFR-5.1, 5.2)

### HMI Pi
```bash
sudo ss -tulpn | grep -E ':(5005|5020|5040|5070|5075)\b'
```
| Port | Expect |
|---|---|
| UDP 5005, 5040 | `python3` (same PID): `hmi_ingest` in the `ingest` container (S1, S5) |
| UDP 127.0.0.1:5075 | `python3`: the dashboard (ingest → dashboard relay) |
| TCP 5020 (all interfaces) | **`docker-proxy`**: published from the controller container (S3, FR-6.3) |
| TCP **127.0.0.1**:5070 | **`docker-proxy`**: S8, localhost only (FR-6.4) |

```bash
sudo ss -tnp state established | grep -E ':(3306|5020)\b'     # S7 to the NAS, S3 from 192.168.5.13
sudo lsof -nP -i :5005 -i :5040 -i :5075 -i :5020 -i :5070 -i :3306
docker compose ps                                              # the containers behind docker-proxy (NFR-5.2)
```

### Sense HAT Pi
```bash
sudo ss -tulpn | grep -E ':(5010|5030|5050|5060)\b'
```
| Port | Expect |
|---|---|
| TCP 192.168.5.13:5010 | `command_service` (S2) |
| TCP 192.168.5.13:5030 | `enforcement_agent`, **running as root** (S4, NFR-2.4) |
| TCP 192.168.5.13:5060 | `canary_listener` (S6) |
| UDP 127.0.0.1:5050 | `event_reporter`, the local event relay |

```bash
sudo ss -tnp state established | grep -E ':(5020|5030)\b'     # S3 out to .12:5020, S4 in from .12
ps -o user,pid,cmd -C python3                                  # only enforcement_agent runs as root
```

### Proving S8 is unreachable from the network (FR-6.4)
**Attack host:**
```bash
nc -z -w 2 192.168.5.12 5070 && echo OPEN || echo "closed (correct)"
```

---

## 3. Link and route health (NFR-3.1)

Run on either Pi:
```bash
ip -br addr show eth0                 # 192.168.5.12 or .13, UP
ip route show default                 # unchanged default route
ip -s link show eth0                  # RX/TX counters climbing, errors 0
sudo ethtool eth0 | grep -E 'Speed|Duplex|Link detected'      # 1000Mb/s, Full, yes
```
**HMI Pi:**
```bash
ping -c 4 192.168.5.13                # Sense HAT Pi
ping -c 4 192.168.5.254               # NAS
```

---

## 4. Live telemetry (FR-3.1, FR-4.2, NFR-5.3)

Point out the dashboard: temperature, humidity and pressure update every second.

**HMI Pi:** one datagram per second, and the payload is visible because S1 is plain JSON:
```bash
sudo tcpdump -i eth0 -n udp port 5005 -c 10
sudo tcpdump -i eth0 -n -A udp port 5005 -c 2       # -A prints the JSON payload
docker compose logs --tail=5 ingest                 # "#1234 from 192.168.5.13 ... (delay N ms)"
```

---

## 5. Authorized actuator command (FR-2.5, FR-4.7)

**⏳ Dashboard:** tap the **LED test pattern** button, and the acknowledgment appears on screen.

**Fallback, from the HMI Pi** (the only authorized source):
```bash
printf '{"type":"command","request_id":"demo-1","command":"led_pattern","pattern":"test"}\n' | nc -q 2 192.168.5.13 5010
# -> {"type": "ack", "request_id": "demo-1", "status": "executed"}   and the LED shows a rainbow
printf '{"type":"command","request_id":"demo-2","command":"led_clear"}\n' | nc -q 2 192.168.5.13 5010
# -> LED back to green
```

---

## 6. Attack 1: canary probe → automatic quarantine (FR-3.6, 3.7, 3.8, NFR-5.4)

**Sense HAT Pi: before.** No drop rules:
```bash
sudo nft list table inet cps_quarantine
```

**Watch it happen** (optional second terminal on each Pi):
```bash
journalctl -u cps-canary -u cps-reporter -u cps-enforce -f      # Sense HAT Pi
docker compose logs -f controller                               # HMI Pi
```

**Attack host:**
```bash
nmap -sT -p 5060 192.168.5.13        # -sT = full connect scan
# or: nc -z -w 2 192.168.5.13 5060
```
Use `-sT`. `sudo nmap` defaults to a SYN scan, which never completes the TCP handshake, so the canary never sees it.

**Within 2 seconds (FR-3.8):**
- [ ] The controller log shows `canary_hit from 192.168.5.x` → `QUARANTINE` → `applied`
- [ ] **The LED turns solid red** (FR-2.6)
- [ ] **⏳** The dashboard's quarantine list shows the attacker's IP, and the banner turns red (FR-4.6, 4.8)

**Sense HAT Pi: after.** One drop rule, with a packet counter:
```bash
sudo nft -a list table inet cps_quarantine
# ip saddr 192.168.5.x counter packets N bytes M drop comment "q-…|canary_hit|…"
```

**Attack host: it's actually blocked.**
```bash
ping -c 3 192.168.5.13               # 100% packet loss
nc -z -w 2 192.168.5.13 5010         # times out
```
Then run the `nft` command again: the packet counter has gone up, because those pings were dropped.

---

## 7. Operator release (FR-4.6)

**⏳ Dashboard:** tap **Release** next to the attacker's IP.

**Fallback, from the HMI Pi** (S8 is localhost only):
```bash
printf '{"kind":"release","target_ip":"192.168.5.171"}\n' | nc -q 2 127.0.0.1 5070 | grep -v controller_status
# -> order_result ... "release" ... "applied", then the quarantine list is empty: []
```
**Expected:** the LED goes back to green, the `nft` rule is gone, and the attack host can ping again.

---

## 8. Attack 2: three unauthorized commands in 60 s → quarantine (FR-2.5, FR-3.7)

**Attack host** (must already be released from step 7):
```bash
for i in 1 2 3; do
  printf '{"type":"command","request_id":"evil-%s","command":"led_pattern","pattern":"test"}\n' $i | nc -w 2 192.168.5.13 5010
  sleep 1
done
```
**Expected:**
- Each attempt replies `"status": "rejected", "reason": "unauthorized source"`, and the LED does **not** change.
- The controller log counts `1/3`, `2/3`, `3/3` and then sends **QUARANTINE**, and the LED turns red.
- A fourth attempt just times out.

Release it again, as in step 7.

---

## 9. Tamper detection and operator acknowledgment (FR-3.3, 3.4, 3.5)

1. **Shake or tap the Sense HAT Pi.** Expect an **amber** LED border, and `TAMPER detected: N.NN g` in `docker compose logs ingest`.
2. **Press the joystick in (center).** The LED goes back to green, and ingest logs `joystick middle pressed`.
3. Acknowledging **never** clears a quarantine. If a host is quarantined, the LED stays red after the joystick press.

---

## 10. Edge offline detection (FR-4.3)

**Sense HAT Pi:**
```bash
sudo systemctl stop cps-heartbeat
```
Within **6 seconds** the dashboard banner shows **EDGE NODE OFFLINE** in red, and the readings dim.
```bash
sudo systemctl start cps-heartbeat
```
The banner goes back to **ONLINE**.

---

## 11. Audit trail on the NAS (FR-5.1–5.5, FR-5.7)

**HMI Pi** (uses `~/.my.cnf` from the pre-flight):

**Telemetry with network delay** (FR-5.2, 5.5):
```bash
mariadb -e "
  SELECT seq, edge_ts, hmi_rx_ts, temp_c, humidity, pressure_hpa,
         TIMESTAMPDIFF(MICROSECOND, edge_ts, hmi_rx_ts)/1000 AS delay_ms
  FROM telemetry ORDER BY id DESC LIMIT 10;"
```

**Security events** (FR-5.3): canary hits, unauthorized commands, tamper, operator acknowledgments:
```bash
mariadb -e "
  SELECT hmi_rx_ts, event_type, src_ip, src_port, details
  FROM security_events ORDER BY id DESC LIMIT 10;"
```

**Full quarantine history in one query** (FR-5.4, 5.7). It also shows **detection-to-block time** (FR-3.8):
```bash
mariadb -e "
  SELECT q.ordered_at, q.action, q.target_ip, q.reason, q.status,
         e.event_type, e.src_port,
         TIMESTAMPDIFF(MICROSECOND, e.edge_ts, q.confirmed_at)/1000 AS detect_to_block_ms
  FROM quarantine_actions q
  LEFT JOIN security_events e ON e.event_uid = q.trigger_event_uid
  WHERE q.ordered_at >= CURDATE()
  ORDER BY q.ordered_at;"
```
Releases have no triggering event, so their `event_type` and `detect_to_block_ms` are `NULL`.

---

## 12. Docker evidence (FR-6.1–6.7)

**HMI Pi:**
```bash
docker compose ps                                   # 3 services Up (controller built from hmi/Dockerfile, FR-6.1, 6.2)
docker compose logs --tail=20 controller            # controller logs on stdout (FR-6.7)
docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' edgeguard-controller    # unless-stopped (FR-6.6)
docker inspect -f '{{json .HostConfig.PortBindings}}' edgeguard-controller     # 5020 on all interfaces, 5070 on 127.0.0.1 only (FR-6.3, 6.4)
docker exec edgeguard-controller env | grep -E 'SENSEHAT_IP|UNAUTH_CMD_LIMIT'   # settings arrive as env vars from config.env (FR-6.5)
```
`docker exec … env` also lists the NAS password from `secrets.env`, which is why the command above filters with `grep`. Don't run it unfiltered in front of the audience.

---

## Resilience tests (before the Expo; not part of the live demo)

### NAS unreachable → records buffered, then written in order (FR-5.6)
**HMI Pi.** This temporarily blocks only the NAS, in its own nft table:
```bash
sudo nft add table inet nastest
sudo nft add chain inet nastest out '{ type filter hook output priority 0 ; policy accept ; }'
sudo nft add rule inet nastest out ip daddr 192.168.5.254 tcp dport 3306 drop
sleep 30; docker compose logs --tail=5 ingest       # "cannot connect ... N record(s) buffered"
sudo nft delete table inet nastest                  # unblock
sleep 15; docker compose logs --tail=5 ingest       # "connected"; buffer drained
```
Then check the telemetry query in step 11: there should be **no gap** in `seq` for the 30 s the NAS was blocked.

### HMI down → the edge keeps its quarantine rules (FR-2.8)
1. Quarantine the attack host (step 6).
2. **HMI Pi:** `docker compose stop controller`
3. **Sense HAT Pi:** `sudo nft list table inet cps_quarantine` still shows the rule, and the LED stays red.
4. **HMI Pi:** `docker compose start controller`. It prints `restored 1 quarantine(s)`. Then release (step 7).

---

## Emergency recovery

| Problem | Fix |
|---|---|
| Locked out of the Sense HAT Pi by a quarantine rule | From its **local keyboard and screen**: `sudo nft delete table inet cps_quarantine` (NFR-3.5) |
| An edge service misbehaving | `sudo systemctl restart cps-edge.target` |
| An HMI service misbehaving | `docker compose restart <controller\|ingest\|dashboard>` |
| Dashboard won't appear after a reboot | From the Pi's **desktop** terminal: `xhost +SI:localuser:admin`, then `docker compose restart dashboard` |
| Stop everything | Sense HAT Pi: `sudo systemctl stop cps-edge.target`. HMI Pi: `docker compose down` |
