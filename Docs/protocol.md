# EdgeGuard Socket Protocol

This is the contract between the **Sense HAT Pi** (Cameron) and the **HMI Pi** (Isaac). If you change a field name, type, or port, update this file first and tell the other person, because the receiving side rejects any message that doesn't match.

| Status | Sockets |
|---|---|
| **Agreed.** The HMI receiver is built and validates these exact fields (`hmi/hmi_ingest.py`) | S1, S5 |
| **Draft.** To be confirmed before Week 13 | S2, S3, S4 |
| No message payload | S6, S7 |

---

## General Rules

These apply to every socket.

| Rule | Detail |
|---|---|
| **Encoding** | UTF-8 JSON. Every message is a single JSON **object** (`{...}`), never a list or a bare value |
| **UDP framing** (S1, S5) | One JSON object per datagram, at most 4096 bytes. A trailing newline is allowed but not required |
| **TCP framing** (S2, S3, S4) | Newline-delimited JSON: one object per line, ending in `\n`. Python's `json.dumps()` output contains no newlines, so `json.dumps(msg) + "\n"` is safe |
| **Timestamps** (`ts`) | Unix epoch seconds as a float, taken from the sender's clock: `time.time()` in Python. Both Pis must be NTP-synced (`timedatectl` should show `System clock synchronized: yes`) |
| **Node ID** (`node`) | `"sensehat"` for the edge node |
| **Numbers** | Use JSON numbers (`23.4`, `41`). Never send numbers as strings (`"23.4"`) or booleans (`true`). The receiver rejects both |
| **Extra fields** | Allowed and ignored by the receiver. Missing required fields cause the message to be rejected |
| **Rejected messages** | The receiver counts them as malformed, logs them, and keeps running. One bad message never crashes a service |

### Ports

| # | Proto | Port | Server (listens) | Client (sends/connects) | Purpose |
|---|---|---|---|---|---|
| S1 | UDP | 5005 | HMI `hmi_ingest` | Sense HAT sensor daemon | Telemetry |
| S2 | TCP | 5010 | Sense HAT command service | HMI command client | Actuator commands |
| S3 | TCP | 5020 | HMI controller (Docker) | Sense HAT event reporter | Security events |
| S4 | TCP | 5030 | Sense HAT enforcement agent | HMI controller (Docker) | Quarantine orders |
| S5 | UDP | 5040 | HMI `hmi_ingest` | Sense HAT heartbeat sender | Heartbeat, joystick, tamper |
| S6 | TCP | 5060 | Sense HAT canary listener | Untrusted hosts only | Canary (no payload) |
| S7 | TCP | 3306 | Classroom NAS (MariaDB) | HMI logger | SQL logging |
| S8 | TCP | 5070 (127.0.0.1) | HMI controller | HMI dashboard | HMI-internal, see below |
| (n/a) | UDP | 5075 (127.0.0.1) | HMI dashboard | HMI `hmi_ingest` | HMI-internal, see below |

---

## S1: Telemetry (UDP 5005) ✅ Agreed

**Direction:** Sense HAT Pi → HMI Pi. Send one datagram per reading at **1 Hz** (FR-3.1).

| Field | Type | Unit / meaning |
|---|---|---|
| `node` | string | `"sensehat"` |
| `seq` | integer | Starts at 1 and goes up by 1 per reading. It may reset to 1 when the daemon restarts, and the HMI handles that |
| `ts` | number | Sense HAT clock when the reading was taken |
| `temp_c` | number | Temperature, °C |
| `humidity` | number | Relative humidity, % |
| `pressure_hpa` | number | Barometric pressure, hPa |

```json
{"node": "sensehat", "seq": 42, "ts": 1731250000.123, "temp_c": 23.4, "humidity": 41.2, "pressure_hpa": 1012.8}
```

The HMI uses gaps in `seq` to count lost datagrams, and adds its own receive timestamp (`rx_ts`) to calculate network delay (FR-5.5).

---

## S5: Heartbeat, Joystick, Tamper (UDP 5040) ✅ Agreed

**Direction:** Sense HAT Pi → HMI Pi. All three message types use the same port and are told apart by the `type` field.

### `heartbeat`, every 2 seconds

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"heartbeat"` |
| `node` | string | `"sensehat"` |
| `ts` | number | Sense HAT clock |
| `uptime_s` | number | Seconds since the edge services started (or since boot) |
| `quarantine_count` | integer | Number of IPs currently quarantined by the enforcement agent |

```json
{"type": "heartbeat", "node": "sensehat", "ts": 1731250000.0, "uptime_s": 3600, "quarantine_count": 0}
```

The HMI marks the edge node **offline after 6 s** without a heartbeat, which is 3 missed heartbeats (FR-4.3).

### `joystick`, on each press

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"joystick"` |
| `node` | string | `"sensehat"` |
| `ts` | number | Sense HAT clock |
| `direction` | string | `"up"`, `"down"`, `"left"`, `"right"`, or `"middle"` |
| `action` | string | `"pressed"`, `"held"`, or `"released"` |

```json
{"type": "joystick", "node": "sensehat", "ts": 1731250000.0, "direction": "middle", "action": "pressed"}
```

- `direction` and `action` come straight from the Sense HAT library's joystick events (`sense.stick`), so you can copy them across without changes.
- **`middle` + `pressed` is the operator acknowledgment** (FR-3.5). It clears amber alerts but never clears a quarantine.
- Sending only `pressed` events is fine and keeps traffic low.

### `tamper`, when the IMU detects a hit

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"tamper"` |
| `node` | string | `"sensehat"` |
| `ts` | number | Sense HAT clock |
| `accel_g` | number | Total acceleration magnitude that triggered the event, in g |

```json
{"type": "tamper", "node": "sensehat", "ts": 1731250000.0, "accel_g": 2.31}
```

- Sample the accelerometer at 10 Hz and send a tamper event when the magnitude is above **1.5 g** (FR-3.3).
- **Suggestion:** send at most one tamper event every 2 seconds. Shaking the Pi would otherwise send one event per sample.

---

## S2: Actuator Commands (TCP 5010) 📝 Draft

**Direction:** the HMI command client connects to the Sense HAT command service. The edge executes commands **only when the connection comes from the HMI Pi's IP** (FR-2.5).

**Request (HMI → edge):**

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"command"` |
| `request_id` | string | Unique per command, e.g. `"c-0001"`. It is echoed back in the ack |
| `command` | string | `"led_pattern"`, `"led_clear"`, or `"setpoint"` |
| `pattern` | string | Only for `led_pattern`, e.g. `"test"` |
| `name`, `value` | string, number | Only for `setpoint`, e.g. `"temp_alarm_c"`, `40` |

```json
{"type": "command", "request_id": "c-0001", "command": "led_pattern", "pattern": "test"}
{"type": "command", "request_id": "c-0002", "command": "led_clear"}
```

**Response (edge → HMI), one per request:**

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"ack"` |
| `request_id` | string | Same value as the request |
| `status` | string | `"executed"` or `"rejected"` |
| `reason` | string | Only when rejected, e.g. `"unauthorized source"`, `"unknown command"` |

```json
{"type": "ack", "request_id": "c-0001", "status": "executed"}
```

**When a connection comes from any IP other than the HMI's:** reply `rejected`, close the connection, and report an `unauthorized_command` event over S3. While a quarantine is active, the LED stays red regardless of `led_pattern` commands (FR-2.6).

---

## S3: Security Events (TCP 5020) 📝 Draft

**Direction:** the Sense HAT event reporter keeps a persistent connection to the HMI controller. It reconnects every 2 s if the connection drops (NFR-6.3).

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"security_event"` |
| `event` | string | `"canary_hit"` or `"unauthorized_command"` |
| `node` | string | `"sensehat"` |
| `ts` | number | Sense HAT clock when the event was detected |
| `src_ip` | string | The offending host's IP |
| `src_port` | integer | The offending host's source port |
| `details` | object | Free-form extra info. For example, for `unauthorized_command`: `{"command": "led_pattern"}` |

```json
{"type": "security_event", "event": "canary_hit", "node": "sensehat", "ts": 1731250000.5, "src_ip": "192.168.5.99", "src_port": 51234, "details": {}}
```

**Controller policy** (FR-3.7): quarantine after **1** `canary_hit`, or after **3** `unauthorized_command` events from the same `src_ip` within 60 s. The controller sends no reply on S3. Its decision goes out over S4.

---

## S4: Quarantine Orders (TCP 5030) 📝 Draft

**Direction:** the HMI controller connects to the Sense HAT enforcement agent. The agent accepts orders **only when the connection comes from the HMI Pi's IP**. The controller runs in Docker, but its outgoing connections still appear to come from the HMI Pi's IP because of Docker's NAT.

**Order (controller → edge):**

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"order"` |
| `order_id` | string | Unique per order, e.g. `"q-0001"`. It is echoed back in the result |
| `action` | string | `"quarantine"` or `"release"` |
| `target_ip` | string | The IP to block or unblock |
| `reason` | string | Short text for logs, e.g. `"canary_hit"` |

```json
{"type": "order", "order_id": "q-0001", "action": "quarantine", "target_ip": "192.168.5.99", "reason": "canary_hit"}
```

**Result (edge → controller), one per order:**

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `"order_result"` |
| `order_id` | string | Same value as the order |
| `status` | string | `"applied"`, `"refused"`, or `"error"` |
| `detail` | string | e.g. `"rule added"`, `"target is allowlisted"`, the nft error message |

```json
{"type": "order_result", "order_id": "q-0001", "status": "applied", "detail": "rule added to inet cps_quarantine"}
```

- `refused` means the target is on the allowlist: the HMI Pi, the management host, or the gateway (FR-2.4, NFR-3.3).
- The agent never quarantines a host unless it receives an order (FR-2.2).
- Rules stay in place if the HMI goes away (FR-2.8).

---

## S6: Canary Listener (TCP 5060)

**There is no payload.** Legitimate clients never connect here. On any connection, the canary listener should:
1. record the source IP and port,
2. close the connection, and
3. send a `canary_hit` event over S3.

It never reads or replies to anything the connecting host sends.

## S7: NAS Logging (TCP 3306)

The HMI logger runs SQL `INSERT`s into the Table 1 MariaDB database. The table schema goes in `hmi/schema.sql`. The NAS login lives in `common/secrets.env`, which is gitignored and must never be committed.

## HMI-Internal Channels (S8 and 5075)

Both bind to `127.0.0.1` only, so they can't be reached from the network, and nothing on the Sense HAT Pi talks to them. They will be documented here once built:
- **S8 (TCP 5070):** dashboard ↔ controller. The controller pushes quarantine updates and the dashboard sends release requests.
- **UDP 5075:** `hmi_ingest` → dashboard. Relays live readings, edge status, and socket stats.

---

## Testing Without the Other Pi

| You want to… | Run |
|---|---|
| See what your sender transmits (Cameron) | `nc -ul 5005` or `nc -ul 5040` on any machine, then point your daemon at that machine's IP |
| Send a fake reading to the HMI (Isaac) | `echo '{"node":"sensehat","seq":1,"ts":1731250000,"temp_c":23.4,"humidity":41.2,"pressure_hpa":1012.8}' \| nc -u -w1 <HMI_IP> 5005` |
| Send a fake quarantine order to the edge (Cameron) | `echo '{"type":"order","order_id":"q-test","action":"quarantine","target_ip":"192.168.5.99","reason":"test"}' \| nc <SenseHAT_IP> 5030` |
| Trip the canary (from the team test host only, NFR-4.3) | `nmap -p 5060 <SenseHAT_IP>` |
