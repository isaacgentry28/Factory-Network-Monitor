# Factory-Network-Monitor
# EdgeGuard: Automated Quarantine for a Cyber-Physical Edge Node

**CS 450: Computer Networks — Semester Project**
**Application Category:** Security Monitor (Cyber-Physical System)
**Team Members:** _TBD_
**Sandbox Table:** _TBD_

---

## 1. Project Overview

### 1.1 Project Purpose

Industrial control environments in small manufacturing plants, quarries, and utilities often depend on edge devices that use unauthenticated network protocols and can't run endpoint security software, so any host that reaches the network can probe those devices or send commands that change physical outputs. These organizations rarely have dedicated security staff, which means a rogue or compromised host can disrupt operations long before anyone notices. This project builds a distributed edge security system in which a Raspberry Pi edge node streams live environmental sensor data and accepts actuator commands, while a central controller on the HMI Pi monitors for malicious behavior such as canary port probes, commands from unauthorized hosts, and repeated rejected access attempts. When a threat is detected, the controller automatically orders an enforcement agent on the edge node to firewall the offending host within seconds, and the operator can review alerts and release quarantined hosts from a live touchscreen interface. The intended operator is a small IT or OT team, and the system's value is fast, automated containment through centralized policy and distributed enforcement, with every security event logged to remote storage for later review.

### 1.2 Project Scope and Hardware Role Mapping

#### HMI Pi (Raspberry Pi 5 + Touchscreen)

The central control station. It hosts the containerized quarantine controller, the operator touchscreen dashboard, and the logging pipeline to remote storage, and it is the only host authorized to issue actuator commands.

- **Quarantine controller (Docker):** Receives security event reports from the edge node, applies the detection policy, and sends quarantine and release orders to the enforcement agent.
- **Telemetry receiver:** Receives the sensor stream, heartbeats, and joystick events from the Sense HAT Pi.
- **Command client:** Sends legitimate actuator commands (LED matrix, setpoints) to the edge node.
- **Logger:** Writes telemetry and security events to remote storage.
- **Touchscreen dashboard:** Displays live sensor readings, edge node health, recent security events, and the current quarantine list, with controls to release hosts and send commands.

#### Sense HAT Pi (Raspberry Pi 5 + Sense HAT)

The protected edge node. It streams live sensor telemetry, executes actuator commands only from the authorized HMI, detects unauthorized access through its command service and canary port, and enforces quarantine orders through local firewall rules.

- **Sensor daemon:** Samples temperature, humidity, and pressure (and optionally the IMU for tamper detection) and streams readings to the HMI Pi.
- **Command service:** The protected actuator service. Executes LED matrix and setpoint commands from the HMI Pi only; rejects and reports all others.
- **Canary listener:** Listens on an unused port that no legitimate client contacts. Any connection is reported as a probe.
- **Enforcement agent:** Applies and removes nftables rules on orders from the controller. Maintains an allowlist (HMI Pi and management host) that can never be quarantined.
- **Event reporter and heartbeat:** Reports security events to the controller and sends periodic heartbeats and joystick events.
- **LED matrix status:** Green for normal operation, amber for an alert under review, red for an active quarantine.
- **Joystick:** Allows a local operator to acknowledge alarms at the edge node.

#### Remote Storage (Classroom NAS Database)

Persistent historian and security log. Stores sensor telemetry and all security events (detections, quarantines, releases) off the edge node, so a compromised edge device cannot erase the record.

#### Optional Additional Nodes

None planned. Attack scenarios are generated from a team-controlled test host and target only this team's own nodes.

#### Out-of-Scope Boundaries

- **Layer 2 attacks and defenses (ARP spoofing, MAC flooding):** Excluded because they would disrupt neighboring tables on the shared classroom LAN. Detection and containment operate at the transport and application layers only.
- **Encrypted or authenticated sockets (TLS, mutual authentication):** Custom channels carry plaintext JSON, and authorization is based on source IP. A production deployment would encrypt and authenticate this traffic.
