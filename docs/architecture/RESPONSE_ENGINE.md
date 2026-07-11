# 🛡️ AEGIS EDR - Response & Containment Engine Architecture

This document details the architecture, platform containment mechanisms, automated response execution loops, and recovery rollback strategies of the AEGIS Containment Engine.

---

## 1. High-Level Response Subsystem Architecture

The Containment Engine resides inside the privileged daemon (`aegisd`). It handles manual commands from the administrative CLI and triggers automated remediation playbooks when risk thresholds are exceeded.

```
                    +------------------------------------+
                    |       Response Request Ingest      |
                    |     (CLI Socket / Autotriage)      |
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    |       Validation & Safety Guard     |
                    |   (Verify Token & Protect Wininit) |
                    +-----------------+------------------+
                                      | Validated
                                      v
                    +------------------------------------+
                    |     Orchestration Dispatcher       |
                    +------+----------+----------+-------+
                           |          |          |
                           v          v          v
                    +------------------------------------+
                    |        Platform Containers         |
                    | (Windows WFP, Linux eBPF, Darwin)  |
                    +------------------------------------+
```

### 1.1 The Validation & Safety Guard
Before executing containment actions, the engine runs safety checks to prevent self-denial of service (DoS) or host instability:
- **Identifier Validation**: Verifies that user-supplied target identifiers (PIDs, file paths, IP blocks) exist.
- **System Protection Whitelist**: Rejects containment commands targeting critical system components (e.g., PID `1`, `wininit.exe`, `lsass.exe`, `systemd`, launchd, or the AEGIS daemon itself).
- **Audit Logging**: Logs all requests to the tamper-evident SQLite audit log database, capturing target details, action types, execution status, and caller user accounts.

---

## 2. Process Containment Subsystem (Kill/Suspend)

The Process Containment Subsystem terminates or suspends active process trees to contain malicious execution.

```
                      +------------------------------------------+
                      |         Process Containment Trigger      |
                      +--------------------+---------------------+
                                           | Verify Safety Whitelist
                                           v
+------------------------------------------+---------------------------------------------+
|                               OS Containment API                                       |
|                                                                                        |
|   +--------------------------+  +--------------------------+  +----------------------+ |
|   |         Windows          |  |          Linux           |  |        macOS         | |
|   |  - TerminateProcess      |  |  - syscall.Kill(SIGKILL) |  |  - syscall.Kill(SIGK)| |
|   |  - NtSuspendProcess      |  |  - syscall.Kill(SIGSTOP) |  |  - syscall.Kill(SIGS)| |
|   +--------------------------+  +--------------------------+  +----------------------+ |
+----------------------------------------+-----------------------------------------------+
                                         |
                                         v
                      +------------------------------------------+
                      |           Verification Check             |
                      |   (Check PID exited / thread paused)     |
                      +------------------------------------------+
```

### 2.1 Process Suspension (Freeze)
- **Use Case**: Temporarily freezing a process to run forensics without losing volatile memory data.
- **Windows**: Calls `NtSuspendProcess` via system calls.
- **Linux**: Sends a `SIGSTOP` signal to the process ID and all associated thread groups.
- **macOS**: Sends a `SIGSTOP` signal to the target process ID.

### 2.2 Process Termination (Kill)
- **Use Case**: Terminating malicious processes.
- **Mechanism**: Spawns process tree traversals using PPID mapping keys. It recursively terminates child processes before killing the parent process:
  - *Windows*: Calls the `TerminateProcess` API.
  - *Linux/macOS*: Sends `SIGKILL` to target process groups.

---

## 3. Cryptographic File Quarantine

The File Quarantine Subsystem isolates malicious files on the host, preventing execution while preserving the file for forensic analysis.

```
[Target File Path] -> [Acquire Exclusive Lock] -> [AES-256-GCM Encrypt Payload]
                                                 -> [Move to /var/lib/aegis/quarantine]
                                                 -> [Strip ACL Permissions]
```

1. **Locking**: Acquires an exclusive file handle lock to block other system processes.
2. **Encryption**: Reads the file contents and encrypts the payload using AES-256-GCM. The encryption key is generated locally and stored securely in the system keyring.
3. **Relocation**: Moves the encrypted payload to the secure quarantine folder (`/var/lib/aegis/quarantine/` or `C:\ProgramData\Aegis\Quarantine\`).
4. **ACL Stripping**: Strips the file's Access Control List (ACL) permissions. Sets ownership to the EDR service account and removes all execution rights.

---

## 4. Network Isolation Subsystem

Network Isolation blocks host network communications except for authorized AEGIS command-and-control (C2) and local loopback traffic.

- **Windows**: Adds block rules to the Windows Filtering Platform (WFP), bypassing only the designated AEGIS server port.
- **Linux**: Inserts isolation rules at the top of the `iptables` / `nftables` chain.
- **macOS**: Loads isolation rules into the Packet Filter (`pfctl`) subsystem.
- **Emergency Whitelist**: To prevent agents from losing contact with the fleet console, the isolation sub-system whitelists the AEGIS gRPC service port, DNS ports, and DHCP configurations.

---

## 5. Peripheral USB Blocking Subsystem

This subsystem blocks unauthorized USB storage devices to prevent data exfiltration and USB-based attacks.

- **Windows**: Interacts with the `SetupAPI` driver layer to disable target USB mass storage device nodes.
- **Linux**: Intercepts USB connections. Writes `0` to the device's authorization file in sysfs (`/sys/bus/usb/devices/.../authorized`) to prevent mounting.
- **macOS**: Blocks device mount events using Endpoint Security authorization callbacks.

---

## 6. Automated Playbook Response Engine

The automated response engine executes pre-configured remediation playbooks when risk scores cross critical thresholds.

- **Playbook Manifest**: Rules define triggers, thresholds, and containment sequences:
  ```yaml
  name: CobaltStrike Mitigation
  trigger:
    rule_name: "Cobalt_Strike_Beacon"
    risk_score_threshold: 8.5
  actions:
    - kill_process_tree
    - isolate_network
    - quarantine_file
  ```
- **Lifecycle Loop**: When a threat is detected, the engine matches the event against active playbooks, runs safety checks, and executes the remediation sequence.

---

## 7. Rollback & Recovery Strategy

AEGIS supports rollback commands to restore endpoints to their original state once a threat is resolved.

- **Un-Quarantine**: Decrypts the quarantined file and moves it back to its original path, restoring its original ACL permissions.
- **Remove Network Isolation**: Flushes containment rules from WFP, iptables, or Packet Filter configurations, restoring normal network traffic.
- **Restore Services**: Restores service configurations and registry keys from local backups if they were modified during remediation.
- **Un-freeze Processes**: Sends `SIGCONT` signals to suspended processes to resume execution.

---

## 8. Future SOAR Integration Architecture

The response engine is designed to integrate with Security Orchestration, Automation, and Response (SOAR) platforms:

```
[AEGIS Alert (JSON Payload)] 
       |
       v (Forward Event Stream)
[Event Webhook / SIEM Connector]
       |
       v (Ingest Alert & Trigger Playbook)
[Enterprise SOAR Platform (Splunk SOAR, Cortex XSOAR)]
       |
       v (Issue Response Actions API Request)
[AEGIS Daemon (gRPC endpoint / REST API)]
```

- **Outbound Webhooks**: The daemon sends alerts as structured JSON payloads to SIEM or SOAR endpoints.
- **Inbound gRPC Actions**: SOAR platforms can trigger containment actions directly on endpoints by calling the AEGIS gRPC API.
- **Auditable Tokens**: Remote response requests must supply valid JSON Web Tokens (JWT) signed by a trusted identity provider.
