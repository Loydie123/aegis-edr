# 🖥️ AEGIS EDR - Monitoring Engine Subsystem Specifications

This document defines the architecture, platform-specific hooks, and metadata structures for the telemetry-gathering subsystems of the AEGIS EDR agent.

---

## 1. Subsystem Integration Overview

The Monitoring Engine wraps platform-specific telemetry APIs inside a unified **Platform Abstraction Layer (PAL)**. This architecture converts raw OS events into normalized event structures before routing them to detection engines.

```
+---------------------------------------------------------------------------------------+
|                                    Telemetry Source                                   |
|   +--------------------------+  +--------------------------+  +--------------------+  |
|   |         Windows          |  |          Linux           |  |       macOS        |  |
|   |    (ETW, WFP, Registry)  |  |    (eBPF, fanotify)      |  |  (Endpoint Security)|  |
|   +------------+-------------+  +------------+-------------+  +---------+----------+  |
+----------------|-----------------------------|--------------------------|-------------+
                 |                             |                          |
                 +-----------------------------+--------------------------+
                                               | Raw Event Data
                                               v
+---------------------------------------------------------------------------------------+
|                              Platform Abstraction Layer (PAL)                         |
|                                                                                       |
|  +--------------------+      +--------------------+      +-------------------------+  |
|  |  Event Extraction  | ===> |  ECS Normalizer    | ===> |    Ingest Queue         |  |
|  |   (Syscall hooks)  |      |  (Aegis Schema)    |      | (Concurrent Ring Buffer)|  |
|  +--------------------+      +--------------------+      +-------------------------+  |
+---------------------------------------------------------------------------------------+
```

---

## 2. Process Monitoring Subsystem

The Process Monitoring Subsystem tracks process life cycles (creation, termination, arguments, credentials, and parent-child lineages).

```
                  +-----------------------------------------+
                  |            Process Spawn Event          |
                  +--------------------+--------------------+
                                       |
          +----------------------------+----------------------------+
          |                            |                            |
          v                            v                            v
   [Windows ETW]                 [Linux eBPF]                 [macOS ESF]
Microsoft-Windows-Kernel-Process   sys_enter_execve tracepoint   ES_EVENT_TYPE_NOTIFY_EXEC
```

### 2.1 OS-Level Ingestion Hooks
- **Windows**: Subscribes to the `Microsoft-Windows-Kernel-Process` ETW provider. Captures process starts, thread creations, and token changes.
- **Linux**: Attaches eBPF tracepoint probes to `sys_enter_execve` and `sys_enter_execveat` to extract execution paths and command arguments.
- **macOS**: Registers callback listeners with the Endpoint Security Framework (ESF) for `ES_EVENT_TYPE_NOTIFY_EXEC` and `ES_EVENT_TYPE_NOTIFY_FORK` events.

### 2.2 Telemetry Metadata Model
Every process event captures:
- `ProcessId` (PID) and `ParentProcessId` (PPID)
- Binary path and SHA256 file hash (calculated lazily)
- Raw Command Line arguments string
- Execution User SID/UID and Group SID/GID
- Environment variables (if flagged by policy)

---

## 3. File Monitoring Subsystem

The File Monitoring Subsystem monitors modifications to critical filesystem areas.

- **Windows**: Subscribes to the `Microsoft-Windows-Kernel-File` ETW provider to capture creation, overwrite, rename, and deletion events.
- **Linux**: Employs the `fanotify` API configuration to intercept file write and rename operations.
- **macOS**: Subscribes to ESF notify events: `ES_EVENT_TYPE_NOTIFY_OPEN`, `ES_EVENT_TYPE_NOTIFY_WRITE`, and `ES_EVENT_TYPE_NOTIFY_CLOSE`.

### 3.1 Performance Isolation (Lazy Hashing)
Calculating file hashes (SHA256) on every disk write can saturate storage bandwidth. AEGIS avoids this by hashing files only when a new executable is written or when a file modification triggers a suspicious YARA/Sigma behavioral rule.

---

## 4. Registry Monitoring Subsystem (Windows-Specific)

The Registry Subsystem monitors registry keys commonly targeted by malware for persistence and privilege escalation.

```
[Registry Modification Event]
              |
              v (Filter Key Paths)
[Examine Targets]
              |
              +---> Matches Persistence Key? (e.g. Run, RunOnce, Winlogon) ===> [FLAG ALERT]
              |
              +---> Matches Service Configuration? (e.g. System\CurrentControlSet\Services) ===> [FLAG ALERT]
```

- **ETW Providers**: Subscribes to the `Microsoft-Windows-Kernel-Registry` provider.
- **Auditing Scopes**:
  - Auto-run keys (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`).
  - Active Service registration keys (`HKLM\System\CurrentControlSet\Services`).
  - Local security policies and authentication provider paths (LSA, security providers).

---

## 5. Driver & Kernel Module Monitoring Subsystem

This subsystem monitors attempts to load kernel extension code (drivers, modules, or extensions).

- **Windows**: Monitors driver registrations via the `Microsoft-Windows-Kernel-Image` ETW provider. It logs signed status, loading address, and vendor hashes.
- **Linux**: Intercepts `sys_init_module` and `sys_finit_module` syscalls via eBPF probes, logging newly loaded kernel modules (`.ko` files).
- **macOS**: Subscribes to ESF notify callbacks for macOS kernel extension loading events: `ES_EVENT_TYPE_NOTIFY_KEXTLOAD`.

---

## 6. USB & Peripheral Monitoring Subsystem

This subsystem monitors physical USB storage connections to prevent data exfiltration and USB-based malware execution.

```
[USB Mount Event]
        |
        v (Parse Vendor & Product Details)
[Verify Whitelist]
        |
        +---> VID/PID Allowed? (Authorize mounting path)
        |
        +---> VID/PID Rejected? (Disable node / unmount storage)
```

- **Telemetry Collection**: Captures device descriptor metadata (Vendor ID, Product ID, Serial Number, class codes) on connection.
- **Control Rules**: If a USB connection violates security policy, the subsystem triggers the containment response API:
  - *Windows*: Disables the device instance path using the `SetupAPI` library.
  - *Linux*: Disables the USB interface node by writing `0` to the device's authorization path: `/sys/bus/usb/devices/.../authorized`.
  - *macOS*: Unmounts or disables USB storage devices via Endpoint Security controls.

---

## 7. Network Monitoring Subsystem

The Network Monitoring Subsystem tracks local socket states, connection attempts, and remote connection destinations.

```
                      +------------------------------------------+
                      |         Outbound Network Request         |
                      +--------------------+---------------------+
                                           | Intercept Socket Call
                                           v
+----------------------------------------------------------------------------------------+
|                               Network Inspection Layer                                 |
|                                                                                        |
|   +--------------------------+  +--------------------------+  +----------------------+ |
|   | Windows WFP Filter Provider |  | Linux eBPF Socket Probes |  | macOS Network Ext.   | |
|   +--------------------------+  +--------------------------+  +----------------------+ |
+----------------------------------------+-----------------------------------------------+
                                         | Retrieve Event Details
                                         v
                      +------------------------------------------+
                      |            Network Parser                |
                      |   (Logs DNS, HTTP SNI, IP Destinations)  |
                      +------------------------------------------+
```

- **Windows**: Integrates a Windows Filtering Platform (WFP) callout driver to intercept network flows.
- **Linux**: Attaches eBPF probes to `tcp_v4_connect`, `tcp_v6_connect`, and `udp_sendmsg` to capture outbound connection metadata.
- **macOS**: Implements a macOS Network Extension to monitor socket connections and network traffic.
- **Ingress Inspections**: Parses network layer details:
  - DNS request/response payloads to detect Domain Generation Algorithms (DGA).
  - Server Name Indication (SNI) handshakes on TLS connections to block requests to known malicious domain hosts.

---

## 8. Memory Monitoring Subsystem

This subsystem monitors process memory space allocations to identify in-memory execution vectors, such as shellcode or reflective DLL loading.

- **VMA Address Space Traversal**: Regularly scans active process virtual memory mappings.
- **Anomalous Memory Flags**: Searches for virtual memory segments with execution and write permissions (`PAGE_EXECUTE_READWRITE` or `PROT_EXEC` without mapped files on disk).
- **Hook Detection**: Compares loaded memory segment offsets of system DLLs/shared libraries against their on-disk formats to detect inline redirection patching.
