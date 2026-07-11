# 📋 AEGIS EDR - Development Backlog (Backlog Backlog)

This document contains the complete development backlog for the AEGIS EDR project. All tasks are marked as `Todo` and ordered sequentially to ensure smooth implementation without circular blockers.

---

## 📖 Backlog Phases Overview

```
+---------------------------------------------------------+
| Phase 1: Core Architecture & Foundations                |
| (Setup, Daemon-CLI split, DB Schema, Logging)           |
+----------------------------+----------------------------+
                             |
                             v
+---------------------------------------------------------+
| Phase 2: Telemetry Ingress Probes                       |
| (PAL Interface, Normalizer event router, Ingest Queue)  |
+----------------------------+----------------------------+
                             |
                             v
+---------------------------------------------------------+
| Phase 3: Multi-Engine Detection Core                    |
| (YARA, Sigma, Heuristics memory scanning, Risk score)   |
+----------------------------+----------------------------+
                             |
                             v
+---------------------------------------------------------+
| Phase 4: Active Response Containment & Forensics        |
| (Isolation firewalls, quarantine, process kill, timeline)|
+----------------------------+----------------------------+
                             |
                             v
+---------------------------------------------------------+
| Phase 5: Plugin SDK & Enterprise Integrations           |
| (WASM plugin VM, STIX/TAXII sync feeds, TLS sync)       |
+----------------------------+----------------------------+
                             |
                             v
+---------------------------------------------------------+
| Phase 6: CI/CD, Packaging & Release                     |
| (Testing suites, GitHub pipelines, installers)           |
+---------------------------------------------------------+
```

---

## 📌 Phase 1: Core Architecture & Foundations
- **Objectives**: Establish repository layout, initialize gRPC IPC channel, compile logger, and configure SQLite WAL databases.
- **Deliverables**: Main binaries (`aegis`, `aegisd`), gRPC local client/server loops, schema migration configurations.
- **Dependencies**: None.
- **Estimated Complexity**: Medium.
- **Priority**: Critical.
- **Acceptance Criteria**:
  - `aegis status` connects to running `aegisd` service and returns status codes.
  - Telemetry database file `telemetry.db` is initialized on startup in WAL mode.

### Tasks List

#### Task 1.1: Project Monorepo Initialization
- **Description**: Setup project folders and initialize the Go root modules.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: XS
- **Dependencies**: None
- **Expected Outcome**: Standard monorepo folder layout created with root `go.mod`.

#### Task 1.2: Local IPC Service Definition (gRPC)
- **Description**: Write proto contracts and compile Go client/server stubs.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: S
- **Dependencies**: Task 1.1
- **Expected Outcome**: Generated API stubs under `pkg/api/`.

#### Task 1.3: Daemon-CLI Client Integration
- **Description**: Wire CLI Cobra flags to gRPC client. Create background runner in daemon.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: M
- **Dependencies**: Task 1.2
- **Expected Outcome**: Client can ping running daemon via gRPC Unix Domain Socket.

#### Task 1.4: Database Schema & Migration Setup
- **Description**: Configure SQLite connection pool in WAL mode. Create tables: `processes`, `file_modifications`, `network_connections`, and `alert_logs`.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: M
- **Dependencies**: Task 1.3
- **Expected Outcome**: Schema migrated on startup; verification locks verified.

#### Task 1.5: Zero-Allocation Structured Logger
- **Description**: Instantiate Zap JSON logger.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: S
- **Dependencies**: Task 1.1
- **Expected Outcome**: Event audits printed to stdout in JSON formats.

---

## 📌 Phase 2: Telemetry Ingress Probes
- **Objectives**: Build Platform Abstraction Layer (PAL) and norm event router queues.
- **Deliverables**: Telemetry event capture routines (process, file, registry, network).
- **Dependencies**: Phase 1.
- **Estimated Complexity**: High.
- **Priority**: Critical.
- **Acceptance Criteria**:
  - Executing test binaries triggers process/file logs in SQLite.
  - Ring buffer drop policy handles event overflow gracefully.

### Tasks List

#### Task 2.1: PAL Process Telemetry Hook
- **Description**: Implement process capture callbacks (Windows ETW, Linux eBPF execve, macOS ESF notify exec).
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: L
- **Dependencies**: Task 1.4
- **Expected Outcome**: Raw binary execution metadata streams into the PAL package.

#### Task 2.2: PAL File Telemetry Hook
- **Description**: Implement file write/rename modifications callbacks.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: L
- **Dependencies**: Task 1.4
- **Expected Outcome**: Raw file access alerts stream to the PAL package.

#### Task 2.3: PAL Network Telemetry Hook
- **Description**: Implement socket capture callbacks (WFP, Linux connect tracepoint, macOS Network Extension).
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: L
- **Dependencies**: Task 1.4
- **Expected Outcome**: Socket connect events stream to the PAL package.

#### Task 2.4: Windows Registry Telemetry Hook
- **Description**: Implement registry key monitor (ETW Registry provider).
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: M
- **Dependencies**: Task 1.4
- **Expected Outcome**: Persistence key modification events logged on Windows.

#### Task 2.5: Ingress Queue & Normalizer
- **Description**: Setup standard ECS map schema. Configure Go ring buffer channels with drop logic.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: M
- **Dependencies**: Tasks 2.1, 2.2, 2.3
- **Expected Outcome**: Normalizer pushes normalized events to SQLite database.

---

## 📌 Phase 3: Multi-Engine Detection Core
- **Objectives**: Compile YARA bytes, stream Sigma log filters, analyze memory allocations, and calculate risk scoring.
- **Deliverables**: Rules evaluation runtime loop, compound risk calculator.
- **Dependencies**: Phase 2.
- **Estimated Complexity**: High.
- **Priority**: High.
- **Acceptance Criteria**:
  - YARA signatures trigger alert events.
  - Sigma YAML rules evaluate streams correctly in memory.

### Tasks List

#### Task 3.1: libyara Cgo Engine Wrapper
- **Description**: Wrap YARA library bindings. Coordinate background scan threads.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: L
- **Dependencies**: Task 2.5
- **Expected Outcome**: In-memory YARA scanner matches executable segments.

#### Task 3.2: Streaming Sigma Rules Parser
- **Description**: Construct Sigma YAML parser and state matching cache.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: L
- **Dependencies**: Task 2.5
- **Expected Outcome**: Sigma rules trigger alerts on suspicious event sequences.

#### Task 3.3: Virtual Memory Heuristics Monitor
- **Description**: Add process virtual memory range traversals checking for RWX segments.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: L
- **Dependencies**: Task 2.5
- **Expected Outcome**: Unbacked executable pages flagged dynamically.

#### Task 3.4: Compound Risk Scoring Engine
- **Description**: Implement weighted calculations formula, outputting alerts metadata.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: M
- **Dependencies**: Tasks 3.1, 3.2, 3.3
- **Expected Outcome**: Normalized alert logs contain MITRE mapping tags.

---

## 📌 Phase 4: Active Response Containment & Forensics
- **Objectives**: Implement remediation controls (firewalls, quarantine) and timeline generation.
- **Deliverables**: Process termination trees, host isolations, timeline CSV reports.
- **Dependencies**: Phase 3.
- **Estimated Complexity**: Medium.
- **Priority**: High.
- **Acceptance Criteria**:
  - `aegis response kill` terminates child process trees.
  - Network isolation stops outbound traffic without dropping gRPC connections.

### Tasks List

#### Task 4.1: Process Tree Containment Action
- **Description**: Build recursive tree kill tool using native OS APIs.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: M
- **Dependencies**: Task 3.4
- **Expected Outcome**: Target PID and children terminated securely.

#### Task 4.2: Host Network Isolation Action
- **Description**: Inject firewall rules blocking network traffic except control API ports.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: L
- **Dependencies**: Task 3.4
- **Expected Outcome**: Outbound traffic blocked via iptables/nftables/WFP.

#### Task 4.3: Cryptographic File Quarantine Protocol
- **Description**: Write AES-256-GCM file encryptor. Relocate files and strip permissions.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: M
- **Dependencies**: Task 3.4
- **Expected Outcome**: File payload encrypted and moved to quarantine folder.

#### Task 4.4: Chronological Timeline Forensics
- **Description**: Query database telemetry chronologically and compile reports.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: M
- **Dependencies**: Task 1.4
- **Expected Outcome**: Reports output as Markdown, CSV, or JSON streams.

---

## 📌 Phase 5: Plugin SDK & Enterprise Integrations
- **Objectives**: Build sandboxed WebAssembly execution VM and STIX/TAXII client feeds.
- **Deliverables**: Plugin SDK loader, threat sync client routines.
- **Dependencies**: Phase 4.
- **Estimated Complexity**: High.
- **Priority**: Medium.
- **Acceptance Criteria**:
  - Compiled TinyGo WASM plugin runs within memory limits (16MB).
  - TAXII client downloads indicators and loads them to reputation database.

### Tasks List

#### Task 5.1: WebAssembly Plugin Sandbox (Wasmtime)
- **Description**: Integrate Wasmtime SDK. Implement lifecycle validation and memory pages limit.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: XL
- **Dependencies**: Task 4.1
- **Expected Outcome**: WASM plugins execute safely in sandbox.

#### Task 5.2: TAXII Threat Ingestion Engine
- **Description**: Build TAXII 2.1 client poller and STIX JSON parser.
- **Status**: Done
- **Priority**: Medium
- **Estimated Effort**: L
- **Dependencies**: Task 1.4
- **Expected Outcome**: IOC database updated automatically from threat feeds.

#### Task 5.3: mTLS Certificates Sync Setup
- **Description**: Implement dynamic rotation client loops using HTTPS payloads.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: M
- **Dependencies**: Task 1.2
- **Expected Outcome**: Secure gRPC connection maintained using CA certs.

---

## 📌 Phase 6: CI/CD, Testing, Packaging & Release
- **Objectives**: Construct testing suites, configure lint checkers, compile builders, and build package installers.
- **Deliverables**: GitHub Action workflow files, package configs (.msi, .deb, .pkg).
- **Dependencies**: Phase 5.
- **Estimated Complexity**: Medium.
- **Priority**: High.
- **Acceptance Criteria**:
  - Fuzz tests run without panics.
  - Installers register aegisd service successfully under target OS managers.

### Tasks List

#### Task 6.1: Core Fuzz Testing Suite
- **Description**: Set up Go fuzz tests on format parsers (PE, ELF) and rule builders.
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: M
- **Dependencies**: Tasks 3.1, 3.2
- **Expected Outcome**: Invalid byte payloads handled gracefully without crashing the daemon.

#### Task 6.2: Benchmark Latency Analysis
- **Description**: Implement CI performance tests.
- **Status**: Done
- **Priority**: Medium
- **Estimated Effort**: S
- **Dependencies**: Task 2.5
- **Expected Outcome**: Alerts logged if normalizer latency exceeds 1ms per event.

#### Task 6.3: GitHub Actions CI/CD Pipeline
- **Description**: Write workflows for linters, dependency audits, build compilations, and SBOM exports.
- **Status**: Done
- **Priority**: Critical
- **Estimated Effort**: M
- **Dependencies**: Task 1.1
- **Expected Outcome**: Automatic release binaries signed using Cosign.

#### Task 6.4: OS Native Package Installers
- **Description**: Package binaries into native formats: deb/rpm (Linux), pkg/dmg (macOS), and msi (Windows).
- **Status**: Done
- **Priority**: High
- **Estimated Effort**: L
- **Dependencies**: Task 6.3
- **Expected Outcome**: Service daemon registers under systemd/launchd/Service Control Manager.
