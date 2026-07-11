# 📋 AEGIS EDR - Development Implementation Order

This document defines the sequential implementation blueprint for the AEGIS EDR platform. It categorizes tasks into logical milestones, maps dependencies, identifies blockers, and highlights independent development paths to ensure compilation safety and zero circular references.

---

## 🗺️ Milestone Roadmap

```
+-------------------------------------------------------------+
| Milestone 1: Monorepo Foundation & Local IPC                |
| (Tasks 1.1 -> 1.5) [CRITICAL PATH]                          |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| Milestone 2: Telemetry Ingestion Pipeline                   |
| (Tasks 2.1 -> 2.5) [BLOCKER FOR DETECTION]                  |
+------------------------------+------------------------------+
                               |
                               v
+------------------------------+------------------------------+
| Milestone 3: Multi-Engine Detection Core                    |
| (Tasks 3.1 -> 3.4)                                          |
+------------------------------+------------------------------+
                               |
                               v
+------------------------------+------------------------------+
| Milestone 4: Remediation Response & Forensics               |
| (Tasks 4.1 -> 4.4)                                          |
+------------------------------+------------------------------+
                               |
                               v
+------------------------------+------------------------------+
| Milestone 5: Sandboxed Plugins & Intel Sync                 |
| (Tasks 5.1 -> 5.3)                                          |
+------------------------------+------------------------------+
                               |
                               v
+------------------------------+------------------------------+
| Milestone 6: Quality Assurance, packaging, & Release        |
| (Tasks 6.1 -> 6.4)                                          |
+------------------------------+------------------------------+
```

---

## 📌 Detailed Implementation Order

### Milestone 1: Monorepo Foundation & Local IPC
*   **Prerequisites**: None.
*   **Focus**: Establishing initial repository scaffolding, logging configurations, local database schema migrations, and local gRPC client/server handshakes.
*   **Execution Sequence**:
    1.  **Task 1.1: Project Monorepo Initialization** [CRITICAL PATH]
        *   Prerequisites: None.
    2.  **Task 1.5: Zero-Allocation Structured Logger**
        *   Prerequisites: Task 1.1.
    3.  **Task 1.2: Local IPC Service Definition (gRPC)** [CRITICAL PATH]
        *   Prerequisites: Task 1.1.
    4.  **Task 1.3: Daemon-CLI Client Integration** [CRITICAL PATH]
        *   Prerequisites: Task 1.2.
    5.  **Task 1.4: Database Schema & Migration Setup** [CRITICAL PATH]
        *   Prerequisites: Task 1.3.

---

### Milestone 2: Telemetry Ingestion Pipeline
*   **Prerequisites**: Milestone 1.
*   **Focus**: Capturing operating system telemetry probes natively and routing them to the normalized database.
*   **Execution Sequence**:
    1.  **Task 2.1: PAL Process Telemetry Hook** [CRITICAL PATH]
        *   Prerequisites: Task 1.4.
    2.  **Task 2.2: PAL File Telemetry Hook**
        *   Prerequisites: Task 1.4.
    3.  **Task 2.3: PAL Network Telemetry Hook**
        *   Prerequisites: Task 1.4.
    4.  **Task 2.4: Windows Registry Telemetry Hook** [WINDOWS-ONLY]
        *   Prerequisites: Task 1.4.
    5.  **Task 2.5: Ingress Queue & Normalizer** [CRITICAL PATH]
        *   Prerequisites: Tasks 2.1, 2.2, 2.3.

---

### Milestone 3: Multi-Engine Detection Core
*   **Prerequisites**: Milestone 2.
*   **Focus**: In-memory rule compilation, event sequence analysis, and threat scoring.
*   **Execution Sequence**:
    1.  **Task 3.1: libyara Cgo Engine Wrapper**
        *   Prerequisites: Task 2.5.
    2.  **Task 3.2: Streaming Sigma Rules Parser**
        *   Prerequisites: Task 2.5.
    3.  **Task 3.3: Virtual Memory Heuristics Monitor**
        *   Prerequisites: Task 2.5.
    4.  **Task 3.4: Compound Risk Scoring Engine** [CRITICAL PATH]
        *   Prerequisites: Tasks 3.1, 3.2, 3.3.

---

### Milestone 4: Remediation Response & Forensics
*   **Prerequisites**: Milestone 3.
*   **Focus**: Active containment measures and post-incident investigation timeline tools.
*   **Execution Sequence**:
    1.  **Task 4.1: Process Tree Containment Action**
        *   Prerequisites: Task 3.4.
    2.  **Task 4.2: Host Network Isolation Action**
        *   Prerequisites: Task 3.4.
    3.  **Task 4.3: Cryptographic File Quarantine Protocol**
        *   Prerequisites: Task 3.4.
    4.  **Task 4.4: Chronological Timeline Forensics**
        *   Prerequisites: Task 1.4.

---

### Milestone 5: Sandboxed Plugins & Intel Sync
*   **Prerequisites**: Milestone 4.
*   **Focus**: Dynamic WebAssembly integrations and automated threat feeds polling.
*   **Execution Sequence**:
    1.  **Task 5.1: WebAssembly Plugin Sandbox (Wasmtime)**
        *   Prerequisites: Task 4.1.
    2.  **Task 5.2: TAXII Threat Ingestion Engine**
        *   Prerequisites: Task 1.4.
    3.  **Task 5.3: mTLS Certificates Sync Setup**
        *   Prerequisites: Task 1.2.

---

### Milestone 6: Quality Assurance, Packaging, & Release
*   **Prerequisites**: Milestone 5.
*   **Focus**: Stability testing, continuous delivery validation, and native OS service configuration scripts.
*   **Execution Sequence**:
    1.  **Task 6.1: Core Fuzz Testing Suite**
        *   Prerequisites: Tasks 3.1, 3.2.
    2.  **Task 6.2: Benchmark Latency Analysis**
        *   Prerequisites: Task 2.5.
    3.  **Task 6.3: GitHub Actions CI/CD Pipeline**
        *   Prerequisites: Task 1.1.
    4.  **Task 6.4: OS Native Package Installers**
        *   Prerequisites: Task 6.3.

---

## 🚦 Key Blockers & Critical Path

### 1. Blocker: Database Schema Migration (`Task 1.4`)
*   **Impact**: Telemetry queues and detection logs cannot execute without an initialized SQLite schema.
*   **Mitigation**: Standardize mock SQLite tables inside test files (`*_test.go`) to allow concurrent use-case coding before the primary migration handler is complete.

### 2. Blocker: Ingress Queue Normalizer (`Task 2.5`)
*   **Impact**: Threat evaluation engines depend on normalized data mapping structures.
*   **Mitigation**: Define the shared event structs early inside `eventrouter/` so signature engines can mock inputs without referencing the PAL package.

### 3. Critical Path Sequence
```text
Task 1.1 (Repo Init) -> Task 1.2 (gRPC definition) -> Task 1.3 (IPC split) -> Task 1.4 (SQLite WAL migrations)
  -> Task 2.1 (PAL Process hooks) -> Task 2.5 (Normalizer queue)
  -> Task 3.4 (Risk Scoring core) -> Task 6.3 (CI/CD Pipeline) -> Task 6.4 (Installers)
```

---

## 🛠️ Independent Development Modules

The following packages contain zero shared dependencies and can be developed concurrently by separate team members:
1.  **Logging Interface (`Task 1.5`)**: Only imports standard libraries. Can be plugged into any module as needed.
2.  **Platform Abstraction Probes (`Tasks 2.1, 2.2, 2.3, 2.4`)**: Process, file, registry, and network system hooks do not depend on each other and can be written asynchronously.
3.  **WASM Plugin Sandbox (`Task 5.1`)**: Uses an isolated WebAssembly JIT interpreter environment and does not depend on the active EDR database or platform telemetry probes.
4.  **TAXII Client Poller (`Task 5.2`)**: Connects to remote threat feeds and only requires the database storage connector interface.
