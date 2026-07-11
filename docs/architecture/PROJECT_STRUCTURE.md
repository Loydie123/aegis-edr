# 📁 AEGIS EDR - Monorepo Project Structure

This document outlines the directory structure, package responsibilities, dependency rules, and architectural layout for the AEGIS monorepo. It serves as a guide for developers and maintainers to ensure clean architecture compliance, prevent circular dependencies, and maintain scalability across all supported operating systems (Windows, Linux, macOS).

---

## 🗂️ Proposed Directory Tree

Below is the updated layout of the Go-based monorepo, aligning with the official Go project layout (`golang-standards/project-layout`) and enterprise-grade design principles:

```text
aegis-edr/
├── cmd/                       # Entry points for compiling binaries
│   ├── aegis/                 # Administrative user space CLI client (aegis)
│   └── aegisd/                # Highly privileged background service daemon (aegisd)
├── pkg/                       # Publicly exportable libraries and modules
│   ├── api/                   # gRPC Protobuf definitions and compiled stubs
│   └── sdk/                   # Developer Plugin SDK & WebAssembly (WASM) definitions
├── internal/                  # Private application packages (not importable externally)
│   ├── config/                # YAML configuration parser and operational profiles
│   ├── detect/                # Detection Engine Modules
│   │   ├── behavioral/        # Sigma-style event stream correlation engine
│   │   ├── heuristics/        # In-memory execution heuristics and entropy math
│   │   ├── signature/         # Hash reputation and YARA scanner wrappers
│   │   └── scoring/           # Compound risk scoring engine
│   ├── forensics/             # Artifact collectors and chronological timeline parser
│   ├── logger/                # Zero-allocation structured Zap logger
│   ├── monitor/               # Telemetry Capture Pipeline
│   │   ├── eventrouter/       # Normalizes system events to standard ECS schemas
│   │   └── platform/          # Platform Abstraction Layer (PAL) OS wrappers
│   │       ├── windows/       # Windows ETW and WFP telemetry hooks
│   │       ├── linux/         # Linux eBPF probes and fanotify handlers
│   │       └── darwin/        # macOS Endpoint Security Framework (ESF) subscribers
│   ├── response/              # Containment and active remediation controllers
│   │   ├── network/           # Host network isolation action
│   │   ├── process/           # Process tree containment action
│   │   └── quarantine/        # Cryptographic file quarantine protocol
│   └── storage/               # Persistent database handlers (SQLite WAL connection pools)
├── configs/                   # Sample policies, YAML rules, and deploy templates
├── docs/                      # Technical manuals, API schema docs, and guides
├── packaging/                 # Systemd/Launchd/SCM setup packages
├── go.mod                     # Go module definitions
├── go.sum                     # Go module dependency checksums
└── Makefile                   # Build pipeline orchestration tasks
```

---

## 🔍 Folders & Packages Deep Dive

### 1. `cmd/` (Application Entry Points)
This folder holds the main execution entries. It contains no business logic; its sole responsibility is initializing dependencies, parsing flags, loading configuration profiles, and invoking the core packages.
- **`cmd/aegis/`**: Compiles to the `aegis` administrative CLI. Handles standard input/output formatting, interactive terminal sessions (TUI), and issues gRPC payloads to the local daemon socket.
- **`cmd/aegisd/`**: Compiles to the `aegisd` background daemon. Executes with root/SYSTEM privileges. It instantiates the telemetry monitors, rules engines, local database storage, and serves the gRPC socket interface.

### 2. `pkg/` (Public Libraries)
The `pkg/` directory contains code meant to be publicly exportable and consumable by external repositories or integrations.
- **`pkg/api/`**: Contains protobuf schemas (`.proto`) and compiled Go client/server stubs. This allows third-party services or consoles to easily interact with the daemon's IPC interfaces.
- **`pkg/sdk/`**: Houses public SDK contracts and interface signatures for plugin development. Third-party developers use these interfaces to compile custom WASM detection plugins.

### 3. `internal/` (Private Core Modules)
To prevent unauthorized external dependencies on core internals, all private code resides within `internal/`. Go prevents external repositories from importing any package located inside this folder.

#### `internal/config/` (Settings Coordinator)
- **Why it exists**: To manage configuration states uniformly.
- **Responsibilities**: Ingests, validates, and exposes variables defined in the `aegis.yaml` file, environment overrides, and global CLI flags.

#### `internal/detect/` (The Detection Brain)
- **Why it exists**: To house isolated detection engines matching separate threat paradigms.
- **Responsibilities**:
  - **`behavioral/`**: Matches streaming events against Sigma rules.
  - **`heuristics/`**: Tracks memory anomalies, identifies unbacked memory spaces (reflective loads), and parses maps.
  - **`signature/`**: Wraps `libyara` and performs static file match checks.
  - **`scoring/`**: Computes compound risk scores dynamically and outputs alerts metadata with MITRE tags.

#### `internal/forensics/` (Forensics timeline)
- **Why it exists**: To query database telemetry chronologically and compile reports.
- **Responsibilities**: Builds chronological timeline streams from sqlite tables.

#### `internal/logger/` (Structured Auditor)
- **Why it exists**: Zero-allocation logging wrappers.
- **Responsibilities**: Initializes Zap JSON logging handlers.

#### `internal/monitor/` (System Telemetry Stream)
- **Why it exists**: To capture raw OS operations and convert them into a unified stream.
- **Responsibilities**:
  - **`platform/`**: The Platform Abstraction Layer (PAL). Segregates platform-dependent code via Go build tags.
  - **`eventrouter/`**: Normalized raw events into the standardized Aegis Event Format (AEF) based on the Elastic Common Schema (ECS).

#### `internal/response/` (Containment Execution)
- **Why it exists**: To quarantine infected assets and contain active threats.
- **Responsibilities**: Implements process tree killers, host network isolation filters, and cryptographic file quarantines.

#### `internal/storage/` (Telemetry Database)
- **Why it exists**: To persist events locally without causing performance drops.
- **Responsibilities**: Wraps SQLite connection pool configurations, migrations, indices, and WAL setups.

---

## ⚖️ Architectural Decisions & Comparison

### 1. `pkg/` vs `internal/` Separation
- **Enterprise Standard**: Large-scale production platforms (e.g. Kubernetes, Docker, HashiCorp vault) strictly isolate internal structures under the `internal/` tree. This prevents "import lock-in" where third-party packages import internal helper functions, blocking API refactoring.
- **Aegis Implementation**: We restrict `pkg/` to only public contracts (`api` and `sdk`). This guarantees that security rules, database queries, and response actions remain completely protected and cannot be imported by external Go modules.

### 2. Monorepo Layout and Single `go.mod`
- **Go Best Practice**: Having a single `go.mod` file at the root simplifies dependency alignment, vulnerability auditing, and CI pipeline checks. It ensures that the CLI client and the daemon run matching versions of all shared libraries (such as gRPC and protobuf).

### 3. Platform Abstraction Layer (PAL) tag-isolation
- **Design Pattern**: Low-level telemetry capture utilizes OS-specific system libraries (ETW on Windows, Fanotify/eBPF on Linux, ESF on macOS). Shifting these into `internal/monitor/platform/` with explicit build tags (`//go:build`) ensures clean separation and compilation safety across build targets.

---

## 🔄 Dependency Flow & Import Boundaries

To maintain clean hexagonal architecture boundaries, packages must adhere to strict import rules. **Circular dependencies are blocked.**

```
+-----------------------------------------------------------+
|                        cmd/aegis                          |
+-----------------------------+-----------------------------+
                              | Imports
                              v
                      +---------------+
                      |    pkg/api    |
                      +-------+-------+
                              ^
                              | Imported via gRPC Stub
+-----------------------------+-----------------------------+
|                        cmd/aegisd                         |
+-----------------------------+-----------------------------+
                              | Imports
                              v
+-----------------------------------------------------------+
|                      internal/detect                      |
+-----------------------------+-----------------------------+
                              | Imports Normalized Events
                              v
+-----------------------------------------------------------+
|                      internal/monitor                     |
+-----------------------------+-----------------------------+
                              | Stores Normalized Events
                              v
+-----------------------------------------------------------+
|                      internal/storage                     |
+-----------------------------------------------------------+
```

### Import Rules:
1. **No System Telemetry in Detection Engines**: `internal/detect/` must never import `internal/monitor/`. Detection engines consume *normalized event structs* and rules; they do not collect telemetry directly.
2. **Independence of PAL**: Packages inside `internal/monitor/platform/` must be isolated. A Linux module must never import a Windows-specific header or library.
3. **Database Isolation**: No module other than `internal/storage/` may run raw SQL queries. Modules requesting data must interface with the defined Storage interfaces.

---

## 🛡️ Clean Architecture PAL Separation

The Platform Abstraction Layer (PAL) separates low-level operating system APIs from core agent logic:

```
+------------------------------------------------------------+
|                internal/monitor/eventrouter                |
|           (Consumes Normalized Event Structures)           |
+------------------------------------+-----------------------+
                                     | Normalizes
                                     v
+------------------------------------+-----------------------+
|                  internal/monitor/platform                 |
|             (Platform Abstraction Layer Interface)          |
+-----------------+------------------+-----------------------+
                  |                  |
                  | (Win build tag)  | (Linux build tag)
                  v                  v
        +---------+--------+  +------+---------+
        |   platform/win   |  |  platform/linux| ... (Darwin)
        | (ETW, WFP, Reg)  |  | (eBPF, fanotif)|
        +------------------+  +----------------+
```

Go conditional compilation build tags isolate these modules at compile-time:
- Files containing `//go:build windows` are compiled exclusively for Windows systems.
- Files containing `//go:build linux` are compiled exclusively for Linux kernels.
- Files containing `//go:build darwin` are compiled exclusively for macOS systems.

This ensures the generated binaries contain zero redundant binary code or unresolvable system libraries for non-target platforms.

---

## 🚀 Go Monorepo Best Practices Enforced

- **Single `go.mod`**: To prevent dependency version mismatches and simplify CI/CD pipelines, a single `go.mod` file is maintained at the root of the repository.
- **Zero Raw Global State**: All components utilize dependency injection. Database connections, rule compilers, and client sockets are passed explicitly during application initialization in `cmd/`.
- **Parallel Testing**: Tests inside packages are isolated and run concurrently using `t.Parallel()`.
- **Interface Segregation**: Package consumers import small, specific interfaces rather than concrete, wide implementation structures.
