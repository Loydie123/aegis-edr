# 📁 AEGIS EDR - Monorepo Project Structure

This document outlines the directory structure, package responsibilities, dependency rules, and architectural layout for the AEGIS monorepo. It serves as a guide for developers and maintainers to ensure clean architecture compliance, prevent circular dependencies, and maintain scalability across all supported operating systems (Windows, Linux, macOS).

---

## 🗂️ Directory Tree

Below is the conceptual structure of the Go-based monorepo, following Go Monorepo standards and Clean Architecture principles:

```text
aegis-edr/
├── cmd/                       # Entry points for compiling binaries
│   ├── aegis/                 # Administrative user space CLI client (aegis)
│   └── aegisd/                # Highly privileged background service daemon (aegisd)
├── pkg/                       # Shared libraries & modules (importable by internal/external)
│   ├── api/                   # gRPC Protobuf definitions and compiled stubs
│   ├── config/                # YAML configuration parser and operational profiles
│   ├── detect/                # Detection Engine Modules
│   │   ├── behavioral/        # Sigma-style event stream correlation engine
│   │   ├── heuristics/        # In-memory execution heuristics and entropy math
│   │   └── signature/         # Hash reputation and YARA scanner wrappers
│   ├── forensics/             # Artifact collectors and chronological timeline parser
│   ├── monitor/               # Telemetry Capture Pipeline
│   │   ├── eventrouter/       # Normalizes system events to standard ECS schemas
│   │   └── platform/          # Platform Abstraction Layer (PAL) OS wrappers
│   │       ├── windows/       # Windows ETW and WFP telemetry hooks
│   │       ├── linux/         # Linux eBPF probes and fanotify handlers
│   │       └── darwin/        # macOS Endpoint Security Framework (ESF) subscribers
│   ├── response/              # Containment and active remediation controller
│   ├── sdk/                   # Developer Plugin SDK & WebAssembly (WASM) runner
│   └── storage/               # Persistent database handlers (SQLite WAL / BadgerDB)
├── configs/                   # Sample policies, YAML rules, and deploy templates
├── docs/                      # Technical manuals, API schema docs, and guides
├── scripts/                   # Systemd/Launchd install files and automation scripts
├── test/                      # End-to-end integration test suites and threat vectors
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

### 2. `pkg/` (Core Libraries)
The `pkg/` directory contains logic grouped by domain. Packages inside `pkg/` are designed to be modular and reusable.

#### `pkg/api/` (IPC Contracts)
- **Why it exists**: To maintain a strongly typed API contract between the CLI tool and the service daemon.
- **Responsibilities**: Contains protobuf schema files (`.proto`) and compiled Go stubs for local and remote gRPC services.

#### `pkg/config/` (Settings Coordinator)
- **Why it exists**: To manage configuration states uniformly.
- **Responsibilities**: Ingests, validates, and exposes variables defined in the `aegis.yaml` file, environment overrides, and global CLI flags.

#### `pkg/detect/` (The Detection Brain)
- **Why it exists**: To house isolated detection engines matching separate threat paradigms.
- **Responsibilities**:
  - **`behavioral/`**: Matches streaming events chronologically against Sigma rules. Maintains state machines tracking event sequences (e.g., process write -> registry addition -> network connect).
  - **`heuristics/`**: Tracks memory anomalies, identifies unbacked memory spaces (reflective loads), and computes Shannon Entropy on binary file sections.
  - **`signature/`**: Wraps the YARA runtime library (`libyara`) and runs static file matches. Queries local reputation hash tables.

#### `pkg/monitor/` (System Telemetry Stream)
- **Why it exists**: To capture raw OS operations and convert them into a unified stream.
- **Responsibilities**:
  - **`platform/`**: The Platform Abstraction Layer (PAL). Segregates platform-dependent code via Go build tags (e.g., `//go:build windows` or `//go:build linux`). Implements low-level event collection (ETW, eBPF, ESF).
  - **`eventrouter/`**: Normalized raw events into the standardized Aegis Event Format (AEF) based on the Elastic Common Schema (ECS).

#### `pkg/response/` (Containment Execution)
- **Why it exists**: To quarantine infected assets and contain active threats.
- **Responsibilities**: Implements native containment routines: process termination trees, network isolation (firewall changes), file isolation (GCM encryption + permission stripping), and peripheral disabling.

#### `pkg/storage/` (Telemetry Database)
- **Why it exists**: To persist events locally without causing performance drops.
- **Responsibilities**: Wraps SQLite and BadgerDB configurations. Manages schema migrations, writes logs in WAL mode, builds B-Tree indices on timeline fields, and handles data cleanup/retention rules.

#### `pkg/sdk/` (Extensibility Module)
- **Why it exists**: To enable third-party plugins without modifying EDR agent code.
- **Responsibilities**: Registers custom hooks and loads sandboxed WebAssembly (WASM) plugin binaries via the Wasmtime interpreter wrapper.

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
|                        pkg/detect                         |
|  (signature, behavioral, heuristics)                      |
+-----------------------------+-----------------------------+
                              | Imports Normalized Events
                              v
+-----------------------------------------------------------+
|                        pkg/monitor                        |
|  (eventrouter, platform-specific collectors)               |
+-----------------------------+-----------------------------+
                              | Stores Normalized Events
                              v
+-----------------------------------------------------------+
|                        pkg/storage                        |
+-----------------------------------------------------------+
```

### Import Rules:
1. **No System Telemetry in Detection Engines**: `pkg/detect/` must never import `pkg/monitor/`. Detection engines consume *normalized event structs* and rules; they do not collect telemetry directly.
2. **Independence of PAL**: Packages inside `pkg/monitor/platform/` (e.g., `windows/`, `linux/`, `darwin/`) must be isolated. A Linux module must never import a Windows-specific header or library.
3. **Database Isolation**: No module other than `pkg/storage/` may run raw SQL queries. Modules requesting data must interface with the defined Storage interfaces.

---

## 🛡️ Clean Architecture PAL Separation

The Platform Abstraction Layer (PAL) separates low-level operating system APIs from core agent logic:

```
+------------------------------------------------------------+
|                  pkg/monitor/eventrouter                   |
|           (Consumes Normalized Event Structures)           |
+------------------------------------+-----------------------+
                                     | Normalizes
                                     v
+------------------------------------+-----------------------+
|                    pkg/monitor/platform                    |
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

## 📈 Future Scalability Guidelines

This Go monorepo is designed to grow smoothly as features expand:

### 1. Adding a New Telemetry Event Probe
1. Define the new event struct parameters inside the shared ECS models in `pkg/monitor/eventrouter/`.
2. Implement the platform-specific hook under the corresponding folder in `pkg/monitor/platform/<os>/`.
3. Expose the collector inside the `PlatformMonitor` interface and bind the normalized event output to the `eventrouter` queue.

### 2. Adding a Custom Containment Response Action
1. Register the response function inside the interface defined in `pkg/response/`.
2. Implement the OS-specific commands under native code routines in `pkg/response/platform_<os>.go`.
3. Add config flags inside the `response.actions` block of the `aegis.yaml` parser under `pkg/config/`.

### 3. Integrating a New Engine (e.g., Machine Learning / Anomaly Scan)
1. Create a subfolder under `pkg/detect/ml/`.
2. Implement the standard detection evaluator interface:
   ```go
   type DetectionEngine interface {
       Evaluate(event *eventrouter.Event) (*detect.Alert, error)
   }
   ```
3. Register the engine inside `cmd/aegisd` and wire the normalized event ring buffer to feed the new evaluator.

---

## 🚀 Go Monorepo Best Practices Enforced

- **Single `go.mod`**: To prevent dependency version mismatches and simplify CI/CD pipelines, a single `go.mod` file is maintained at the root of the repository.
- **Zero Raw Global State**: All components utilize dependency injection. Database connections, rule compilers, and client sockets are passed explicitly during application initialization in `cmd/`.
- **Parallel Testing**: Tests inside packages are isolated and run concurrently using `t.Parallel()`.
- **Interface Segregation**: Package consumers import small, specific interfaces rather than concrete, wide implementation structures.
