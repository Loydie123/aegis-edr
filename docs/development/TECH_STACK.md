# 🛠️ AEGIS EDR - Technology Stack Decision Records

This document catalogs the technologies chosen for the AEGIS EDR platform. For each component, it details the selection rationale, evaluates trade-offs, reviews alternatives, identifies Phase 1 requirement status, and tags the deployment lifecycle.

---

## 📖 Table of Contents
1. [Go (Golang)](#1-go-golang)
2. [C / Assembly](#2-c--assembly)
3. [Cobra (CLI Framework)](#3-cobra-cli-framework)
4. [Bubbletea (TUI Framework)](#4-bubbletea-tui-framework)
5. [React / Tailwind / TypeScript](#5-react--tailwind--typescript)
6. [SQLite 3](#6-sqlite-3)
7. [BadgerDB](#7-badgerdb)
8. [libyara (YARA Engine)](#8-libyara-yara-engine)
9. [Sigma Go Parser](#9-sigma-go-parser)
10. [gRPC / Protobuf](#10-grpc--protobuf)
11. [Zap (Logging Library)](#11-zap-logging-library)
12. [Viper (Configuration Parser)](#12-viper-configuration-parser)
13. [Go Templates](#13-go-templates)
14. [Wasmtime (WebAssembly SDK)](#14-wasmtime-webassembly-sdk)
15. [GNU Make](#15-gnu-make)
16. [pnpm](#16-pnpm)
17. [GitHub Actions](#17-github-actions)

---

## 1. Go (Golang)
- **Role**: Primary Language for Daemon and CLI applications.
- **Why Selected**: Provides native, cross-compilation binaries out-of-the-box, contains built-in concurrency primitives (Goroutines and Channels), and runs with a lightweight runtime memory profile.
- **Phase 1 Required**: Yes.
- **Status**: Required Now.
- **Recommendation**: Keep.
- **Pros**: Fast build times, simple concurrency model, stable standard library, garbage collection with target limit controls (`GOMEMLIMIT`).
- **Cons**: GC execution can introduce microsecond latency spikes; C-go boundary crossings (e.g., calling YARA libraries) add minor memory overhead.
- **Future Replacement**: Rust, if absolute real-time guarantee without GC is required in later production phases.

---

## 2. C / Assembly
- **Role**: High-speed, unmanaged routines (e.g., block entropy calculation).
- **Why Selected**: Direct access to hardware instructions (e.g., SSE/AVX registers) enables highly optimized math operations, such as calculating Shannon Entropy for file segments.
- **Phase 1 Required**: No.
- **Status**: Future Phase (Phase 3).
- **Recommendation**: Delay integration until Phase 3 to simplify the early monorepo compilation build paths.
- **Pros**: Direct control over hardware registers, zero instruction overhead, maximum loop efficiency.
- **Cons**: Difficult to maintain, lacks type safety, breaks direct Go cross-compilation workflows unless managed carefully with cgo and assembly files.
- **Future Replacement**: Intrinsics or native assembly routines compiled directly inside Go.

---

## 3. Cobra (CLI Framework)
- **Role**: Subcommand parser and flag coordinator.
- **Why Selected**: De-facto industry standard for CLI applications in the Go ecosystem (used by Kubernetes and Docker). It handles subcommand routing, auto-generates help screens, and binds configuration flags seamlessly.
- **Phase 1 Required**: Yes.
- **Status**: Required Now.
- **Recommendation**: Keep (Standard for Go subcommands).
- **Pros**: Built-in shell auto-completion generator, POSIX-compliant flag parsing, nested subcommand support.
- **Cons**: Relatively heavy codebase size for simple, single-command utility applications.
- **Future Replacement**: None planned.

---

## 4. Bubbletea (TUI Framework)
- **Role**: Controls interactive monitoring views on the terminal.
- **Why Selected**: Implementing the Elm architecture in Go, it enables reactive, beautiful, and component-driven terminal user interfaces (TUIs) without direct management of raw terminal escape codes.
- **Phase 1 Required**: No.
- **Status**: Optional.
- **Recommendation**: Remove or delay. The status commands can output raw text or JSON, keeping the CLI binary small.
- **Pros**: Reactive component rendering, built-in support for tables, progress bars, and forms, clean state management.
- **Cons**: High cognitive load during design phase due to nested state updates.
- **Future Replacement**: Custom thin TUI renderer if binary size constraints become critical.

---

## 5. React / Tailwind / TypeScript
- **Role**: Admin console UI stack (Fleet Dashboard).
- **Why Selected**: React has a mature ecosystem of charting libraries (Recharts) and table grids. Tailwind enables rapid UI construction, and TypeScript guarantees type safety for fleet state payloads.
- **Phase 1 Required**: No.
- **Status**: Optional.
- **Recommendation**: Remove from early releases. The core CLI and daemon do not depend on a graphical dashboard for endpoint controls.
- **Pros**: Fast component renders, consistent UI styling via Tailwind classes, robust client-state validation.
- **Cons**: Requires a compilation build step (Vite/Next.js) and increases package build complexity.
- **Future Replacement**: Svelte, if client bundle size optimization becomes a primary target.

---

## 6. SQLite 3
- **Role**: Persistent local database store for event logs and configuration profiles.
- **Why Selected**: Self-contained, serverless database that supports full SQL syntax, transactions, and index creation. It is highly optimized for local read-heavy operations when configured in Write-Ahead Log (WAL) mode.
- **Phase 1 Required**: Yes.
- **Status**: Required Now.
- **Recommendation**: Keep. Utilize pure Go SQL drivers (like modernc.org/sqlite) to maintain Cgo-free and cross-platform compilation.
- **Pros**: Zero service configuration, single-file database, transactions support, WAL mode for concurrent reads/writes.
- **Cons**: Database file writes block under heavy concurrent write operations if not handled using dedicated write-queues.
- **Future Replacement**: DuckDB, if columnar, analytic aggregations on telemetry are required.

---

## 7. BadgerDB
- **Role**: Key-Value LSM-Tree log cache.
- **Why Selected**: Pure Go implementation of a Log-Structured Merge (LSM) database. It is optimized for high-throughput write streams, serving as a staging database for incoming raw event bursts.
- **Phase 1 Required**: No.
- **Status**: Optional.
- **Recommendation**: Remove. Using SQLite in WAL mode is sufficient for local caching and saves memory footprint.
- **Pros**: High-throughput write performance, zero external C library dependencies, built-in key compression.
- **Cons**: High memory utilization during write compaction loops.
- **Future Replacement**: Pebble (developed by CockroachDB team), if more stable memory usage profiles are needed under high load.

---

## 8. libyara (YARA Engine)
- **Role**: Static and memory signature matching.
- **Why Selected**: Industry-standard signature scanning tool. It compiles rules to bytecode and scans raw files or process memory spaces with high efficiency.
- **Phase 1 Required**: No.
- **Status**: Future Phase (Phase 3).
- **Recommendation**: Delay. Introduces Cgo dependency which complicates CI pipelines.
- **Pros**: Standardized rule format used by threat researchers, fast multi-pattern string matching, regex engine support.
- **Cons**: Uses C-go bindings which add compilation complexity and minor execution overhead.
- **Future Replacement**: YARA-Rust compiled to WebAssembly (WASM) or a pure-Go YARA implementation.

---

## 9. Sigma Go Parser
- **Role**: Behavioral rule parser and stream engine.
- **Why Selected**: Sigma rules represent behavioral threats in an OS-independent format. A native Go parser enables streaming event evaluation without external Python runtimes.
- **Phase 1 Required**: No.
- **Status**: Future Phase (Phase 3).
- **Recommendation**: Delay rules integration to Phase 3.
- **Pros**: Pure Go, evaluates rules in-memory, supports standard Sigma YAML format.
- **Cons**: Stateful rule evaluation (e.g., event A followed by event B) requires custom timing windows and consumes memory.
- **Future Replacement**: Custom stream-processing correlation engines.

---

## 10. gRPC / Protobuf
- **Role**: Local IPC (between `aegis` and `aegisd`) and agent-to-fleet communications.
- **Why Selected**: Strongly-typed schema definitions, low CPU serialization overhead, built-in support for streaming APIs, and secure TLS validation out-of-the-box.
- **Phase 1 Required**: Yes.
- **Status**: Required Now.
- **Recommendation**: Keep.
- **Pros**: Small payload sizes, code generator support for multiple target languages, bidirectional streaming.
- **Cons**: Payloads are binary and cannot be debugged easily with text-only network sniffers.
- **Future Replacement**: Cap'n Proto, if zero-copy serialization becomes necessary for high-throughput pipelines.

---

## 11. Zap (Logging Library)
- **Role**: Structured logging handler.
- **Why Selected**: Designed for zero heap allocations in critical code paths, Zap is the fastest structured logger in Go, preventing logging statements from introducing latency spikes.
- **Phase 1 Required**: Yes.
- **Status**: Replace.
- **Recommendation**: Replace with Go 1.21's standard library `log/slog` to eliminate external Zap dependency and keep the project lightweight.
- **Pros**: Fastest Go structured logger, supports both structured JSON and speed-optimized logs.
- **Cons**: Verbose syntax compared to standard library loggers.
- **Future Replacement**: Standard library `slog`.

---

## 12. Viper (Configuration Parser)
- **Role**: Ingests configuration files, environment variables, and CLI overrides.
- **Why Selected**: Cobra integration out-of-the-box. It parses configuration variables from YAML files, OS environment variables, and CLI flag overrides seamlessly.
- **Phase 1 Required**: Yes.
- **Status**: Replace.
- **Recommendation**: Replace with Go's standard library `encoding/json` or clean `yaml.v3` parser to reduce dependency footprint.
- **Pros**: Automatic environment variable mapping, supports multiple file formats (JSON, TOML, YAML), binds flags to config values directly.
- **Cons**: Large dependency footprint.
- **Future Replacement**: Simple custom YAML parser.

---

## 13. Go Templates
- **Role**: Compiles forensic timelines and compliance reports.
- **Why Selected**: Part of the standard library, it provides a safe, injection-resistant engine for rendering dynamic text structures (Markdown, CSV, HTML).
- **Phase 1 Required**: No.
- **Status**: Future Phase (Phase 4).
- **Recommendation**: Delay until Phase 4 timeline reporting.
- **Pros**: Standard library component, safe against template-injection bugs, fast render speeds.
- **Cons**: Syntax can be difficult to read and debug for complex nested layouts.
- **Future Replacement**: None planned.

---

## 14. Wasmtime (WebAssembly SDK)
- **Role**: Runs sandboxed SDK plugins.
- **Why Selected**: Wasmtime provides a highly secure, memory-isolated, JIT-compiled execution environment for WebAssembly (WASM) binaries on multiple CPU architectures.
- **Phase 1 Required**: No.
- **Status**: Replace.
- **Recommendation**: Replace with `github.com/tetratelabs/wazero` (pure Go WebAssembly runtime) to completely eliminate Cgo compiler bindings requirements during builds.
- **Pros**: Strictly sandboxed execution, memory isolation, support for multiple source languages (Rust, Go, C).
- **Cons**: High initial footprint size, overhead when passing large data structures across the WASM boundary.
- **Future Replacement**: Wazero.

---

## 15. GNU Make
- **Role**: Build pipeline coordination.
- **Why Selected**: Pre-installed on almost all Unix-like platforms. It automates compilation flags, cross-compilation matrix builds, and code formatter runs.
- **Phase 1 Required**: Yes.
- **Status**: Required Now.
- **Recommendation**: Keep.
- **Pros**: Pre-installed on most build hosts, simple syntax, dependency-based execution routing.
- **Cons**: Tab-sensitive syntax, syntax differences between GNU Make on Linux and BSD Make on macOS.
- **Future Replacement**: Taskfile, if YAML-based build automation is preferred.

---

## 16. pnpm
- **Role**: Package manager for frontend assets.
- **Why Selected**: Uses a shared content-addressable store to optimize disk space, provides fast installation speeds, and supports monorepos natively.
- **Phase 1 Required**: No.
- **Status**: Optional.
- **Recommendation**: Remove (not needed since React frontend is delayed/removed from MVP).
- **Pros**: Fast install times, saves disk space via hard linking, built-in monorepo workspace support.
- **Cons**: Minor compatibility issues with packages that rely on nested `node_modules` structures.
- **Future Replacement**: Bun.

---

## 17. GitHub Actions
- **Role**: Automation pipeline (CI/CD) and automated release compiler.
- **Why Selected**: Direct integration with the project's GitHub repository. It automates testing, code linting, security audits, and compilation matrix builds across all target OS architectures.
- **Phase 1 Required**: Yes.
- **Status**: Required Now.
- **Recommendation**: Keep.
- **Pros**: Deep integration with GitHub, free for open-source repositories, massive ecosystem of pre-built actions.
- **Cons**: Build runners can suffer from resource bottlenecks, causing execution delays.
- **Future Replacement**: None planned.
