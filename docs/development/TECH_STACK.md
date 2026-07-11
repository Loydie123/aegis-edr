# 🛠️ AEGIS EDR - Technology Stack Decision Records

This document catalogs the technologies chosen for the AEGIS EDR platform. For each component, it details the selection rationale, evaluates trade-offs, reviews alternatives, and provides quick implementation examples.

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
- **Alternatives**:
  - **Rust**: Higher memory safety and zero garbage collection overhead. However, it suffers from a steeper learning curve and slower build compilation rates.
  - **C++**: Low-level control but introduces significant memory leak risks and buffer overflow vulnerabilities that malware could exploit to compromise the agent.
- **Pros**: Fast build times, simple concurrency model, stable standard library, garbage collection with target limit controls (`GOMEMLIMIT`).
- **Cons**: GC execution can introduce microsecond latency spikes; C-go boundary crossings (e.g., calling YARA libraries) add minor memory overhead.
- **Future Replacement**: Rust, if absolute real-time guarantee without GC is required in later production phases.
- **Example Usage**:
  ```go
  package main
  import "fmt"

  func main() {
      fmt.Println("AEGIS Agent Initialized")
  }
  ```

---

## 2. C / Assembly
- **Role**: High-speed, unmanaged routines (e.g., block entropy calculation).
- **Why Selected**: Direct access to hardware instructions (e.g., SSE/AVX registers) enables highly optimized math operations, such as calculating Shannon Entropy for file segments.
- **Alternatives**: Inline Go code (significantly slower due to compiler safety boundary checks on slices).
- **Pros**: Direct control over hardware registers, zero instruction overhead, maximum loop efficiency.
- **Cons**: Difficult to maintain, lacks type safety, breaks direct Go cross-compilation workflows unless managed carefully with cgo and assembly files.
- **Future Replacement**: Intrinsics or native assembly routines compiled directly inside Go.
- **Example Usage (Shannon Entropy in C)**:
  ```c
  #include <math.h>
  double calculate_entropy(const unsigned char *data, int len) {
      int count[256] = {0};
      for (int i = 0; i < len; ++i) count[data[i]]++;
      double entropy = 0.0;
      for (int i = 0; i < 256; ++i) {
          if (count[i] > 0) {
              double p = (double)count[i] / len;
              entropy -= p * log2(p);
          }
      }
      return entropy;
  }
  ```

---

## 3. Cobra (CLI Framework)
- **Role**: Subcommand parser and flag coordinator.
- **Why Selected**: De-facto industry standard for CLI applications in the Go ecosystem (used by Kubernetes and Docker). It handles subcommand routing, auto-generates help screens, and binds configuration flags seamlessly.
- **Alternatives**: Custom flag parser (harder to maintain), `urfave/cli` (excellent but lacks Cobra's nested subcommand structure).
- **Pros**: Built-in shell auto-completion generator, POSIX-compliant flag parsing, nested subcommand support.
- **Cons**: Relatively heavy codebase size for simple, single-command utility applications.
- **Future Replacement**: None planned.
- **Example Usage**:
  ```go
  var rootCmd = &cobra.Command{
      Use:   "aegis",
      Short: "AEGIS EDR Agent CLI",
      Run: func(cmd *cobra.Command, args []string) {
          cmd.Help()
      },
  }
  ```

---

## 4. Bubbletea (TUI Framework)
- **Role**: Controls interactive monitoring views on the terminal.
- **Why Selected**: Implementing the Elm architecture in Go, it enables reactive, beautiful, and component-driven terminal user interfaces (TUIs) without direct management of raw terminal escape codes.
- **Alternatives**: `termbox-go` (lower level, requires manual redraw loops), `tview` (solid, but more static and less customizable).
- **Pros**: Reactive component rendering, built-in support for tables, progress bars, and forms, clean state management.
- **Cons**: High cognitive load during design phase due to nested state updates.
- **Future Replacement**: Custom thin TUI renderer if binary size constraints become critical.
- **Example Usage**:
  ```go
  type model struct {
      events []string
  }
  func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
      // Process TUI events
      return m, nil
  }
  ```

---

## 5. React / Tailwind / TypeScript
- **Role**: Admin console UI stack (Fleet Dashboard).
- **Why Selected**: React has a mature ecosystem of charting libraries (Recharts) and table grids. Tailwind enables rapid UI construction, and TypeScript guarantees type safety for fleet state payloads.
- **Alternatives**: Vue.js (good but has a smaller component ecosystem), Vanilla HTML/JS (difficult to scale for complex dashboards).
- **Pros**: Fast component renders, consistent UI styling via Tailwind classes, robust client-state validation.
- **Cons**: Requires a compilation build step (Vite/Next.js) and increases package build complexity.
- **Future Replacement**: Svelte, if client bundle size optimization becomes a primary target.
- **Example Usage**:
  ```tsx
  import React from 'react';
  export const AlertCard = ({ title, score }: { title: string, score: number }) => (
    <div className="p-4 bg-red-950/20 border border-red-500 rounded-lg">
      <h3 className="text-red-500 font-bold">{title}</h3>
      <p className="text-sm">Risk Score: {score}</p>
    </div>
  );
  ```

---

## 6. SQLite 3
- **Role**: Persistent local database store for event logs and configuration profiles.
- **Why Selected**: Self-contained, serverless database that supports full SQL syntax, transactions, and index creation. It is highly optimized for local read-heavy operations when configured in Write-Ahead Log (WAL) mode.
- **Alternatives**:
  - **PostgreSQL**: Requires running a separate database server daemon on the endpoint, which is unacceptable for an EDR agent.
  - **Flat Files / JSON Logs**: Reading and filtering chronological events via flat files is inefficient and cannot support quick timeline generation queries.
- **Pros**: Zero service configuration, single-file database, transactions support, WAL mode for concurrent reads/writes.
- **Cons**: Database file writes block under heavy concurrent write operations if not handled using dedicated write-queues.
- **Future Replacement**: DuckDB, if columnar, analytic aggregations on telemetry are required.
- **Example Usage**:
  ```go
  db, err := sql.Open("sqlite3", "file:telemetry.db?_journal_mode=WAL")
  if err != nil {
      log.Fatal(err)
  }
  defer db.Close()
  ```

---

## 7. BadgerDB
- **Role**: Key-Value LSM-Tree log cache.
- **Why Selected**: Pure Go implementation of a Log-Structured Merge (LSM) database. It is optimized for high-throughput write streams, serving as a staging database for incoming raw event bursts.
- **Alternatives**: LevelDB (requires C bindings), RocksDB (C++ codebase, complex compilation wrapper).
- **Pros**: High-throughput write performance, zero external C library dependencies, built-in key compression.
- **Cons**: High memory utilization during write compaction loops.
- **Future Replacement**: Pebble (developed by CockroachDB team), if more stable memory usage profiles are needed under high load.
- **Example Usage**:
  ```go
  opts := badger.DefaultOptions("/var/lib/aegis/badger")
  db, err := badger.Open(opts)
  if err != nil {
      log.Fatal(err)
  }
  defer db.Close()
  ```

---

## 8. libyara (YARA Engine)
- **Role**: Static and memory signature matching.
- **Why Selected**: Industry-standard signature scanning tool. It compiles rules to bytecode and scans raw files or process memory spaces with high efficiency.
- **Alternatives**: Custom string search engines (too slow and lack support for standardized YARA syntax).
- **Pros**: Standardized rule format used by threat researchers, fast multi-pattern string matching, regex engine support.
- **Cons**: Uses C-go bindings which add compilation complexity and minor execution overhead.
- **Future Replacement**: YARA-Rust compiled to WebAssembly (WASM) or a pure-Go YARA implementation.
- **Example Usage**:
  ```c
  #include <yara.h>
  int scan_file(const char* filepath, YR_RULES* rules) {
      return yr_rules_scan_file(rules, filepath, 0, callback_func, NULL, 0);
  }
  ```

---

## 9. Sigma Go Parser
- **Role**: Behavioral rule parser and stream engine.
- **Why Selected**: Sigma rules represent behavioral threats in an OS-independent format. A native Go parser enables streaming event evaluation without external Python runtimes.
- **Alternatives**: Converting Sigma to SQL queries (adds telemetry lookup delays and lacks real-time streaming capability).
- **Pros**: Pure Go, evaluates rules in-memory, supports standard Sigma YAML format.
- **Cons**: Stateful rule evaluation (e.g., event A followed by event B) requires custom timing windows and consumes memory.
- **Future Replacement**: Custom stream-processing correlation engines.
- **Example Usage (Sigma rule evaluation logic)**:
  ```go
  func MatchEvent(event map[string]interface{}, rule SigmaRule) bool {
      // Run field evaluation logic
      return event["CommandLine"] == "powershell.exe"
  }
  ```

---

## 10. gRPC / Protobuf
- **Role**: Local IPC (between `aegis` and `aegisd`) and agent-to-fleet communications.
- **Why Selected**: Strongly-typed schema definitions, low CPU serialization overhead, built-in support for streaming APIs, and secure TLS validation out-of-the-box.
- **Alternatives**: JSON over HTTP (high serialization overhead, lacks strong schemas), WebSockets (good for streaming but lacks built-in RPC routing).
- **Pros**: Small payload sizes, code generator support for multiple target languages, bidirectional streaming.
- **Cons**: Payloads are binary and cannot be debugged easily with text-only network sniffers.
- **Future Replacement**: Cap'n Proto, if zero-copy serialization becomes necessary for high-throughput pipelines.
- **Example Usage**:
  ```protobuf
  service AegisService {
    rpc GetStatus(StatusRequest) returns (StatusResponse);
  }
  ```

---

## 11. Zap (Logging Library)
- **Role**: Structured logging handler.
- **Why Selected**: Designed for zero heap allocations in critical code paths, Zap is the fastest structured logger in Go, preventing logging statements from introducing latency spikes.
- **Alternatives**: standard library `log` (lacks JSON formatting), `logrus` (high CPU and allocation overhead).
- **Pros**: Fastest Go structured logger, supports both structured JSON and speed-optimized logs.
- **Cons**: Verbose syntax compared to standard library loggers.
- **Future Replacement**: Standard library `slog` (introduced in Go 1.21), to reduce external package dependencies.
- **Example Usage**:
  ```go
  logger, _ := zap.NewProduction()
  defer logger.Sync()
  logger.Info("Ingest pipeline started", zap.Int("workers", 8))
  ```

---

## 12. Viper (Configuration Parser)
- **Role**: Ingests configuration files, environment variables, and CLI overrides.
- **Why Selected**: Cobra integration out-of-the-box. It parses configuration variables from YAML files, OS environment variables, and CLI flag overrides seamlessly.
- **Alternatives**: Standard library `flag` and `encoding/json` (requires manual mapping code).
- **Pros**: Automatic environment variable mapping, supports multiple file formats (JSON, TOML, YAML), binds flags to config values directly.
- **Cons**: Large dependency footprint.
- **Future Replacement**: Clean, lightweight custom YAML parser if dependency management requires minimal imports.
- **Example Usage**:
  ```go
  viper.SetConfigName("aegis")
  viper.AddConfigPath("/etc/aegis/")
  viper.AutomaticEnv()
  viper.ReadInConfig()
  ```

---

## 13. Go Templates
- **Role**: Compiles forensic timelines and compliance reports.
- **Why Selected**: Part of the standard library, it provides a safe, injection-resistant engine for rendering dynamic text structures (Markdown, CSV, HTML).
- **Alternatives**: Third-party template engines (e.g. Mustache/Handlebars, which increase binary size).
- **Pros**: Standard library component, safe against template-injection bugs, fast render speeds.
- **Cons**: Syntax can be difficult to read and debug for complex nested layouts.
- **Future Replacement**: None planned.
- **Example Usage**:
  ```go
  tmpl := template.Must(template.New("report").Parse("Alert Match: {{.RuleName}}"))
  tmpl.Execute(os.Stdout, alertInstance)
  ```

---

## 14. Wasmtime (WebAssembly SDK)
- **Role**: Runs sandboxed SDK plugins.
- **Why Selected**: Wasmtime provides a highly secure, memory-isolated, JIT-compiled execution environment for WebAssembly (WASM) binaries on multiple CPU architectures.
- **Alternatives**:
  - **Go Plugins**: Lacks sandbox isolation (crashes in the plugin will crash the main daemon) and requires strict compiler version matching.
  - **gRPC Sidecars**: High communication overhead compared to running in-process WASM modules.
- **Pros**: Strictly sandboxed execution, memory isolation, support for multiple source languages (Rust, Go, C).
- **Cons**: High initial footprint size, overhead when passing large data structures across the WASM boundary.
- **Future Replacement**: Wazero, a pure Go WebAssembly runtime, to eliminate C-go dependencies.
- **Example Usage**:
  ```go
  engine := wasmtime.NewEngine()
  store := wasmtime.NewStore(engine)
  module, _ := wasmtime.NewModuleFromFile(engine, "plugin.wasm")
  ```

---

## 15. GNU Make
- **Role**: Build pipeline coordination.
- **Why Selected**: Pre-installed on almost all Unix-like platforms. It automates compilation flags, cross-compilation matrix builds, and code formatter runs.
- **Alternatives**: Bazel (powerful but complex setup), Taskfile (YAML based, but requires separate installation step).
- **Pros**: Pre-installed on most build hosts, simple syntax, dependency-based execution routing.
- **Cons**: Tab-sensitive syntax, syntax differences between GNU Make on Linux and BSD Make on macOS.
- **Future Replacement**: Taskfile, if YAML-based build automation is preferred.
- **Example Usage**:
  ```makefile
  build:
  	go build -o bin/aegis cmd/aegis/main.go
  ```

---

## 16. pnpm
- **Role**: Package manager for frontend assets.
- **Why Selected**: Uses a shared content-addressable store to optimize disk space, provides fast installation speeds, and supports monorepos natively.
- **Alternatives**: npm (slow, lacks workspace management features), yarn (heavy footprint).
- **Pros**: Fast install times, saves disk space via hard linking, built-in monorepo workspace support.
- **Cons**: Minor compatibility issues with packages that rely on nested `node_modules` structures.
- **Future Replacement**: Bun, if inline JS/TS runtime compilation is integrated.
- **Example Usage**:
  ```bash
  pnpm install
  pnpm --filter dashboard run dev
  ```

---

## 17. GitHub Actions
- **Role**: Automation pipeline (CI/CD) and automated release compiler.
- **Why Selected**: Direct integration with the project's GitHub repository. It automates testing, code linting, security audits, and compilation matrix builds across all target OS architectures.
- **Alternatives**: GitLab CI (requires hosting separate runners), Jenkins (high maintenance overhead).
- **Pros**: Deep integration with GitHub, free for open-source repositories, massive ecosystem of pre-built actions.
- **Cons**: Build runners can suffer from resource bottlenecks, causing execution delays.
- **Future Replacement**: None planned.
- **Example Usage (CI Workflow Segment)**:
  ```yaml
  jobs:
    test:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - name: Set up Go
          uses: actions/setup-go@v5
          with:
            go-version: '1.22'
        - run: go test -v ./...
  ```
