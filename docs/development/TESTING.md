# 🧪 AEGIS EDR - Testing Strategy & Standards

This document outlines the testing methodology, validation guidelines, profiling procedures, and coverage requirements for the AEGIS EDR codebase.

---

## 📖 Table of Contents
1. [Overview & Testing Strategy](#1-overview--testing-strategy)
2. [Unit Testing Guidelines](#2-unit-testing-guidelines)
3. [Integration Testing Framework](#3-integration-testing-framework)
4. [End-to-End (E2E) Testing in Sandboxes](#4-end-to-end-e2e-testing-in-sandboxes)
5. [Benchmark & Performance Profiling](#5-benchmark--performance-profiling)
6. [Load & Stress Testing](#6-load--stress-testing)
7. [Fuzz Testing Specifications](#7-fuzz-testing-specifications)
8. [Code Coverage & CI Enforcement](#8-code-coverage--ci-enforcement)

---

## 1. Overview & Testing Strategy

Because EDR agents run with high system privileges, testing must verify both threat detection efficacy and endpoint stability. The AEGIS testing matrix spans four validation layers:

```
+-------------------------------------------------------------+
|               End-to-End (E2E) Threat Simulation            |
|         (Executes benign shellcode and tests containment)   |
|      +-----------------------------------------------+      |
|      |               Integration Tests               |      |
|      |    (Verifies gRPC sockets and DB transactions) |      |
|      |      +---------------------------------+      |      |
|      |                   Unit Tests                   |      |
|      |        (Verifies parsing and rule logic)       |      |
|      +-----------------------------------------------+      |
+-------------------------------------------------------------+
```

---

## 2. Unit Testing Guidelines

Unit tests verify the logic of isolated packages without initiating actual system calls or opening disk files:
- **Parallel Execution**: Unit tests must run concurrently by invoking `t.Parallel()` at the start of each test.
- **Mock Interfaces**: OS telemetry APIs and database wrappers are mocked using interfaces:
  ```go
  // Mock the SQLite repository to isolate logic during unit testing
  type MockStorage struct {
      OnSaveProcess func(p *processes.Process) error
  }
  ```
- **Execution Command**:
  ```bash
  go test -v -short ./...
  ```

---

## 3. Integration Testing Framework

Integration tests verify interactions between database repositories, rule compilers, configuration overrides, and gRPC endpoints:
- **Local DB Transactions**: Verifies SQLite execution in WAL mode, database migrations, and telemetry ingestion loops.
- **IPC Connectivity**: Spins up the background daemon on a temporary Unix socket or Named Pipe and validates gRPC payloads issued by the CLI client.
- **Execution Command**:
  ```bash
  go test -v -run=Integration ./...
  ```

---

## 4. End-to-End (E2E) Testing in Sandboxes

E2E tests verify EDR agent behavior by executing simulated attacks in virtualized test environments:
- **Sandbox Isolation**: Tests run in isolated environments (e.g., Docker containers for Linux, Windows Sandbox VMs).
- **Benign Threat Vectors**: Test scripts trigger simulated attacks (e.g., spawning shell scripts from mock document folders, issuing unexpected connection requests).
- **Containment Verification**: The test framework verifies that the agent correctly blocks threat vectors, terminates simulated process trees, and logs alerts to the database.

---

## 5. Benchmark & Performance Profiling

Benchmark tests profile the execution latency of critical path code:
- **Zero-Allocation Tracking**: Benchmarks track heap allocations per operation to prevent garbage collection bottlenecks:
  ```go
  func BenchmarkEventNormalization(b *testing.B) {
      for i := 0; i < b.N; i++ {
          NormalizeRawEvent(mockRawData)
      }
  }
  ```
- **CPU & Memory Profiling**: Profiling logs are exported to generate visual execution graphs (pprof):
  ```bash
  go test -bench=. -cpuprofile=cpu.pprof -memprofile=mem.pprof ./pkg/monitor/...
  ```

---

## 6. Load & Stress Testing

Load tests simulate heavy system event storms to verify queue stability and backpressure mechanisms:
- **Event Storm Ingestion**: Injects a high volume of telemetry events (e.g., 50,000 file writes/sec) into the normalizer queue.
- **Backpressure Verification**: Verifies that the queue correctly transitions to Triage Mode when the 80% watermark is crossed, dropping verbose logs while preserving critical process creation and network events.

---

## 7. Fuzz Testing Specifications

Fuzz tests verify the resilience of parsing libraries against malformed binary structures and rule files:
- **Parser Fuzzing**: Feeds random byte arrays to format parsers (PE, ELF, Mach-O) and rule compilers (YARA, Sigma) to identify memory leaks and panic vulnerabilities:
  ```go
  func FuzzPEHeaderParser(f *testing.F) {
      f.Add([]byte{0x4d, 0x5a, 0x00, 0x00}) // Add MZ header seed
      f.Fuzz(func(t *testing.T, data []byte) {
          ParsePEHeaders(data)
      })
  }
  ```
- **Execution Command**:
  ```bash
  go test -fuzz=FuzzPEHeaderParser ./pkg/detect/signature/...
  ```

---

## 8. Code Coverage & CI Enforcement

- **Coverage Thresholds**: Coverage metrics are tracked by target packages:
  - Core Detection Engines (`pkg/detect/`): **> 90%**
  - Event Normalization (`pkg/monitor/eventrouter/`): **> 85%**
  - Platform Abstraction Layer (`pkg/monitor/platform/`): **> 70%** (limited by OS-specific sandbox APIs)
- **CI Pipelines**: Pull Requests must meet coverage thresholds before they can be merged. Code coverage trends are verified during CI runs:
  ```bash
  go test -coverprofile=coverage.out ./...
  go tool cover -html=coverage.out -o coverage.html
  ```
