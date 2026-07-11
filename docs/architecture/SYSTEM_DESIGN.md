# ⚙️ AEGIS EDR - Low-Level System Design & Concurrency Model
*Target Audience: Senior Go Engineers, Systems Architects, Infrastructure Engineers*

This document defines the technical design, concurrent data structures, threading strategies, and failure modes of the AEGIS EDR agent daemon (`aegisd`). It details how the system achieves sub-second detection and containment while operating within a strict CPU and memory budget.

---

## 1. Concurrency & Threading Strategy

AEGIS uses Go's runtime scheduler to run telemetry capture and rule evaluation in parallel. To maintain a CPU footprint below 2% and prevent garbage collection (GC) pauses from causing telemetry loss, several runtime tuning and optimization patterns are implemented:

```
                  +-----------------------------------------+
                  |            OS Kernel Probes             |
                  |          (eBPF, ETW, ESF Rings)         |
                  +--------------------+--------------------+
                                       | Ring Buffer read
                                       v
                  +-----------------------------------------+
                  |         Pinned OS Threads (M)           |
                  |          (Lockless Ingestion)           |
                  +--------------------+--------------------+
                                       | channel push
                                       v
+--------------------------------------v------------------------------------+
|                             Go Runtime (G)                                |
|                                                                           |
|   +--------------------------+          +-----------------------------+   |
|   |    sync.Pool Recycler    |          |      Worker Goroutines      |   |
|   |  (Reduces GC Allocations) |          |   (YARA, Sigma, Heuristics) |   |
|   +--------------------------+          +-----------------------------+   |
+---------------------------------------------------------------------------+
```

### 1.1 OS Thread Pinning (`runtime.LockOSThread`)
- **Ingress Loops**: Goroutines reading raw events from eBPF ring buffers or Windows ETW sessions invoke `runtime.LockOSThread()`. This pins the execution context to a dedicated OS thread (M), minimizing scheduling jitter and avoiding context-switch overhead during high network or process activity.
- **C-go Boundaries (YARA)**: Since YARA is written in C, calling YARA matching engines involves C-go crossings. Because C-go executes on a pinned OS thread, AEGIS manages a dedicated pool of OS threads specifically for YARA tasks to prevent blocking the primary Go scheduler.

### 1.2 Garbage Collection & Memory Management
- **Zero-Allocation Pipeline**: Event structs are recycled using a global `sync.Pool` to avoid heap allocations and subsequent GC sweeps.
- **Escape Analysis Guardrails**: Pointers are passed down the pipeline using pass-by-value or pooled wrappers, preventing data from escaping to the heap.
- **GOGC Tuning**: The daemon initializes with `GOGC=50` and `GOMEMLIMIT=120MiB` limits. This tells the runtime to garbage collect aggressively if memory approaches the footprint limit, ensuring memory safety on constrained hosts.

---

## 2. The Queue System & Event Bus

AEGIS routes normalized events using a custom ring buffer that supports backpressure handling and event triaging.

```
                  +----------------------------+
                  |       Normalized Event     |
                  +--------------+-------------+
                                 |
                                 v
+--------------------------------+--------------------------------+
|                   Ingest Queue (Ring Buffer)                    |
|                                                                 |
|   [Event A] -> [Event B] -> [Event C] -> [Event D] -> [...]     |
|                                                                 |
|   * High Watermark (80% Capacity): Triage Mode Enabled          |
|   * Critical Limit (100% Capacity): Drop Low-Priority Events    |
+--------------------------------+--------------------------------+
                                 |
                                 v
+--------------------------------+--------------------------------+
|                           Event Bus                            |
|                 (Thread-Safe Fan-Out Dispatcher)                |
|                                                                 |
|         +-----------------+-----------------+-----------------+ |
|         |                 |                 |                 | |
|         v                 v                 v                 v |
|     Sub: YARA         Sub: Sigma        Sub: Forensics    Sub: DB   |
+-----------------------------------------------------------------+
```

### 2.1 The Ingest Queue
The primary queue is implemented as a thread-safe, lock-free ring buffer:
- **Struct Representation**:
  ```go
  type IngestQueue struct {
      buffer    []*eventrouter.Event
      capacity  uint32
      writeIdx  uint32
      readIdx   uint32
      gatekeeper sync.Cond
  }
  ```
- **Watermark Thresholds**:
  - **High Watermark (80% capacity)**: The queue enters `Triage Mode`. The normalizer starts dropping verbose read-only events (e.g., directory traversals, registry reads).
  - **Critical Limit (100% capacity)**: To prevent blocking kernel hooks, the queue drops incoming events that do not carry execution flags (`execve`, process creation, raw socket writes). Diagnostic counters track dropped events: `aegis_dropped_events_total`.

### 2.2 The Fan-Out Event Bus
Events are dispatched to detection sub-systems via a thread-safe, pub-sub Event Bus. Subscribers register channels to receive filtered subsets of the event stream (e.g., the YARA engine subscribes only to process starts and file write events).

---

## 3. Worker Pool Architecture

The Worker Pool manages parallel rule execution, isolating tasks to prevent crashes in one engine from affecting other telemetry processors.

```
                      +-----------------------------+
                      |         Event Bus           |
                      +--------------+--------------+
                                     |
                                     v
+------------------------------------+--------------------------------------+
|                         Worker Coordinator                                |
|                                                                           |
|   +------------------+     +------------------+     +------------------+  |
|   | Worker 1 (Sigma) |     | Worker 2 (Heur.) |     | Worker 3 (YARA)  |  |
|   |  - local context |     |  - local context |     |  - Cgo boundary  |  |
|   +------------------+     +------------------+     +------------------+  |
|                                                                           |
|   * Task timeout enforced via context.WithTimeout                         |
+---------------------------------------------------------------------------+
```

### 3.1 Task Dispatching & Lifecycle
- **Worker Workers**: A dispatcher goroutine reads events from the Event Bus and routes them to idle worker goroutines.
- **Context-Bound Lifetime**: Every task execution is wrapped in a Go `context.Context` containing a strict timeout limit:
  ```go
  ctx, cancel := context.WithTimeout(parentCtx, 50*time.Millisecond)
  defer cancel()
  ```
  If a rule evaluation hangs (e.g., an expensive regex search in YARA), the context cancels the worker, reclaiming the execution thread and logging a diagnostic warning.

### 3.2 Thread-Pool Sizing
The pool size is calculated dynamically at runtime:
\[N_{\text{workers}} = \max\left(2, \text{NumCPU} - 1\right)\]
This leaves at least one CPU core free for OS telemetry kernel processing loops and administrative CLI requests, preventing agent operations from degrading host system responsiveness.

---

## 4. Ingress & Monitoring Pipelines

OS-native events are normalized and ingested through a structured pipeline:

```
[Target Kernel API]
        |
        v (Raw Binary Payload)
[Platform Telemetry Monitor (PAL)]
        |
        v (Raw Event Struct)
[Event Router (eventrouter)]
        |
        v (Validate Field Types & Parse UTC Timestamp)
[Normalized AEF Struct (ECS Format)]
        |
        v (Push to Ring Buffer)
[Ingest Queue]
```

### 4.1 Ingress Flow Details
1. **Low-level Ingest**: OS-specific monitoring packages retrieve raw event logs.
2. **Platform Translation**: The PAL package parses these logs into Go structs, converting OS-specific identifiers (e.g., Windows SIDs, macOS UIDs) into string variables.
3. **ECS Normalization**: The `eventrouter` maps parameters to unified keys.
4. **Validation**: The normalizer validates timestamps, parses command arguments, and hashes target binaries.
5. **Enqueue**: The normalized event is pushed to the `IngestQueue`.

---

## 5. Detection Engine Pipeline

The detection pipeline coordinates signature scans, behavioral matching, and heuristics scoring:

```
                         +-----------------------------+
                         |       Event Ingestion       |
                         +--------------+--------------+
                                        |
                                        v
                         +-----------------------------+
                         |       Reputation Lock       |
                         |     (Quick Hash Lookup)     |
                         +--------------+--------------+
                                        | Cache Miss
                                        v
                         +-----------------------------+
                         |      Worker Coordinator     |
                         +-------+--------------+------+
                                 |              |
                +----------------+              +----------------+
                v                                                v
+---------------+---------------+                +---------------+---------------+
|       YARA Engine (Static)    |                |       Sigma Engine (Streams)  |
|  - Cgo worker execution pool  |                |  - In-memory state correlation|
+---------------+---------------+                +---------------+---------------+
                |                                                |
                +----------------+              +----------------+
                                 v              v
                         +-----------------------------+
                         |      Scoring Evaluator      |
                         |   (Compound calculation)    |
                         +-----------------------------+
```

### 5.1 C-go Management (YARA)
To prevent blocking Go scheduler threads during long YARA scans, the YARA engine runs scans inside isolated OS threads, passing results back to the Go runtime via non-blocking channels.

### 5.2 Sigma Stateful Matching
The behavioral engine correlates telemetry events in memory:
- Matches events chronologically against rules with multi-event conditions (e.g., Process A writes file B, then Process C executes file B).
- Tracks event history using an in-memory sliding window cache, discarding events once they fall outside the rule's time boundary.

---

## 6. Response & Orchestration Pipeline

Containment actions run securely through a controlled execution loop:

```
[aegis CLI command]
        |
        v (gRPC request via Unix Socket / Named Pipe)
[aegisd gRPC Server]
        |
        v (Authenticate caller & Validate parameters)
[Request Authenticator]
        |
        v (Validate target PID is not a system protector)
[Safety Shield]
        |
        v (Invoke OS-native containment APIs)
[Response Action Controller]
```

### 6.1 Containment Execution Loop
1. **gRPC Ingest**: The daemon receives a containment request via the local IPC socket.
2. **Authentication**: The daemon verifies client permissions against the socket's owner credentials.
3. **Safety Verification**: The Safety Shield checks if the target PID is a protected system process (e.g., `systemd` or `wininit.exe`), rejecting requests to terminate critical OS components.
4. **Execution**: The containment action runs via platform-specific APIs.
5. **Logging**: The action is recorded to the local SQLite audit log.

---

## 7. Scheduler & Daemon Maintenance tasks

`aegisd` implements a lightweight, low-overhead scheduling loop to coordinate background maintenance tasks:

```go
type ScheduledTask struct {
    Interval time.Duration
    TaskName string
    RunFunc  func(ctx context.Context) error
}
```

The scheduler runs on a single goroutine using standard Go timers (`time.Ticker`).

### 7.1 Background Tasks
- **Heartbeat (Every 30 seconds)**: Sends health metrics (CPU usage, memory footprint, event counts) to the central management console.
- **Database Maintenance (Every 24 hours)**: Deletes telemetry logs older than 7 days and vacuums the database files:
  ```sql
  DELETE FROM processes WHERE launched_at < datetime('now', '-7 days');
  VACUUM;
  ```
- **Rule Reload check (Every 5 minutes)**: Scans rule folders for new configuration changes, recompiling YARA and Sigma rules dynamically without restarting the daemon.

---

## 8. Robust Error Handling & Resiliency Model

AEGIS is designed to handle failure states gracefully, protecting endpoint security and stability.

### 8.1 Panic Recovery Guardrails
Crucial monitoring loops are protected by panic recovery blocks:
```go
func SafeWorkerLoop() {
    defer func() {
        if r := recover(); r != nil {
            log.Error("Recovered from panic in worker loop", "error", r, "stack", string(debug.Stack()))
            // Trigger auto-restart routine
            go SafeWorkerLoop()
        }
    }()
    // Core loop execution
}
```
If a panic occurs inside a rule parser or detection engine, the goroutine logs a stack trace, registers a diagnostic metric, and restarts the loop safely.

### 8.2 Graceful Shutdown Flow
When receiving termination signals (`SIGTERM`, `SIGINT`, Windows Service Stop):
1. **Stop Telemetry Capture**: Closes active handles to ETW sessions, eBPF probes, and ESF clients to prevent kernel memory leaks.
2. **Drain Ring Buffer**: Allows active workers to finish processing queued events (with a maximum timeout of 3 seconds).
3. **Close Databases**: Commits WAL logs and closes database files safely to prevent corruption.
4. **Exit Daemon**: The service daemon exits gracefully, returning code `0`.
