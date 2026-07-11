# 🔌 AEGIS EDR - WebAssembly Plugin SDK & Lifecycle Architecture

This document details the plugin subsystem architecture, SDK specifications, lifecycle states, sandbox boundaries, and security verification models of AEGIS EDR.

---

## 1. WebAssembly (WASM) Sandbox Architecture

To prevent third-party extensions from compromising EDR agent stability, AEGIS uses a WebAssembly (WASM) sandbox architecture:
- **Sandbox Container**: Plugins are compiled to WebAssembly bytecode and execute within a guest sandbox managed by the **Wasmtime** runtime.
- **In-Process Memory Isolation**: The guest WASM plugin cannot access the parent Go process's heap or run arbitrary system calls unless explicitly permitted via host export functions.
- **Resource Constraints**: Each plugin runs with strict bounds on memory allocations (default: 16MB) and execution CPU limits (WASM fuel tracking), preventing resource starvation issues.

```
+---------------------------------------------------------------------------------+
|                                 AEGIS DAEMON                                    |
|                                                                                 |
|  +--------------------+        +--------------------+                           |
|  |    Event Router    | =====> |  Telemetry Event   |                           |
|  +--------------------+        +---------+----------+                           |
|                                          |                                      |
|                                          v                                      |
|  +---------------------------------------v-----------------------------------+  |
|  |                          Wasmtime Guest Sandbox                           |  |
|  |                                                                           |  |
|  |   +---------------------+  +--------------------+  +-------------------+  |  |
|  |   |  Memory Constraint  |  |  CPU Fuel Limits   |  | Signed Public Key |  |  |
|  |   |    (Max 16MB)       |  |  (Anti-Infinite)   |  |   (Validation)    |  |  |
|  |   +---------------------+  +--------------------+  +-------------------+  |  |
|  |                                                                           |  |
|  |                          Third-Party WASM Plugin                          |  |
|  |                         (Custom parsing logic)                            |  |
|  +---------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------+
```

---

## 2. Plugin SDK Design

The SDK supports compiling plugins from multiple languages (Go/TinyGo, Rust, and C/C++) to standard WASM targets.

### 2.1 Interface Definitions (TinyGo Example)
Plugins implement the following export interfaces defined in the SDK library:
```go
package main

//export aegis_plugin_init
func Init() int32 {
    // Initialization setup
    return 0 // Success
}

//export aegis_on_process_create
func OnProcessCreate(eventPtr uint32, eventLen uint32) int32 {
    // Telemetry inspection hook logic
    return 0
}
```

---

## 3. Plugin Lifecycle Model

The daemon orchestrates plugin execution states securely:

```
[Discovery] ---> [Crypto Sign Check] ---> [Instantiate VM] ---> [Init Hook]
                                                                     |
                                                                     v
[Shutdown] <--- [Unregister Hooks]  <--- [Execution Loop] <--- [Register Event]
```

1. **Discovery**: The daemon scans the plugin folder (`/var/lib/aegis/plugins/` or `C:\ProgramData\Aegis\Plugins\`) for `.wasm` files.
2. **Signature Verification**: Validates file hashes and digital signatures against the trusted public keys store. Unsigned plugins are rejected.
3. **VM Instantiation**: Initializes a Wasmtime runtime engine instance for the verified plugin.
4. **Execution Initialization**: Calls the guest `aegis_plugin_init` function to establish hooks.
5. **Event Loop Hook**: The event router forwards telemetry events to registered hooks.
6. **Graceful Shutdown**: When stopping, the daemon calls `aegis_plugin_shutdown` to allow plugins to clean up states and flush diagnostic logs.

---

## 4. Plugin Interfaces & Protobuf Contracts

Communications across the host-guest boundary use Protobuf serialization:

```protobuf
syntax = "proto3";
package aegis.plugin.v1;

// Host-to-Guest call payloads
message ProcessEventPayload {
  int32 pid = 1;
  string binary_path = 2;
  string cmdline = 3;
  string username = 4;
}

// Guest-to-Host inspection returns
message HookDecision {
  bool block_action = 1;
  double score_override = 2;
  string log_message = 3;
}
```

---

## 5. Extension Points Map

Plugins can register hooks at specific stages of the ingestion and evaluation pipeline:

| Hook Hooking Point | Input Event Type | Capability | Use Case |
|---|---|---|---|
| `PreNormalize` | Raw OS byte blocks | Modify raw log parameters | Custom event parsing |
| `PostNormalize` | Standard ECS structs | Inspect normalized events | Contextual enrichment |
| `PreMitigation` | High-risk alert maps | Block or override actions | Custom response rules |
| `AlertRouter` | Outbound alerts | Route alerts to destinations | Custom SIEM connectors |

---

## 6. Security Model & API Permissions

To prevent malicious or compromised plugins from accessing host systems, plugins run with **Zero-Trust defaults**:
- **No Direct System Calls**: Plugins cannot call OS filesystem, network socket, or process APIs.
- **Host Exports Gateway**: Interactions must go through host export functions, which enforce strict permission checks:
  ```go
  //go:wasmimport aegis_host log_message
  func HostLogMessage(ptr uint32, len uint32)
  ```
- **Permission Manifests**: Plugins must provide a manifest file declaring required capability permissions:
  ```yaml
  plugin_id: "http-parser-plugin"
  permissions:
    allow_network_read: false
    allow_host_logging: true
    max_memory_pages: 256
  ```

---

## 7. Future Plugin Marketplace Integration

A future phase will support a central plugin registry:
- **Registry API**: Search, retrieve metadata, and download verified plugins.
- **Secure Hash Verification**: The daemon checks downloaded plugins against registry hash signatures before loading them on endpoints.
