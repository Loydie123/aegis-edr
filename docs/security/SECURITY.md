# 📐 AEGIS EDR - Security Architecture & Threat Model

This document outlines the internal security controls, threat models, secure coding requirements, secrets management configurations, and supply chain security specifications for developers contributing to the AEGIS EDR agent.

---

## 1. Threat Model (STRIDE Framework)

Because the EDR service daemon runs with high privileges (`SYSTEM` / `root`), it is designed to mitigate attacks across the STRIDE threat spectrum:

### 1.1 Spoofing (Daemon Impersonation)
- **Threat**: A non-privileged local process attempts to impersonate the daemon or inject spoofed telemetry commands to the CLI.
- **Mitigation**: The local gRPC channel utilizes mutual TLS (mTLS) over Unix Domain Sockets (UDS) and Named Pipes. TLS certificates are generated dynamically at startup by the daemon.

### 1.2 Tampering (Rule and Database Modification)
- **Threat**: Local malware attempts to delete the event database (`telemetry.db`) or modify YARA rules to bypass detection.
- **Mitigation**: Standard filesystem ACL permissions (0600 on Unix, administrative-only ownership on Windows) restrict database folders and rules to the privileged EDR service account.

### 1.3 Repudiation (Audit Log Erasure)
- **Threat**: An administrator kills a critical process and deletes the local logs to deny the action.
- **Mitigation**: Administrative actions are written to a write-only, tamper-evident `audit_trail` table within the database, which is replicated to the Central Fleet Server in real-time.

### 1.4 Information Disclosure (Telemetry Snooping)
- **Threat**: Non-privileged users read raw event logs containing other users' system activities.
- **Mitigation**: Database files are locked down using OS-level permissions. Raw memory scanning segments are wiped from RAM using zero-allocation object pools once analyzed.

### 1.5 Denial of Service (Infinite Rule Loops)
- **Threat**: Maliciously crafted YARA rules or third-party plugins trigger infinite execution loops, consuming 100% CPU.
- **Mitigation**: YARA scans execute with strict thread execution timeouts. WebAssembly (WASM) plugins run in a guest VM with CPU fuel constraints enforced.

### 1.6 Elevation of Privilege (Buffer Overflows)
- **Threat**: Exploiting memory allocation vulnerabilities in the Cgo YARA compiler to execute arbitrary code as root.
- **Mitigation**: The core agent daemon is written in memory-safe Go. Cgo inputs undergo validation before cross-compiling, and all dynamically allocated C memory is freed immediately.

---

## 2. Secure Coding Guidelines

To prevent security regressions, contributors must adhere to these coding constraints:

- **No `unsafe` Pointers**: The use of the Go `unsafe` package is prohibited in core logic. Memory offsets must be parsed using standard slice validations.
- **Cgo Boundary Safety**: Raw bytes passed to C libraries (like `libyara`) must undergo explicit length bounds-checks.
- **Input Sanitization**: Process command arguments, registry paths, and API parameters must be sanitized using strict regex filters before database indexing or shell execution.

---

## 3. Secrets Management

- **DPAPI (Windows)**: Credentials and API tokens are encrypted using the Windows Data Protection API (DPAPI).
- **Keychain Services (macOS)**: API credentials are saved in the system Keychain.
- **Secret Service API / Keyring (Linux)**: Credentials are held in the encrypted kernel keyring.

---

## 4. Supply Chain Security

- **Software Bill of Materials (SBOM)**: Release pipelines compile CycloneDX-compliant JSON SBOM files detailing all library dependencies.
- **SLSA Level 3 Compliance**: Build pipelines run inside isolated runners. Generated binary checksum files are signed using **Cosign** to produce verifiable build provenance.

---

## 5. Code & Rule Signing

- **YARA/Sigma Signatures**: The daemon validates rule files using cryptographic hash signatures before compiling them.
- **Authenticode (Windows)**: Windows binary releases are signed using an Authenticode code-signing certificate.
- **Apple Notarization (macOS)**: macOS package releases are notarized using an Apple Developer ID.
