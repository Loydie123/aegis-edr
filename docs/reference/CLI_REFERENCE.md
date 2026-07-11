# 💻 AEGIS EDR - Command Line Interface (CLI) Reference

This document is the definitive CLI reference guide for the `aegis` administration client. The interface is designed to follow modern, POSIX-compliant CLI patterns similar to `kubectl`, `docker`, and `trivy`.

---

## 📖 Table of Contents
1. [Global Flags](#1-global-flags)
2. [Command Reference](#2-command-reference)
   - [aegis status](#aegis-status)
   - [aegis scan](#aegis-scan)
   - [aegis monitor](#aegis-monitor)
   - [aegis rule](#aegis-rule)
   - [aegis response](#aegis-response)
   - [aegis forensics](#aegis-forensics)
   - [aegis config](#aegis-config)
3. [JSON Output Schemas](#3-json-output-schemas)
4. [System Exit Codes](#4-system-exit-codes)
5. [Piping & Command Chain Examples](#5-piping--command-chain-examples)

---

## 1. Global Flags

These flags are supported across all `aegis` commands:

- `--config <path>`: Specifies a custom configuration file path. Default: `/etc/aegis/aegis.yaml` (Linux/macOS) or `C:\ProgramData\Aegis\config\aegis.yaml` (Windows).
- `--socket <path_or_pipe>`: Direct override path for the daemon gRPC Unix socket or Named Pipe. Default: `/var/run/aegis.sock` or `\\.\pipe\aegis`.
- `-f, --format <table|json|csv|yaml>`: Target output serialization format. Default: `table`.
- `-v, --verbose`: Enables verbose debug messages on command execution.
- `-h, --help`: Displays help messages for the target command.

---

## 2. Command Reference

### `aegis status`
Retrieves agent health metrics, telemetry status, loaded rules counts, and local database size details.

#### Syntax
```bash
aegis status [flags]
```

#### Flags
- None.

#### Example Output (Table Format)
```text
AEGIS AGENT STATUS
=======================================
Daemon Status : RUNNING
Agent ID      : agent-node-01
Version       : v1.0.0-Beta
Profile       : Forensic
Uptime        : 4h 12m 30s
CPU Usage     : 1.2%
RAM Footprint : 76.4 MB
Rules Loaded  : 1,245 (YARA: 800, Sigma: 445)
Database Size : 142.5 MB
Telemetry     : PROCESS [OK]  FILE [OK]  NET [OK]  USB [OK]
```

---

### `aegis scan`
Runs immediate static scans (YARA rules, hashes check) against files and folders.

#### Syntax
```bash
aegis scan [path] [flags]
```

#### Flags
- `-r, --recursive`: Recursively scan directories.
- `--rules-dir <path>`: Override the default YARA rules folder path.
- `--output <path>`: Saves the scan report directly to a file.

#### Examples
```bash
# Scan a directory recursively and save results to a JSON file
aegis scan /var/www/html --recursive --format json --output /tmp/web_scan.json
```

---

### `aegis monitor`
Streams normalized telemetry events or launches the interactive terminal dashboard (TUI).

#### Syntax
```bash
aegis monitor [flags]
```

#### Flags
- `-i, --interactive`: Launches the terminal user interface dashboard (TUI).
- `--filter <event_type>`: Filter streamed events (e.g. `process`, `file`, `network`, `usb`).
- `--limit <number>`: Limit streamed stdout rows.

#### Examples
```bash
# Stream network events in JSON format
aegis monitor --filter network --format json

# Launch TUI dashboard
aegis monitor --interactive
```

---

### `aegis rule`
Manages YARA and Sigma rules compiled within the EDR detection loop.

#### Syntax
```bash
aegis rule [subcommand] [flags]
```

#### Subcommands
- `list`: Displays all rules loaded in memory.
- `add <rule_path>`: Compiles and registers new rules.
- `validate <rule_path>`: Verifies rule syntax before loading.

#### Flags
- `--type <yara|sigma>`: Filters rules list by engine type.

#### Examples
```bash
# List all active Sigma rules
aegis rule list --type sigma

# Validate a new YARA rule syntax
aegis rule validate ./custom_rule.yar
```

---

### `aegis response`
Manages host containment and active mitigation playbooks.

#### Syntax
```bash
aegis response [action] [flags]
```

#### Actions
- `kill`: Terminates target process trees recursively.
- `suspend`: Suspends active processes.
- `isolate`: Blocks host network communication.
- `quarantine`: Encrypts and relocates target files.
- `rollback`: Reverses containment actions.

#### Flags
- `--pid <number>`: Target process ID. Required for `kill` and `suspend`.
- `--file <path>`: Target file path. Required for `quarantine`.
- `--ip <cidr>`: Threat IP address (used to exclude console connections).
- `--token <id>`: Action authorization token. Required when safety overrides are requested.

#### Examples
```bash
# Terminate process tree 1045
aegis response kill --pid 1045

# Isolate the host from network interfaces
aegis response isolate

# Reverse host network isolation
aegis response rollback --action isolate
```

---

### `aegis forensics`
Acquires target evidence logs and compiles chronological threat timelines.

#### Syntax
```bash
aegis forensics [subcommand] [flags]
```

#### Subcommands
- `timeline`: Aggregates telemetry records chronologically.
- `collect`: Copies OS artifacts (Prefetch, shell history, plists) to a zip archive.

#### Flags
- `-d, --duration <duration>`: Time range for timeline reports (e.g. `1h`, `12h`, `2d`). Default: `1h`.
- `--output-zip <path>`: Output destination path for the collected zip bundle.

#### Examples
```bash
# Compile a markdown timeline of events for the last 6 hours
aegis forensics timeline --duration 6h --format markdown

# Collect system artifacts and export them to a forensic zip package
aegis forensics collect --output-zip /tmp/evidence.zip
```

---

### `aegis config`
Manages runtime configuration settings.

#### Syntax
```bash
aegis config [action] [key] [value] [flags]
```

#### Actions
- `get <key>`: Queries active configuration key value.
- `set <key> <value>`: Updates configuration values.

#### Examples
```bash
# Query the active storage retention policy
aegis config get storage.retention_days

# Enable auto-mitigation rules on the agent
aegis config set response.auto_mitigation true
```

---

## 3. JSON Output Schemas

JSON outputs are structured to integrate with SIEM pipelines and automated parsers:

### Example `aegis status` Output
```json
{
  "timestamp": "2026-07-11T09:08:54Z",
  "status": "success",
  "data": {
    "agent_id": "agent-node-01",
    "daemon_status": "RUNNING",
    "version": "v1.0.0-Beta",
    "profile": "Forensic",
    "resource_usage": {
      "cpu_percent": 1.2,
      "ram_bytes": 80111222
    },
    "rules": {
      "yara_count": 800,
      "sigma_count": 445
    }
  }
}
```

### Example `aegis scan` Alert Output
```json
{
  "timestamp": "2026-07-11T09:08:54Z",
  "status": "threat_detected",
  "results": {
    "file_path": "/tmp/webshell.php",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "detections": [
      {
        "engine": "YARA",
        "rule_name": "SUSP_PHP_Webshell",
        "risk_score": 9.2,
        "mitre_id": "T1505.003"
      }
    ]
  }
}
```

---

## 4. System Exit Codes

Exit codes are standardized to facilitate automation:

| Code | Label | Description |
|---|---|---|
| **0** | `SUCCESS` | Operation completed without errors or alerts. |
| **1** | `ERROR_GENERAL` | General command-line syntax failure or database error. |
| **2** | `THREAT_DETECTED` | Telemetry scan matched YARA/Sigma rules (Alert state). |
| **3** | `CONTAINMENT_EXECUTED` | Response action was executed successfully. |
| **4** | `CONNECTION_FAILED` | CLI client was unable to connect to the daemon socket. |
| **5** | `INVALID_AUTH` | Token authentication failed or permission was denied. |

---

## 5. Piping & Command Chain Examples

Use standard utilities like `jq` to parse `aegis` JSON streams:

### Extract alerts with a risk score greater than 8.0:
```bash
aegis monitor --filter network --format json | jq 'select(.data.risk_score > 8.0)'
```

### Automate containment of high-risk processes:
```bash
# Query the live monitor, filter for high-risk alerts, and kill the process tree automatically
aegis monitor --filter process --format json | jq -r 'select(.data.risk_score >= 9.0) | .data.pid' | while read pid; do
    aegis response kill --pid "$pid"
done
```
