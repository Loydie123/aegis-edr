# 🌐 AEGIS EDR - Threat Intelligence & Correlation Subsystem

This document details the threat intelligence architecture, local IOC database schema, STIX/TAXII ingestion pipelines, MITRE ATT&CK mapping frameworks, and multi-indicator correlation engines of AEGIS.

---

## 1. High-Level Threat Intelligence Architecture

The Threat Intelligence subsystem manages external threat feeds, stores indicators of compromise (IOCs) locally, and correlates them with real-time system events.

```
+-----------------------------------------------------------------------------------+
|                            External Threat Feeds                                  |
|   +--------------------------+  +--------------------------+  +----------------+  |
|   |    TAXII 2.1 Server      |  |    Custom JSON Feeds     |  | MISP API Ports |  |
|   |  (STIX IOC collections)  |  |  (Domain reputation lists|  | (Hash feeds)   |  |
|   +------------+-------------+  +------------+-------------+  +---------+----------+  |
+----------------|-----------------------------|--------------------------|-------------+
                 |                             |                          |
                 +-----------------------------+--------------------------+
                                               | mTLS Sync Pull
                                               v
+---------------------------------------------------------------------------------------+
|                                    AEGIS DAEMON                                       |
|                                                                                       |
|  +--------------------+      +--------------------+      +-------------------------+  |
|  |    TAXII Client    | ===> |   STIX/IOC Parser  | ===> |    Local IOC Database   |  |
|  | (Collection Poller)|      | (Normalizes schema)|      | (SQLite Reputation db)  |  |
|  +--------------------+      +--------------------+      +------------+------------+  |
|                                                                       |               |
|                                                                       v               |
|  +--------------------+      +--------------------+      +------------+------------+  |
|  |  Containment Engine | <=== | Correlation Router | <=== | Ingress Telemetry Stream|  |
|  | (Block IPS/Hashes) |      | (Matches IOC keys) |      |   (ECS normalized)      |  |
|  +--------------------+      +--------------------+      +-------------------------+  |
+---------------------------------------------------------------------------------------+
```

---

## 2. In-Memory IOC & Reputation Database (SQLite Cache)

AEGIS keeps a local cache of threat indicators in a read-optimized SQLite database (`reputation.db`) to enable sub-millisecond lookups during event ingestion:

```
+------------------------------------+
|            IOC_REPUTATION          |
+------------------------------------+
| ioc_value    : TEXT (PK / Indexed) |
| ioc_type     : TEXT NOT NULL       | -- 'sha256', 'domain', 'ipv4', 'registry'
| threat_actor : TEXT                |
| mitre_tactic : TEXT                |
| severity     : REAL NOT NULL       |
| updated_at   : TIMESTAMP           |
+------------------------------------+
```

### 2.1 Database Operations
- **Index Optimization**: B-Tree indexing is applied to the `ioc_value` field, enabling fast matching on process hashes or target network IPs.
- **Cache Eviction**: Records are assigned an expiration timestamp. A background database vacuum loop removes expired IOCs daily to control disk utilization.

---

## 3. STIX/TAXII Ingestion Subsystem

This subsystem connects to threat sharing servers (e.g., MISP, Anomali, or custom intel pools) to fetch structured threat intelligence.

```
                  +-----------------------------------------+
                  |           TAXII Client Poller           |
                  +--------------------+--------------------+
                                       |
                                       +----> 1. Request Collections (Discovery API)
                                       |
                                       +----> 2. Poll Objects (STIX 2.1 JSON Payload)
                                       v
                  +-----------------------------------------+
                  |         STIX 2.1 Deserializer           |
                  +--------------------+--------------------+
                                       |
                                       +----> Extract: Hash, Domain, IP, Registry Key
                                       v
                  +-----------------------------------------+
                  |           SQLite Reputation DB          |
                  +-----------------------------------------+
```

- **TAXII Client**: Implements Discovery, Collection, and Poll APIs to communicate with TAXII 2.1 servers.
- **STIX 2.1 Parser**: Deserializes STIX 2.1 JSON schemas into Go data models.
- **Indicator Extraction**: Identifies threat indicators (e.g., file hashes, malicious domains, C2 IP addresses) and registers them in the local reputation cache.

---

## 4. Threat Feeds & Synchronization Engine

The sync engine manages configuration updates and handles network limits:
- **mTLS Transport**: Connects to feeds securely using mutual TLS (mTLS) with pinned client certificates.
- **Update Scheduling**: Ingests updates during off-peak hours using staggered intervals to prevent network congestion.
- **Rate-Limiting**: Limits bandwidth usage dynamically to ensure EDR sync tasks do not consume network resources needed by production applications.

---

## 5. MITRE ATT&CK Mapping Subsystem

The MITRE ATT&CK mapping subsystem tags security events with standardized tactic and technique identifiers:

```
+----------------------------------------------------------------------------------+
|                              Rule Definition (YAML)                              |
|                                                                                  |
|   title: PowerShell Remote Download                                              |
|   mitre_attack:                                                                  |
|     - tactic: TA0002 (Execution)                                                 |
|     - technique: T1059.001 (PowerShell)                                          |
+----------------------------------------+-----------------------------------------+
                                         |
                                         v
+----------------------------------------+-----------------------------------------+
|                               Event Normalizer                                   |
|                                                                                  |
|   - Maps event to ECS telemetry structure                                        |
|   - Appends MITRE ATT&CK metadata tags to generated alert                        |
+----------------------------------------------------------------------------------+
```

- **Rule Metadata**: YARA, Sigma, and heuristic rules include tags matching MITRE ATT&CK technique IDs (e.g., `T1059.001`).
- **Telemetry Enrichment**: When a rule triggers, the engine appends these ATT&CK mappings to the alert output. This simplifies threat triage for security analysts.

---

## 6. Multi-Indicator Threat Correlation Engine

The Correlation Engine matches telemetry events against multiple indicators to detect complex attack patterns:

```
                   +---------------------------------------+
                   |          ECS Normalized Event         |
                   +-------------------+-------------------+
                                       |
                   +-------------------+-------------------+
                   |          Extract Search Keys          |
                   |       (Hash, IP, Domain, Path)        |
                   +-------------------+-------------------+
                                       |
                   +-------------------+-------------------+
                   |         Correlation Router            |
                   +------+------------+------------+------+
                          |            |            |
                          v            v            v
                   +------+----+  +----+------+  +--+------+
                   | Hash DB   |  | Domain DB |  | IP DB   |
                   | Lookup    |  | Lookup    |  | Lookup  |
                   +------+----+  +----+------+  +--+------+
                          |            |            |
                          +------------+------------+
                                       | Matches?
                                       v
                   +-------------------+-------------------+
                   |          Alert Dispatcher             |
                   |   (Risk score calculation update)     |
                   +---------------------------------------+
```

- **Extract Search Keys**: Extracts search fields (hash, domain, destination IP, registry path) from incoming events.
- **Database Lookup**: Queries the SQLite reputation tables for matches.
- **Risk Score Update**: If a match is found, the engine updates the event's risk score based on the threat indicator's severity level.
