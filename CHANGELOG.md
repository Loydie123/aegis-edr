# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-Beta] - 2026-07-11

### Added
- Privileged background EDR daemon service (`aegisd`) for system-wide auditing.
- User space administrative CLI client (`aegis`) with Cobra framework subcommands.
- Local gRPC IPC channel utilizing Unix Domain Sockets on Linux/macOS and Windows Named Pipes.
- Platform Abstraction Layer (PAL) with Windows ETW, Linux eBPF, and macOS ESF hooks.
- Local telemetry database using SQLite in WAL mode with indexes on high-frequency metadata.
- Structured logging configuration utilizing the Zap library for zero-allocation JSON logs.
- Technical documentation framework outlining system design, databases, rule engines, APIs, and roadmap.
