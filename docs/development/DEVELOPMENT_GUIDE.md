# 🛠️ AEGIS EDR - Software Engineering & Development Guide

This document defines the architectural principles, domain designs, coding standards, Git branching models, commit conventions, and pull request guidelines for the AEGIS EDR codebase.

---

## 📖 Table of Contents
1. [Core Architectural Frameworks](#1-core-architectural-frameworks)
   - [Clean Architecture & Hexagonal Structure](#clean-architecture--hexagonal-structure)
   - [Domain-Driven Design (DDD)](#domain-driven-design-ddd)
   - [SOLID Principles in Go](#solid-principles-in-go)
2. [Git Workflow & Branching Strategy](#2-git-workflow--branching-strategy)
3. [Conventional Commits Specification](#3-conventional-commits-specification)
4. [Pull Request & Code Review Standards](#4-pull-request--code-review-standards)
5. [Dependency Management & Tooling Guidelines](#5-dependency-management--tooling-guidelines)

---

## 1. Core Architectural Frameworks

### Clean Architecture & Hexagonal Structure
AEGIS separates core business rules from external frameworks (operating system APIs, database drivers, and network sockets). This isolation is achieved by mapping the codebase into concentric layers:

```
+-------------------------------------------------------------+
| Frameworks & Drivers (Windows ETW, Linux eBPF, SQLite WAL) |
|      +-----------------------------------------------+      |
|      |    Interface Adapters (gRPC Controllers, Repos) |      |
|      |      +---------------------------------+      |      |
|      |      |   Use Cases (ScanRunner, Monitor) |      |      |
|      |      |      +-------------------+      |      |      |
|      |      |      |  Entities (Event) |      |      |      |
|      |      |      +-------------------+      |      |      |
|      |      +---------------------------------+      |      |
|      +-----------------------------------------------+      |
+-------------------------------------------------------------+
```

- **Entities**: Contain the core data structures (e.g., the normalized event object). They must have zero dependencies on outer packages.
- **Use Cases**: Coordinate event evaluation and containment logic.
- **Adapters (Ports & Adapters)**:
  - *Ports (Interfaces)*: Interfaces defined in Go packages declaring required behaviors (e.g., `StorageRepository` or `ContainmentExecutor`).
  - *Adapters (Implementations)*: OS-specific drivers (WFP, eBPF) and database drivers (SQLite) that implement the defined port interfaces.

---

### Domain-Driven Design (DDD)
The monorepo separates domains into distinct bounded contexts:

- **Telemetry Monitor Context (`pkg/monitor/`)**: Responsible for system state inspection and event schema normalization.
- **Detection Context (`pkg/detect/`)**: Evaluates events against signatures, heuristics, and behavioral rules.
- **Remediation Context (`pkg/response/`)**: Orchestrates containment and rollback workflows.
- **Forensic Context (`pkg/forensics/`)**: Compiles event histories into timelines and collects system artifacts.

**AGGREGATE RULES**: Bounded contexts must communicate across boundaries strictly using value objects and normalized data structures (e.g., the Aegis Event Format). They must never share raw database handles or OS-specific contexts directly.

---

### SOLID Principles in Go
- **Single Responsibility (SRP)**: Group Go structs around specific capabilities (e.g., a `YaraScanner` should only compile rules and scan files; it should not handle alert routing or storage).
- **Open/Closed (OCP)**: Write functions to accept interfaces instead of concrete types, allowing developers to extend behavior without modifying existing code.
- **Liskov Substitution (LSP)**: Go struct compositions implementing interfaces must preserve method contracts (e.g., any `ContainmentExecutor` implementation must handle process suspension without changing the method signature).
- **Interface Segregation (ISP)**: Define small, focused interfaces rather than single wide interfaces:
  ```go
  // Good: Single-responsibility interfaces
  type Reader interface { Read() ([]byte, error) }
  type Writer interface { Write(p []byte) (int, error) }
  ```
- **Dependency Inversion (DIP)**: High-level modules must depend on interfaces, not concrete implementations. Struct fields must reference interfaces:
  ```go
  type DetectionService struct {
      storage StorageRepository // Interface dependency, NOT concrete SQLite handle
  }
  ```

---

## 2. Git Workflow & Branching Strategy

AEGIS uses a Git Flow branching model to manage releases:

```
[main]          ----------------------------* (Release v1.0.0 Tagged)
                                           /
[release-1.0]   ------------------*-------*
                                 /       /
[develop]       ---*------------*-------*
                    \          /
[feature/net]        *--------* (Feature merged via Squash PR)
```

- **`main`**: Reflects the active, production-ready release state. Only stable tags are merged here.
- **`develop`**: The primary integration branch. All feature branches branch off and merge back into `develop`.
- **`feature/<name>`**: Short-lived branches for feature development.
- **`bugfix/<issue_id>`**: Branches dedicated to bug fixes.
- **`hotfix/<version>`**: Critical patches branched directly from `main` and merged back to both `main` and `develop`.

---

## 3. Conventional Commits Specification

Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) format to enable automated changelog generation:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Supported Types:
- **`feat`**: Introduces a new feature to the codebase.
- **`fix`**: Fixes a bug in the application.
- **`docs`**: Modifies documentation only.
- **`style`**: Changes code style formatting without altering logic.
- **`refactor`**: Reorganizes code without fixing bugs or adding features.
- **`perf`**: Enhances execution performance.
- **`test`**: Adds or updates test files.
- **`ci`**: Updates build automation configurations (e.g. GitHub Actions).

### Examples:
```
feat(monitor): add support for USB VID/PID parsing under Linux
fix(detect): resolve memory leak on C-go YARA scan context close
docs(cli): update commands list in CLI reference manual
```

---

## 4. Pull Request & Code Review Standards

Pull Requests (PRs) must meet the following validation criteria before review:

1. **Compilation Checklist**: Code must compile cleanly across all target configurations:
   ```bash
   make build-all
   ```
2. **Lint Verification**: Code must pass the project's linting configuration without warnings:
   ```bash
   golangci-lint run ./...
   ```
3. **Test Coverage**: All package-level tests must pass, and changes must maintain or improve test coverage targets:
   ```bash
   make test
   ```
4. **Architectural Review**: Reviewers must verify that imports do not violate layered dependency boundaries (e.g., checking that `pkg/detect` does not import `pkg/monitor`).
5. **Approval Threshold**: Merging into the `develop` branch requires approval from at least two Code Owners.

---

## 5. Dependency Management & Tooling Guidelines

We manage dependencies strictly to maintain a secure and lightweight codebase:

- **Single Module**: Keep a single `go.mod` file at the root of the workspace.
- **Dependency Ingestion Policy**:
  - Run `go mod tidy` to clean up unused references before submitting PRs.
  - New dependency imports must undergo security auditing using `govulncheck` to verify they contain no open CVEs.
- **Vendor Constraints**: External C libraries (like `libyara`) must be pinned to specific release versions in build scripts.
- **pnpm Workspaces**: Frontend packages for the fleet console must be managed within pnpm workspaces, sharing a common lockfile.
