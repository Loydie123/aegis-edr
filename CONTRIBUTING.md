# 🤝 Contributing to AEGIS EDR

First off, thank you for taking the time to contribute! Contributions from the cybersecurity and open-source communities make AEGIS a stronger, more resilient security platform.

Please review the guidelines below to ensure a smooth contribution process.

---

## 📖 Table of Contents
1. [Code of Conduct](#-code-of-conduct)
2. [How Can I Contribute?](#-how-can-i-contribute)
3. [Development Environment Setup](#-development-environment-setup)
4. [Coding Standards & Architecture](#-coding-standards--architecture)
5. [Git Branching Strategy](#-git-branching-strategy)
6. [Conventional Commits](#-conventional-commits)
7. [Pull Request (PR) Submission Guidelines](#-pull-request-pr-submission-guidelines)

---

## 📜 Code of Conduct
By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any violations or inappropriate behavior to the project team at `security@aegis-edr.org`.

---

## 💡 How Can I Contribute?
- **Report Bugs**: Open a GitHub issue describing the bug, steps to reproduce, and environment details. (For security vulnerabilities, see our [Security Policy](SECURITY.md)).
- **Suggest Features**: Open an issue detailing the requested capability and use cases.
- **Submit PRs**: Resolve open bugs or implement roadmap tasks and submit a pull request.

---

## 🛠️ Development Environment Setup

Ensure you have the following tools installed on your host system:
- **Go**: Version 1.22 or higher.
- **GNU Make**: To run build automation tasks.
- **golangci-lint**: The static analysis tool for checking code layout rules.
- **pnpm**: Node package manager (only required if modifying the fleet console).

### Quick Build Verification
```bash
# 1. Clone the repository
git clone https://github.com/aegis-edr/aegis.git
cd aegis

# 2. Ingest dependencies
go mod tidy

# 3. Compile client and service daemon binaries
make build-all

# 4. Execute the unit testing suite
make test
```

---

## 📐 Coding Standards & Architecture
We follow strict software engineering paradigms to keep the codebase maintainable and secure:
- **Clean & Hexagonal Architecture**: Core logic must remain separate from OS-specific monitoring libraries. Place OS-dependent code strictly under `pkg/monitor/platform/`.
- **SOLID Principles**: Use small interfaces, avoid raw global state, and employ dependency injection.
- **Domain-Driven Design (DDD)**: Group code by bounded contexts. Do not share raw DB pointers between domains.
- **Test Coverage**: Keep coverage above **85%** for core logic packages. Write unit tests with mock interfaces.

---

## 🌿 Git Branching Strategy
We use a Git Flow model to manage versions:
- `main`: Reflects the production-ready release state.
- `develop`: The primary integration branch. All features must merge here.
- `feature/<name>`: Short-lived branches for new feature development.
- `bugfix/<issue_id>`: Dedicated branches for bug fixes.

---

## 💬 Conventional Commits
All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
```
<type>(<scope>): <description>
```
### Types:
- `feat`: Introduces a new feature.
- `fix`: Fixes a bug.
- `docs`: Modifies documentation.
- `refactor`: Restructures code without changing behavior.
- `perf`: Optimizes execution speeds.
- `test`: Adds or updates tests.
- `ci`: Configures build runners.

*Example:* `feat(monitor): add support for USB VID/PID parsing under Linux`

---

## 🚀 Pull Request (PR) Submission Guidelines

1. **Update Backlog**: Ensure there is an open issue in [TASKS.md](docs/planning/TASKS.md) associated with your PR.
2. **Lint & Format**: Your code must pass lint checks and follow standard formatting:
   ```bash
   make lint
   ```
3. **Write Tests**: Ensure unit and integration tests are added for your modifications.
4. **Documentation**: Update API, CLI, or architecture manuals if your PR alters system configurations.
5. **PR Review**: Open a PR pointing to the `develop` branch. PRs require approval from at least two Code Owners before merging.
