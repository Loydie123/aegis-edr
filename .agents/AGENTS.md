# AEGIS AI Agent Rules

## Project Philosophy

PROJECT_SPECIFICATION.md is the single source of truth.

Never contradict it.

Never remove existing features.

Never simplify the architecture.

Never make assumptions without documentation.

When uncertain, ask before implementing.

---

## Development Workflow

Always follow this workflow.

1. Read PROJECT_SPECIFICATION.md
2. Understand the current task
3. Check existing architecture
4. Propose changes
5. Wait for approval if architecture changes are required
6. Implement
7. Update documentation
8. Run tests
9. Verify formatting
10. Verify security

---

## Architecture Rules

The project must always follow:

- Clean Architecture
- SOLID
- Domain Driven Design
- Hexagonal Architecture
- Modular Design
- Dependency Injection
- Interface-first Development

Never violate these principles.

---

## Documentation Rules

Documentation comes before implementation.

Whenever functionality changes:

- Update documentation first.
- Then update implementation.

PROJECT_SPECIFICATION.md remains the source of truth.

---

## Coding Standards

Language:

Go

Requirements:

- Idiomatic Go
- Small packages
- Small interfaces
- Explicit errors
- No global state
- Context-aware APIs
- Thread-safe code
- High performance

---

## Security Rules

Security is the highest priority.

Never:

- Hardcode secrets
- Disable validation
- Ignore errors
- Ignore security warnings
- Introduce unnecessary dependencies

Always prefer secure defaults.

---

## Dependency Rules

Only introduce new dependencies when necessary.

Prefer:

- Go standard library
- Well-maintained libraries
- Minimal dependencies

---

## CLI Rules

The CLI is the primary interface.

Never redesign the CLI without approval.

Keep commands consistent.

Output should support:

- Human-readable
- JSON
- Quiet mode

---

## Performance Goals

Optimize for:

- Low memory usage
- Low CPU usage
- Fast startup
- Fast scanning
- High concurrency

Avoid premature optimization, but never introduce obvious bottlenecks.

---

## Git Rules

Never modify:

LICENSE

SECURITY.md

Without explicit approval.

Never rewrite Git history.

Never delete files unless requested.

---

## File Organization

Every package must have one responsibility.

Avoid circular dependencies.

Avoid giant packages.

Avoid giant files.

---

## Refactoring Rules

Never perform large refactors automatically.

Always explain architectural changes.

Always preserve backward compatibility unless instructed otherwise.

---

## Testing

Before considering any task complete:

- Build succeeds
- Tests pass
- Lint passes
- Formatting passes

---

## Communication Style

When responding:

- Explain reasoning briefly.
- Keep answers concise.
- Ask questions when requirements are unclear.
- Never assume missing requirements.

---

## Long-Term Vision

AEGIS is a CLI-first, enterprise-grade, open-source cyber defense platform.

Every implementation decision should support:

- Scalability
- Security
- Maintainability
- Extensibility
- Cross-platform compatibility

Always think long-term rather than implementing short-term fixes.