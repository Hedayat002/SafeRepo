# ADR-003 — Start with Modular Monolith

**Status:** Accepted  **Date:** 2026-08-07

---

## Context
Team = 1 + AI, MVP small. Microservices add deployment complexity.

## Decision
Single **Fastify monolith** with clear modules (auth, files, shares, audit). Each module owns its routes/services/tests.

## Consequences
- + Fast to ship, simple deploy, single DB
- - Must respect module boundaries to allow future split
- Trigger to split: >5 devs or perf bottleneck proven

## Alternatives
| Option | Why Not Now |
|--------|-------------|
| Microservices | Overkill for MVP, slower |

## Follow-up
- Enforce module imports via ESLint boundaries
