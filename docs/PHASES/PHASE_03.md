# Phase 03 — Semgrep Integration

**Status:** Not Started

---

## Objective

Implement static application security testing (SAST) using Semgrep running inside a hardened, network-isolated Docker container (Stage 1).
Phase 03 connects the safe repository acquisition from Phase 02 with the scanner execution pipeline, normalizes Semgrep JSON output into SafeRepo's unified findings schema, stores findings in MongoDB, computes scan severity summary statistics, ensures workspace cleanup, and provides the findings query API (`GET /api/v1/scans/:id/findings`).

---

## Prerequisites

- Phase 02 completed and approved ✅
- Local Docker daemon running
- Pinned Semgrep Docker image available (`semgrep/semgrep:1.100.0`)
- MongoDB 7 running locally via Docker Compose

---

## Approved Scope

### In Scope
- Mongoose `Finding` model (`findings` collection) per `DATABASE_DESIGN.md` with compound unique indexes
- Scanner Runner trusted boundary for Stage 1 Docker execution (`--network=none`, `--read-only`, tmpfs, caps dropped, non-root UID 1000, CPU/memory limits, timeouts)
- Curated offline Semgrep ruleset mounted as `/rules:ro` for `--network=none` execution
- Semgrep CLI runner, buffer limiter (10MB max stdout), and JSON output parser
- Unified findings normalizer with deterministic SHA-256 fingerprint generation
- Lifecycle progression: `queued` → `cloning` → `scanning` → `normalizing` → `completed` / `failed` / `timed_out`
- Scan summary aggregation (`total`, `critical`, `high`, `medium`, `low`, `info`)
- Ephemeral workspace cleanup on scan completion or failure
- API endpoint: `GET /api/v1/scans/:id/findings` with pagination and filtering (`severity`, `category`, `scanner`)
- Unit and integration tests for models, scanner runner, normalizer, and findings API

### Out of Scope
- Dependency vulnerability scanners — Trivy, OSV, npm audit, pip-audit (Phase 04)
- Secret scanning — Gitleaks (Phase 05)
- Unified multi-scanner orchestrator (Phase 06)
- Frontend dashboard visualization of findings (Phase 07)
- Production cloud deployment (Phase 09)

---

## Security Requirements

- **Stage 1 Container Isolation:**
  - `--network=none` (strictly no network access)
  - `--read-only` root filesystem
  - `--tmpfs /tmp:rw,noexec,nosuid,size=64m`
  - `--security-opt=no-new-privileges`
  - `--cap-drop=ALL`
  - `--user 1000:1000`
  - `--cpus=1`, `--memory=512m` (configurable up to 1024m), `--pids-limit=256`
  - `--rm` (automatic cleanup)
  - Read-only workspace bind mount: `-v <workspacePath>:/src:ro`
  - Read-only rules bind mount: `-v <rulesPath>:/rules:ro`
- **Docker Socket Security (Decision C2):** Docker daemon access isolated to trusted Scanner Runner; Docker socket is never mounted into scanner containers or web containers.
- **Untrusted Code Defense (NFR-03):** Scanned repository code is treated as untrusted data and is never executed.
- **Resource Protection:** Stdout buffer limit (10MB) and hard timeout (180s) with SIGKILL on container process tree.

---

## Review Criteria

- [ ] `Finding` model created and validated with compound indexes in MongoDB
- [ ] Curated offline Semgrep ruleset added and verified for `--network=none` execution
- [ ] `ScannerRunner` executes Semgrep in Docker with all Stage 1 security restrictions
- [ ] Semgrep raw JSON parsed and mapped to unified `Finding` schema
- [ ] Deterministic SHA-256 deduplication fingerprints generated
- [ ] Scan status transitions accurately (`queued` → `cloning` → `scanning` → `normalizing` → `completed` / `failed` / `timed_out`)
- [ ] Severity summary counts (`total`, `critical`, `high`, `medium`, `low`, `info`) updated in `Scan`
- [ ] Ephemeral workspace cleaned up after scan execution
- [ ] `GET /api/v1/scans/:id/findings` returns filtered, paginated findings with strict multi-tenant authorization
- [ ] All unit and integration tests pass with ≥ 80% line coverage on new code
- [ ] Lint, typecheck, and build pass cleanly with 0 errors
