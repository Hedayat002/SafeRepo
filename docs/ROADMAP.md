# ROADMAP.md — SafeRepo

---

## Overview

| Phase | Goal | Status |
|-------|------|--------|
| Phase 00 | Project Definition and Architecture | Completed |
| Phase 01 | Application Foundation | Completed |
| Phase 02 | Safe Repository Acquisition | Completed |
| Phase 03 | Semgrep Integration | Completed |
| Phase 04 | Dependency Vulnerability Scanning | Completed |
| Phase 05 | Secret Scanning | Completed |
| Phase 06 | Unified Scan Engine | Completed |
| Phase 07 | Security Dashboard | Completed |
| Phase 08 | Production Hardening | Completed |
| Phase 09 | Deployment and Beta Infrastructure | Completed (`4a74682`) |
| Phase 10 | 100-User Beta Testing | In Progress (Step 1 Complete) |

---

## Phase 00 — Project Definition and Architecture (NO CODE)

- [ ] Validate vision, requirements, architecture
- [ ] Identify risks + mitigations (top 5)
- [ ] Finalize documentation suite
- [ ] Populate .ai/ memory files
- [ ] Deliver Phase 00 Report
- **Owner:** AI Lead + You  **Gate:** Your approval

---

## Phase 01 — Application Foundation

- Next.js scaffold, TypeScript, Tailwind CSS
- Authentication (GitHub App)
- MongoDB connection (Mongoose)
- Basic routing and project structure
- Tests for foundation

---

## Phase 02 — Safe Repository Acquisition

- Clone/download untrusted repositories safely
- Repository size and depth limits
- Temporary workspace management
- Cleanup procedures

---

## Phase 03 — Semgrep Integration

- Docker-isolated Semgrep execution
- Parse and normalize Semgrep findings
- Store results in MongoDB

---

## Phase 04 — Dependency Vulnerability Scanning

- Trivy integration
- OSV API integration
- npm audit integration
- pip-audit integration (where applicable)
- Normalize dependency findings

---

## Phase 05 — Secret Scanning

- Gitleaks integration (Docker-isolated)
- Secret value redaction
- Store redacted findings only

---

## Phase 06 — Unified Scan Engine

- Orchestrate all scanners
- Ecosystem detection (Node.js, Python)
- Result normalization and deduplication
- Scan status tracking (queued → scanning → completed/failed)

---

## Phase 07 — Security Dashboard

- User-facing findings display
- Severity classification and filtering
- Per-scan and per-repository views
- Remediation guidance

---

## Phase 08 — Production Hardening

- [x] Scan retention policy & TTL cleanup (`cleanupExpiredScans`)
- [x] Per-user scan cap enforcement (`MAX_SCANS_PER_USER = 500`)
- [x] Scan deletion API (`DELETE /api/v1/scans/:id`) with cascade finding deletion
- [x] Scan cancellation API (`POST /api/v1/scans/:id/cancel`)
- [x] Worker heartbeat cancellation detection and graceful abort
- [x] Enhanced health endpoint (`GET /api/health` with version, queue depth, uptime)
- [x] Request ID and structured request logging middleware with header redaction
- [x] Content-Security-Policy & security header hardening
- [x] Findings API rate limiting (100 req/min/user)
- [x] CI dependency audit gate (`npm audit --omit=dev --audit-level=high`)
- [x] Error response security audit (no information leakage)
- [x] Comprehensive documentation (`SECURITY.md`, `TESTING.md`, `PHASE_08.md`)

---

## Phase 09 — Deployment and Beta Infrastructure

**Status:** Completed (`4a74682` / `origin/main`)

### Implementation Steps & Status:
- [x] **Step 1: Web Standalone Containerization** — `apps/web/Dockerfile`, `apps/web/next.config.mjs`, `.dockerignore` (Accepted)
- [x] **Step 2: Scan Worker Containerization** — `apps/web/Dockerfile.worker`, non-root `workeruser`, minimal tools (Accepted)
- [x] **Step 3: Production Compose Orchestration** — `docker-compose.prod.yml`, Docker proxy security boundary (Approved)
- [x] **Step 4: Pre-Flight Environment Validator** — `scripts/validate-production.ts`, 49 static checks (Accepted)
- [x] **Step 5: Production Docker Image Builds** — `saferepo-web:0.9.0`, `saferepo-worker:0.9.0` (Accepted)
- [x] **Step 6: Scanner Image Pre-Caching** — `scripts/preload-scanners.ps1`, `scripts/preload-scanners.sh` (Accepted)
- [x] **Step 7: Production HTTP Smoke Test Suite** — `scripts/smoke-test.ts`, 23 live/infra checks (Accepted)
- [x] **Step 8: Production Operations Runbook & Documentation** — `docs/DEPLOYMENT_RUNBOOK.md` (Accepted)
- [x] **Step 9: Full Quality Gates & Wrap-Up** — 506 tests regression suite (100% PASS), lint, typecheck, audit, production validation (49/49 PASS), committed and pushed (Accepted)

---

## Phase 10 — 100-User Beta Testing

**Status:** In Progress (Step 1 Complete; Awaiting Step 1 Review)

### Implementation Steps & Status:
- [x] **Step 1: Beta Documentation & Runbook** — Authored `docs/BETA/BETA_TEST_PLAN.md`, `COHORT_ROLLOUT_LOG.md`, `SECURITY_AUDIT_LOG.md`, `DEFECT_TRACKER.md`, `FINAL_READINESS_REPORT.md` (Complete)
- [ ] **Step 2: Beta Environment Setup & Host Provisioning** — Server preparation per `DEPLOYMENT_RUNBOOK.md` (Pending)
- [ ] **Step 3: Cohort 1 Execution (Internal Canary)** — 1 to 5 maintainers, benchmark & synthetic fixtures (Pending)
- [ ] **Step 4: Cohort 2 Execution (Small External Cohort)** — 10 to 25 developers, multi-ecosystem public repositories (Pending)
- [ ] **Step 5: Cohort 3 Execution (Expanded Cohort)** — 25 to 50 users, concurrency & queue stress testing (Pending)
- [ ] **Step 6: Cohort 4 Execution (Full Beta Cohort)** — Up to 100 users, sustained multi-day operational workload (Pending)
- [ ] **Step 7: Defect Remediation & Regression Testing** — Full regression on any discovered defects (Pending)
- [ ] **Step 8: Final Exit Assessment & Operational Readiness Report** — Final closeout report for GA approval (Pending)

---

## Phase Gate Rule

Each phase follows:

```
PLAN → IMPLEMENT → TEST → DOCUMENT → REVIEW → STOP → HUMAN APPROVAL → NEXT PHASE
```

Do not skip phases or automatically continue to the next phase without explicit human approval.

---

## Architecture Principle

SafeRepo must be fully functional in a local Docker-based environment.

Deployment platform is secondary. The product must remain functional independently of any specific hosting provider.

---

## Database

- **Local:** MongoDB 7 (Docker)
- **Production:** MongoDB Atlas
- **ODM:** Mongoose

Not approved for MVP: PostgreSQL, Prisma, Redis.
