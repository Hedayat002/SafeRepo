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
| Phase 08 | Production Hardening | Implemented (Awaiting Human Approval) |
| Phase 09 | Deployment and Beta Infrastructure | Not Started |
| Phase 10 | 100-User Beta Testing | Not Started |

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

Objectives:

- Validate the complete production architecture
- Determine appropriate hosting for the web/API layer
- Determine appropriate hosting for the scanner service
- Verify MongoDB Atlas configuration
- Verify GitHub integration
- Verify secure secret management
- Verify scanner isolation in production
- Estimate expected infrastructure cost
- Evaluate free-tier feasibility
- Decide whether Vercel is appropriate for the web/API layer (option, not mandatory)
- Decide where the scanner service should run
- Prepare the 100-user beta environment

Code must be pushed to GitHub before any remote deployment.

Do not deploy anything during this phase without human approval.

---

## Phase 10 — 100-User Beta Testing

- Real-world testing with ~100 beta users
- Feedback collection and iteration
- Bug fixes and polish

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
