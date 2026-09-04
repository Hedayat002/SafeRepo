# ROADMAP.md — SafeRepo

---

## Overview

| Phase | Goal | Status |
|-------|------|--------|
| Phase 00 | Project Definition and Architecture | Completed |
| Phase 01 | Application Foundation | Completed |
| Phase 02 | Safe Repository Acquisition | Completed |
| Phase 03 | Semgrep Integration | Completed |
| Phase 04 | Dependency Vulnerability Scanning | Completed (Awaiting Approval) |
| Phase 05 | Secret Scanning | Not Started (Next Phase) |
| Phase 06 | Unified Scan Engine | Not Started |
| Phase 07 | Security Dashboard | Not Started |
| Phase 08 | Production Hardening | Not Started |
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

- Rate limiting
- Monitoring and logging
- Error handling
- Performance tuning
- Security audit

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
