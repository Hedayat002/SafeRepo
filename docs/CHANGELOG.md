# Changelog — SafeRepo

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.10.0] - Unreleased (Phase 10 In Progress)

### Added - Phase 10: 100-User Beta Testing (Step 1)

- **Beta Test Plan & Operational Specification (`docs/BETA/BETA_TEST_PLAN.md`):**
  - Authored comprehensive beta operational master plan defining measurable evaluation objectives, staged 4-cohort rollout, and empirical measurement targets.
  - Formulated user journey matrix grounded strictly in implemented capabilities across authentication, scan initiation, polling, and triage (archive/upload explicit non-target).
  - Explicitly mapped full scanner architecture coverage: Semgrep SAST, Trivy SCA, Gitleaks, OSV batch client, npm audit, and pip-audit.
  - Documented strict separation between configured limits, observed metrics, and proposed targets.
  - Preserved Phase 09 CSP baseline (`script-src 'self' 'unsafe-inline'`) and defined 7 mandatory zero-tolerance security stop conditions.
- **Cohort Rollout Tracking Log (`docs/BETA/COHORT_ROLLOUT_LOG.md`):**
  - Established sequential entry/exit gating framework across Cohorts 1 to 4 with structured observation logs and human approval checkpoints.
- **Security & Invariant Audit Log (`docs/BETA/SECURITY_AUDIT_LOG.md`):**
  - Documented audit verification procedures for zero scanner network egress, host filesystem sandboxing, web Docker socket exclusion, Docker proxy API blocks, non-root containment, cross-user isolation, and secret redaction.
- **Defect & Issue Tracker (`docs/BETA/DEFECT_TRACKER.md`):**
  - Established 5-tier defect severity model (P0 Blocker to P4 Low), intake triage workflow, and active defect log.
- **Final Beta Readiness Report Framework (`docs/BETA/FINAL_READINESS_REPORT.md`):**
  - Authored reporting structure for empirical telemetry, security audit summaries, defect backlogs, and categorized GA exit criteria.

---

## [0.9.0] - 2026-09-20

### Added - Phase 09: Production Deployment & Beta Infrastructure

- **Production Operations Runbook (`docs/DEPLOYMENT_RUNBOOK.md`):**
  - Authored comprehensive operational manual for Ubuntu 24.04 LTS host provisioning, Docker Engine setup, UFW firewall configuration, and SSH hardening.
  - Documented secure server-side `.env.production` secret management and rotation procedures without repository leakage.
  - Documented MongoDB deployment choices (MongoDB Atlas vs self-hosted MongoDB 7 container) with backup and restore validation.
  - Documented GitHub App configuration, least-privilege repository permissions (`Contents: Read`, `Metadata: Read`), and callback routing.
  - Formulated deployment verification checklist, ordered 10-step startup procedure, and incident response runbooks.
- **Full Quality Gates & Wrap-Up (Step 9):**
  - Updated `apps/web/src/test/setup.ts` to respect configurable `process.env.MONGODB_URI` while preserving default localhost:27017 fallback, resolving host port conflicts with existing Windows services.
  - Executed full 506-test regression suite across 34 test files against temporary Docker MongoDB instance (`mongo:7.0.18-jammy`) on port 27018: 100% PASS (506/506 passed, 62.61s).
  - Verified zero `MongoMemoryServer` fallbacks and zero downloads from `fastdl.mongodb.org`.
  - Achieved 92.62% line coverage (statements: 92.62%, branches: 83.00%, functions: 93.95%), surpassing the 80% project threshold.
  - Verified full quality gates: `tsc --noEmit` (0 errors), `eslint .` (0 errors), Next.js 16 production build (clean pass), `npm audit --omit=dev --audit-level=high` (0 vulnerabilities), `scripts/validate-production.ts` (49/49 PASS), and `docker compose -f docker-compose.prod.yml config -q` (0 errors).
  - Committed and pushed to `origin/main` (`4a74682c3e9998bf916c891b7a66394cbbf8b19b`).

---

## [0.8.0] - 2026-09-08

### Added - Phase 08: Production Hardening

- **Scan Data Retention & Cleanup:**
  - Configurable `SCAN_RETENTION_DAYS` (default: 90 days) and `MAX_SCANS_PER_USER` (default: 500 scans).
  - Implemented `cleanupExpiredScans()` utility for automated pruning of terminal scans past retention TTL and enforcement of per-user scan caps.
  - Integrated retention cleanup into worker startup cycle and 24-hour periodic interval.
- **Scan Deletion API:**
  - `DELETE /api/v1/scans/:id` endpoint with user authorization, 409 in-progress rejection, rate limiting (10 req/min/user), and cascade finding deletion.
- **Scan Cancellation API:**
  - `POST /api/v1/scans/:id/cancel` endpoint supporting immediate transition of queued scans to failed and setting `cancelRequested: true` on in-progress scans.
  - Worker heartbeat loop checks `cancelRequested` flag and triggers graceful execution abort.
- **Enhanced Health Endpoint:**
  - Extended `GET /api/health` with `version`, `queue.pending` count, and process `uptime`.
- **Observability & Request Tracing:**
  - Added `withRequestLogging` middleware generating/propagating `X-Request-Id` UUID headers.
  - Redaction of sensitive headers (`authorization`, `cookie`, `token`) in request logs.
- **Security Hardening:**
  - Added strict `Content-Security-Policy` and verified standard security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, `Referrer-Policy`).
  - Added rate limiting to `GET /api/v1/scans/:id/findings` (100 req/min/user).
  - Enforced anti-enumeration across scan endpoints (returns 404, never 403, for cross-user requests).
- **CI/CD & Documentation:**
  - Added `npm audit --omit=dev --audit-level=high` step to GitHub Actions CI workflow.
  - Populated comprehensive `docs/SECURITY.md` and `docs/TESTING.md`.
  - Added 60 new unit, integration, and security tests (total: 506 tests, 100% pass rate).

## [0.1.0] - 2026-08-24

### Added - Phase 01: Application Foundation & Authentication

- Next.js 14 App Router scaffold in `apps/web/` with TypeScript strict mode and Tailwind CSS.
- MongoDB 7 + Mongoose connection singleton with connection pooling.
- `User` Mongoose model with unique GitHub ID index.
- `Session` Mongoose model with TTL auto-expiration index.
- Server-side session engine with opaque UUID tokens and HttpOnly/Secure cookies.
- GitHub App authentication flow (OAuth initiation, callback, state CSRF verification).
- Safe API endpoints:
  - `GET /api/health` — Health check
  - `GET /api/v1/auth/github` — OAuth start
  - `GET /api/v1/auth/github/callback` — OAuth callback
  - `GET /api/v1/auth/me` — Authenticated user profile
  - `POST /api/v1/auth/logout` — Session revocation
  - `GET /api/v1/repos` — User repository listing
  - `GET /api/v1/repos/:owner/:name` — Single repository metadata
- Security infrastructure: Zod schema validation, fail-fast environment validation, Pino structured logging with PII masking, in-memory rate limiting, and typed API errors.
- Basic frontend pages: Landing (`/`), Login (`/login`), and Protected Dashboard (`/dashboard`).
- CI workflow in `.github/workflows/ci.yml`.
- Unit and integration test suites.
