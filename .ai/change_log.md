# Change Log

---

### 2026-09-17 — Phase 09 Step 9: Local Test Database Configuration Fix & Full Regression Quality Gates

- **Test Setup Configurable MongoDB URI (Step 9):** Updated `apps/web/src/test/setup.ts` to respect `process.env.MONGODB_URI` if provided while preserving the existing default `mongodb://admin:password@localhost:27017/saferepo_test?authSource=admin`. Resolves host port conflict with the Windows MongoDB service, preventing unwanted fallback to `MongoMemoryServer` and avoiding 509 MB binary downloads from `fastdl.mongodb.org`.
- **Full Regression Test Suite:** Executed full 506-test regression suite across 34 test files against temporary Docker MongoDB (`mongo:7.0.18-jammy` on `127.0.0.1:27018`): 34/34 test files passed, 506/506 tests passed (100% PASS, 62.61s). Zero fallback to `MongoMemoryServer` and zero external downloads.
- **Code Coverage:** Achieved 92.62% line coverage (statements: 92.62%, branches: 83.00%, functions: 93.95%, lines: 92.62%), exceeding the 80% line threshold.
- **Comprehensive Quality Gates:**
  - `npm run typecheck` (`tsc --noEmit`): 0 errors.
  - `npm run lint` (`eslint .`): 0 errors, 3 pre-existing warnings.
  - Next.js 16 production build (`next build`): clean Turbopack build.
  - `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
  - Pre-flight environment auditor (`scripts/validate-production.ts`): 49/49 PASS.
  - Production Compose validation (`docker compose -f docker-compose.prod.yml config -q`): 0 errors.
  - Clean teardown of temporary test container (`saferepo-regression-mongo`) and network (`saferepo-test-net`).
- **Phase 09 Closeout:** Marked Phase 09 COMPLETE — PENDING FINAL HUMAN REVIEW.

---

### 2026-09-16 — Phase 09: Production Deployment & Beta Infrastructure (Steps 1–8)

- **Production Operations Runbook (Step 8):** Authored `docs/DEPLOYMENT_RUNBOOK.md` containing all 21 production operations sections (architecture, prerequisites, host preparation, deployment workflow, secret hygiene, MongoDB Atlas vs self-hosted, GitHub App least-privilege permissions, pinned scanner images, validation tooling, ordered 10-step deployment procedure, health and smoke test specifications, Caddy TLS termination, firewall exposure, logging & request ID tracing, backup/restore/rollback procedures, incident response, non-negotiable security rules, and Beta vs GA architectural boundaries). Synchronized `docs/ROADMAP.md` and `docs/CHANGELOG.md`.
- **Smoke Test Suite (Step 7):** Authored `scripts/smoke-test.ts` to execute automated live HTTP contract testing (`/api/health`, CSP/XFO/nosniff headers, 404 error response sanitization, and infrastructure invariants from `docker-compose.prod.yml`). Verified clean pass (23 PASS / 0 WARN / 0 FAIL) against temporary local container stack with full cleanup.
- **Web Containerization (Step 1):** Configured `output: 'standalone'` in `apps/web/next.config.mjs`. Authored `apps/web/Dockerfile` with multi-stage build, unprivileged user `nextjs` (UID 1001), zero Docker socket or CLI binaries. Added root and app `.dockerignore` files excluding `.git`, `.env*.local`, and `.ai`.
- **Worker Packaging (Step 2):** Authored `apps/web/Dockerfile.worker` with Node 24 Alpine runtime, unprivileged user `workeruser` (UID 1001), minimal `docker-cli` and `git` tools, restricted workspace `/tmp/saferepo-workspaces` (0700), zero embedded daemon or static socket.
- **Production Compose Orchestration (Step 3):** Authored `docker-compose.prod.yml` defining 5 services (`caddy`, `web`, `worker`, `docker-proxy`, `mongo`) across 4 isolated internal networks. Restricted `tecnativa/docker-socket-proxy` to `worker-proxy-net` only with dangerous APIs disabled.
- **Pre-Flight Validation (Step 4):** Authored `scripts/validate-production.ts` executing 49 deterministic static checks (files, tooling, compose syntax, security invariants, image tags, secret-safe environment schemas). Result: 49 PASS / 0 WARN / 0 FAIL.
- **Image Build Verification (Step 5):** Built and inspected local production images `saferepo-web:0.9.0` (72.5 MB) and `saferepo-worker:0.9.0` (304 MB). Verified non-root execution, zero secrets, zero exposed worker ports.
- **Scanner Pre-Caching (Step 6):** Authored `scripts/preload-scanners.ps1` and `scripts/preload-scanners.sh`. Pre-cached and verified pinned scanner images `semgrep/semgrep:1.100.0`, `aquasec/trivy:0.59.1`, `zricethezav/gitleaks:v8.24.0` (3/3 PASS).

---

### 2026-09-08 — CI Baseline: Node 24.19.0 LTS Migration (`9fb53b0`)

- Migrated GitHub Actions CI workflow to Node 24.19.0 LTS runtime.
- Updated Linux rollup dependencies and confirmed green CI pass across all test suites.

---

### 2026-09-07 — Phase 08: Production Hardening (`521c722`)

- Implemented automated scan data retention policy (`SCAN_RETENTION_DAYS = 90`, `MAX_SCANS_PER_USER = 500`).
- Added scan deletion API endpoint (`DELETE /api/v1/scans/:id`) with cascade cleanup.
- Added in-flight scan cancellation API endpoint (`POST /api/v1/scans/:id/cancel`) with cooperative worker termination.
- Hardened Content-Security-Policy (CSP) headers and added request correlation ID logging middleware.

---

### 2026-09-06 — Phase 07: Security Dashboard (`f52da07`)

- Implemented React Server Components dashboard rendering authenticated scan statistics.
- Built scan history table with client-side search, filtering, and pagination.
- Added real-time scan progress view with exponential backoff polling.
- Built findings breakdown view displaying severity, scanner source, and remediation guidance.

---

### 2026-09-06 — Phase 06: Unified Scan Engine (`dab9f8f`)

- Implemented MongoDB-backed atomic queue (`queue.ts`) with conditional find-and-modify leasing.
- Built scan heartbeat monitor and background orphaned-job reconciliation sweeper.
- Built sequential multi-scanner orchestrator (`orchestrator.ts`) managing Semgrep, Trivy, OSV, and Gitleaks under global deadline.
- Built standalone worker entrypoint (`worker-entrypoint.ts`).

---

### 2026-09-05 — Phase 05: Secret Scanning (`b533887`)

- Integrated `zricethezav/gitleaks:v8.24.0` into Stage 1 Docker runner.
- Enforced zero secret logging: stdout/stderr redaction, in-memory parsing, code snippet replacement with `[REDACTED SECRET]`.

---

### 2026-09-04 — Phase 04: Dependency Vulnerability Scanning (`35fc70b`)

- Integrated `aquasec/trivy:0.59.1` for container-isolated lockfile scanning.
- Built batch OSV API client for advisory lookups without running repository code.
- Merged and deduplicated dependency findings into unified findings model.

---

### 2026-09-02 — Phase 03: Semgrep SAST Integration

- Built hardened Stage 1 Docker runner (`runner.ts`) with `--network=none`, `--read-only`, tmpfs mounts, and resource caps.
- Configured offline Semgrep rules directory and output normalization into SafeRepo findings schema.

---

### 2026-08-28 — Phase 02: Safe Repository Acquisition

- Built safe repository acquisition engine (`acquisition.ts`) performing shallow git clones with depth 1 into isolated workspaces (`workspace.ts`).
- Added path traversal prevention and automatic workspace cleanup.

---

### 2026-08-24 — Phase 01: Application Foundation & Authentication (`1c82105`)

- **Next.js Scaffold:** Bootstrapped Next.js 14 App Router project in `apps/web/` with TypeScript strict mode, Tailwind CSS, ESLint, and Prettier.
- **Database Layer:** Created Mongoose singleton connection in `apps/web/src/lib/db.ts`, `User` model in `apps/web/src/models/user.ts`, and `Session` model in `apps/web/src/models/session.ts` with TTL auto-expiration index.
- **Authentication Engine:** Built server-side session management (`apps/web/src/lib/session.ts`) utilizing opaque UUIDs, MongoDB persistence, and HttpOnly cookies. GitHub access tokens remain strictly server-side.
- **GitHub App Helpers:** Implemented server-side GitHub App helpers in `apps/web/src/lib/github.ts` using Node built-in fetch.
- **API Routes:** Implemented `GET /api/health`, `GET /api/v1/auth/github`, `GET /api/v1/auth/github/callback`, `GET /api/v1/auth/me`, `POST /api/v1/auth/logout`, `GET /api/v1/repos`, and `GET /api/v1/repos/:owner/:name`.
- **Security & Validation:** Added Zod validation schemas (`lib/schemas.ts`), environment fail-fast validation (`lib/env.ts`), structured logging (`lib/logger.ts`), typed error classes (`lib/errors.ts`), and in-memory rate limiting (`lib/rate-limit.ts`).
- **Frontend Pages:** Implemented root layout, home landing page, login page, and server-side authenticated dashboard.
- **CI & Tests:** Added `.github/workflows/ci.yml` and 11 Vitest test suites.

---

### 2026-08-23 — Phase 00: Approval and Scope Finalization

- Finalized Phase 00 documentation and architecture.
- Finalized ADRs and decision records in `.ai/decisions.md`.
