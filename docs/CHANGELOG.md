# Changelog — SafeRepo

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
