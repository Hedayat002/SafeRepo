# Phase 08 — Production Hardening

**Status:** Planning (Awaiting Human Approval)

---

## 1. Objective

Prepare SafeRepo for production deployment (Phase 09) and 100-user beta (Phase 10) by closing the remaining engineering, security, and operational gaps that exist after Phases 01–07.

Phase 08 is NOT about adding new features. It is about hardening, completing, and validating the existing system so it is safe, reliable, and maintainable when exposed to real users and real-world conditions.

---

## 2. Current System Baseline

### Completed Phases

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 01 | Application Foundation (Next.js, Auth, MongoDB, Sessions) | ✅ Complete |
| Phase 02 | Safe Repository Acquisition (clone, workspace, symlinks) | ✅ Complete |
| Phase 03 | Semgrep SAST Integration (Docker Stage 1, findings API) | ✅ Complete |
| Phase 04 | Dependency Scanning (Trivy + OSV, deduplication) | ✅ Complete |
| Phase 05 | Secret Scanning (Gitleaks, redaction) | ✅ Complete |
| Phase 06 | Unified Scan Engine (queue, worker, orchestrator, reconciliation) | ✅ Complete |
| Phase 07 | Security Dashboard (UI, polling, filters, new scan form) | ✅ Complete |

### Current Metrics (Phase 07 Close)

| Metric | Value |
|--------|-------|
| Total tests | 446 |
| Test pass rate | 100% |
| Line coverage | 92.65% |
| TypeScript errors | 0 |
| Lint errors | 0 |
| Production build | PASS |
| Commit | `f52da07` |

### Existing Architecture Summary

```
Browser → Next.js App Router (RSC + Client Components)
           ├── API Routes (auth, repos, scans, findings, health)
           ├── Dashboard Pages (scan history, scan detail, findings, new scan)
           └── MongoDB (users, sessions, scans, findings)

Trusted Worker (standalone tsx process)
           ├── Queue (MongoDB-backed, atomic FIFO claiming)
           ├── Orchestrator (sequential: Semgrep → Trivy → OSV → Gitleaks)
           ├── Runner (Docker Stage 1 isolation)
           ├── Normalizer (cross-scanner deduplication, fingerprinting)
           └── Reconciliation Sweeper (orphan container/workspace cleanup)
```

### Existing Dependencies

**Production:** `mongoose ^8.24.4`, `next ^16.3.3`, `pino ^9.6.0`, `react ^19.2.8`, `react-dom ^19.2.8`, `zod ^3.24.2`

**Dev:** `@types/node`, `@types/react`, `@types/react-dom`, `@vitest/coverage-v8`, `eslint`, `eslint-config-next`, `mongodb-memory-server`, `pino-pretty`, `postcss`, `prettier`, `tailwindcss`, `typescript`, `tsx`, `vitest`

---

## 3. Problem / Gap Analysis

The following analysis identifies genuine remaining gaps by cross-referencing `REQUIREMENTS.md`, `TESTING_PLAN.md`, `USER_STORIES.md`, `API_SPEC.md`, `DATABASE_DESIGN.md`, `SYSTEM_ARCHITECTURE.md`, `ROADMAP.md`, and all completed phase documents.

### 3.1 Scan Data Retention & Cleanup (TBD in REQUIREMENTS.md §6)

**Gap:** `REQUIREMENTS.md` line 91 identifies "Scan Retention Policy" as a TBD item. `DATABASE_DESIGN.md` §9 lists "Scan history retention policy (how long to keep old scans)" as an open schema question. No TTL, cleanup, or storage management exists. On MongoDB Atlas free tier (M0, 512MB), unbounded scan+findings accumulation will cause storage exhaustion during beta.

**Impact:** Production blocker for Phase 09/10.

### 3.2 Scan Deletion API (API_SPEC.md Gap)

**Gap:** The `API_SPEC.md` documents proposed endpoints but no `DELETE /api/v1/scans/:id` exists. Users have no way to remove old scans or findings. `DATABASE_DESIGN.md` §8 documents cascade delete behavior (`Deleting a scan → application deletes all its findings`) but no API surface exposes this capability.

**Impact:** Users accumulate orphaned data indefinitely; no self-service cleanup.

### 3.3 Scan Cancellation (API_SPEC.md §TBD)

**Gap:** `API_SPEC.md` identifies "Scan cancellation endpoint" as TBD. Users cannot cancel an in-progress scan. The worker queue (`queue.ts`) and orchestrator (`orchestrator.ts`) have AbortController infrastructure, but no API endpoint triggers cancellation from the user.

**Impact:** User is stuck waiting for timed-out scans; no way to abort a queued-but-not-started scan.

### 3.4 Health Endpoint Completeness

**Gap:** The existing `/api/health` returns basic `{ status, db, timestamp }`. Phase 09 requires "health checks" and "monitoring" for production deployment. The health check does not report worker status, queue depth, or application version.

**Impact:** Operations team cannot verify worker liveness or queue health in production.

### 3.5 Observability & Structured Logging Gaps

**Gap:** `pino` is installed and `logger.ts` exists, but logging coverage is inconsistent across modules. API routes do not log request metadata (method, path, status, duration). Scanner execution logs are present but not structured for production log aggregation. No request correlation IDs exist for tracing.

**Impact:** Production debugging and incident response are impaired without structured, traceable logs.

### 3.6 Security Hardening for Production

**Gap (a):** The `npm audit` requirement from Phase 01 (`PHASE_01.md` line 101: "npm audit must pass with 0 critical/high vulnerabilities") has not been formally verified since Phase 01. Dependencies have been added across phases.

**Gap (b):** No `Content-Security-Policy` header is configured. Phase 07 (§5.2) states "No additional CSP headers required" but production deployment (Phase 09) benefits from explicit CSP to prevent XSS.

**Gap (c):** Session cookie `SameSite` attribute configuration should be verified for production cross-origin scenarios.

**Gap (d):** Rate limiting on scan creation exists, but rate limiting on findings API queries does not. High-volume scraping of findings could stress MongoDB.

### 3.7 CI/CD Pipeline Hardening

**Gap:** The current `.github/workflows/ci.yml` does not run `npm audit`, does not enforce coverage thresholds as a CI gate, and does not cache Docker images for scanner tests. Phase 09 requires CI passing before deployment.

**Impact:** CI does not catch dependency vulnerabilities or coverage regressions.

### 3.8 Error Handling Consistency

**Gap:** API routes use the `errors.ts` framework, but error responses across all routes have not been audited for consistency. Some routes may return raw error messages in non-standard formats, potentially leaking internal details.

**Impact:** Inconsistent error responses complicate frontend error handling and may leak server internals.

### 3.9 Documentation Completeness

**Gap:** Several documentation files are stubs:
- `docs/DATABASE.md` (14 bytes — placeholder)
- `docs/SECURITY.md` (14 bytes — placeholder)
- `docs/TESTING.md` (13 bytes — placeholder)

These should be populated or consolidated before production deployment. `ROADMAP.md` phase statuses are also outdated (shows Phase 04 as "Awaiting Approval", Phase 05+ as "Not Started").

### 3.10 Deferred Phase 07 Testing Items

Phase 07 (§13.10) explicitly deferred the following to Phase 08:
1. DOM-based user event simulation (`jsdom`/`happy-dom` + `@testing-library/react`)
2. Cross-browser E2E testing (Playwright)
3. Visual regression testing
4. Automated accessibility auditing (axe-core)
5. Exhaustive non-critical component coverage

**Assessment:** Items 1, 3, 4, and 5 are explicitly deferred to Phase 08 by Phase 07. However, implementing the full scope of these (Playwright, jsdom, axe-core, visual regression) would add significant dependencies, complexity, and maintenance burden for a pre-beta product. **Phase 08 should implement only what is genuinely necessary for safe production operation**, not exhaustive UI testing. See §4 Scope and §5 Non-Goals for the scoping decision.

---

## 4. Scope

Phase 08 addresses the genuine production readiness gaps identified above. Each item is directly traceable to a documented requirement, TBD item, or Phase 09 prerequisite.

### 4.1 Scan Data Retention Policy (resolves TBD from REQUIREMENTS.md §6)

- Implement configurable `SCAN_RETENTION_DAYS` environment variable (default: 90 days).
- Implement `cleanupExpiredScans()` utility function that:
  - Queries scans with `completedAt < now - retentionPeriod` in terminal states (`completed`, `failed`, `timed_out`).
  - Cascade-deletes associated findings via `Finding.deleteMany({ scanId })`.
  - Deletes the scan document.
  - Logs cleanup activity (count of deleted scans/findings).
- Integrate cleanup into the worker startup reconciliation cycle (runs once on worker boot, alongside orphan reconciliation).
- Add periodic cleanup execution (configurable, default: once per 24 hours via worker interval).
- Hard limit: Maximum 500 scans per user (oldest terminal scans auto-pruned when exceeded).

### 4.2 Scan Deletion API

- `DELETE /api/v1/scans/:id` — Authenticated, user-scoped.
  - Validates scan ownership (`scan.userId === session.userId`).
  - Rejects deletion of in-progress scans (`queued`, `cloning`, `scanning`, `normalizing`) — returns 409 Conflict.
  - Cascade-deletes associated findings.
  - Returns 204 No Content on success.
  - Rate-limited (10 deletions per minute per user).

### 4.3 Scan Cancellation API

- `POST /api/v1/scans/:id/cancel` — Authenticated, user-scoped.
  - Validates scan ownership.
  - Only cancels scans in `queued` status (atomically transitions to `failed` with `error: "Cancelled by user"`).
  - For in-progress scans (`cloning`, `scanning`, `normalizing`): sets a `cancelRequested: true` flag on the scan document. The worker checks this flag during heartbeat updates and gracefully aborts execution if set.
  - Returns 200 with updated scan status.
  - Returns 409 if scan is already in a terminal state.

### 4.4 Enhanced Health Endpoint

- Extend `/api/health` response to include:
  - `version`: Application version from `package.json`.
  - `queue`: `{ pending: number }` — count of scans with status `queued`.
  - `uptime`: Process uptime in seconds.
- No new dependencies; uses existing MongoDB queries and `process.uptime()`.

### 4.5 Structured Logging & Request Tracing

- Add request logging middleware to API routes:
  - Log: `method`, `path`, `statusCode`, `durationMs`, `userId` (if authenticated).
  - Generate and propagate `requestId` (UUID) via response header `X-Request-Id`.
  - Redact sensitive headers (`authorization`, `cookie`) from logs.
- Ensure all scanner worker logs include `scanId` and `workerId` for correlation.
- Verify that no raw secrets, tokens, or PII (beyond `userId`) appear in log output.

### 4.6 Security Hardening

- **npm audit enforcement:** Add `npm audit --audit-level=high` to CI pipeline. Resolve any critical/high vulnerabilities in current dependency tree.
- **Content-Security-Policy:** Add baseline CSP header via middleware:
  - `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https://avatars.githubusercontent.com; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.
  - `'unsafe-inline'` for styles required by Tailwind CSS and React inline styles.
- **Session cookie audit:** Verify `Secure`, `HttpOnly`, `SameSite=Lax` attributes are correctly set. Document any adjustments for production.
- **API response audit:** Ensure all error responses use the standard `ApiErrorResponse` format. No raw `Error.message` or stack traces in production responses.
- **Findings API rate limiting:** Apply existing rate limiter to `GET /api/v1/scans/:id/findings` (100 requests per minute per user).

### 4.7 CI/CD Pipeline Hardening

- Add `npm audit --audit-level=high` step to `.github/workflows/ci.yml`.
- Add explicit coverage threshold enforcement (already configured in `vitest.config.ts` at 80% but not verified as a CI gate — ensure the step fails if thresholds are violated).
- Update CI to report coverage summary in job output.

### 4.8 Error Response Consistency Audit

- Audit all API route handlers (`/api/v1/**`) to ensure:
  - All error responses use `ApiErrorResponse` format from `errors.ts`.
  - No internal error messages or stack traces leak in production.
  - All Zod validation failures return structured 400 responses.
  - All auth failures return 401 with consistent codes.
  - All authorization failures return 404 (not 403, to avoid scan ID enumeration).

### 4.9 Documentation Completion

- Populate `docs/SECURITY.md` with SafeRepo's security architecture summary (Docker isolation, session security, secret redaction, CSP, rate limiting).
- Populate `docs/TESTING.md` with current testing architecture summary (Vitest, mongodb-memory-server, coverage targets, test categories).
- Remove or consolidate `docs/DATABASE.md` (redirect to `DATABASE_DESIGN.md`).
- Update `docs/ROADMAP.md` phase statuses to reflect Phases 01–07 as completed.
- Update `docs/CHANGELOG.md` with Phase 08 entries.

### 4.10 Scan Model Enhancement (cancelRequested flag)

- Add `cancelRequested: boolean` field (default: `false`) to the Scan model to support user-initiated cancellation.
- Worker heartbeat loop checks `cancelRequested` and triggers graceful abort if set.

---

## 5. Non-Goals

The following items are explicitly **NOT** in scope for Phase 08:

1. **Playwright E2E tests:** Full cross-browser E2E testing adds Playwright as a new dependency and requires a running application with database and Docker. This is deferred to Phase 10 (beta testing) where real user flows are validated in a deployed environment. Rationale: Playwright provides limited value before deployment and significantly increases CI complexity and runtime.

2. **jsdom / happy-dom user event simulation:** Adding DOM-based testing libraries (`@testing-library/react`, `jsdom`) for client component interaction tests. Rationale: Phase 07 already tests all critical component rendering via `react-dom/server`, and all interactive logic (polling, filters, pagination) is tested via pure unit tests on extracted logic modules. DOM event simulation provides marginal additional coverage at significant dependency cost.

3. **Visual regression testing:** Screenshot comparison tools (e.g., Playwright screenshots, Percy, Chromatic). Rationale: No visual baseline exists, and the product is pre-beta with expected UI iteration.

4. **axe-core accessibility auditing:** Automated accessibility testing. Rationale: Important for GA but not a production blocker for beta. Can be added incrementally in Phase 10.

5. **WebSocket / SSE real-time updates:** Replacing polling with push-based updates. Consistently deferred across Phases 06 and 07. Not needed for 100-user beta.

6. **New scanning features:** No new scanners, no new finding categories, no new ecosystems.

7. **Frontend feature additions:** No new dashboard pages, no new UI components, no scan comparison, no findings export.

8. **Database schema migrations beyond `cancelRequested`:** No collection restructuring, no index changes beyond what is needed for retention cleanup.

9. **Performance benchmarking / load testing:** Useful but deferred to Phase 10 where real traffic patterns are available.

10. **Containerized `npm audit` / `pip-audit`:** Remains deferred per Phase 04/06 — requires egress allowlist proxy architecture.

11. **Multi-tenant / RBAC:** Out of MVP scope per `REQUIREMENTS.md` §5.

---

## 6. Architecture Impact

### 6.1 New API Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/api/v1/scans/:id` | DELETE | Delete a completed scan and its findings |
| `/api/v1/scans/:id/cancel` | POST | Cancel a queued or in-progress scan |

### 6.2 Modified API Routes

| Route | Change |
|-------|--------|
| `/api/health` | Extended response with `version`, `queue.pending`, `uptime` |

### 6.3 Middleware Changes

- New request logging middleware (wraps API route handlers).
- CSP header middleware (added to Next.js middleware or `next.config.mjs` headers).
- Rate limiting extended to findings endpoint.

### 6.4 No Architectural Changes

- No changes to the worker/queue/orchestrator architecture.
- No changes to the scanner runner or Docker isolation model.
- No changes to the authentication/session system.
- No changes to the rendering strategy (RSC + Client Components).
- No new external services or infrastructure.

---

## 7. Security Requirements

### 7.1 Preserved Security Invariants (from Phases 01–07)

All existing security boundaries remain strictly unchanged:

- Docker Stage 1 isolation (`--network=none`, `--read-only`, dropped caps, unprivileged user)
- Docker socket restricted to Trusted Worker only
- Secret redaction (`[REDACTED SECRET]` in findings)
- User-scoped data access (all queries filter by `userId`)
- Server-side sessions (opaque cookie, MongoDB-backed)
- GitHub tokens stored server-side only
- Zod validation on all API inputs
- Rate limiting on scan creation

### 7.2 New Security Measures in Phase 08

| Measure | Description |
|---------|-------------|
| Content-Security-Policy | Explicit CSP header preventing XSS, clickjacking, and data injection |
| npm audit CI gate | Automated dependency vulnerability scanning in CI |
| Findings API rate limiting | Prevents bulk scraping of security findings |
| Scan deletion authorization | User can only delete their own scans; in-progress scans protected |
| Scan cancellation authorization | User can only cancel their own scans |
| Error response audit | Eliminates potential information leakage via error messages |
| Request logging with redaction | Structured logs without sensitive data exposure |

### 7.3 Security Acceptance Criteria

- [ ] `npm audit --audit-level=high` returns 0 vulnerabilities.
- [ ] CSP header present on all page responses.
- [ ] No raw `Error.message` or stack traces in API responses when `NODE_ENV=production`.
- [ ] Scan deletion rejects cross-user access (returns 404, not 403).
- [ ] Scan cancellation rejects cross-user access (returns 404, not 403).
- [ ] Request logs contain no `cookie`, `authorization`, or `session` header values.
- [ ] Gitleaks secret redaction invariant preserved (no regressions in auth boundary tests).

---

## 8. Data / API Impact

### 8.1 Schema Change

**Scan model (`apps/web/src/models/scan.ts`):**

```diff
+ cancelRequested: {
+   type: Boolean,
+   default: false,
+ },
```

This is a backwards-compatible addition. Existing documents default to `false`. No migration required.

### 8.2 Environment Variable Addition

**`apps/web/src/lib/env.ts`:**

```diff
+ // Phase 08: Retention
+ SCAN_RETENTION_DAYS: z.coerce
+   .number()
+   .int()
+   .positive()
+   .default(90),
+ MAX_SCANS_PER_USER: z.coerce
+   .number()
+   .int()
+   .positive()
+   .default(500),
```

### 8.3 New API Contracts

#### DELETE /api/v1/scans/:id

**Request:** Authenticated (session cookie). No body.

**Success Response:** `204 No Content`

**Error Responses:**
- `401 Unauthorized` — No valid session.
- `404 Not Found` — Scan not found or not owned by user.
- `409 Conflict` — Scan is in progress and cannot be deleted.
- `429 Too Many Requests` — Rate limit exceeded.

#### POST /api/v1/scans/:id/cancel

**Request:** Authenticated (session cookie). No body.

**Success Response:** `200 OK` with updated scan object.

**Error Responses:**
- `401 Unauthorized` — No valid session.
- `404 Not Found` — Scan not found or not owned by user.
- `409 Conflict` — Scan is already in a terminal state.

---

## 9. Implementation Plan

### Phase 1: Scan Model & Retention (Day 1)

1. Add `cancelRequested` field to Scan model.
2. Add `SCAN_RETENTION_DAYS` and `MAX_SCANS_PER_USER` to `env.ts`.
3. Implement `cleanupExpiredScans()` in `apps/web/src/lib/scanner/retention.ts`.
4. Integrate retention cleanup into worker boot and periodic interval.
5. Write unit tests for retention logic.

### Phase 2: Scan Deletion & Cancellation APIs (Day 1–2)

1. Implement `DELETE /api/v1/scans/:id` route handler.
2. Implement `POST /api/v1/scans/:id/cancel` route handler.
3. Add cancellation check to worker heartbeat loop in `queue.ts`.
4. Write integration tests for both endpoints (auth, authorization, edge cases).
5. Verify cascade deletion with findings.

### Phase 3: Health Endpoint & Observability (Day 2)

1. Extend `/api/health` response with `version`, `queue.pending`, `uptime`.
2. Implement request logging middleware with `requestId` and redaction.
3. Ensure worker logs consistently include `scanId` and `workerId`.
4. Write tests for enhanced health endpoint.

### Phase 4: Security Hardening (Day 2–3)

1. Add CSP header configuration.
2. Extend rate limiting to findings API.
3. Audit all API route error responses for consistency and information leakage.
4. Run `npm audit` and resolve any critical/high vulnerabilities.
5. Verify session cookie attributes.
6. Write security-focused tests.

### Phase 5: CI/CD & Documentation (Day 3)

1. Add `npm audit` step to CI workflow.
2. Verify coverage threshold enforcement in CI.
3. Populate `docs/SECURITY.md`, `docs/TESTING.md`.
4. Clean up `docs/DATABASE.md`.
5. Update `docs/ROADMAP.md` statuses.
6. Update `docs/CHANGELOG.md`.

### Phase 6: Validation & Close (Day 3)

1. Run full validation suite.
2. Verify all acceptance criteria.
3. Generate validation report.

---

## 10. Testing Strategy

### 10.1 Unit Tests

**New test files:**

| File | Tests | Description |
|------|-------|-------------|
| `apps/web/src/lib/scanner/__tests__/retention.test.ts` | ~15 tests | Retention cleanup: TTL calculation, query construction, cascade deletion, per-user cap enforcement, edge cases (no expired scans, in-progress scans excluded) |

**Modified test files:**

| File | Additional Tests | Description |
|------|-----------------|-------------|
| `apps/web/src/lib/scanner/__tests__/queue.test.ts` | ~5 tests | Cancellation flag detection in heartbeat loop, graceful abort on cancel |

### 10.2 Integration Tests

**New test files:**

| File | Tests | Description |
|------|-------|-------------|
| `apps/web/src/app/api/__tests__/scan-lifecycle.test.ts` | ~25 tests | DELETE scan (success, auth, cross-user, in-progress 409, cascade findings deletion, rate limit); CANCEL scan (queued success, in-progress flag set, terminal 409, cross-user 404); Enhanced health endpoint (version, queue pending, uptime) |

### 10.3 Security Tests

**New test files:**

| File | Tests | Description |
|------|-------|-------------|
| `apps/web/src/app/api/__tests__/security-hardening.test.ts` | ~15 tests | CSP header presence, error response format consistency, no stack traces in production errors, findings API rate limiting, request ID header presence, scan enumeration prevention (404 not 403) |

### 10.4 Regression Tests

- All existing 446 tests MUST continue passing with 0 regressions.
- All Phase 01–07 security boundary tests unchanged.
- All scanner, normalizer, and orchestrator tests unchanged.

### 10.5 Coverage Targets

| Metric | Target |
|--------|--------|
| New module coverage (`retention.ts`) | ≥ 90% line coverage |
| New API routes coverage | ≥ 85% line coverage |
| Overall repository coverage | ≥ 90% (maintain baseline) |
| Total new test cases | ≥ 60 |

### 10.6 Validation Commands

```bash
npm run typecheck     # 0 errors
npm run lint          # 0 errors
npm run test          # 100% pass rate (446 existing + ~60 new = ~506 total)
npm run test:coverage # ≥ 90% overall, ≥ 80% threshold
npm run build         # SUCCESS
npm audit --audit-level=high  # 0 critical/high
```

---

## 11. Validation Gates

Phase 08 implementation follows a strict gated workflow:

```
Human approves Phase 08 plan
       ↓
Implement Phase 1 (Model + Retention)
       ↓
Run: typecheck + lint + test → All pass
       ↓
Implement Phase 2 (Deletion + Cancellation APIs)
       ↓
Run: typecheck + lint + test → All pass
       ↓
Implement Phase 3 (Health + Observability)
       ↓
Run: typecheck + lint + test → All pass
       ↓
Implement Phase 4 (Security Hardening)
       ↓
Run: typecheck + lint + test + npm audit → All pass
       ↓
Implement Phase 5 (CI/CD + Docs)
       ↓
Run: full validation suite → All pass
       ↓
Phase 6: Final validation, audit, and close
       ↓
Human reviews validation report
       ↓
Commit and push (single commit or squashed)
```

---

## 12. Acceptance Criteria

### Functional

- [ ] `cleanupExpiredScans()` correctly deletes scans older than `SCAN_RETENTION_DAYS` and their findings.
- [ ] Per-user scan cap (`MAX_SCANS_PER_USER`) enforced; oldest terminal scans pruned when exceeded.
- [ ] `DELETE /api/v1/scans/:id` deletes scan and cascade-deletes findings for authenticated owner.
- [ ] `DELETE /api/v1/scans/:id` returns 409 for in-progress scans.
- [ ] `POST /api/v1/scans/:id/cancel` transitions queued scans to `failed` with cancellation error.
- [ ] `POST /api/v1/scans/:id/cancel` sets `cancelRequested` flag for in-progress scans.
- [ ] Worker detects `cancelRequested` during heartbeat and gracefully aborts execution.
- [ ] `GET /api/health` returns `version`, `queue.pending`, and `uptime`.

### Security

- [ ] CSP header present on all page responses.
- [ ] `npm audit --audit-level=high` returns 0 vulnerabilities.
- [ ] All API error responses use `ApiErrorResponse` format.
- [ ] No stack traces or internal error messages in production responses.
- [ ] Findings API rate-limited (100 req/min/user).
- [ ] Request logs redact sensitive headers.
- [ ] Scan deletion/cancellation reject cross-user access with 404.
- [ ] All existing Phase 01–07 security invariants preserved.

### Observability

- [ ] API request logging middleware active with `requestId`, `method`, `path`, `status`, `durationMs`.
- [ ] `X-Request-Id` header present in API responses.
- [ ] Worker logs include `scanId` and `workerId` correlation.

### Documentation

- [ ] `docs/SECURITY.md` populated with security architecture summary.
- [ ] `docs/TESTING.md` populated with testing architecture summary.
- [ ] `docs/ROADMAP.md` statuses updated for Phases 01–08.
- [ ] `docs/CHANGELOG.md` updated with Phase 08 entries.

### Quality

- [ ] `npm run typecheck` — 0 errors.
- [ ] `npm run lint` — 0 errors.
- [ ] `npm run test` — 100% pass rate (~506 total tests).
- [ ] `npm run test:coverage` — ≥ 90% overall line coverage.
- [ ] `npm run build` — SUCCESS.
- [ ] CI pipeline includes `npm audit` step.
- [ ] ≥ 60 new test cases added.

### Change Boundary

- [ ] No new production dependencies added to `package.json`.
- [ ] No scanner/runner/Docker isolation code modified (security boundary preserved).
- [ ] No authentication/session system modified.
- [ ] No dashboard UI features added (only middleware/headers).
- [ ] No database collection restructuring.

---

## 13. Rollback Strategy

Phase 08 changes are low-risk and reversible:

1. **Schema addition (`cancelRequested`):** Backwards-compatible boolean field with default `false`. Rolling back leaves the field unused. No data loss.

2. **New API routes (`DELETE`, `POST cancel`):** Additive routes. Rolling back removes the routes. No existing functionality affected.

3. **Health endpoint extension:** Backwards-compatible response field additions. Rolling back restores the original response.

4. **Retention cleanup:** The cleanup function runs periodically and deletes only terminal scans past retention threshold. Rolling back stops cleanup; no data loss (data accumulates as before).

5. **Middleware (logging, CSP, rate limiting):** Added as wrappers. Rolling back removes them; existing functionality unchanged.

6. **CI changes:** `npm audit` step can be removed from CI. Coverage enforcement is already configured.

7. **Documentation:** Purely additive.

**Rollback procedure:** `git revert <phase-08-commit>`. All Phase 01–07 functionality is completely unaffected.

---

## 14. Future Deferrals

The following items are explicitly deferred beyond Phase 08:

| Item | Deferred To | Rationale |
|------|-------------|-----------|
| Playwright E2E tests | Phase 10 | Requires deployed environment; complexity vs value for pre-beta |
| jsdom/happy-dom component tests | Phase 10+ | Marginal coverage gain over existing react-dom/server tests |
| Visual regression testing | Phase 10+ | No stable UI baseline exists yet |
| axe-core accessibility auditing | Phase 10+ | Important but not a beta blocker |
| WebSocket/SSE real-time updates | Phase 10+ | Polling sufficient for 100-user beta |
| Containerized npm audit/pip-audit | Future | Requires egress proxy architecture |
| Findings export (CSV/PDF) | Future | User convenience feature, not production blocker |
| Scan comparison | Future | Feature addition, not hardening |
| Repository detail pages | Future | Feature addition, not hardening |
| Performance/load testing | Phase 10 | Requires real traffic patterns |
| Multi-tenant RBAC | Post-MVP | Out of MVP scope |

---

## 15. Expected Files / Change Boundary

### New Files to Create

| # | File | Purpose |
|---|------|---------|
| 1 | `apps/web/src/lib/scanner/retention.ts` | Scan retention cleanup logic (TTL, per-user cap) |
| 2 | `apps/web/src/lib/scanner/__tests__/retention.test.ts` | Retention unit tests |
| 3 | `apps/web/src/app/api/v1/scans/[id]/route.ts` | DELETE handler for scan deletion |
| 4 | `apps/web/src/app/api/v1/scans/[id]/cancel/route.ts` | POST handler for scan cancellation |
| 5 | `apps/web/src/app/api/__tests__/scan-lifecycle.test.ts` | Integration tests for delete, cancel, health |
| 6 | `apps/web/src/app/api/__tests__/security-hardening.test.ts` | Security hardening tests |
| 7 | `apps/web/src/lib/middleware/request-logger.ts` | Request logging middleware |
| 8 | `docs/SECURITY.md` | Security architecture documentation (overwrite placeholder) |
| 9 | `docs/TESTING.md` | Testing architecture documentation (overwrite placeholder) |

### Files to Modify

| # | File | Change |
|---|------|--------|
| 1 | `apps/web/src/models/scan.ts` | Add `cancelRequested: Boolean` field |
| 2 | `apps/web/src/lib/env.ts` | Add `SCAN_RETENTION_DAYS`, `MAX_SCANS_PER_USER` |
| 3 | `apps/web/src/lib/scanner/queue.ts` | Check `cancelRequested` in heartbeat loop |
| 4 | `apps/web/src/app/api/health/route.ts` | Extended response (version, queue, uptime) |
| 5 | `apps/web/src/app/api/v1/scans/[id]/findings/route.ts` | Add rate limiting wrapper |
| 6 | `.github/workflows/ci.yml` | Add `npm audit` step |
| 7 | `.env.example` | Add `SCAN_RETENTION_DAYS`, `MAX_SCANS_PER_USER` |
| 8 | `docs/ROADMAP.md` | Update phase statuses |
| 9 | `docs/CHANGELOG.md` | Add Phase 08 entries |
| 10 | `apps/web/src/lib/scanner/__tests__/queue.test.ts` | Add cancellation detection tests |
| 11 | `apps/web/next.config.mjs` | Add CSP and security headers |

### Files Explicitly Protected from Modification

The following files MUST NOT be modified in Phase 08:

- `apps/web/src/lib/scanner/runner.ts` — No scanner runner changes.
- `apps/web/src/lib/scanner/orchestrator.ts` — No orchestrator changes (beyond cancel check if needed).
- `apps/web/src/lib/scanner/semgrep.ts` — No scanner changes.
- `apps/web/src/lib/scanner/trivy.ts` — No scanner changes.
- `apps/web/src/lib/scanner/gitleaks.ts` — No scanner changes.
- `apps/web/src/lib/scanner/osv.ts` — No scanner changes.
- `apps/web/src/lib/scanner/normalizer.ts` — No normalizer changes.
- `apps/web/src/lib/scanner/workspace.ts` — No workspace changes.
- `apps/web/src/lib/auth.ts` — No auth changes.
- `apps/web/src/lib/session.ts` — No session changes.
- `apps/web/src/lib/schemas.ts` — No schema changes.
- `apps/web/src/models/user.ts` — No user model changes.
- `apps/web/src/models/finding.ts` — No finding model changes.
- `apps/web/src/models/session.ts` — No session model changes.
- `apps/web/src/types/index.ts` — No type changes (unless minimal additions for cancellation types).
- `apps/web/src/components/**` — No component changes.
- `apps/web/src/app/dashboard/**` — No dashboard page changes.
- `apps/web/vitest.config.ts` — No test config changes.
- `apps/web/src/test/setup.ts` — No test setup changes.

---

## 16. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Retention cleanup accidentally deletes in-progress scans | Low | High | Query filter strictly limits to terminal statuses (`completed`, `failed`, `timed_out`). Unit tests verify exclusion. |
| Scan cancellation race condition (cancel arrives after worker claims but before heartbeat check) | Medium | Low | `cancelRequested` is checked atomically during heartbeat. Worst case: scan completes before cancel is observed — harmless. |
| CSP header breaks existing functionality (inline styles) | Low | Medium | Use `'unsafe-inline'` for `style-src` (required by Tailwind/React). Test with existing dashboard pages. |
| `npm audit` finds unfixable vulnerabilities in transitive dependencies | Medium | Medium | Document known exceptions. Use `npm audit --audit-level=high` (not `--audit-level=moderate`). Add `--omit=dev` for production audit. |
| Rate limiting on findings API breaks legitimate dashboard polling | Low | Medium | Set generous limit (100 req/min/user). Dashboard pagination fetches at most 1 request per user interaction. |

---

## 17. Final Human Approval Gate

This document requires **explicit human approval** before any implementation begins.

**No source code, API route, model field, middleware, CI configuration, or documentation file may be created or modified until the Phase 08 plan is approved.**

### Approval Checklist for Reviewer

- [ ] Scope is appropriate — no unnecessary features invented.
- [ ] Non-goals are reasonable — deferred items are genuinely deferrable.
- [ ] Security measures are adequate for 100-user beta.
- [ ] Schema change (`cancelRequested`) is acceptable.
- [ ] New API surfaces (DELETE, CANCEL) are reasonable.
- [ ] File change boundary is acceptable.
- [ ] Testing strategy is sufficient.
- [ ] Rollback strategy is credible.
- [ ] Phase 08 does not compromise any Phase 01–07 security invariants.

---

## 18. Git Checkpoint Strategy

- **Checkpoint 1 (Planning):** `docs: complete phase 08 planning` (Current document).
- **Checkpoint 2 (Retention + Model):** `feat: implement scan retention policy and cancellation model` (retention.ts, scan model, env, tests).
- **Checkpoint 3 (APIs):** `feat: implement scan deletion and cancellation APIs` (DELETE, CANCEL routes, integration tests).
- **Checkpoint 4 (Observability + Security):** `feat: add request logging, CSP, and security hardening` (middleware, headers, audit).
- **Checkpoint 5 (CI + Docs):** `chore: harden CI pipeline and update documentation` (ci.yml, docs).
- **Checkpoint 6 (Verification + Close):** `feat: complete phase 08 production hardening` (validation, phase status).
