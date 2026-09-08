# SafeRepo Testing Architecture & Guide

## 1. Overview

SafeRepo maintains a comprehensive, automated test suite designed to verify functional correctness, system invariants, security boundaries, and architectural isolation.

### Current Test Metrics
- **Test Framework:** Vitest v1.6.1 with V8 Coverage
- **Total Test Cases:** 506 tests across 28 test suites
- **Pass Rate:** 100%
- **Line Coverage Target:** ≥ 90% overall (minimum enforced threshold: 80%)

---

## 2. Testing Stack & Environment

| Component | Technology | Purpose |
|-----------|------------|---------|
| Test Runner | [Vitest](https://vitest.dev/) | High-performance ESM test execution |
| Coverage Engine | `@vitest/coverage-v8` | Accurate line, statement, and branch coverage reporting |
| Test Database | Docker MongoDB (`saferepo_test`) / `mongodb-memory-server` | Full MongoDB database instance for realistic aggregation, indexing, and TTL behavior |
| Mocking | Vitest built-in (`vi.spyOn`, `vi.fn`, `vi.mock`) | Module and network isolation without third-party libraries |
| UI Rendering | `react-dom/server` | Fast server-side component rendering and HTML snapshot verification without heavy DOM emulators |

---

## 3. Test Categories & Organization

Test files reside in `__tests__` subdirectories adjacent to the modules they validate:

### 3.1 Scanner & Worker Tests (`src/lib/scanner/__tests__/`)
- **`queue.test.ts`:** FIFO queue claiming, atomic `findOneAndUpdate` leasing, stale scan sweeper, heartbeat updates, cancellation handling.
- **`retention.test.ts`:** TTL expiration cleanup, cascade deletion of findings, per-user scan cap enforcement, active scan protection.
- **`normalizer.test.ts`:** Cross-scanner deduplication, deterministic vulnerability fingerprinting, SARIF/OSV/Trivy normalization.
- **`semgrep.test.ts`:** SAST rule execution, output parsing, Stage 1 Docker runner isolation.
- **`trivy.test.ts`:** SCA dependency vulnerability scanning, lockfile parsing.
- **`osv.test.ts`:** OSV API batch vulnerability query client, retry logic, timeout handling.
- **`gitleaks.test.ts`:** Secret detection and automatic redaction of leaked credentials.
- **`workspace.test.ts`:** Workspace acquisition, symlink escape prevention, directory cleanup.
- **`orchestrator.test.ts`:** Multi-scanner sequential execution, global deadline enforcement, container abort handling.

### 3.2 API Route Integration Tests (`src/app/api/**/__tests__/`)
- **`scan-lifecycle.test.ts`:** `DELETE /api/v1/scans/:id` (cascade deletion, 409 in-progress rejection, 429 rate limit), `POST /api/v1/scans/:id/cancel` (queued/in-progress cancellation), and extended `GET /api/health`.
- **`security-hardening.test.ts`:** CSP headers, error sanitization, anti-enumeration boundaries (404 not 403), request ID tracing, header redaction.
- **`scans.test.ts`:** `POST /api/v1/scans` creation, input validation, repository size checks, pagination.
- **`findings.test.ts`:** Findings filtering (severity, scanner, category), pagination, and rate limiting.
- **`health.test.ts`:** Health check availability and status.

### 3.3 Security & Auth Tests (`src/lib/**/__tests__/`)
- **`session.test.ts`:** Opaque session creation, TTL expiration, logout, cookie attributes.
- **`rate-limit.test.ts`:** In-memory sliding window algorithm, window reset, header generation.
- **`github.test.ts`:** GitHub App token exchange, repository metadata fetching.

### 3.4 Dashboard UI Component Tests (`src/components/__tests__/`)
- **`dashboard-components.test.ts`:** Server-side component rendering tests for scan cards, findings tables, badge components, and filters using `react-dom/server`.

---

## 4. Test Execution Commands

All commands should be executed from the `apps/web/` directory:

```bash
# Run all tests once
npm run test

# Run tests with V8 coverage report
npm run test:coverage

# Run tests in watch mode
npx vitest

# Run a specific targeted test file
npx vitest run src/lib/scanner/__tests__/retention.test.ts
npx vitest run src/app/api/__tests__/scan-lifecycle.test.ts
npx vitest run src/app/api/__tests__/security-hardening.test.ts

# Run tests matching a pattern
npx vitest run queue
```

---

## 5. Database Setup for Tests

Tests connect to MongoDB via `src/test/setup.ts`:
1. **Primary:** Connects to Docker MongoDB instance on `localhost:27017` (`mongodb://admin:password@localhost:27017/saferepo_test?authSource=admin`).
2. **Fallback:** Automatically starts `MongoMemoryServer` if Docker is unavailable (e.g., in minimal CI environments).
3. **Isolation:** Collections are purged automatically `afterEach()` test to guarantee pristine state for every test case.

---

## 6. CI/CD Enforcement

The GitHub Actions workflow (`.github/workflows/ci.yml`) enforces the following gates before code can be merged:
- `npm run lint` — 0 ESLint warnings or errors
- `npm run typecheck` — 0 TypeScript compiler errors (`tsc --noEmit`)
- `npm run test:coverage` — 100% test pass rate and line coverage meeting the 80% threshold
- `npm audit --omit=dev --audit-level=high` — 0 high/critical production dependency vulnerabilities
- `npm run build` — Production Next.js build succeeds cleanly
