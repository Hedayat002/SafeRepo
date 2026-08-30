# TESTING_PLAN.md — SafeRepo

**Status:** Draft — Tests will be written during implementation phases, not before.

---

## Strategy (Testing Pyramid)

```
E2E (Playwright)       — 10% — critical user flows
Integration            — 30% — API + DB + scanner orchestration
Unit                   — 60% — services, utils, normalizers
```

---

## Coverage

- Target: 80% line coverage for `services/`, `lib/`, `packages/`
- CI fails if coverage drops below 80% or any test fails

---

## Test Categories

### 1. Unit Testing

Test individual functions and modules in isolation.

**Areas:**
- Finding normalization (each scanner's output → unified schema)
- Severity classification logic
- Fingerprint generation (deduplication hashes)
- Input validation schemas (Zod)
- Secret redaction logic (ensure secret values are stripped)
- Repository URL parsing and validation
- Scan status state machine transitions

**Framework:** Vitest

---

### 2. Integration Testing

Test API routes with real database and mocked external services.

**Areas:**
- Authentication flow (GitHub OAuth mock)
- Scan creation and status tracking
- Findings storage and retrieval
- Findings filtering and pagination
- Rate limiting behavior
- Error responses (400, 401, 403, 404, rate limit)
- Database cascade deletes (user → scans → findings)
- Health check endpoint

**Framework:** Vitest + Supertest
**Test DB:** mongodb-memory-server (in-memory MongoDB for test isolation)

---

### 3. End-to-End Testing

Test complete user flows through the browser.

**Flows:**
- Login via GitHub → Dashboard → Select repo → Start scan → View findings
- Scan timeout handling → user sees appropriate status
- Finding filtering by severity and category
- Scan history navigation

**Framework:** Playwright

---

### 4. Security Testing

Validate security controls are enforced.

**Areas:**
- Authentication required on protected endpoints
- Authorization: users can only access their own scans
- Input validation rejects malicious input (NoSQL injection attempts, XSS payloads)
- Rate limiting triggers on excessive requests
- CORS rejects unauthorized origins
- Secret redaction: no secret values in API responses or logs
- No secrets committed in source code (`npm audit`, Gitleaks on SafeRepo itself)
- Security headers present (Helmet)

---

### 5. Scanner Testing

Validate scanner integration and output normalization.

**Areas:**
- Semgrep: runs on a known-vulnerable test repo, produces expected findings
- Trivy: detects known CVEs in a test `package-lock.json`
- Gitleaks: detects planted test secrets, verifies redaction
- OSV API: returns expected vulnerabilities for known packages
- npm audit: produces expected output for a test `package-lock.json`
- pip-audit: produces expected output for a test `requirements.txt` (where applicable)
- Normalization: each scanner's raw output maps correctly to the unified findings schema
- Partial failure: one scanner failing does not prevent other results from being stored

**Approach:** Use a fixed test repository with known vulnerabilities, secrets, and dependency issues. Assert expected findings count and content.

---

### 6. Container Isolation Testing

Validate Docker container security controls.

**Areas:**
- Container runs with `--network=none` (no outbound network access)
- Container runs with `--read-only` filesystem
- Container runs with `--cap-drop=ALL`
- Container runs with `--security-opt=no-new-privileges`
- Container respects memory limit (`--memory=512m`)
- Container respects CPU limit (`--cpus=1`)
- Container respects PID limit (`--pids-limit=256`)
- Container is removed after execution (`--rm`)
- Timeout kills container after configured duration
- Symlinks outside workspace are blocked

---

### 7. Input Validation Testing

Validate all user-facing inputs are properly validated.

**Areas:**
- Repository URL validation (must be valid GitHub URL)
- Branch name validation
- Scan request validation (required fields, types)
- Query parameter validation (pagination, filters)
- Rejection of unexpected/extra fields
- Rejection of oversized payloads

---

### 8. Authentication & Authorization Testing

**Areas:**
- Unauthenticated requests → 401
- Valid authentication → 200
- User A cannot access User B's scans → 403
- Expired/invalid sessions → 401
- OAuth callback with invalid state → 400
- Logout properly terminates session

---

### 9. Failure & Timeout Testing

Validate graceful handling of errors and timeouts.

**Areas:**
- Scanner timeout: container killed, scan marked "timed_out"
- Scanner crash: container error captured, scan marked "failed" with error message
- MongoDB connection failure: health check reports "down", API returns 503
- GitHub API failure: graceful error with retry guidance
- Repository clone failure (repo too large, private without access): scan marked "failed"
- Partial scanner failure: successful scanner results are still stored

---

## Tooling

| Tool | Purpose |
|------|---------|
| Vitest | Unit and integration tests |
| Supertest | HTTP-level API testing |
| Playwright | End-to-end browser tests |
| mongodb-memory-server | In-memory MongoDB for test isolation |

No additional test tooling without justification.

---

## Running Tests

```bash
npm run test          # unit + integration
npm run test:e2e      # playwright (requires running app)
npm run test:coverage # coverage report
```

CI runs all tests on push/PR. Build fails if tests fail or coverage drops below threshold.

---

## Test Data

- Use a fixed, version-controlled test repository with known vulnerabilities, secrets, and dependency issues for scanner integration tests
- Use mongodb-memory-server for database tests (isolated per test suite)
- Seed data for integration tests created in test setup, cleaned up in teardown
- No hardcoded credentials in test fixtures

---

## Open Testing Questions

> TBD — The following require decisions during implementation:

- Test repository hosting (fixture in repo vs external test repo)
- Docker-in-Docker testing strategy for CI (GitHub Actions)
- Performance/load testing approach for scan queue under concurrent users
- Visual regression testing for dashboard components
