# SafeRepo Phase 10 — Beta Test Plan & Operational Specification

> **Phase:** Phase 10 — 100-User Beta Testing & Operational Readiness Validation
> **Committed Baseline:** `4a74682c3e9998bf916c891b7a66394cbbf8b19b` (`fix: resolve phase 09 production e2e issues`)
> **Document Status:** Operational Master Plan — Governed by Phase 10 Implementation Approval Gate

---

## 1. Overview & Objective

The objective of Phase 10 is to execute a controlled, empirical, evidence-driven beta testing program with up to 100 users on the containerized SafeRepo deployment architecture established in Phase 09.

Phase 10 evaluates operational reliability, scanner pipeline stability, queue integrity, database lifecycle management, user journey ergonomics, and threat boundary resilience under realistic multi-user usage patterns.

**Phase 10 is strictly an operational validation and hardening phase, NOT a feature-expansion phase.**

### 1.1 Scope Boundaries & Non-Goals
The following activities are strictly **OUT OF SCOPE** for Phase 10:
- No new scanners (Semgrep, Trivy, OSV, Gitleaks, npm audit, and pip-audit only).
- No Kubernetes or Helm migrations; the Phase 09 Docker Compose architecture is preserved.
- No architecture rewrite; the dual-tier web/worker design is maintained.
- No external message brokers (no Redis, RabbitMQ, Kafka, or Celery); the MongoDB atomic FIFO queue is retained.
- No dashboard redesigns or feature creep beyond Phase 07/08.
- No multi-tenant organizations or RBAC.
- No WebSockets or SSE; polling with exponential backoff is maintained.
- No replacement of MongoDB or the Docker socket proxy boundary.
- No automated cloud deployment; deployment remains human-controlled.

---

## 2. Beta User Model & Rollout Strategy

### 2.1 Population vs. Concurrency Invariant
> [!IMPORTANT]
> **"Up to 100 beta users does not imply 100 simultaneous scans."**
> SafeRepo's Phase 09 architecture uses a dedicated scan worker configured for sequential execution (`MAX_CONCURRENT_SCANS: 1`). A population of 100 registered beta users represents an asynchronous, distributed user base with estimated concurrency parameters that must be empirically measured rather than assumed:
> - **Total Beta Participants:** Up to 100 invited GitHub accounts registered over the entire beta period.
> - **Simultaneously Active Users (Browsing):** Estimated 3–8 concurrent users browsing dashboards and viewing findings.
> - **Concurrent In-Flight Scans:** 1 active scan executing on the worker, with additional scans buffered in MongoDB in `queued` status.

### 2.2 Staged Rollout Cohorts

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           STAGED BETA ROLLOUT COHORTS                             │
├─────────────────┬─────────────────┬───────────────────┬───────────────────────────┤
│ Cohort 1        │ Cohort 2        │ Cohort 3          │ Cohort 4                  │
│ Internal Canary │ Small Cohort    │ Expanded Cohort   │ Full 100-User Beta        │
│ (1–5 users)     │ (10–25 users)   │ (25–50 users)     │ (Up to 100 users)         │
│ Baseline checks │ Real public repos│ Mixed workloads   │ High concurrency & stress │
└────────┬────────┴────────┬────────┴─────────┬─────────┴─────────────┬─────────────┘
         ▼                 ▼                  ▼                       ▼
    Gate 1 Review     Gate 2 Review      Gate 3 Review           Exit Assessment
```

| Cohort | Size | Target Persona | Repository Types | Validation Scope | Gating Requirement for Advancement |
|---|---|---|---|---|---|
| **Cohort 1: Internal Canary** | 1–5 users | SafeRepo maintainers | Known test fixtures, benchmark vulnerable repos | Stack startup, log output, Semgrep/Trivy/Gitleaks/OSV baseline execution | Zero security invariant violations; clean test execution on standard fixtures |
| **Cohort 2: Small Cohort** | 10–25 users | Trusted external developers | Public repos (< 50MB) across Node.js & Python | Ecosystem detection, lockfile parsing, finding normalization, npm audit / pip-audit parity | Zero unhandled worker crashes; baseline completion rate established |
| **Cohort 3: Expanded Cohort** | 25–50 users | Open-source maintainers | Varied public repos, larger codebases (< 100MB) | Measure queue buffering under concurrent requests; test cancellation and timeouts | Mean scan duration measured; queue recovery verified under burst submissions |
| **Cohort 4: Full Beta** | Up to 100 users | General beta signups | Full spectrum of authorized repositories within size limits | Measure multi-day stability, TTL retention cleanup, rate-limit enforcement, and user defect intake | All Phase 10 Exit Criteria satisfied |

### 2.3 Authentication & Test Identity Invariant
- **Authentication Model:** SafeRepo relies strictly on GitHub App OAuth exchanging tokens for server-side sessions stored in MongoDB.
- **No Synthetic In-Memory Users:** Mock or synthetic authentication bypasses (e.g. `test-user-*`) must NOT be used for beta validation.
- **Controlled Test Accounts:** Where automated or isolated maintainer testing is required, human operators provision dedicated GitHub test accounts.
- **Credential Hygiene Invariant:** All OAuth Client IDs, Client Secrets, and GitHub App private keys remain human-managed in server-side `.env.production` (`chmod 600`). No real credentials will ever be placed in version control or supplied to AI agents.

---

## 3. User Journey Validation Matrix

Each journey is reviewed strictly against the actual implemented codebase:

| ID | User Journey | Implemented in Codebase? | Implementation Reference | Validation Objective & Invariants |
|---|---|---|---|---|
| **UJ-A** | GitHub App OAuth & Session Initiation | **YES** | `/api/v1/auth/github`, `session.ts` | Verify redirect to GitHub, code exchange, creation of session with default 24h TTL, and setting of HttpOnly cookie (`SameSite=Lax`). |
| **UJ-B** | Dashboard Overview & Metrics | **YES** | `/dashboard`, RSC, Mongoose | Measure server-render latency for total scans and findings breakdown; verify zero client-side layout shift. |
| **UJ-C** | Public Repo Scan by Manual Owner/Name | **YES** | `NewScanForm.tsx`, `/api/v1/scans` | Authenticated user enters public repo owner/name (e.g. `facebook/react`); verify GitHub access check, queueing, and execution. |
| **UJ-D** | Archive / File Upload Scan | **NO** | *None* | **Not currently implemented / not a Phase 10 validation target.** (SafeRepo acquires repos strictly via git clone from GitHub). |
| **UJ-E** | GitHub App Installation Repo Selection | **YES** | `NewScanForm.tsx`, `/api/v1/repos` | Verify listing of repositories where the user has authorized the GitHub App; select repo and default branch. |
| **UJ-F** | Scan Initiation via UI | **YES** | `NewScanForm.tsx`, `/api/v1/scans` | Verify form validation, button loading state, submission to `/api/v1/scans`, receipt of HTTP 201, and redirect to detail page. |
| **UJ-G** | Scan Lifecycle & Real-Time Polling | **YES** | `ScanDetail.tsx`, `ScanPollingWrapper.tsx` | Observe status progression `queued` → `cloning` → `scanning` → `normalizing` → `completed`; verify exponential backoff stops on terminal state. |
| **UJ-H** | Findings Triage & Remediation View | **YES** | `FindingRow.tsx`, `FindingsFilter.tsx` | Verify severity categorization (Critical, High, Medium, Low); verify secret findings show `[REDACTED SECRET]`; test filtering by scanner and file. |
| **UJ-I** | Scan History & Pagination | **YES** | `/dashboard`, Scan Model | Verify historical scans listed with correct status badges; test pagination cursor behavior. |
| **UJ-J** | Failed Scan Handling | **YES** | `orchestrator.ts`, Scan Model | Inject invalid build file; verify transition to `failed`; measure error sanitization (zero stack traces leaked). |
| **UJ-K** | Timed-Out Scan Handling | **YES** | `orchestrator.ts`, `runner.ts` | Force execution beyond `SCAN_TIMEOUT_SECONDS` (300s); verify abort controller kills containers; verify status marked `timed_out`. |
| **UJ-L** | Invalid Repository Input | **YES** | `schemas.ts`, `/api/v1/scans` | Submit empty owner, invalid characters, or non-existent repo; verify HTTP 400/404 response with structured error JSON. |
| **UJ-M** | Empty / Minimal Repository | **YES** | `acquisition.ts`, `orchestrator.ts` | Scan repository with 0 code files; verify clean completion in < 15s with 0 findings and status `completed`. |
| **UJ-N** | Large Repository Threshold Guard | **YES** | `/api/v1/scans/route.ts` (`MAX_REPO_SIZE_MB`) | Submit repo reporting size > `MAX_REPO_SIZE_MB` (100MB default); verify pre-flight rejection with HTTP 400 before cloning. |
| **UJ-O** | In-Flight Scan Cancellation | **YES** | `POST /api/v1/scans/:id/cancel`, worker | Request cancellation of active scan; verify `cancelRequested: true` detected by worker heartbeat; measure time to container termination. |
| **UJ-P** | Session Expiration & Re-Authentication | **YES** | `auth.ts`, `session.ts` | Test API and dashboard behavior when session expires in MongoDB; verify HTTP 401 on API and redirect to `/login` on UI. |

---

## 4. Complete Scanner Architecture Coverage

SafeRepo's static analysis and dependency scanning engine encompasses six integrations. Phase 10 explicitly validates all six:

```
                               SAFE REPO UNIFIED SCAN ENGINE
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             STATIC ANALYSIS (SAST & SECRETS)             DEPENDENCY VULNERABILITY (SCA)
             • Semgrep SAST (Docker Stage 1)              • Trivy Container SCA
             • Gitleaks Secrets (Docker Stage 1)          • OSV Batch API Client
                                                          • npm audit Parser / Normalizer
                                                          • pip-audit Parser / Normalizer
```

| Scanner Engine | Architecture / Mechanism | Sandbox & Resource Constraints | Target Ecosystem | Cohort Validation Strategy |
|---|---|---|---|---|
| **Semgrep SAST** | Ephemeral Docker container (`semgrep:1.100.0`) with offline rules | `--network=none`, `--read-only`, tmpfs, 512MB RAM, unprivileged UID | JavaScript, TypeScript, Python, Go | **Cohorts 1–4:** Validated across all codebases for syntax patterns, CWE, and OWASP Top 10 rules. |
| **Trivy SCA** | Ephemeral Docker container (`trivy:0.59.1`) | `--network=none`, `--read-only`, tmpfs, 512MB RAM, unprivileged UID | Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`) | **Cohorts 1–4:** Validated against known vulnerable lockfile fixtures and open-source project lockfiles. |
| **Gitleaks** | Ephemeral Docker container (`gitleaks:v8.24.0`) with stdout redaction | `--network=none`, `--read-only`, tmpfs, 512MB RAM, unprivileged UID | Git history and working tree | **Cohorts 1–4:** Validated with synthetic leaked credentials; verify secret replacement with `[REDACTED SECRET]`. |
| **OSV Batch Client** | In-process HTTPS client querying `api.osv.dev/v1/querybatch` | 30s timeout, exponential backoff retries, manifest coordinates only | npm and Python package coordinates | **Cohorts 1–4:** Validated for direct dependency vulnerability enrichment; results merged and deduplicated with Trivy. |
| **npm audit** | Ecosystem detection in `ecosystem.ts` + normalizer in `normalizer.ts` | Static manifest parsing without executing npm lifecycle scripts | Node.js (`package.json`, `package-lock.json`) | **Cohorts 2–4:** Validated on Node.js repositories; verify advisory parity and finding classification. |
| **pip-audit** | Ecosystem detection in `ecosystem.ts` + PEP 503 normalization | Static manifest parsing (`requirements.txt`, `Pipfile.lock`, `poetry.lock`) | Python ecosystem | **Cohorts 2–4:** Validated on Python repositories; verify package normalization and advisory extraction. |

---

## 5. Concurrency, Queue, & Resource Validation Plan

### 5.1 Configured Limits vs. Observed Metrics vs. Proposed Targets

| Component | Configured Limit (Phase 09 Invariant) | Metric to be Observed & Measured | Proposed Acceptance Target (Hypothesis) |
|---|---|---|---|
| **Web Container** | 1.0 vCPU, 512MB RAM cap | Peak CPU%, RSS memory during dashboard browsing | RSS memory remains < 350MB under 10 concurrent requests |
| **Worker Container** | 1.5 vCPU, 1024MB RAM cap | Memory growth over 25+ consecutive scans | Zero unbounded memory leak; baseline RSS < 300MB |
| **Scanner Child Containers** | 512MB RAM cap per container | OOM termination frequency and container exit codes | 0 OOM kills on standard repos (< 50MB) |
| **Global Scan Deadline** | `SCAN_TIMEOUT_SECONDS = 300s` | Scan duration distribution across repository sizes | Mean scan duration < 120s for repos < 50MB |
| **Queue Concurrency** | 1 active scan per worker instance (`MAX_CONCURRENT_SCANS: 1`) | Queue wait duration from `queued` to `cloning` | FIFO order strictly maintained; zero dropped jobs |
| **Heartbeat & Sweeper** | Heartbeat 15s; Stale threshold 360s (`SCAN_STALE_TIMEOUT_MS`) | Frequency of sweeper intervention and recovery delay | Stale scans finalized as `failed` within 15s after stale threshold |

### 5.2 Controlled Load Scenarios (Cohorts 3 & 4)
- **Scenario L1 (Burst Ingestion):** Concurrently submit 5 scans within 5 seconds.
  *Validation Objective:* Verify all 5 jobs receive `queued` status in MongoDB, and worker processes each sequentially in FIFO order without duplicate execution.
- **Scenario L2 (Dashboard Navigation Under Load):** Simulate 10 concurrent browsing sessions requesting `/dashboard` and `/api/v1/scans/:id/findings`.
  *Validation Objective:* Measure HTTP response latency and verify rate-limiter headers (`X-RateLimit-*`) function without false positives.
- **Scenario L3 (Continuous Pipeline Endurance):** Execute 20 consecutive scans back-to-back.
  *Validation Objective:* Measure host Docker daemon container pruning, worker memory stability, and temporary workspace directory cleanup.

---

## 6. Security Invariants & Stop Conditions

### 6.1 Preserved Phase 09 CSP Baseline
SafeRepo strictly maintains the CSP evaluated and approved in Phase 09:
```text
script-src 'self' 'unsafe-inline'
```
- **Policy Invariant:** Transitioning to a dynamic nonce-based CSP remains a future post-beta hardening item. The current baseline is frozen for Phase 10 unless empirical beta testing uncovers an actionable security vulnerability requiring CSP modification.

### 6.2 Mandatory Security Stop Conditions (Zero Tolerance)
Beta operations must be **immediately halted** if any of the following occur:
1. **Unexpected Scanner Network Access:** Any child scanner container (`semgrep`, `trivy`, `gitleaks`) makes an outbound network call (violating `--network=none`).
2. **Unexpected Host Filesystem Access:** Any container accesses or modifies host paths outside its assigned temporary `/tmp/saferepo-workspaces/*` directory.
3. **Docker Socket Access from Web:** The `web` container establishes communication with `/var/run/docker.sock` or any Docker API.
4. **Unauthorized Docker API Capability:** The worker process triggers an unpermitted Docker API action through `docker-proxy` (e.g. creating volumes, altering networks, triggering builds).
5. **Scanner Container Escape:** Any child scanner process breaks container namespace isolation.
6. **Cross-User Data Access:** Any authenticated user can view, cancel, or delete scans or findings belonging to another user.
7. **Secret or Token Exposure:** Any GitHub token, session secret, or scanned repository credential appears in plain text in logs, error responses, or UI views.

---

## 7. Failure & Recovery Testing Plan (Measurable Objectives)

| Fault Injection Scenario | Injected Condition | Measurable Validation Objective | Expected System Behavior |
|---|---|---|---|
| **FR-1: Web Service Restart** | Execute `docker restart saferepo-web` during active browsing | Measure downtime and client request failure behavior during restart | Test whether client receives 502 from Caddy or buffers cleanly; measure restart time; verify active sessions in DB remain valid post-restart. |
| **FR-2: Worker Interruption During Scan** | Execute `docker kill saferepo-worker` while scan is in `scanning` | Measure time elapsed before stale lease is detected and recovered | Verify worker heartbeat lapses; verify sweeper reclaims job after stale timeout; verify scan finalized as `failed` cleanly. |
| **FR-3: MongoDB Disconnection** | Pause MongoDB container for 15s, then unpause | Measure connection pool reconnection latency in Web and Worker tiers | Verify Mongoose connection buffering; verify zero unhandled process crashes; verify `/api/health` transitions from `degraded` back to `healthy`. |
| **FR-4: Scanner Container Abort / OOM** | Feed scanner container a fixture designed to trigger 512MB RAM cap | Observe exit code handling and error reporting | Verify container terminated with exit code 137; verify orchestrator catches OOM without worker crash; verify scan marked `failed` with sanitized error. |
| **FR-5: Acquisition Failure** | Request scan on non-existent repository branch | Measure error handling and workspace cleanup | Verify git clone fails cleanly; verify workspace directory deleted immediately; verify scan marked `failed`. |
| **FR-6: Active Scan Cancellation** | Call `POST /api/v1/scans/:id/cancel` while Semgrep is executing | Measure time from API request to child container kill and workspace wipe | Verify `cancelRequested: true` detected; verify child container killed within 10s; verify scan marked `failed` ("Cancelled by user"). |

---

## 8. Observability & Monitoring Plan (Zero-New-Dependency Model)

Phase 10 relies strictly on existing Phase 01–09 observability tooling:
- **Pino JSON Structured Logs:** Inspected via `docker logs saferepo-web` and `docker logs saferepo-worker`, filtering on `X-Request-Id` and `scanId`.
- **Health API Endpoint:** Periodic polling of `/api/health` recording:
  - `status`: `"ok"` | `"degraded"`
  - `db`: `"connected"` | `"disconnected"`
  - `queue.pending`: Count of jobs in `queued` status
  - `uptime`: Process uptime in seconds
- **Docker Resource Telemetry:** Periodic snapshots via `docker stats --no-stream` logging CPU%, Memory Usage, and Network I/O.
- **MongoDB Queue Inspection:** Read-only administrative aggregation queries tracking state distribution across `queued`, `cloning`, `scanning`, `normalizing`, `completed`, `failed`, and `timed_out`.

---

## 9. Data Lifecycle & Retention Validation Objectives

1. **Scan Deletion Validation (`DELETE /api/v1/scans/:id`):** Verify that deleting a scan removes the scan document, cascade-deletes all associated finding documents in MongoDB, and wipes any lingering workspace folders. Verify that in-progress scans return HTTP 409 Conflict.
2. **TTL Index Validation:** Observe MongoDB `sessions` collection over 24+ hours to confirm expired sessions are pruned by MongoDB background TTL threads (`expiresAt` index).
3. **Scan Cap Enforcement (`MAX_SCANS_PER_USER = 500`):** Ingest test scans to verify oldest terminal scans are pruned when the per-user cap is reached.

---

## 10. Defect Severity & Response Model

| Severity Level | Definition | Beta Action & Rollout Impact |
|---|---|---|
| **P0: Blocker** | Security invariant violation, data corruption, secret leak, or complete stack crash. | **Immediate Beta Halt.** Trigger Stop Condition; pause onboarding; resolve, verify, and obtain approval before resuming. |
| **P1: Critical** | Core scanning pipeline broken for all repositories; worker queue deadlock; persistent database drop. | Halt cohort advancement. Resolve within 24h; run full regression suite before resuming. |
| **P2: High** | Scanning failure on a specific language ecosystem; cancellation failure; rate limiting false blocks. | Resolve within 48h. Must be resolved before advancing to subsequent cohort. |
| **P3: Medium** | UI presentation glitch, false-positive scanner rule, non-critical filter issue. | Triage into regular iteration cycle. Does not halt cohort advancement. |
| **P4: Low** | Minor cosmetic styling issue, documentation typo, minor suggestion. | Backlog for post-beta polish. |

---

## 11. Beta Exit Criteria (Categorized Gates)

### Category A: Mandatory Security Invariants (Zero Tolerance)
- [ ] 0 occurrences of scanner container network access (`--network=none` strictly maintained).
- [ ] 0 occurrences of host filesystem access outside assigned temporary workspaces.
- [ ] 0 occurrences of Docker socket accessibility from the `web` container.
- [ ] 0 unauthorized Docker API calls permitted by `docker-proxy`.
- [ ] 0 container escapes or privilege escalations.
- [ ] 0 cross-user data leaks in API or UI.
- [ ] 0 plain-text secrets or tokens logged or exposed in responses.

### Category B: Core Project Requirements
- [ ] All 4 beta cohorts executed sequentially with documented gating approvals.
- [ ] All 6 scanner engines (Semgrep, Trivy, Gitleaks, OSV, npm audit, pip-audit) validated on real-world repositories.
- [ ] Scan cancellation (`/cancel`) and scan deletion (`DELETE`) validated in production stack.
- [ ] Zero open P0 (Blocker) or P1 (Critical) defects in the issue tracker.

### Category C: Measured Beta Performance Targets (Empirical)
- [ ] Baseline scan completion rate measured on valid repositories across all cohorts (target: ≥ 98%).
- [ ] Mean scan duration and P95 latency documented across repository size tiers.
- [ ] Stale worker lease recovery time measured and documented under simulated failure.
- [ ] Memory and CPU utilization under sustained scan execution measured and verified stable.

### Category D: Operational & Documentation Readiness
- [ ] Automated TTL cleanup and cascade deletion verified active in MongoDB.
- [ ] All Phase 10 deliverables authored, reviewed, and archived.
- [ ] Final Phase 10 Beta Report presented to human reviewer for GA closeout.
