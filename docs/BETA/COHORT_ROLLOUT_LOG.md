# SafeRepo Phase 10 — Beta Cohort Rollout Log

> **Current Status:** Not Started — Awaiting Phase 10 Implementation Review & Gate Sign-off
> **Committed Baseline:** `4a74682c3e9998bf916c891b7a66394cbbf8b19b` (`fix: resolve phase 09 production e2e issues`)
> **Master Test Plan:** [BETA_TEST_PLAN.md](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/docs/BETA/BETA_TEST_PLAN.md)

---

## 1. Rollout Overview & Cohort Schedule

Progression between beta cohorts is strictly sequential and evidence-gated. Advancing to the next cohort requires meeting all entry and exit criteria with zero unresolved P0 (Blocker) or P1 (Critical) defects.

| Cohort | Target Population | Target Workload | Status | Entry Gate Sign-off | Exit Gate Sign-off |
|---|---|---|---|---|---|
| **Cohort 1: Internal Canary** | 1–5 users (Maintainers) | Benchmark & synthetic fixtures | ⬜ Not Started | Pending | Pending |
| **Cohort 2: Small Cohort** | 10–25 users (Trusted Devs) | Public repos (< 50MB) across JS & Python | ⬜ Not Started | Pending | Pending |
| **Cohort 3: Expanded Cohort** | 25–50 users (OSS Maintainers) | Diverse public codebases & monorepos (< 100MB) | ⬜ Not Started | Pending | Pending |
| **Cohort 4: Full Beta** | Up to 100 users (General Beta) | Full multi-ecosystem repository workload | ⬜ Not Started | Pending | Pending |

---

## 2. Cohort 1: Internal Canary (1 to 5 Users)

### 2.1 Cohort Specification
- **User Population:** Core SafeRepo maintainers using dedicated, controlled test GitHub accounts.
- **Repository Scope:** Known test fixtures, intentionally vulnerable benchmark repositories (e.g. `juice-shop`, `vuln-node`), and minimal repositories.
- **Primary Scanners Tested:** Semgrep SAST, Trivy SCA, Gitleaks Secret Scanner, OSV Batch Client.
- **Validation Objectives:**
  - Verify clean startup of 5-service container stack.
  - Verify Pino structured JSON logs with `X-Request-Id` correlation.
  - Verify Stage 1 scanner isolation (`--network=none`, `--read-only`, tmpfs, unprivileged UID).
  - Verify zero container escapes, zero socket leaks, and zero secret logging.

### 2.2 Entry Criteria
- [ ] Phase 10 implementation plan approved by human reviewer.
- [ ] Production Compose stack (`docker-compose.prod.yml`) verified locally via `validate-production.ts`.
- [ ] Test accounts prepared with least-privilege GitHub App permissions.

### 2.3 Execution & Observation Log
*(To be populated during Cohort 1 execution)*

| Execution Date | Test ID | Repository Tested | Scanner Results | Scan Status | Duration | Anomalies / Observations |
|---|---|---|---|---|---|---|
| *Pending* | C1-01 | Synthetic Clean Repo | Semgrep: 0, Trivy: 0, OSV: 0, Gitleaks: 0 | *Pending* | *Pending* | *Awaiting run* |
| *Pending* | C1-02 | Known Vulnerable Repo | Findings correctly categorized | *Pending* | *Pending* | *Awaiting run* |
| *Pending* | C1-03 | Leaked Secret Fixture | Gitleaks: Redacted snippet confirmed | *Pending* | *Pending* | *Awaiting run* |

### 2.4 Cohort 1 Exit Gate Sign-Off
- [ ] 100% of benchmark scan executions completed without unhandled exceptions.
- [ ] Zero security invariant violations.
- [ ] Human reviewer sign-off granted to advance to Cohort 2.

---

## 3. Cohort 2: Small External Cohort (10 to 25 Users)

### 3.1 Cohort Specification
- **User Population:** 10–25 trusted external software developers.
- **Repository Scope:** Real open-source public repositories (< 50MB) across Node.js (`package.json`, `package-lock.json`) and Python (`requirements.txt`, `Pipfile.lock`, `poetry.lock`).
- **Primary Scanners Tested:** All 6 engines — Semgrep, Trivy, OSV, Gitleaks, npm audit, and pip-audit.
- **Validation Objectives:**
  - Verify ecosystem detection and dependency coordinate extraction.
  - Verify finding deduplication and normalized severity assignment.
  - Measure baseline scan duration and completion rate.
  - Collect initial developer feedback on dashboard findings presentation.

### 3.2 Entry Criteria
- [ ] Cohort 1 successfully closed with verified zero-defect report.
- [ ] Beta user invitation runbook executed for Cohort 2.

### 3.3 Execution & Observation Log
*(To be populated during Cohort 2 execution)*

| Date | User / Org | Repository Scanned | Ecosystems | Total Findings | Duration | Status | Notes / Feedback |
|---|---|---|---|---|---|---|---|
| *Pending* | *User-01* | *Public Node.js Repo* | npm | *Pending* | *Pending* | *Pending* | *Awaiting Cohort 2* |
| *Pending* | *User-02* | *Public Python Repo* | pip | *Pending* | *Pending* | *Pending* | *Awaiting Cohort 2* |

### 3.4 Cohort 2 Exit Gate Sign-Off
- [ ] Baseline scan completion rate established and documented.
- [ ] Zero unhandled worker crashes or queue stalls.
- [ ] Zero unresolved P0/P1 defects.
- [ ] Human reviewer sign-off granted to advance to Cohort 3.

---

## 4. Cohort 3: Expanded Cohort (25 to 50 Users)

### 4.1 Cohort Specification
- **User Population:** 25–50 open-source maintainers and developers.
- **Repository Scope:** Varied public repositories and monorepos (< 100MB).
- **Validation Objectives:**
  - Measure queue buffering and FIFO dispatch under burst submissions.
  - Execute controlled in-flight scan cancellations via UI and API.
  - Observe worker heartbeat logging and stale-scan recovery sweeper.
  - Measure container CPU/RAM utilization during multi-scan processing.

### 4.2 Entry Criteria
- [ ] Cohort 2 successfully closed with verified zero-defect report.
- [ ] Feedback from Cohort 2 triaged and resolved.

### 4.3 Execution & Observation Log
*(To be populated during Cohort 3 execution)*

| Date | Burst / Concurrency Test | Scans Enqueued | Queue Wait Time | Processing Time | Status | System Telemetry |
|---|---|---|---|---|---|---|
| *Pending* | 5-Scan Burst | 5 | *Pending* | *Pending* | *Pending* | *Awaiting Cohort 3* |

### 4.4 Cohort 3 Exit Gate Sign-Off
- [ ] Mean scan duration and queue latency empirically measured.
- [ ] In-flight cancellation verified terminating child containers within 10s.
- [ ] Zero unresolved P0/P1 defects.
- [ ] Human reviewer sign-off granted to advance to Cohort 4.

---

## 5. Cohort 4: Full 100-User Beta Cohort (Up to 100 Users)

### 5.1 Cohort Specification
- **User Population:** Full beta cohort (up to 100 registered GitHub accounts).
- **Workload:** General multi-user operational scanning.
- **Validation Objectives:**
  - Verify sustained multi-day stability with zero memory leakage.
  - Observe automated TTL expiration of 24h sessions in MongoDB.
  - Verify rate-limiting enforcement on high-frequency API requests.
  - Complete operational evaluation of the Phase 09 deployment architecture.

### 5.2 Entry Criteria
- [ ] Cohort 3 successfully closed with verified stability report.
- [ ] Full defect tracker reviewed; all P0/P1/P2 items closed.

### 5.3 Execution & Observation Log
*(To be populated during Cohort 4 execution)*

| Metric / Check | Observed Value | Proposed Target | Assessment |
|---|---|---|---|
| Total Scans Executed | *Pending* | Up to 500 scans | *Awaiting Cohort 4* |
| Scan Success Rate | *Pending* | ≥ 98% | *Awaiting Cohort 4* |
| P95 Dashboard Latency | *Pending* | < 400ms | *Awaiting Cohort 4* |
| Worker Peak RSS Memory | *Pending* | < 300MB | *Awaiting Cohort 4* |

### 5.4 Cohort 4 Exit Gate Sign-Off
- [ ] All Phase 10 Exit Criteria (Categories A, B, C, D) satisfied.
- [ ] Final Readiness Report presented to human reviewer for GA sign-off.
