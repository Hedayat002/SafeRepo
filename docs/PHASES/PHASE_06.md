# Phase 06 — Unified Scan Engine

**Status:** Planning (Awaiting Human Approval)

---

## 1. Phase 06 Objective

Unify, harden, and scale SafeRepo's security scanning pipeline into an enterprise-grade **Unified Scan Engine**:

1. **In-Database Scan Queue & Concurrency Management:** Replace the unmanaged, fire-and-forget scan dispatch in `POST /api/v1/scans` with a durable, MongoDB-backed queue (`scans` collection). Implement atomic FIFO job claiming (`findOneAndUpdate`), bounded concurrency control (`MAX_CONCURRENT_SCANS`), heartbeat monitoring, and automated crash recovery.
2. **Trusted Worker Runtime Architecture:** Formally establish the trusted worker runtime as a persistent execution boundary operating outside of the serverless/stateless Next.js request lifecycle. Enforce that the Trusted Worker / Scanner Runner is the **ONLY** component permitted to control Docker scanner containers.
3. **Modular Scanner Orchestration:** Decouple monolithic acquisition (`acquisition.ts`) into focused, single-responsibility modules: repository acquisition, queue/worker (`queue.ts`), orchestrator (`orchestrator.ts`), and master normalizer.
4. **Unified Multi-Scanner Pipeline:** Execute Semgrep SAST, Trivy SCA, OSV Dependency Advisories, and Gitleaks Secret Detection under a single resilient orchestrator with fine-grained timeout control, active container tracking, dynamic abort/cleanup, and fault-isolated result aggregation.
5. **Deterministic Docker Orphan Reconciliation:** Implement startup and periodic sweeper reconciliation using deterministic container naming (`saferepo-scan-<scanId>-<scanner>`) to terminate orphaned containers, clean leaked workspaces, and purge partial findings following unhandled worker crashes.
6. **Master Normalization & Cross-Scanner Deduplication:** Enforce deterministic category-specific fingerprinting (`sast`, `dependency`, `secret`), cross-scanner duplicate merging, severity precedence ranking, and chunked MongoDB batch persistence (`insertMany`).
7. **Strict Lifecycle State Machine:** Enforce strict, leased state machine transitions (`queued` → `cloning` → `scanning` → `normalizing` → `completed` / `failed` / `timed_out`) backed by a single global 300-second scan deadline.

---

## 2. Functional Requirements Covered

| ID | Category | Requirement | Implementation in Phase 06 |
|---|---|---|---|
| **FR-06** | SAST Scanning | Static code analysis via Semgrep | Orchestrated in Stage 1 Docker container (`--network=none`, offline ruleset, 180s timeout). |
| **FR-07** | SCA Scanning | Dependency vulnerability scanning via Trivy | Orchestrated in Stage 1 Docker container (`--network=none`, offline DB, 180s timeout, non-root tmpfs cache). Approved SCA engine. |
| **FR-08** | Secret Scanning | Secret detection via Gitleaks | Orchestrated in Stage 1 Docker container (`--network=none`, `--redact`, sensitive stream scrubbing). |
| **FR-09** | SCA Scanning | Dependency vulnerability lookup via OSV API | Orchestrated via host-side HTTPS batch queries (max 100 coordinates/chunk, 30s timeout, canonical CVE resolution). Approved SCA engine. |
| **FR-10** | SCA Scanning | Ecosystem-specific dependency auditing (`npm audit`, `pip-audit`) | **Clarification:** Trivy and OSV are the currently approved dependency vulnerability engines. `npm audit` and `pip-audit` remain **deferred** because an approved Stage 2 containerized egress allowlist proxy does not yet exist in `docker-compose.yml`. Standard bridge networking is strictly forbidden, and host-side execution violates NFR-02. SafeRepo does not claim complete or 100% vulnerability coverage. |
| **FR-11** | Scanner Isolation | Docker-isolated execution environment | Enforced via `runner.ts` (Stage 1: no network, read-only root, tmpfs, dropped caps, non-root 1000:1000, 512MB RAM, 1 CPU, 256 PIDs, 10MB stdout limit). Docker socket access restricted strictly to Trusted Worker. |
| **FR-12** | Findings Normalization | Unified finding representation & deduplication | Master normalizer aggregating all categories with deterministic SHA-256 fingerprints and cross-scanner merging. |
| **FR-13** | Secret Redaction | Discovered secrets redaction | Zero plaintext secret storage or logging; `codeSnippet` set to `[REDACTED SECRET]`; sensitive metadata scrubbed. |
| **FR-14** | Scan Lifecycle | State machine for scan lifecycle | Atomic transitions: `queued` → `cloning` → `scanning` → `normalizing` → `completed` / `failed` / `timed_out`. Single 300s global deadline. |
| **NFR-01**| Architecture | Local-first architecture | Fully functional in local Docker Compose environment (MongoDB 7 + isolated ephemeral containers). |
| **NFR-02**| Isolation | Staged container restrictions | Stage 1 network-disabled containers strictly preserved. |
| **NFR-03**| Code Safety | Defense-in-depth against untrusted code | Untrusted repository code never executed; no package lifecycle scripts. |
| **NFR-04**| Performance | Configurable scan timeouts | Single absolute scan deadline (300s), container timeouts (180s), HTTP batch timeouts (30s). |
| **NFR-06**| Persistence | MongoDB 7 with Mongoose ODM | In-database queue and persistence using MongoDB atomic updates and compound indexes. |
| **NFR-07**| Cost | ₹0 development cost target | No Redis, no external queue brokers, no paid cloud APIs. |
| **NFR-09**| Testing | Automated test suite | Minimum 80% line coverage for all new and modified modules. |

---

## 3. Trusted Worker Runtime Architecture

### Runtime Separation
SafeRepo enforces a strict architectural boundary between the HTTP API and the asynchronous execution engine:

```
┌─────────────────────────────────────────────────────────────┐
│                      Next.js API Layer                      │
│                  POST /api/v1/scans                         │
│  - Validates authentication, rate limits, and repo metadata │
│  - Creates Scan document with status: 'queued' in MongoDB   │
│  - STRICTLY ZERO Docker socket access                       │
│  - Returns immediately with 201 Created                     │
└──────────────────────────────┬──────────────────────────────┘
                               │ Durable MongoDB write
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             MongoDB In-Database Scan Queue                  │
│       scans collection (indexed by { status, createdAt })   │
└──────────────────────────────┬──────────────────────────────┘
                               │ Atomic findOneAndUpdate (FIFO)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Trusted Persistent Worker                 │
│              (apps/web/src/lib/scanner/queue.ts)            │
│  - Long-running, persistent Node.js worker runtime          │
│  - Runs outside the serverless/stateless request lifecycle  │
│  - Bounded concurrency control (MAX_CONCURRENT_SCANS = 1)   │
│  - Updates heartbeats periodically (heartbeatAt)            │
│  - Handles graceful shutdown (SIGINT/SIGTERM)               │
│  - Reconciles orphaned Docker containers & stale scans      │
│  - THE ONLY COMPONENT WITH DOCKER API / SOCKET CONTROL      │
└──────────────────────────────┬──────────────────────────────┘
                               │ Dispatches execution
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       Scanner Runner                        │
│             (apps/web/src/lib/scanner/runner.ts)            │
│  - Trusted boundary enforcing explicit container allowlist  │
│  - Issues docker run / docker kill commands                 │
└──────────────────────────────┬──────────────────────────────┘
                               │ Ephemeral containers
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              Hardened Docker Scanner Containers             │
│        (Semgrep, Trivy, Gitleaks — Stage 1 Isolation)       │
│  - --network=none, --read-only, tmpfs, cap-drop=ALL         │
│  - STRICTLY ZERO Docker socket access                       │
└─────────────────────────────────────────────────────────────┘
```

### Worker Process Entrypoint

The persistent worker is a **standalone Node.js process** completely independent from the Next.js application runtime. It is NOT hosted inside a Next.js API route, middleware, or server action.

#### Entrypoint Script
```
apps/web/src/lib/scanner/worker-entrypoint.ts
```

This is a self-contained script that:
1. Establishes its own MongoDB connection via Mongoose (reusing the existing `@/lib/db` connection helper).
2. Instantiates the worker loop from `queue.ts` (`startWorker()`).
3. Registers `SIGINT` / `SIGTERM` handlers for graceful shutdown.
4. Runs the reconciliation sweeper on startup before claiming any work.
5. Enters the polling loop, claiming and executing scan jobs until stopped.

#### Runtime Gap Analysis

The existing project has **no native mechanism** to run a standalone TypeScript file with `@/` path alias resolution outside of Next.js or Vitest:

| Existing Runtime | Can Run Standalone Worker? | Reason |
|---|---|---|
| `next dev` / `next start` | ❌ | Next.js controls the process lifecycle; cannot host a persistent polling loop. |
| `vitest run` | ❌ | Test runner, not a general-purpose script executor. |
| `tsc --noEmit` | ❌ | Type-checker only; does not execute code. |
| `node --experimental-strip-types` | ❌ | Strips TypeScript syntax but does **not** resolve `@/*` path aliases from `tsconfig.json`. All scanner modules import from `@/lib/...`, `@/models/...`, `@/types`. |
| `node --experimental-transform-types` | ❌ | Transforms TypeScript enum/namespace syntax but still does **not** resolve path aliases. |

#### Minimum Required Addition: `tsx` (devDependency)

The worker entrypoint requires **`tsx`** (a zero-config TypeScript executor by esbuild-kit) added as a **devDependency** in `apps/web/package.json`:

```jsonc
// apps/web/package.json — ONLY change to package.json
"devDependencies": {
  "tsx": "^4.x"  // TypeScript executor with tsconfig path alias resolution
}
```

**Justification:**
- `tsx` resolves `@/*` path aliases via the project's existing `tsconfig.json` `paths` configuration.
- `tsx` is a **devDependency** only — it does not affect the production Next.js build or runtime.
- `tsx` has zero configuration requirements — it reads `tsconfig.json` automatically.
- No modifications to `docker-compose.yml`, `.env.local`, or existing source code are required.
- This is the **minimum viable addition** to close the runtime gap. No alternative exists within the current dependency tree.

#### Local Development Launch
In local development, the worker is started as a **separate terminal process** alongside the Next.js dev server:
```bash
# Terminal 1 — Next.js API
npm run dev

# Terminal 2 — Trusted Scan Worker (after npm install adds tsx)
npx tsx apps/web/src/lib/scanner/worker-entrypoint.ts
```

A convenience npm script will be added to `apps/web/package.json` during the implementation phase:
```jsonc
"scripts": {
  "worker": "tsx src/lib/scanner/worker-entrypoint.ts"
}
```
This allows launching via `npm run worker` from the `apps/web` directory.

#### Worker Lifecycle
| Phase | Description |
|---|---|
| **Boot** | Connect to MongoDB. Generate unique `workerId` (`worker-<hostname>-<pid>-<timestamp>-<uuid>`). |
| **Startup Reconciliation** | Run `reconcileStaleScans()` to clean up orphans from any prior crash. |
| **Polling Loop** | Poll MongoDB queue every `SCAN_QUEUE_POLL_INTERVAL_MS` (default: 5000ms). Claim jobs via atomic `findOneAndUpdate`. Execute via orchestrator. Emit heartbeats. |
| **Graceful Shutdown** | On `SIGINT`/`SIGTERM`: stop claiming new jobs, drain active scans (up to grace period), clean up, exit 0. |
| **Forced Termination** | On `SIGKILL`/crash: heartbeat stops. Next startup reconciliation cleans up. |

#### Docker Control Ownership
The worker process is the **exclusive trust boundary** for Docker API access:
- The worker entrypoint process → calls `orchestrator.ts` → calls `runner.ts` → issues `docker run` / `docker kill` commands.
- The Next.js API process MUST NEVER issue Docker commands or mount `/var/run/docker.sock`.
- Scanner containers MUST NEVER have Docker socket access.
- Only the machine/user running the worker entrypoint needs Docker daemon access.

### Key Runtime Invariants
1. **No Serverless Background Execution:** The persistent worker runs as a **separate OS process** started via `npx tsx`. It does not run inside a Next.js API request, server component, middleware, or any short-lived serverless function.
2. **Exclusive Docker Control:** The Trusted Worker / Scanner Runner is the **ONLY** component permitted to interact with the Docker API and control scanner containers. The Next.js API layer and all scanner containers MUST NEVER have `/var/run/docker.sock` mounted or accessible.
3. **Independent Lifecycle:** The worker process starts and stops independently of the Next.js dev server. Restarting Next.js does not affect running scans. Restarting the worker triggers startup reconciliation.

---

## 4. Current Architecture Limitations Relevant to Phase 06

1. **Uncontrolled Concurrency:** `POST /api/v1/scans` invokes `void processScanAcquisition(...)` as a detached in-process promise. Simultaneous scan requests launch concurrent Docker containers without limits, causing host CPU/memory starvation.
2. **Missing Queue Persistence:** Scans enter MongoDB with `status: 'queued'`, but there is no persistent worker loop or queue consumer. If the process restarts, queued or running scans are orphaned forever.
3. **No Heartbeat or Crash Recovery:** If the application process crashes mid-scan, the scan remains indefinitely in `cloning`, `scanning`, or `normalizing`. No sweeper exists to reclaim or fail abandoned scans.
4. **Monolithic Acquisition Module:** `acquisition.ts` conflates git cloning, symlink auditing, scanner dispatching, error mapping, normalization, DB writes, and workspace cleanup.
5. **No Active Container Registry for Aborts:** When a scan exceeds the overall timeout (300s), running Docker containers cannot be deterministically identified and killed across decoupled promises.
6. **Orphaned Workspace & Container Leakage:** A crash during execution can leave abandoned clone directories in `tmp/workspaces` and running containers in Docker.

---

## 5. Existing Components That Must Remain Unchanged

1. **Stage 1 Scanner Security Sandbox (`apps/web/src/lib/scanner/runner.ts`):**
   - `--network=none`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, unprivileged `--user 1000:1000`, `--security-opt=no-new-privileges`, `--cap-drop=ALL`, `--cpus=1`, `--memory=512m`, `--pids-limit=256`, 10MB stdout stream limiter.
2. **Docker Socket Security Boundary (Decision C2):**
   - Docker daemon access isolated strictly to Scanner Runner; Docker socket is never mounted into scanner containers or web containers.
3. **Semgrep Integration (`apps/web/src/lib/scanner/semgrep.ts`):**
   - Curated offline ruleset mounted as `/rules:ro`, JSON output parser, and SAST fingerprint formula:
     `sha256("semgrep:" + ruleId + ":" + file + ":" + line + ":" + message)`.
4. **Trivy Integration (`apps/web/src/lib/scanner/trivy.ts`):**
   - Offline DB validation, unprivileged tmpfs cache at `/home/scanner`, and typed availability contract (`ScannerUnavailableResult`).
5. **OSV API Integration (`apps/web/src/lib/scanner/osv.ts`):**
   - Static coordinate batch queries (max 100 coordinates/chunk), 30s timeout, canonical CVE alias resolution, and zero untrusted code execution.
6. **Gitleaks Integration (`apps/web/src/lib/scanner/gitleaks.ts`):**
   - Process-boundary redaction (`--redact`), exit code semantics (0/1 as success, >1 as failure), zero raw stdout/stderr logging, zero raw JSON persistence, redaction of `Secret`/`Match` metadata, and secret fingerprint formula:
     `sha256("secret:" + ruleId + ":" + file + ":" + line + ":" + column)`.
7. **Dependency Fingerprint Formula (`apps/web/src/lib/scanner/normalizer.ts`):**
   - `sha256("dependency:" + ecosystem + ":" + package + ":" + version + ":" + cve)`.
8. **Workspace Hardening (`apps/web/src/lib/scanner/workspace.ts`):**
   - Traversal protection, symlink validation, and randomized paths.
9. **Mongoose Models (`apps/web/src/models/scan.ts`, `apps/web/src/models/finding.ts`):**
   - Core fields and existing compound unique indexes are strictly preserved.

---

## 6. Docker Orphan Reconciliation Model

SafeRepo does **NOT** rely on Docker's `--rm` flag alone for crash recovery. If a worker process crashes, is force-killed (`SIGKILL`), or encounters an unhandled exception, containers may remain active or lingering.

### Deterministic Container Naming
Every scanner container is deterministically named using the parent scan ID and scanner identifier:
```
saferepo-scan-<scanId>-<scanner>
```
Examples:
- `saferepo-scan-65f1a2b3c4d5e6f7a8b9c0d1-semgrep`
- `saferepo-scan-65f1a2b3c4d5e6f7a8b9c0d1-trivy`
- `saferepo-scan-65f1a2b3c4d5e6f7a8b9c0d1-gitleaks`

### Recovery Semantics: Failed-Finalization (Not Re-Queueing)

Stale scans detected by the reconciliation sweeper are **finalized as `failed`** and are **NOT re-queued** for another execution attempt. This is an intentional design decision:

1. **Poison Job Prevention:** A scan that caused a worker crash (e.g., due to a malicious repository triggering an OOM kill) would cause an infinite crash loop if re-queued automatically.
2. **Deterministic Cleanup:** Re-queueing would require guaranteeing that all partial state (containers, workspace files, partial findings) is perfectly cleaned before a second attempt. Failed-finalization avoids this complexity.
3. **User-Initiated Retry:** If a scan fails due to transient infrastructure issues (e.g., Docker daemon restart), the user can trigger a new scan via the API. This is explicit and auditable.
4. **No Silent Retry Storms:** Automatic re-queueing with bounded retries adds retry counter state, backoff logic, and max-retry configuration — complexity that is not justified for Phase 06's local-first, single-worker architecture.

### Stale Heartbeat Race Safety

The reconciliation sweeper MUST NOT incorrectly finalize a scan that belongs to a healthy, actively-running worker. Race conditions can occur when:
- A worker's heartbeat update is delayed (e.g., due to GC pause or I/O contention).
- The sweeper runs concurrently and observes a momentarily stale `heartbeatAt`.

To prevent this, all sweeper transitions use an **atomic conditional update** that verifies ownership and staleness at write time:

```typescript
// Sweeper: atomic conditional transition
const result = await Scan.findOneAndUpdate(
  {
    _id: scanId,
    status: { $in: ['cloning', 'scanning', 'normalizing'] },
    heartbeatAt: { $lt: staleThreshold },   // Still stale at write time
    workerId: staleWorkerId,                 // Same worker that was detected as stale
  },
  {
    $set: {
      status: 'failed',
      error: 'Scan worker terminated unexpectedly (reconciled by sweeper)',
      completedAt: new Date(),
    },
  },
  { new: true }
);

if (!result) {
  // Worker recovered and updated heartbeat, or scan already transitioned.
  // No cleanup needed — skip this scan.
  return;
}

// Only proceed with container kill, workspace cleanup, and finding purge
// AFTER the atomic transition succeeds.
```

**Invariants:**
1. **Cleanup-after-transition-only:** Container termination, workspace cleanup, and finding purge are performed **only after** the atomic conditional transition succeeds. If the transition returns `null` (worker recovered, or scan already completed/failed), no cleanup is performed.
2. **No active heartbeat overwrite:** The sweeper's `findOneAndUpdate` query includes `heartbeatAt: { $lt: staleThreshold }` as a write-time condition. If a healthy worker updates its heartbeat between the sweeper's read and write, the condition no longer matches and the transition returns `null`. The sweeper **cannot** overwrite an active worker's heartbeat or finalize its scan.
3. **Ownership-locked transition:** The sweeper query includes `workerId: staleWorkerId` to ensure it only finalizes scans owned by the specific worker instance that was detected as stale. A scan that has already been reclaimed by a different worker (via re-queue in a future phase, or manual intervention) is not affected.

### Startup and Periodic Sweeper Reconciliation Flow
Reconciliation executes automatically:
1. **On Worker Boot:** Before claiming any queued jobs.
2. **Periodically:** In a background reconciliation tick (default every 30s).

```
Worker crash / heartbeat expiry
       │
       ▼
Stale scan detected in MongoDB (status IN ['cloning', 'scanning', 'normalizing'] AND heartbeatAt < now - 360s)
       │
       ▼
Atomically verify staleness + ownership + status at write time (conditional findOneAndUpdate)
       │
       ├── Transition returned null → worker recovered or scan already finalized → SKIP
       │
       ▼ (Transition succeeded — scan is now 'failed')
Derive deterministic container names:
  saferepo-scan-<scanId>-semgrep
  saferepo-scan-<scanId>-trivy
  saferepo-scan-<scanId>-gitleaks
       │
       ▼
Verify container identity belongs to SafeRepo scan (prefix: "saferepo-scan-<scanId>-")
       │
       ▼
Terminate and forcefully remove orphan containers (docker kill / docker rm -f via Scanner Runner)
       │
       ▼
Clean workspace directory on host disk (cleanupWorkspace(scan.workspacePath))
       │
       ▼
Purge partial findings in MongoDB (Finding.deleteMany({ scanId: scan._id }))
       │
       ▼
Scan document already marked failed (by the atomic transition above):
  status = 'failed'
  error = 'Scan worker terminated unexpectedly (reconciled by sweeper)'
  completedAt = new Date()
```

---

## 7. Concurrency Model & Resource Calculation

### Intra-Scan Scanner Concurrency: Sequential
Within a single scan, scanners execute **sequentially** by default:
```
Repository Acquisition ──► Semgrep SAST ──► Trivy SCA ──► OSV API (HTTPS) ──► Gitleaks Secrets ──► Normalization
```
- **Rationale:** Semgrep, Trivy, and Gitleaks each spawn a Docker container requiring 512MB RAM, 1 CPU, and up to 256 PIDs. Executing them sequentially ensures that a single scan consumes at most **1 container, 512MB RAM, and 1 CPU** at any given moment.

### Inter-Scan Concurrency: `MAX_CONCURRENT_SCANS`
- **Default:** `MAX_CONCURRENT_SCANS = 1` (safest for local development on laptops and workstations).
- **Safe Range:** `1` to `2`.
- **Resource Footprint Analysis:**
  - `MAX_CONCURRENT_SCANS = 1` (Sequential scanners): Peak **1 container, 512MB RAM, 1 CPU**.
  - `MAX_CONCURRENT_SCANS = 2` (Sequential scanners): Peak **2 containers, 1024MB RAM, 2 CPUs**. Completely safe on typical developer machines (>= 8GB RAM).
  - *Risk of Unbounded / High Concurrency:* If `MAX_CONCURRENT_SCANS = 4` and 3 Docker scanners ran concurrently per scan, up to **12 concurrent Docker containers** could spawn simultaneously, demanding **6GB RAM and 12 CPUs**. This would cause severe CPU thrashing, Docker daemon exhaustion, and cascade timeouts.
  - Setting `MAX_CONCURRENT_SCANS > 2` is **NOT** recommended for local development and requires dedicated compute evaluation in Phase 09.

---

## 8. Global Timeout Model

SafeRepo uses **one absolute scan deadline** rather than independent, reset stage timers.

### Deadline Flow
1. **Clock Starts on Claim:** The instant a worker claims a scan from the queue, `scan.startedAt = new Date()` is recorded.
2. **Absolute Deadline Computation:**
   $$\text{Global Deadline} = \text{startedAt} + (\text{SCAN\_TIMEOUT\_SECONDS} \times 1000) \quad (\text{default: } 300\text{s})$$
3. **Shared Budget:** All stages (`cloning`, `scanning`, and `normalizing`) consume the **SAME** 300-second deadline.
4. **Child Scanner Effective Timeout:**
   When starting a child scanner (e.g., Semgrep with a configured 180s container timeout), the runner computes:
   $$\text{Effective Timeout} = \min(\text{ScannerTimeoutMs}, \text{RemainingGlobalDeadlineMs})$$
   - *Example:* If cloning and previous scanners consumed 240s, only 60s remain in the global deadline. The next scanner container is given an effective hard timeout of **60s**, not 180s.
5. **Global Expiration Handling:**
   If the global 300s deadline expires at any point:
   - An `AbortController` signal fires immediately.
   - The orchestrator issues `killDockerContainer` to all registered active containers for that scan.
   - Partial findings are purged from MongoDB (`Finding.deleteMany({ scanId })`).
   - Ephemeral workspace is cleaned up unconditionally.
   - Scan status is transitioned to `timed_out` with error `"Scan exceeded maximum duration of 300s"`.

---

## 9. State Transition Ownership & Lifecycle State Machine

To prevent race conditions and illegal state mutations, state transitions follow strict ownership:

```
              ┌───────────┐
              │  queued   │
              └─────┬─────┘
                    │ Worker claims job (atomic findOneAndUpdate)
                    ▼
              ┌───────────┐
              │  cloning  │ ────(clone failure / timeout)───► ┌───────────┐
              └─────┬─────┘                                  │  failed   │
                    │ Acquisition completes                  │    or     │
                    ▼                                        │ timed_out │
              ┌───────────┐                                  └─────▲─────┘
              │ scanning  │ ────(all scanners fail / timeout)─────┤
              └─────┬─────┘                                        │
                    │ Scanner execution completes                  │
                    ▼                                              │
              ┌───────────┐                                        │
              │normalizing│ ────(DB write error / timeout)─────────┘
              └─────┬─────┘
                    │ Persistence completes
                    ▼
              ┌───────────┐
              │ completed │
              └───────────┘
```

### Exact Ownership Matrix

| From State | To State | Trigger / Owner | Conditions & Invariants |
|---|---|---|---|
| *(none)* | `queued` | Next.js API (`POST /api/v1/scans`) | Validates payload, rate limit, repo metadata; initial write. |
| `queued` | `cloning` | Trusted Worker (`queue.ts`) | Atomic `findOneAndUpdate` claim; sets `workerId`, `startedAt`, `heartbeatAt`. |
| `cloning` | `scanning` | Orchestrator (`orchestrator.ts`) | Repository acquired successfully, symlinks validated, size within limit. |
| `scanning` | `normalizing` | Orchestrator (`orchestrator.ts`) | Scanner executions completed; at least 1 scanner succeeded. |
| `normalizing` | `completed` | Orchestrator (`orchestrator.ts`) | Master normalization and chunked MongoDB persistence completed. |
| `cloning` | `failed` | Orchestrator (`orchestrator.ts`) | Git clone failed, invalid hooks detected, or size exceeded. |
| `scanning` | `failed` | Orchestrator (`orchestrator.ts`) | All scanners failed to execute. |
| `normalizing`| `failed` | Orchestrator (`orchestrator.ts`) | MongoDB batch insert failed. |
| Any active | `timed_out`| Orchestrator (`orchestrator.ts`) | Absolute global deadline (300s) expired during execution. |
| Any active | `failed` | Reconciliation Sweeper (`queue.ts`) | Worker heartbeat expired (`heartbeatAt < now - 360s`); worker crashed. |

Arbitrary components cannot mutate scan status; mutations enforce worker lease ownership (`workerId`).

---

## 10. Queue, Worker & Reconciliation Responsibility Boundary

All queue-related logic is encapsulated in `apps/web/src/lib/scanner/queue.ts` with distinct functional separation:

### 1. Queue Responsibilities
- `enqueueScanJob(scanInput)`: Validates scan record and enqueues in MongoDB with `status: 'queued'`.
- `claimNextScanJob(workerId)`: Performs atomic FIFO claim via `Scan.findOneAndUpdate` sorted by `createdAt: 1`.
- `updateScanHeartbeat(scanId, workerId)`: Updates `heartbeatAt` for a leased scan.
- `transitionScanStatus(scanId, workerId, fromStatus, toStatus, metadata)`: Enforces leased state transitions.

### 2. Worker Responsibilities
- `startWorker()` / `stopWorker()`: Manages worker polling loop and event triggers.
- `activeScans`: In-memory counter enforcing concurrency slot gating (`activeScans < MAX_CONCURRENT_SCANS`).
- `executeScanJob(scan)`: Dispatches claimed scan to `orchestrator.ts`, manages duration, updates heartbeats, and decrements active counter upon completion.
- `shutdownWorker()`: Manages graceful shutdown sequence.

### 3. Reconciliation Responsibilities
- `reconcileStaleScans()`: Runs on startup and periodically (every 30s).
- Identifies scans in `cloning`, `scanning`, or `normalizing` with expired heartbeats (`> 360s`).
- Derives deterministic container names and invokes Scanner Runner kill/removal.
- Cleans orphaned workspace directories on disk.
- Purges partial findings from MongoDB.
- Transitions stale scans to `failed`.

---

## 11. Shutdown Behavior

### 1. Graceful Shutdown (`SIGINT`, `SIGTERM`)
1. Set `isShuttingDown = true` to immediately halt claiming new jobs from the queue.
2. Active scan jobs are permitted to continue executing up to their remaining global deadline (or a configurable shutdown grace period, e.g., 30s).
3. The worker continues emitting periodic heartbeats for active scans while finishing.
4. If an active job completes, findings are persisted and workspace is cleaned up.
5. If shutdown grace period expires, active scans are aborted gracefully (containers killed, workspaces cleaned, marked `failed`).
6. Unclaimed `queued` jobs in MongoDB are left completely untouched so another worker or the next restart can claim them.
7. Worker process exits with code 0.

### 2. Forced Process Termination (`SIGKILL`, Host Crash, Power Loss)
- Worker heartbeat abruptly halts.
- Lingering containers and workspace directories may remain.
- On the next worker startup, the **Startup Reconciliation Sweeper** runs before claiming any new work:
  - Scans with expired heartbeats are identified.
  - Deterministic container names (`saferepo-scan-<scanId>-*`) are killed and removed.
  - Workspace directories are purged from host disk.
  - Partial findings are purged.
  - Scans are finalized as `failed`.

---

## 12. Multi-Worker Safety & Delivery Semantics

Even though Phase 06 targets a single-node, local-first architecture, multi-worker safety invariants are enforced at the database level.

### Delivery Semantics (Precise Terminology)

| Property | Status | Mechanism |
|---|---|---|
| **Atomic single-owner claim** | ✅ Guaranteed | MongoDB `findOneAndUpdate` with document-level locking ensures that a queued scan is claimed by exactly one worker in a single atomic operation. Competing workers receive `null`. This is an **ownership transfer**, not an execution guarantee. |
| **At-least-once execution possibility** | ⚠️ Acknowledged | Exactly-once execution is **not** guaranteed. If a worker crashes after claiming a scan but before completing it, the reconciliation sweeper finalizes the scan as `failed`. The user may then trigger a new scan of the same repository, resulting in at-least-once execution of the scanning logic across the repository's lifetime. SafeRepo does not automatically re-queue or retry failed scans (see §6 Recovery Semantics). |
| **Idempotent persistence** | ✅ Guaranteed | Finding persistence uses deterministic SHA-256 fingerprints with a compound unique index (`{ scanId: 1, fingerprint: 1 }`). Duplicate findings from overlapping scanners (e.g., Trivy and OSV reporting the same CVE) are safely deduplicated via `insertMany` with `ordered: false` and duplicate key error handling. Even if a user re-scans the same repository, findings within each scan are independently fingerprinted and deduplicated. |

### Atomic Claiming
Jobs are claimed via atomic MongoDB query:
```typescript
const scan = await Scan.findOneAndUpdate(
  { status: 'queued' },
  {
    $set: {
      status: 'cloning',
      workerId: this.workerId,
      startedAt: new Date(),
      heartbeatAt: new Date(),
    },
  },
  { sort: { createdAt: 1 }, new: true }
);
```
MongoDB's atomic `findOneAndUpdate` guarantees **single-owner claiming**: exactly one worker receives the document; all concurrent claimants receive `null`. This is an atomic ownership transfer, not an exactly-once execution guarantee.

### Worker Identity
Each worker generates a unique instance ID on startup (`worker-<hostname>-<pid>-<timestamp>-<uuid>`).

### Leased Updates
All heartbeat and state updates require:
```typescript
{ _id: scanId, workerId: this.workerId, status: currentExpectedStatus }
```
If a stalled worker pauses and its scan is reclaimed by the sweeper, the stalled worker's subsequent write matches 0 documents. The worker detects lease loss, aborts execution, and cleans up without overwriting valid state.

---

## 13. Preservation of Approved Security Boundaries

SafeRepo strictly preserves all established security boundaries:

- **Semgrep Sandbox:** Stage 1 Docker container with `--network=none`, `--read-only`, unprivileged `--user 1000:1000`, dropped capabilities (`--cap-drop=ALL`), `no-new-privileges`, CPU/memory/PID limits.
- **Trivy Sandbox:** Stage 1 Docker container with `--network=none`, `--read-only`, unprivileged `--user 1000:1000`, non-root tmpfs cache at `/home/scanner`, offline DB mount.
- **Gitleaks Sandbox:** Stage 1 Docker container with `--network=none`, `--read-only`, unprivileged `--user 1000:1000`, process-boundary `--redact`.
- **Sensitive Output Scrubbing:** Zero logging of raw stdout/stderr; zero raw JSON persistence on disk or in DB; `codeSnippet` set strictly to `[REDACTED SECRET]`; sensitive metadata scrubbed.
- **OSV Network Boundary:** Controlled host-side HTTPS only to `https://api.osv.dev/v1/querybatch` using static coordinates. Zero untrusted code evaluation.
- **No Unrestricted Bridge Networking:** Docker bridge networking (`--network=bridge`) is strictly forbidden for untrusted scans.
- **No Host-Side Package Manager Audits:** Direct host-side execution of `npm audit` or `pip-audit` is forbidden.
- **Docker Socket Security (Decision C2):** Docker socket access is restricted strictly to the Scanner Runner inside the Trusted Worker. The Next.js API layer and scanner containers never receive Docker socket access.

---

## 14. Exact File Change Boundary

### New Files to Create (Implementation Phase)
1. `apps/web/src/lib/scanner/orchestrator.ts` — Unified multi-scanner orchestrator, container tracking, fault isolation.
2. `apps/web/src/lib/scanner/queue.ts` — MongoDB queue, atomic claim, concurrency control, heartbeat, reconciliation sweeper.
3. `apps/web/src/lib/scanner/worker-entrypoint.ts` — Standalone persistent worker entrypoint script (launched via `npx tsx`). Connects to MongoDB, starts worker loop, registers signal handlers.
4. `apps/web/src/lib/scanner/__tests__/orchestrator.test.ts` — Orchestrator unit and integration tests.
5. `apps/web/src/lib/scanner/__tests__/queue.test.ts` — Queue, worker, and sweeper unit and integration tests.

### Files to Modify (Implementation Phase)
1. `apps/web/src/lib/scanner/acquisition.ts` — Refactor to isolate repo cloning/validation; delegate execution to orchestrator.
2. `apps/web/src/app/api/v1/scans/route.ts` — Replace fire-and-forget promise with queue enqueuing (`enqueueScanJob`).
3. `apps/web/src/lib/env.ts` — Add `MAX_CONCURRENT_SCANS`, `SCAN_QUEUE_POLL_INTERVAL_MS`, `SCAN_STALE_TIMEOUT_MS`.
4. `apps/web/src/models/scan.ts` — Add `heartbeatAt`, `workerId`, and `{ status: 1, createdAt: 1 }` index.
5. `apps/web/src/types/index.ts` — Add queue and orchestrator TypeScript types.
6. `apps/web/src/lib/scanner/__tests__/acquisition.test.ts` — Align tests with refactored interface.
7. `apps/web/package.json` — Add `tsx` as devDependency; add `"worker"` convenience script. (See §3 Runtime Gap Analysis for justification.)

---

## 15. Testing and Validation Plan

### Unit Tests
- `queue.test.ts`:
  - Enqueue scan job and verify initial state.
  - Atomic FIFO job claiming via `findOneAndUpdate`.
  - Concurrency limiter gating when `activeScans >= MAX_CONCURRENT_SCANS`.
  - Periodic heartbeat update verification.
  - Stale scan sweeper detecting abandoned scans and marking `failed`.
  - Startup reconciliation killing orphan containers and cleaning workspaces.
  - Graceful shutdown draining.
- `orchestrator.test.ts`:
  - Full pipeline orchestration across Semgrep, Trivy, OSV, and Gitleaks.
  - Active container tracking and cancellation on timeout.
  - Global 300s deadline enforcement adjusting child scanner timeouts.
  - Partial failure handling and error metadata persistence.
  - Master normalization and cross-scanner deduplication.

### Integration Tests
- In-memory MongoDB (`mongodb-memory-server`):
  - End-to-end queue-to-completion pipeline.
  - Concurrency enforcement with multiple simultaneous scan requests.
  - Multi-worker atomic claiming test ensuring zero duplicate claims.

### Regression Tests
- Verify that Phase 01 through Phase 05 tests continue passing cleanly with 100% pass rate.

### Quality & Coverage Gates
- Minimum **80% line coverage** across all new and modified modules in `apps/web/src/lib/scanner/`.
- Maintain overall codebase coverage $\ge 90\%$ (baseline: 94.43%).

### Exact Validation Commands
```bash
npm run typecheck
npm run lint
npm run test
npm run test:coverage
npm run build
```

---

## 16. Explicit Non-Goals

1. **Frontend Dashboard UI Components:** Deferred to Phase 07 (`FindingsList`, `SeverityChart`, `RemediationPanel`).
2. **WebSockets / Server-Sent Events (SSE):** Real-time UI progress updates deferred to Phase 07 / Phase 08. Polling via `GET /api/v1/scans/:id` is sufficient for MVP.
3. **Redis / External Message Queues:** Strictly excluded per ADR-001 and project architecture.
4. **Containerized `npm audit` and `pip-audit` with Egress Allowlist Proxy:** Deferred pending dedicated forward proxy container in `docker-compose.yml`.
5. **Multi-Node Distributed Worker Cluster:** Local-first architecture; single-node worker is sufficient for Phase 06.
6. **Paid AI APIs or Cloud Infrastructure:** ₹0 cost invariant strictly preserved.

---

## 17. Git Checkpoint Strategy

- **Checkpoint 1 (Planning):** `docs: complete phase 06 planning` (Current artifact).
- **Checkpoint 2 (Queue & Concurrency):** `feat: implement in-database scan queue and worker` (`queue.ts` + tests).
- **Checkpoint 3 (Orchestrator):** `feat: implement unified scanner orchestrator` (`orchestrator.ts` + tests).
- **Checkpoint 4 (API & Pipeline Integration):** `feat: integrate scan queue with api and lifecycle sweeper` (`scans/route.ts`, `acquisition.ts`).
- **Checkpoint 5 (Verification & Phase Close):** `feat: complete phase 06 unified scan engine` (Validation report, changelog, phase status).

---

## Review Criteria & Definition of Done

Phase 06 is complete when:
- [ ] In-database scan queue (`queue.ts`) atomically claims jobs in FIFO order using MongoDB.
- [ ] Trusted worker runtime executes outside serverless Next.js request lifecycle with exclusive Docker socket control.
- [ ] Concurrency limiter prevents exceeding `MAX_CONCURRENT_SCANS` (default: 1).
- [ ] Docker orphan reconciliation terminates lingering containers and cleans workspaces on worker crash.
- [ ] Global 300s deadline is enforced across all stages and adjusts child scanner timeouts.
- [ ] Dedicated orchestrator (`orchestrator.ts`) coordinates Semgrep, Trivy, OSV, and Gitleaks sequentially.
- [ ] Master normalizer deduplicates and aggregates findings across all scanners.
- [ ] All Stage 1 and Stage 2 security isolation invariants are strictly preserved.
- [ ] Unit and integration test coverage $\ge 80\%$ on all new/modified code.
- [ ] `npm run typecheck`, `npm run lint`, `npm run test`, and `npm run build` pass with 0 errors.

