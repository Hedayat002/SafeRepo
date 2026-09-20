# SafeRepo Phase 10 — Security & Invariant Audit Log

> **Current Status:** Invariant Framework Established — Awaiting Beta Execution
> **Committed Baseline:** `4a74682c3e9998bf916c891b7a66394cbbf8b19b` (`fix: resolve phase 09 production e2e issues`)
> **Master Test Plan:** [BETA_TEST_PLAN.md](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/docs/BETA/BETA_TEST_PLAN.md)

---

## 1. Security Invariants & Audit Framework

SafeRepo clones and analyzes untrusted third-party code. To protect the host operating system, database, and user data, Phase 10 defines seven non-negotiable security invariants subject to continuous verification.

Any violation of these invariants constitutes a **P0: Blocker** defect and triggers an immediate **Stop Condition**.

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           MANDATORY SECURITY INVARIANTS                           │
├────┬─────────────────────────────────┬────────────────────────────────────────────┤
│ ID │ Security Invariant              │ Enforcement Mechanism                      │
├────┼─────────────────────────────────┼────────────────────────────────────────────┤
│ I1 │ Zero Scanner Network Access     │ Docker `--network=none` on child containers│
│ I2 │ Host Filesystem Isolation       │ Read-only rootfs + sandboxed tmpfs volume  │
│ I3 │ Web Tier Socket Isolation       │ Zero socket mount or CLI in `web` image    │
│ I4 │ Docker Socket Proxy Denial      │ HAProxy blocking high-risk API categories  │
│ I5 │ Scanner Container Containment   │ Non-root UID, `--cap-drop=ALL`, memory caps│
│ I6 │ Cross-User Data Isolation       │ Server-side session & ownership checks     │
│ I7 │ Zero Secret / Token Leakage     │ Automated stdout redaction & Pino masking  │
└────┴─────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 2. Invariant Specifications & Audit Procedures

### 2.1 Invariant I1: Zero Scanner Network Access
- **Requirement:** Ephemeral scanner containers (`semgrep`, `trivy`, `gitleaks`) must have zero external network connectivity.
- **Audit Procedure:** Inspect active container inspect output:
  ```bash
  docker inspect --format '{{.HostConfig.NetworkMode}}' saferepo-scan-<id>-<scanner>
  ```
  Expected: `"none"`
- **Live Probe:** Execute internal network call test inside container:
  Attempt HTTP connection to external IP (e.g. `1.1.1.1`); verify immediate failure without route.

### 2.2 Invariant I2: Host Filesystem Isolation
- **Requirement:** Scanner containers must never mount or access host directories outside the assigned `/tmp/saferepo-workspaces/<scanId>` directory.
- **Audit Procedure:** Inspect container volume mounts via `docker inspect`:
  Verify root filesystem is marked `"ReadonlyRootfs": true`.
  Verify mounts are restricted to workspace bind mount and tmpfs (`/tmp:rw,noexec,nosuid,size=64m`).
  Verify symlinks pointing to `/etc/passwd`, `/var/run/docker.sock`, or host paths are not dereferenced.

### 2.3 Invariant I3: Web Tier Socket Isolation
- **Requirement:** The `saferepo-web` container must have strictly zero access to `/var/run/docker.sock` or any Docker daemon interface.
- **Audit Procedure:** Execute probe inside running `saferepo-web` container:
  ```bash
  docker exec saferepo-web ls -la /var/run/docker.sock
  docker exec saferepo-web which docker
  ```
  Expected: Socket not found; docker binary not found; zero Docker environment variables.

### 2.4 Invariant I4: Docker Socket Proxy Restrictions
- **Requirement:** The scan worker's communication with the Docker daemon is strictly mediated via `tecnativa/docker-socket-proxy`. High-risk API categories are disabled (`VOLUMES=0`, `NETWORKS=0`, `EXEC=0`, `BUILD=0`, `AUTH=0`, `SECRETS=0`, `SYSTEM=0`).
- **Audit Procedure:** Send unauthorized curl requests from inside `saferepo-worker`:
  ```bash
  docker exec saferepo-worker curl -s -X POST http://docker-proxy:2375/v1.45/volumes/create
  docker exec saferepo-worker curl -s -X POST http://docker-proxy:2375/v1.45/build
  ```
  Expected: HTTP 403 Forbidden on all unauthorized paths.

### 2.5 Invariant I5: Scanner Container Containment
- **Requirement:** Ephemeral containers run as unprivileged user (`UID 1000:1000`), drop all Linux capabilities (`--cap-drop=ALL`), and enforce a 512MB RAM cap.
- **Audit Procedure:** Verify container configuration:
  ```bash
  docker inspect --format 'User: {{.Config.User}}, Caps: {{.HostConfig.CapDrop}}, Memory: {{.HostConfig.Memory}}' <container>
  ```
  Expected: `User: 1000:1000, Caps: [ALL], Memory: 536870912` (512MB).

### 2.6 Invariant I6: Cross-User Data Isolation
- **Requirement:** No authenticated user can access, query, cancel, or delete scans or findings belonging to another user.
- **Audit Procedure:** Execute dual-user automated test:
  User A creates Scan `scan-123`.
  User B sends `GET /api/v1/scans/scan-123`, `POST /api/v1/scans/scan-123/cancel`, and `DELETE /api/v1/scans/scan-123`.
  Expected: HTTP 404 Not Found returned on all attempts (anti-enumeration boundary).

### 2.7 Invariant I7: Zero Secret or Token Leakage
- **Requirement:** GitHub tokens (`gho_*`, `ghp_*`), session secrets, and credentials scanned in source code must never appear in application logs or API responses in plain text.
- **Audit Procedure:**
  1. Scan a repository fixture containing a synthetic AWS access key and GitHub PAT.
  2. Grep Docker logs: `docker logs saferepo-web` and `docker logs saferepo-worker`.
  3. Query database: `db.findings.find({ scanId: ... })`.
  4. Verify all code snippets and error messages show `[REDACTED SECRET]` or `[REDACTED]`.

---

## 3. Scheduled Audit Log Records

*(To be populated during Phase 10 execution across Cohorts 1–4)*

| Audit ID | Date | Cohort | Invariant Checked | Verification Method | Result | Notes / Evidence | Auditor Sign-off |
|---|---|---|---|---|---|---|---|
| *SEC-01* | *Pending* | Cohort 1 | I1: Scanner Network | Inspect `--network=none` | *Pending* | *Scheduled for Cohort 1* | *Pending* |
| *SEC-02* | *Pending* | Cohort 1 | I3: Web Socket Isolation | Probe `/var/run/docker.sock` in web | *Pending* | *Scheduled for Cohort 1* | *Pending* |
| *SEC-03* | *Pending* | Cohort 1 | I4: Docker Proxy API | Probe unauthorized POST paths | *Pending* | *Scheduled for Cohort 1* | *Pending* |
| *SEC-04* | *Pending* | Cohort 1 | I7: Secret Redaction | Verify `[REDACTED SECRET]` in DB | *Pending* | *Scheduled for Cohort 1* | *Pending* |
| *SEC-05* | *Pending* | Cohort 2 | I6: Cross-User Isolation | Verify 404 on cross-user queries | *Pending* | *Scheduled for Cohort 2* | *Pending* |
| *SEC-06* | *Pending* | Cohort 3 | I2: Host Filesystem Bounds | Verify rootfs ro + tmpfs size | *Pending* | *Scheduled for Cohort 3* | *Pending* |
| *SEC-07* | *Pending* | Cohort 4 | All Invariants (I1–I7) | End-of-Beta Full Security Audit | *Pending* | *Scheduled for Cohort 4* | *Pending* |

---

## 4. Security Incident & Anomaly Log

| Incident ID | Date | Invariant Impacted | Description of Anomaly | Root Cause | Immediate Containment | Permanent Remediation | Sign-off |
|---|---|---|---|---|---|---|---|
| *None* | — | — | *No security anomalies recorded.* | — | — | — | — |
