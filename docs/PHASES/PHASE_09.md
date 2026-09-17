# Phase 09 — Production Deployment & Beta Infrastructure

**Status:** Planning (Awaiting Final Human Approval — Revised)

---

## 1. Objective

Package, containerize, configure, and validate SafeRepo's production deployment architecture, establishing a secure, provider-agnostic, dual-tier operational environment (Stateless Next.js 16 Web/API layer + Dedicated Trusted Scan Worker with Docker Stage 1 isolation + Configurable MongoDB Database) ready for the 100-user beta without compromising architectural security boundaries, leaking production secrets, or incurring unnecessary hosting costs.

Phase 09 bridges the gap between local development validation (Phases 01–08) and live multi-user beta operation (Phase 10). It is strictly focused on:
1. **Production packaging & containerization** (Next.js 16 standalone output and worker packaging).
2. **Docker socket security & threat model mitigation** (minimizing trust boundaries for untrusted code execution).
3. **Environment validation & operational tooling** (pre-flight checks, pinned scanner pre-caching, smoke tests).
4. **Comprehensive deployment & incident runbooks** (Ubuntu 24.04 LTS deployment, database options, secret management).
5. **Strict separation between Local Validation and Production Deployment** (no automated cloud provisioning).

No new scanner engines, database models, or UI features are introduced in this phase.

---

## 2. Current System Baseline & Evidence

### 2.1 Completed Phases

| Phase | Scope | Status | Checkpoint Commit |
|-------|-------|--------|-------------------|
| Phase 00 | Project Definition & Architecture | ✅ Complete | Initial baseline |
| Phase 01 | Application Foundation & Authentication | ✅ Complete | `1c82105` |
| Phase 02 | Safe Repository Acquisition & Workspaces | ✅ Complete | Validated |
| Phase 03 | Semgrep SAST Integration (Docker Stage 1) | ✅ Complete | Validated |
| Phase 04 | Dependency Scanning (Trivy + OSV Client) | ✅ Complete | `35fc70b` |
| Phase 05 | Secret Scanning (Gitleaks + Redaction) | ✅ Complete | `b533887` |
| Phase 06 | Unified Scan Engine (Queue, Worker, Sweeper) | ✅ Complete | `dab9f8f` |
| Phase 07 | Security Dashboard (RSC + Client Polling) | ✅ Complete | `f52da07` |
| Phase 08 | Production Hardening (Retention, Cancel, CSP) | ✅ Complete | `521c722` |
| CI Baseline | Node.js 24.19.0 Migration & Linux Rollup | ✅ Complete | `9fb53b0` |

### 2.2 Current Metrics (Checkpoint: `9fb53b0`)

| Metric | Current Value | Evidence Source |
|--------|---------------|-----------------|
| Git Branch | `main` | `git branch --show-current` |
| HEAD Commit | `9fb53b0` | `git rev-parse --short HEAD` |
| Remote Alignment | `HEAD == origin/main` | `git status` / `git rev-parse` |
| Working Tree | Clean (0 modified / 0 untracked) | `git status --short` |
| Total Automated Tests | 506 tests across 28 test suites | `TESTING.md`, `vitest.config.ts` |
| Test Framework | Vitest v1.6.1 + V8 Coverage | `apps/web/package.json` |
| Node.js Runtime | Node.js 24.19.0 LTS | `.github/workflows/ci.yml` |
| Web Application Framework | **Next.js 16.3.3** (`^16.3.3`) | `apps/web/package.json` |
| React Runtime | **React 19.2.8** (`^19.2.8`) | `apps/web/package.json` |
| Production Dependencies | `mongoose ^8.24.4`, `next ^16.3.3`, `pino ^9.6.0`, `react ^19.2.8`, `react-dom ^19.2.8`, `zod ^3.24.2` | `apps/web/package.json` |
| Local Database | MongoDB 7 (`mongo:7` container) | `docker-compose.yml` |

### 2.3 Verified Subsystems in Codebase

1. **Web / API Layer:** Next.js 16.3.3 App Router in `apps/web/src/app/`, with authenticated server-side sessions (`src/lib/session.ts`), Zod schema validation (`src/lib/schemas.ts`), rate limiting (`src/lib/rate-limit.ts`), request ID correlation middleware (`src/lib/middleware/request-logger.ts`), and strict CSP headers (`apps/web/next.config.mjs`).
2. **Scan Queue & Worker:** MongoDB-backed atomic FIFO queue in `apps/web/src/lib/scanner/queue.ts`, standalone worker entrypoint in `apps/web/src/lib/scanner/worker-entrypoint.ts` (`npm run worker`), heartbeat monitoring, periodic reconciliation sweeper, and cancellation detection.
3. **Orchestrator:** Sequential scanner pipeline in `src/lib/scanner/orchestrator.ts` managing Semgrep, Trivy, OSV, and Gitleaks under a global deadline (`SCAN_TIMEOUT_SECONDS = 300s`).
4. **Hardened Runner:** Docker Stage 1 isolation in `src/lib/scanner/runner.ts` executing `--network=none`, `--read-only`, `--cap-drop=ALL`, `--user=1000:1000`, 512MB RAM cap, and stdout buffer limits.
5. **Data Retention & Lifecycle:** Automated TTL cleanup in `src/lib/scanner/retention.ts` (`SCAN_RETENTION_DAYS = 90`, `MAX_SCANS_PER_USER = 500`), scan deletion (`DELETE /api/v1/scans/:id`), and cancellation (`POST /api/v1/scans/:id/cancel`).

---

## 3. Threat Model & Docker Socket Security

### 3.1 The Risk: Why the Docker Socket is a High-Value Security Boundary

SafeRepo clones and scans **untrusted third-party source code** from arbitrary repositories. This fundamentally alters the threat profile:
- Untrusted code repositories may contain malicious build files, nested git configurations, symlink exploits, path traversal attempts, or compiler/parser exploit payloads targeting static analysis tools (Semgrep, Trivy, Gitleaks).
- The scan worker requires Docker access to spawn isolated Stage 1 ephemeral containers for each scanner.
- Access to the Unix domain socket `/var/run/docker.sock` provides **unrestricted API control over the Docker daemon**. In Linux, whoever can communicate with the Docker daemon can effectively achieve **root-equivalent privileges on the host system** by creating a container that mounts the host root (`/`) with write permissions, or by running with `--privileged`.

### 3.2 Why Container Isolation Does NOT Automatically Protect the Docker Host

It is a dangerous misconception that because child scanner containers run with `--network=none`, `--read-only`, and `--cap-drop=ALL`, the host is fully protected:
1. **Stage 1 Isolation Applies Only to Child Containers:** Stage 1 constraints apply *strictly* to the ephemeral containers spawned by the worker for Semgrep, Trivy, and Gitleaks.
2. **Worker Process Vulnerability:** If the scan worker itself were compromised (for example, via an unhandled vulnerability in repository cloning, archive extraction, git command injection, or Node.js runtime memory corruption), an attacker in control of the worker process would possess the Docker socket.
3. **Escape via Daemon API:** With direct socket access, the attacker could issue raw Docker API calls to spawn an unconstrained container (`--privileged -v /:/host`), entirely bypassing all Stage 1 restrictions, escaping all container namespaces, and acquiring full host control.

### 3.3 Worker Isolation & Socket Protection Strategies

To enforce the principle of least privilege, Phase 09 establishes three complementary defenses:

```
UNTRUSTED WORLD           APPLICATION TIER                       TRUSTED WORKER TIER                 SANDBOX TIER
───────────────           ────────────────                       ───────────────────                 ────────────
GitHub Repositories ──►   Next.js 16 Web/API Container    ──►    Scan Worker Container        ──►    Restricted Docker Proxy
(Untrusted Code)          • NO Docker socket mount               • NO public HTTP exposure           • ALLOW: run, kill, rm
                          • Non-root (UID 1000)                  • Claims jobs from DB               • DENY: --privileged
                          • Stateless request/response           • Git clone in isolated dir         • DENY: host mounts
                                                                                                     • Stage 1 containers
```

#### Strategy 1: Absolute Exclusion from Web Tier
- The Web/API container (`apps/web`) handles HTTP requests from the public internet.
- **Invariant:** The Web container **must NEVER** have `/var/run/docker.sock` mounted or reachable. It communicates exclusively with MongoDB.

#### Strategy 2: Restricted Docker Socket Proxy (Local / Single-Host Beta)
- When running in a single-host environment (e.g. local validation or single-VPS beta testing), the worker **must not** have raw, unrestricted access to the Docker daemon.
- Communication is routed through a **restricted Docker socket proxy** (e.g. `tecnativa/docker-socket-proxy` or an equivalent unix socket firewall).
- **Enforced Constraints:**
  - `CONTAINERS=1` (allowed: create, start, stop, kill, wait, delete)
  - `IMAGES=1` (allowed: list, inspect, pull pre-approved images)
  - `POST=1` (required for container creation)
  - `VOLUMES=0` (denied: cannot create or inspect arbitrary Docker volumes)
  - `NETWORKS=0` (denied: cannot alter Docker networks)
  - `EXEC=0` (denied: cannot execute commands in running host containers)
  - `BUILD=0` (denied: cannot trigger image builds)
  - `AUTH=0` / `SECRETS=0` (denied: cannot inspect Docker daemon credentials)
  - Host directory mounts are strictly restricted to the designated temporary workspace directory (`SCAN_WORKSPACE_DIR`), preventing mounts of `/`, `/etc`, or `/var`.

#### Strategy 3: Dedicated Worker Host (Recommended Production Posture)
- **Production Beta Architecture:** The Worker process is deployed on a **dedicated, isolated Worker VM/host** completely separated from the Web application host.
- **Blast Radius Containment:** In the catastrophic event of a host compromise on the Worker instance:
  - The Web server, session tokens, user data, and production secrets are safe on their own host.
  - The database is protected via MongoDB network access rules (worker has restricted read/write to `scans` and `findings` only).
  - The worker host can be instantly terminated and rebuilt from an immutable image.

### 3.4 Beta Decision Matrix for Docker Execution

| Environment | Architecture | Socket Protection | Evaluation |
|-------------|--------------|-------------------|------------|
| **Local Validation (Dev/Test)** | Single Machine (Docker Desktop/Engine) | Raw socket or proxy allowed for testing | Acceptable for developer-owned machine running trusted test repos. |
| **100-User Beta (Single Host)** | Single Hardened Ubuntu VPS (Web + Worker) | **Restricted Docker Socket Proxy REQUIRED** | Acceptable for initial controlled beta IF proxy blocks privileged flags and arbitrary host mounts. |
| **Production GA (Multi-Host)** | Decoupled (Web Host + Dedicated Worker VM) | Separate host + Isolated Docker daemon | **Target architecture** for full production release. |

---

## 4. Next.js 16 Runtime & Standalone Containerization

### 4.1 Actual Framework Baseline

The SafeRepo repository is built on:
- **Next.js:** `^16.3.3` (Installed in `apps/web/package.json`)
- **React:** `^19.2.8`
- **React DOM:** `^19.2.8`
- **Node.js:** `24.19.0 LTS`

Next.js will **not** be downgraded. Next.js 16 natively supports `output: 'standalone'` builds, which automatically trace dependencies and produce a minimal `.next/standalone` folder containing only the files required to run the Node.js production server.

### 4.2 Multi-Stage Web Dockerfile Architecture (`apps/web/Dockerfile`)

```dockerfile
# Stage 1: Base image
FROM node:24.19.0-alpine AS base
WORKDIR /app
RUN apk add --no-cache libc6-compat

# Stage 2: Install dependencies
FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# Stage 3: Build application
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# Stage 4: Minimal production runner
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy standalone output and static assets
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

CMD ["node", "server.js"]
```

### 4.3 Scan Worker Dockerfile Architecture (`apps/web/Dockerfile.worker`)

```dockerfile
FROM node:24.19.0-alpine AS worker-base
WORKDIR /app
RUN apk add --no-cache docker-cli git libc6-compat

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy application source and scanner rules
COPY . .
ENV NODE_ENV=production

# Worker runs as unprivileged user with access to docker socket group
RUN addgroup --system --gid 1001 workergroup && \
    adduser --system --uid 1001 workeruser && \
    addgroup workeruser docker || true

USER workeruser

CMD ["npm", "run", "worker"]
```

---

## 5. Scanner Image Pinning & Integrity Strategy

### 5.1 Strictly Pinned Scanner Versions

To guarantee deterministic, reproducible, and secure static analysis, mutable Docker tags (such as `:latest`, `:edge`, or `:v1`) are **strictly prohibited**. Every scanner is pinned to an immutable semantic release:

| Scanner | Tool | Pinned Tag | Base Image Digest Verification | Memory Cap | Network |
|---------|------|------------|--------------------------------|------------|---------|
| SAST | **Semgrep** | `semgrep/semgrep:1.100.0` | Verified against official Semgrep releases | 512MB | `--network=none` |
| SCA | **Trivy** | `aquasec/trivy:0.59.1` | Verified against Aqua Security releases | 512MB | `--network=none` |
| Secrets | **Gitleaks** | `zricethezav/gitleaks:v8.24.0` | Verified against Gitleaks releases | 512MB | `--network=none` |
| Advisories | **OSV Client** | In-process API client | `https://api.osv.dev/v1/querybatch` | N/A (30s timeout) | Egress allowed for OSV API |

### 5.2 Prohibition of Mutable Tags

- Mutable tags (e.g. `:latest`) create non-deterministic security findings: a scan executed today could report different vulnerabilities than the same commit scanned tomorrow.
- A compromised upstream tag could inject malicious code into the scanning pipeline without changes to the SafeRepo codebase.
- In production, images will be validated by **exact tag and SHA256 digest** in the deployment configuration.

### 5.3 Scanner Upgrade Review & Testing Policy

Scanner versions will only be updated through a formal gated workflow:
1. **Security Changelog Audit:** Review upstream release notes for rule syntax changes, deprecations, or security fixes.
2. **Dependency Vulnerability Scan:** Audit the upstream container image with Trivy before adoption.
3. **Test Suite Verification:** Run Vitest scanner suites (`semgrep.test.ts`, `trivy.test.ts`, `gitleaks.test.ts`, `normalizer.test.ts`) against known test fixtures.
4. **Normalized Finding Parity Check:** Verify that normalized findings match expected schema invariants.
5. **No Blind Pulls:** Images are never pulled automatically during live runtime. Upgrades occur via scheduled maintenance.

---

## 6. Database Deployment Options & Workload Analysis

SafeRepo's database layer uses standard Mongoose 8 connecting via standard URI connection strings (`mongodb://` or `mongodb+srv://`). Database deployment is evaluated based on the 100-user beta workload:

### 6.1 Workload Assumptions for 100-User Beta

- **User Base:** ~100 registered GitHub beta users.
- **Scan Volume:** Estimated 5–20 scans per user over beta period (~500–2,000 total scans).
- **Findings Volume:** Average 25 findings per scan (~12,500–50,000 findings).
- **Data Footprint:** ~5KB per scan document + ~2KB per finding document ≈ **35MB–125MB total data storage**.
- **Retention Guard:** Phase 08 retention policy (`SCAN_RETENTION_DAYS = 90`, `MAX_SCANS_PER_USER = 500`) automatically auto-prunes oldest terminal scans, strictly bounding database growth.
- **Connection Load:** Next.js pool (`maxPoolSize: 10`) + Worker pool (`maxPoolSize: 5`) ≈ 15–25 concurrent connections.

### 6.2 Evaluation of Database Deployment Options

| Concern | Option A: MongoDB Atlas M0 (Free Tier) | Option B: MongoDB Atlas M10 (Dedicated Cluster) | Option C: Self-Hosted MongoDB 7 (Container on VPS) |
|---------|---------------------------------------|------------------------------------------------|-----------------------------------------------------|
| **Suitability for Beta** | **Viable for initial start** | **Production Recommended** | **Viable for Local / Single Host** |
| **Cost** | ₹0 | ~$57/month | Included in VPS cost ($4–$6/month) |
| **Storage Limit** | 512MB (Fits 100-user beta) | 10GB+ (Auto-scaling) | Limited only by VPS disk (e.g. 40GB SSD) |
| **Connection Limit** | 500 connections (Sufficient) | 1,500+ connections | Configurable (Default: 65,536) |
| **Network Access / IP Rules** | IP Access List (Static IP of host) | VPC Peering / PrivateLink / IP List | Internal Docker network (no public port) |
| **TLS/SSL Encryption** | Enforced TLS 1.3 | Enforced TLS 1.3 | Configurable (Self-signed or internal CA) |
| **Automated Backups** | None (Requires manual `mongodump`) | Automated continuous point-in-time | Cron `mongodump` script to S3/B2 |
| **Availability SLA** | No SLA (Shared infrastructure) | 99.995% SLA (Replica set) | Dependent on host uptime |

### 6.3 Recommendation for Phase 09 Beta

1. **Option 1 (Zero-Cost Beta):** MongoDB Atlas M0 Free Tier configured with:
   - TLS 1.3 enforced.
   - IP Access List strictly restricted to the production host IP (no `0.0.0.0/0`).
   - Dedicated unprivileged database user (`readWrite` on `saferepo` only).
   - Automated daily backup script via `mongodump`.
2. **Option 2 (Self-Hosted Single-Host Beta):** MongoDB 7 container running on the same hardened host inside a private Docker bridge network, with persistence via Docker named volume (`mongodata`), completely shielded from public internet exposure.
3. **Upgrade Path:** If database storage exceeds 350MB or Atlas M0 connection throttling occurs, upgrade seamlessly to Atlas M10 or migrate to a managed replica set without changing application code.

---

## 7. Production Secret Handling & Operational Security

SafeRepo enforces a strict **Zero-Leakage Secret Policy**:

### 7.1 Absolute Invariants

1. **No Production Secrets in Version Control:** No real secrets, tokens, connection strings, or private keys will ever be committed to Git. Enforced by `.gitignore`, pre-commit hooks, and Gitleaks CI checks.
2. **No Production Secrets in Dockerfiles or Build Layers:** Dockerfiles will never contain `ARG` or `ENV` values holding production credentials. Builds must be completely free of secret data.
3. **No Production Secrets in Container Images:** Secrets are injected exclusively at runtime via secure environment variables or read-only volume mounts (`.env.production` with `chmod 600`).
4. **No Production Secrets in Logs:** Pino logger masks sensitive headers (`authorization`, `cookie`, `set-cookie`, `session`, `token`). `sanitizeErrorMessage()` redacts GitHub tokens (`gho_*`, `ghp_*`) from all error strings.
5. **No Production Secrets Supplied to AI Agents:** AI development tools and assistants must never be provided with real production credentials, API keys, or production database connection strings. Placeholders are used exclusively during planning and local testing.
6. **Minimum Privilege GitHub App:**
   - Production GitHub App credentials are created manually by the human operator.
   - Repository permissions: `Contents: Read`, `Metadata: Read`. Zero write permissions. Zero admin permissions.

---

## 8. Local Validation vs. Production Deployment Boundary

To prevent accidental deployments or untested infrastructure changes, Phase 09 establishes a strict operational boundary:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           LOCAL VALIDATION (PHASE 09 SCOPE)                     │
│                                                                                 │
│  1. Standalone Next.js 16 build verification (`apps/web/Dockerfile`)            │
│  2. Worker packaging verification (`apps/web/Dockerfile.worker`)                │
│  3. Multi-container orchestration test (`docker-compose.prod.yml`)               │
│  4. Pre-flight environment validation script (`scripts/validate-production.ts`) │
│  5. Scanner image pre-caching scripts (`scripts/preload-scanners.sh` / `.ps1`)  │
│  6. Automated live smoke test suite (`scripts/smoke-test.ts`)                   │
│  7. Complete production runbook documentation (`docs/DEPLOYMENT_RUNBOOK.md`)    │
│  8. Full test suite (506 tests) regression verification                         │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                         [HUMAN APPROVAL & MANUAL EXECUTION]
                                         │
┌────────────────────────────────────────▼────────────────────────────────────────┐
│                      PRODUCTION DEPLOYMENT (HUMAN-CONTROLLED)                   │
│                                                                                 │
│  • Human operator provisions Ubuntu 24.04 LTS server (Hetzner / DO / AWS)       │
│  • Human operator registers production GitHub App & obtains real credentials    │
│  • Human operator creates MongoDB Atlas cluster & configures IP allowlist       │
│  • Human operator creates `.env.production` on server (permissions `chmod 600`) │
│  • Human operator executes deployment runbook                                   │
│  • Human operator validates live deployment with `scripts/smoke-test.ts`        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

- **Phase 09 Implementation performs LOCAL VALIDATION ONLY.**
- There is **zero automated cloud provisioning**, zero automatic external API calls, and zero automatic remote deployment.
- Production deployment is executed manually by the human operator following the validated runbook.

---

## 9. Scope of Phase 09 Implementation

### 9.1 Deliverable 1: Next.js 16 Standalone Containerization
- Configure `output: 'standalone'` in `apps/web/next.config.mjs`.
- Author `apps/web/Dockerfile` with multi-stage build, non-root user (`nextjs:nodejs`), and minimal Alpine base.

### 9.2 Deliverable 2: Scan Worker Containerization
- Author `apps/web/Dockerfile.worker` containing Node.js 24 runtime, Docker CLI binary, scanner rules, and non-root execution.

### 9.3 Deliverable 3: Production Docker Compose Orchestration
- Author `docker-compose.prod.yml`:
  - `web` service: Internal bridge network only, port 3000, resource caps (1 vCPU, 512MB RAM), health check on `/api/health`.
  - `worker` service: Resource caps (1.5 vCPU, 1GB RAM), isolated workspace volume mount, communicates with Docker daemon via restricted proxy or dedicated socket.
  - `docker-proxy` service: Restricted Docker socket proxy blocking privileged mode and unauthorized volume mounts.
  - `caddy` service: Automatic HTTPS/TLS reverse proxy terminating ports 80/443, enforcing security headers, proxying to `web:3000`.

### 9.4 Deliverable 4: Pre-Flight Environment & Infrastructure Validator
- Author `scripts/validate-production.ts`:
  - Validates environment schema via Zod (`env.ts`).
  - Tests MongoDB connectivity (ping, replica set status, write test).
  - Tests Docker daemon availability and API version compatibility.
  - Verifies presence of pinned scanner container images.

### 9.5 Deliverable 5: Scanner Image Warmup Scripts
- Author `scripts/preload-scanners.sh` and `scripts/preload-scanners.ps1` to pull and dry-run verify pinned images:
  - `semgrep/semgrep:1.100.0`
  - `aquasec/trivy:0.59.1`
  - `zricethezav/gitleaks:v8.24.0`

### 9.6 Deliverable 6: Production Smoke Test Suite
- Author `scripts/smoke-test.ts` executing live HTTP verification:
  - Validates `/api/health` status, database connection, and uptime.
  - Validates security headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`.
  - Validates `X-Request-Id` header generation and propagation.

### 9.7 Deliverable 7: Production Operations Runbook
- Author `docs/DEPLOYMENT_RUNBOOK.md`:
  - Complete Ubuntu 24.04 LTS host provisioning guide.
  - MongoDB Atlas configuration & IP allowlisting guide.
  - GitHub App production setup guide.
  - Step-by-step local validation & deployment instructions.
  - Queue draining, service restart, and disaster recovery procedures.

---

## 10. Explicit Non-Goals & Scope Control

The following items are strictly **excluded** from Phase 09:

1. **Kubernetes / Helm Charts:** Disproportionate complexity for a 100-user beta.
2. **External Message Brokers (RabbitMQ, Redis, Celery):** SafeRepo's MongoDB-backed queue (`queue.ts`) provides atomic leasing, conditional transitions, heartbeat recovery, and stale-job reconciliation. Adding Redis or RabbitMQ introduces unnecessary failure domains and cost.
3. **New Security Scanners:** Semgrep, Trivy, OSV, and Gitleaks are feature-complete.
4. **Dashboard UI Redesign or New Features:** UI remains unchanged from Phase 07/08.
5. **Multi-Tenant Organizations / RBAC:** Single-user GitHub mapping is maintained.
6. **WebSockets / SSE:** Polling with exponential backoff is validated and sufficient for 100 users.
7. **Automated Cloud Push:** Packaging is created and verified locally; deployment to cloud hosts will occur only with explicit human execution.

---

## 11. Testing Strategy

| Category | Scope | Verification Method |
|----------|-------|---------------------|
| **Unit Tests** | `env.ts` validation, health response parser, validator logic | `npx vitest run src/lib/__tests__/env.test.ts` |
| **Build Tests** | Standalone Next.js 16 build output verification | `npm run build` generates valid `.next/standalone` |
| **Security Tests** | Web container has zero Docker socket access; non-root user execution | Dockerfile inspection & container privilege checks |
| **Smoke Tests** | Live container HTTP endpoint and security header verification | `npx tsx scripts/smoke-test.ts` |
| **Regression Tests** | All existing 506 automated tests | `npm run test` maintains 100% pass rate |
| **CI Gate** | Lint, typecheck, high-audit dependency check, build | `.github/workflows/ci.yml` passes on Node 24.19.0 |

---

## 12. Acceptance Criteria

### Security & Isolation
- [ ] **Web Container Isolation:** The Web application container has **zero** access to `/var/run/docker.sock` or any Docker daemon interface.
- [ ] **Docker Socket Security:** The Scan Worker's Docker access is explicitly mediated via a restricted proxy or dedicated host boundary, with threat model and mitigations fully documented.
- [ ] **Non-Root Execution:** All production containers (`web`, `worker`) execute as non-root users (`UID 1001`).
- [ ] **Stage 1 Scanner Invariants:** Ephemeral scanner containers maintain `--network=none`, `--read-only`, `--cap-drop=ALL`, `--user=1000:1000`, and 512MB RAM cap.
- [ ] **Zero Secrets Committed:** No production credentials, tokens, or private keys exist in Git, Dockerfiles, or image layers.

### Packaging & Configuration
- [ ] **Next.js 16 Standalone Output:** `output: 'standalone'` is configured in `apps/web/next.config.mjs`, verified against the actual installed Next.js `16.3.3` baseline without downgrading.
- [ ] **Multi-Stage Dockerfiles:** `apps/web/Dockerfile` and `apps/web/Dockerfile.worker` build cleanly.
- [ ] **Pinned Scanner Images:** `semgrep/semgrep:1.100.0`, `aquasec/trivy:0.59.1`, and `zricethezav/gitleaks:v8.24.0` are explicitly pinned with mutable tags strictly prohibited.
- [ ] **Database Flexibility:** MongoDB Atlas and self-hosted options are documented with workload limits and security requirements.

### Tooling & Runbooks
- [ ] **Pre-Flight Validation:** `scripts/validate-production.ts` executes and validates environment variables, database connectivity, and Docker daemon API.
- [ ] **Image Pre-Caching:** `scripts/preload-scanners.sh` and `.ps1` pre-pull and dry-run verify all pinned scanner images.
- [ ] **Live Smoke Test:** `scripts/smoke-test.ts` verifies `/api/health`, CSP headers, and `X-Request-Id` on running containers.
- [ ] **Deployment Runbook:** `docs/DEPLOYMENT_RUNBOOK.md` provides complete, human-executable instructions for server provisioning, GitHub App configuration, and incident recovery.

### Quality & Process
- [ ] **Local Validation First:** All Phase 09 deliverables are validated locally in containers before any production deployment.
- [ ] **Manual Production Gate:** Actual server deployment remains an explicit, human-controlled action.
- [ ] **Zero Code Regressions:** All 506 existing automated tests pass with 100% pass rate.
- [ ] **CI Passing:** GitHub Actions CI workflow passes cleanly on Node.js 24.19.0 with 0 high/critical audit vulnerabilities.

---

## 13. Implementation Order

1. **Step 1: Next.js 16 Standalone Configuration & Containerization**
   - Configure `output: 'standalone'` in `apps/web/next.config.mjs`.
   - Author `apps/web/Dockerfile` (multi-stage Next.js 16 runner).
   - Author `apps/web/Dockerfile.worker` (unprivileged worker with Docker CLI).
2. **Step 2: Production Orchestration & Tooling Scripts**
   - Author `docker-compose.prod.yml` with restricted Docker socket proxy, Caddy TLS reverse proxy, and resource bounds.
   - Author `scripts/validate-production.ts` (pre-flight environment and infrastructure validator).
   - Author `scripts/preload-scanners.sh` and `.ps1` (scanner image pre-caching).
   - Author `scripts/smoke-test.ts` (automated HTTP smoke test).
3. **Step 3: Operational Documentation**
   - Author `docs/DEPLOYMENT_RUNBOOK.md` (complete deployment and operations manual).
   - Update `docs/ROADMAP.md` and `docs/CHANGELOG.md`.
4. **Step 4: Local Container Validation & Quality Gates**
   - Build local Docker images and verify multi-container compose startup.
   - Run pre-flight validator and smoke test against local container stack.
   - Run full regression test suite (506 tests), lint, typecheck, and audit.
   - Present final Phase 09 validation report for human review.

---

## 14. Human Approval Gate

**STOP.** Phase 09 implementation **must not begin** until this revised plan is explicitly reviewed and approved by the human reviewer.

No application code, Dockerfiles, scripts, or compose manifests may be created or committed until approval is granted.
