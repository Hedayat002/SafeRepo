# SafeRepo System Architecture & Context

**Document Role:** Stable reference for SafeRepo system architecture, components, boundaries, and security invariants.<br>
**Authority:** Architectural decisions documented here reflect approved ADRs in [.ai/decisions.md](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/decisions.md) and [docs/SYSTEM_ARCHITECTURE.md](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/docs/SYSTEM_ARCHITECTURE.md).

---

## 1. System Overview

SafeRepo is an automated vulnerability detection platform designed to safely acquire, sandbox, and scan GitHub repositories for security vulnerabilities, software composition analysis (SCA), and leaked credentials without exposing the host system or application data to untrusted code execution.

---

## 2. Core Technology Stack

| Layer | Technology | Baseline Version | Purpose |
|---|---|---|---|
| **Runtime** | Node.js | `24.19.0 LTS` | Unified JavaScript runtime across web, worker, and CI |
| **Web Framework** | Next.js | `^16.3.3` (App Router) | Stateless Web UI & API layer with `output: 'standalone'` |
| **UI Library** | React / React DOM | `^19.2.8` | Server and client components |
| **Styling** | Tailwind CSS | `^3.4.19` | Scoped utility styling |
| **Database** | MongoDB | `7.0` / Atlas | Document storage for users, sessions, scans, findings |
| **ODM** | Mongoose | `^8.24.4` | Data modeling, validation, and lifecycle hooks |
| **Validation** | Zod | `^3.24.2` | Runtime schema validation for inputs and environment |
| **Logging** | Pino / Pino-Pretty | `^9.6.0` | Structured JSON logging with automated PII masking |
| **Testing** | Vitest | `^1.6.1` | Unit, integration, and security test suites (506 tests) |
| **Proxy / Ingress** | Caddy | `2.9-alpine` | Automatic HTTPS termination and reverse proxy |
| **Docker Proxy** | Docker Socket Proxy | `0.1.1` (Tecnativa) | Defense-in-depth API filtering for scan worker |

---

## 3. Dual-Tier Architectural Components

SafeRepo enforces strict separation of privileges across distinct operational tiers:

```text
INTERNET / GITHUB           PUBLIC INGRESS                     APPLICATION TIER
─────────────────           ──────────────                     ────────────────
GitHub OAuth / Webhook ──►  Caddy Reverse Proxy  ───────────►  Next.js 16 Web/API Container
                            • Ports 80, 443 (Public)           • Port 3000 (Internal on web-net)
                            • Automatic TLS                    • Non-root (USER nextjs, UID 1001)
                            • Security Headers                 • Pure Server-Side Sessions
                                                               • ZERO Docker CLI or socket access
                                                                       │
                                                                       ▼
                                                               MongoDB 7 Database
                                                               • Port 27017 (backend-net only)
                                                               • Users, Sessions, Scans, Findings
                                                                       ▲
                                                                       │ (Atomic Queue Polling)
SANDBOX TIER                                                   TRUSTED WORKER TIER
────────────                                                   ───────────────────
Ephemeral Stage 1 Scanners ◄── Restricted Docker Proxy ◄────── Scan Worker Container
• semgrep:1.100.0 (SAST)       • Port 2375 (worker-proxy-net)   • Non-root (USER workeruser, UID 1001)
• trivy:0.59.1 (SCA)           • CONTAINERS=1, POST=1           • Minimal CLI tools (docker-cli, git)
• gitleaks:v8.24.0 (Secrets)   • Dangerous APIs disabled (=0)   • Ephemeral workspace (/tmp/saferepo-workspaces)
• --network=none, --read-only  • Unix socket: /var/run/docker.sock • Zero daemon; mediated socket access
```

### 3.1 Web Application Tier (`apps/web`)
- Stateless Next.js 16.3.3 App Router handling user interaction, authentication, and reporting.
- Authenticated via server-side sessions stored in MongoDB with HttpOnly cookies.
- **Critical Boundary:** The Web container has **ZERO** access to the Docker socket, Docker CLI, or Docker daemon.

### 3.2 Trusted Scan Worker Tier
- Independent Node.js 24 background polling worker (`apps/web/src/lib/scanner/worker-entrypoint.ts`).
- Claims pending scan jobs from MongoDB using atomic find-and-modify conditional leasing (`queue.ts`).
- Executes multi-scanner orchestration pipeline under a global deadline (`SCAN_TIMEOUT_SECONDS = 300s`).
- Runs as an unprivileged system user (`workeruser:workergroup`, UID/GID 1001).
- Operates in a dedicated, isolated workspace directory (`/tmp/saferepo-workspaces`) with permissions `0700`.
- Contains minimal client CLI binaries (`docker-cli`, `git`). Contains **no Docker daemon**.

### 3.3 Restricted Docker Socket Proxy (`docker-proxy`)
- Single-host beta mediation boundary using `tecnativa/docker-socket-proxy:0.1.1`.
- Accessible strictly on the internal `worker-proxy-net` network. Port 2375 is **never** published to host or internet.
- Restricts Docker API endpoints: permits container lifecycle (`CONTAINERS=1`, `POST=1`, `PING=1`) while strictly disabling high-risk endpoints (`VOLUMES=0`, `NETWORKS=0`, `EXEC=0`, `BUILD=0`, `AUTH=0`, `SECRETS=0`, `SYSTEM=0`).

### 3.4 Database Tier
- MongoDB 7 deployed in container (local/single-host beta) or MongoDB Atlas (production).
- Network access restricted exclusively to the internal `backend-net` network. Port 27017 is **never** publicly exposed.

---

## 4. Core Security Invariants

1. **Docker Socket Isolation:**
   - Web application container has zero socket access.
   - Scan worker container has no direct socket mount; communicates via `DOCKER_HOST=tcp://docker-proxy:2375`.
   - Child scanner containers never receive socket mounts.
2. **Scanner Sandbox Execution (Stage 1):**
   - Ephemeral containers run with `--network=none`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user=1000:1000`, 512MB RAM cap, and hard timeouts.
   - Pinned immutable versions: `semgrep/semgrep:1.100.0`, `aquasec/trivy:0.59.1`, `zricethezav/gitleaks:v8.24.0`.
3. **Dependency Scanning Isolation (Stage 2):**
   - OSV advisory queries execute via parsed dependency manifests only. Untrusted repository code is never executed; lifecycle scripts (`postinstall`) are never run.
4. **Secret Hygiene & Redaction:**
   - Plaintext credentials and tokens are redacted at the process boundary.
   - Gitleaks output is scrubbed in-memory; raw matches and stdout/stderr are never written to logs or database.
   - Zero secrets committed to Git, baked into Dockerfiles, or exposed in image layers.
5. **Architectural Boundary for Production:**
   - The Docker socket proxy provides defense-in-depth for single-host beta testing.
   - For GA production, the required architecture is a **Dedicated Isolated Worker VM** with its own Docker daemon, physically separated from Web/API and database.
