# REQUIREMENTS.md — SafeRepo

**Version:** 0.3.0  **Date:** 2026-08-23  **Status:** Draft

---

## 1. Product Objective

SafeRepo is an open-source security analysis platform that allows developers to safely analyze a GitHub repository and understand its security risks before running or trusting it.

---

## 2. Functional Requirements

| ID | Category | Requirement | Priority | Acceptance Criteria |
|----|----------|-------------|----------|---------------------|
| **FR-01** | Authentication | User can authenticate with GitHub | Must | Connect GitHub account via GitHub App/OAuth, establish secure session, record user identity in MongoDB. |
| **FR-02** | Authentication | User can securely log out | Must | Terminates current session, clears authentication tokens/cookies, redirects to landing page. |
| **FR-03** | GitHub Integration | User can view accessible repositories | Must | List repositories accessible to the authenticated GitHub account with owner, name, visibility, and metadata. |
| **FR-04** | GitHub Integration | User can select a repository and branch | Must | Select specific repository, identify owner/name, target branch (default or selected), and commit SHA where applicable. |
| **FR-05** | Repository Acquisition | Safe acquisition of untrusted repository contents | Must | Safely clone/fetch target repository with depth limits (`--depth 1`), enforce maximum repository size limits, disallow external symlink traversal. Never execute untrusted repository code directly on the host machine. |
| **FR-06** | Security Scanning | Static code analysis via Semgrep | Must | Execute Semgrep CLI against acquired source code in an isolated environment, output structured findings. |
| **FR-07** | Security Scanning | Dependency vulnerability scanning via Trivy | Must | Run Trivy filesystem scanner for known CVEs and manifest misconfigurations in an isolated environment. |
| **FR-08** | Security Scanning | Secret detection via Gitleaks | Must | Scan repository history/files with Gitleaks in an isolated environment. Discovered secret values must be redacted immediately. |
| **FR-09** | Security Scanning | Dependency vulnerability lookup via OSV API | Must | Query the OSV API using extracted dependency manifest data without requiring paid API keys. |
| **FR-10** | Security Scanning | Ecosystem-specific dependency auditing | Must | Run `npm audit` for Node.js projects (`package-lock.json`) and `pip-audit` for Python projects (`requirements.txt`/`pyproject.toml`) where applicable. |
| **FR-11** | Scanner Isolation | Docker-isolated execution environment | Must | Run security scanners inside ephemeral Docker containers with restricted privileges, resource limits, network restrictions, timeouts, and automatic cleanup. |
| **FR-12** | Findings Normalization | Unified finding representation | Must | Map all scanner outputs to a standardized schema: scanner, severity (critical, high, medium, low, info), category (sast, dependency, secret, configuration, license), title, description, file, line, package, vulnerability identifier, remediation, and deduplication fingerprint. |
| **FR-13** | Secret Redaction | Redact discovered secrets | Must | Avoid storing or displaying discovered plaintext secrets. Store only metadata (file, line, secret type). |
| **FR-14** | Scan Lifecycle | State machine for scan lifecycle | Must | Track scan lifecycle states: `queued` → `cloning` → `scanning` → `normalizing` → `completed` / `failed` / `timed_out`. |
| **FR-15** | Security Dashboard | View repository security findings | Must | Display aggregated findings, overall severity breakdown (counts of critical, high, medium, low, info), and individual finding details. |
| **FR-16** | Security Dashboard | Filter findings by severity and category | Must | Interactive filtering by severity level and vulnerability category. |
| **FR-17** | Security Dashboard | Review remediation advice | Must | Display actionable remediation guidance for identified vulnerabilities where available. |
| **FR-18** | Scan History | View past scans | Should | List previous repository scans with status, timestamp, duration, and summary counts. |

---

## 3. Non-Functional Requirements

| ID | Category | Requirement | How Verified |
|----|----------|-------------|--------------|
| **NFR-01** | Local-First Architecture | Full functionality in a local Docker-based environment | Verified locally using Docker Compose (MongoDB 7 + isolated scanner containers) without external cloud hosting dependencies. |
| **NFR-02** | Scanner Isolation & Safety | Staged container-level restrictions | **Stage 1 (code scanners — Semgrep, Gitleaks, Trivy):** Ephemeral containers with `--network=none`, `--read-only` root filesystem, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, `--security-opt=no-new-privileges`, `--cap-drop=ALL`, CPU limits (`--cpus=1`), memory limits (`--memory=512m`, configurable per scanner), PID limits (`--pids-limit=256`), execution timeouts, and automatic cleanup (`--rm`). **Stage 2 (dependency/advisory — OSV, npm audit, pip-audit):** Dedicated restricted containers with controlled outbound network access, `--read-only` root filesystem, `--tmpfs`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, CPU/memory/PID limits, execution timeouts, automatic cleanup, no Docker socket, least privilege. MUST NOT execute directly on the host. Never executes repository code. Never runs lifecycle scripts. Uses explicit outbound allowlisting where technically possible. |
| **NFR-03** | Isolation Defense-in-Depth | No absolute trust in container boundaries | Scanned code is treated as untrusted input. No arbitrary code execution, build scripts, or package lifecycle scripts (`preinstall`, `postinstall`) may ever run during acquisition or scanning. |
| **NFR-04** | Performance & Timeouts | Configurable scan timeouts | Scans terminate and transition to `timed_out` if execution exceeds timeout limit (default 300s). UI p95 response time <300ms for dashboard queries. |
| **NFR-05** | Security & Input Validation | Robust validation and least privilege | Zod validation on all API endpoints. Helmet headers, CORS origin whitelisting, rate-limiting on scan requests. No secrets committed or logged. |
| **NFR-06** | Database & Persistence | MongoDB with Mongoose ODM | Local MongoDB 7 via Docker, MongoDB Atlas for production. Application-level referential integrity and cascade deletion. |
| **NFR-07** | Open Source & Cost | ₹0 development cost target | Built with open-source tools (Next.js, TypeScript, Tailwind CSS, Semgrep OSS, Trivy, Gitleaks, OSV API, pip-audit, npm audit). Minimal dependencies. No paid services required for MVP. |
| **NFR-08** | Hosting Independence | Vercel is optional | Web application can be deployed to Vercel or alternative hosting evaluated in Phase 09. Core scanning engine remains decoupled and functional independently of hosting vendor. |
| **NFR-09** | Testing Coverage | Automated test suite | Minimum 80% line coverage for services and utilities. Unit tests (Vitest), integration tests (Supertest + mongodb-memory-server), and E2E tests (Playwright). |

---

## 4. Architecture & Technology Constraints

### Approved Stack
- **Web Application:** Next.js (App Router), React, TypeScript, Tailwind CSS
- **Database:** MongoDB 7 (local Docker) / MongoDB Atlas (production)
- **ODM:** Mongoose
- **Containerization & Isolation:** Docker
- **Source Control & Auth:** GitHub / GitHub App
- **Scanners:** Semgrep CLI (OSS rules), Trivy CLI, Gitleaks CLI, OSV API, npm audit, pip-audit

### Explicitly Excluded from MVP
- **PostgreSQL** — ❌ Not approved
- **Prisma** — ❌ Not approved
- **Redis** — ❌ Not approved for MVP
- **AWS S3 / Supabase Storage** — ❌ Not approved / Not required for MVP

---

## 5. Out of Scope for MVP

- Multi-tenant team workspaces and RBAC
- Paid subscription and payment processing
- Custom user-uploaded scanner rules / rule builder
- Real-time GitHub PR/Commit auto-blocking bots
- Standalone mobile applications

---

## 6. Open Decisions & TBD Items

> The following items are marked **TBD — Requires architectural decision**:

- ~~**TBD — Authentication Session Strategy:**~~ **RESOLVED (2026-08-23):** Server-side sessions with opaque session ID, Secure/HttpOnly cookie, MongoDB-backed persistence, session expiration and revocation. See `.ai/decisions.md`.
- **TBD — Scan Queue Architecture:** Decision on in-database job queue vs lightweight worker mechanism for concurrent scans (Phase 02 / Phase 06).
- **TBD — Repository Size Limit:** Exact threshold for maximum repository clone size (e.g., 100MB vs 500MB) (Phase 02).
- **TBD — Production Hosting Platforms:** Selection of production hosting platform for web layer (Vercel vs alternatives) and scanner execution service (Phase 09).
- **TBD — Scan Retention Policy:** Scan history cleanup and data retention thresholds on free-tier database (Phase 08).
