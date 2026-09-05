# Decisions

---

### 2026-08-22 — Database: MongoDB + Mongoose (Finalized)

- **Context:** SafeRepo needs a primary database for storing users, scans, and findings.
- **Decision:** MongoDB 7 (local via Docker) + MongoDB Atlas (production) + Mongoose ODM.
- **Status:** Finalized and approved.
- **Consequences:**
  - (+) Flexible document schema for scan findings
  - (+) Atlas provides automated backups and monitoring
  - (+) Mongoose provides schema validation and middleware
  - (-) No native foreign key enforcement (handled at application layer)
  - (-) Referential integrity managed in Mongoose hooks
- **ADR:** docs/adr/ADR-001-postgres.md (superseded original PostgreSQL decision)
- **Exclusions:** PostgreSQL, Prisma, and Redis are explicitly excluded from the MVP. Do not reintroduce.

---

### 2026-08-22 — Docker: MongoDB 7 Only

- **Context:** Docker Compose is used for local development database and scanner isolation.
- **Decision:** Docker Compose contains MongoDB 7 as the local database service with persistent named volume (`mongodata:/data/db`).
- **Status:** Verified and approved.
- **Exclusions:** Do not add PostgreSQL, Redis, or Prisma infrastructure to Docker Compose.

---

### 2026-08-22 — Deployment: GitHub Before Any Remote Deployment (Mandatory)

- **Context:** SafeRepo code must be reviewed and pushed to GitHub before deploying to any remote platform.
- **Decision:** Code must be on GitHub before any remote deployment occurs. Direct deployment without reviewed code on GitHub is not permitted.
- **Status:** Approved.
- **Reference:** docs/DEPLOYMENT.md, docs/PHASES/PHASE_09.md

---

### 2026-08-22 — Architecture: Local-First, Vercel Optional (Supersedes previous Vercel-mandatory decision)

- **Context:** The previous deployment decision assumed Vercel as a mandatory deployment target. After review, this has been changed.
- **Previous decision:** Vercel was treated as the mandatory deployment platform for the web application.
- **New decision:** SafeRepo must be fully functional in a local Docker-based environment. Vercel is OPTIONAL — one possible hosting option for the web/API layer, not a requirement.
- **Status:** Approved.
- **Rationale:**
  - The core product (security scanning) must not depend on Vercel
  - The scanner service requires Docker, which Vercel cannot run
  - Deployment platform is secondary to product functionality
  - Hosting decisions deferred to Phase 09 for proper evaluation
- **Consequences:**
  - (+) No vendor lock-in to a specific hosting provider
  - (+) Full local development and testing without external dependencies
  - (+) Scanner and web/API hosting can be evaluated independently
  - (-) Hosting decision is deferred, adding a decision point in Phase 09
- **What Vercel is NOT:**
  - Not required for scanning
  - Not required for Docker
  - Not required for MongoDB
  - Not required for security analysis
  - Not required for local testing
- **Reference:** docs/DEPLOYMENT.md, docs/SYSTEM_ARCHITECTURE.md, docs/PHASES/PHASE_09.md

---

### 2026-08-22 — Phase 09: Renamed from "Vercel Deployment" to "Deployment and Beta Infrastructure"

- **Context:** Phase 09 previously assumed Vercel deployment. Now it covers broader hosting evaluation.
- **Decision:** Phase 09 will evaluate hosting for both web/API and scanner service, decide on platforms based on security/cost/reliability criteria, and prepare the beta environment.
- **Status:** Approved.
- **Reference:** docs/ROADMAP.md, docs/PHASES/PHASE_09.md

---

### 2026-08-23 — C1: Staged Scanner Network Policy (Phase 00 Review — Corrected)

- **Context:** The Phase 00 review identified that OSV API, npm audit, and pip-audit require outbound HTTP access, which conflicts with the `--network=none` policy documented for all scanners. A single network policy cannot apply to all scanner types.
- **Decision:** Use a staged scanning architecture with two distinct network policies:
  - **Stage 1 — Network-Disabled:** Semgrep, Gitleaks, and Trivy (with pre-loaded offline vulnerability database) run inside Docker containers with `--network=none`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, CPU/memory/PID limits, timeouts, and automatic cleanup.
  - **Stage 2 — Controlled Network:** OSV API, npm audit, and pip-audit run inside dedicated restricted containers with controlled outbound network access, `--read-only`, `--tmpfs`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, CPU/memory/PID limits, timeouts, automatic cleanup, and no Docker socket access. Dependency scanners MUST NOT execute directly on the developer/production host. They query advisory APIs using parsed manifest data only. They NEVER execute repository code, NEVER run lifecycle scripts, and NEVER perform unrestricted package installation. Explicit outbound allowlisting is used where technically possible.
- **Status:** Approved (corrected 2026-08-23 — changed Stage 2 from host-side to container-isolated).
- **Consequences:**
  - (+) Untrusted repository code never has network access
  - (+) Dependency analysis can query up-to-date vulnerability databases
  - (+) Clear separation between code execution and advisory lookup
  - (+) Both stages are isolated from the host
  - (-) Two distinct container configurations to maintain (network-disabled vs controlled-network)
- **Reference:** docs/SYSTEM_ARCHITECTURE.md (Section 5), docs/REQUIREMENTS.md (NFR-02)

---

### 2026-08-23 — C2: Docker Socket Security Boundary (Phase 00 Review)

- **Context:** The Scanner Service needs to create Docker containers for isolated scanning. Docker socket access (`/var/run/docker.sock`) grants root-equivalent privileges. If exposed to untrusted code, this is a critical security vulnerability.
- **Decision:** Introduce a dedicated Scanner Runner as a trusted boundary between the SafeRepo API and the Docker engine. The Docker socket MUST NOT be mounted into:
  - The web application container
  - The API container
  - Any scanner container
  - Any container processing untrusted repository contents
- **Scanner Runner responsibilities:**
  - Only component with Docker API access
  - Enforces explicit allowlist of: scanner image, command, arguments, mounts, CPU/memory/PID limits, timeout, network policy, filesystem policy
  - Repository contents MUST NEVER control Docker configuration directly
  - Only pre-approved, pinned scanner images may be used
- **Status:** Approved.
- **Consequences:**
  - (+) Untrusted code cannot access Docker daemon
  - (+) Explicit allowlist prevents arbitrary container creation
  - (+) Clear security boundary documented and enforceable
  - (-) Adds architectural complexity (Scanner Runner component)
- **Reference:** docs/SYSTEM_ARCHITECTURE.md (Scanner Runner section, Section 5)

---

### 2026-08-23 — H1: Server-Side Sessions for Authentication (Phase 00 Review)

- **Context:** Authentication session strategy was TBD (JWT vs server-side sessions). Phase 01 requires this decision to implement GitHub App authentication.
- **Decision:** Use server-side sessions with the following characteristics:
  - Opaque session identifier (not JWT)
  - Secure cookie with HttpOnly flag
  - Appropriate SameSite policy
  - Server-side session state stored in MongoDB
  - Session expiration with configurable timeout
  - Session revocation on logout
  - No authentication tokens in localStorage or client-accessible storage
  - GitHub authorization credentials/tokens remain server-side only
- **Status:** Approved.
- **Rationale:**
  - Server-side sessions allow immediate revocation (unlike JWT)
  - No sensitive data in client-accessible storage
  - MongoDB is already the approved database — no new infrastructure needed
  - GitHub tokens must stay server-side for security
- **Consequences:**
  - (+) Immediate session revocation on logout
  - (+) No sensitive tokens in browser storage
  - (+) Session state centralized and auditable
  - (-) Requires MongoDB for session persistence (acceptable — MongoDB is already in the stack)
  - (-) Slightly more complex than stateless JWT
- **Supersedes:** TBD item in REQUIREMENTS.md Section 6
- **Reference:** docs/SYSTEM_ARCHITECTURE.md (Section 5), docs/REQUIREMENTS.md (Section 6)

---

### 2026-09-05 — Phase 05: Secret Scanning Redaction & Zero Raw Secret Persistence

- **Context:** Secret scanning identifies credentials and keys. Logging or storing plaintext secrets introduces critical exposure risks.
- **Decision:**
  - Pinned scanner image `zricethezav/gitleaks:v8.24.0` running in Stage 1 Docker isolation (`--network=none`, `--read-only`, tmpfs, unprivileged user `1000:1000`, dropped capabilities).
  - Explicit process-boundary redaction flags: `dir /src --report-format json --report-path - --redact --no-banner --no-color`.
  - Process stdout and stderr treated as sensitive: zero logging of stdout/stderr, zero persistence of raw Gitleaks JSON, in-memory parsing only, sanitized error metadata.
  - Normalization scrubbing: `codeSnippet` set strictly to `[REDACTED SECRET]`, metadata scrubbed of `Secret` and `Match` attributes.
  - Exit code semantics: Exit code 0 (no leaks) and 1 (leaks detected) are both normal success completions; exit code >1 represents scanner failure.
  - Deterministic fingerprinting: SHA-256 of `RuleID:file:StartLine:EndLine`.
- **Status:** Approved & Implemented.
- **Reference:** docs/PHASES/PHASE_05.md, docs/SYSTEM_ARCHITECTURE.md (Section 5)

