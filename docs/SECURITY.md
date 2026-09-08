# SafeRepo Security Policy & Architecture

## 1. Reporting Security Vulnerabilities

If you discover a security vulnerability in SafeRepo, please do not open a public GitHub issue. Instead, report it privately to:

**Email:** `security@saferepo.dev` (or via GitHub Private Vulnerability Reporting)

We aim to acknowledge reports within 48 hours and provide status updates as fixes are validated.

---

## 2. Architectural Security Principles

SafeRepo processes untrusted third-party code repositories and executes multi-scanner static analysis. The system is designed with defense-in-depth across multiple trust boundaries:

```
Untrusted World           Next.js Application Layer               Trusted Scan Worker                Isolated Sandbox
─────────────────        ───────────────────────────             ─────────────────────              ──────────────────
Client Browser    ──►    API Routes / Dashboard RSC       ──►    Queue & Orchestrator        ──►    Docker Stage 1 Container
(CSP, SameSite)          • Server-Side Sessions (MongoDB)        • Standalone Node Process          • --network=none
                         • Zod Request Validation                • Heartbeat & Leased Claims        • --read-only filesystem
                         • Rate Limiting (Sliding Window)        • Secret Redaction                 • Dropped capabilities
                         • Anti-Enumeration (404 on ID mismatch) • Cascade Cleanup                  • Unprivileged user
```

---

## 3. Security Controls & Invariants

### 3.1 Container Isolation (Stage 1)
- **Zero Network Access:** All Docker scanner containers run with `--network=none` to prevent egress exfiltration of scanned code or environment data.
- **Read-Only Root Filesystem:** Containers mount root as read-only (`--read-only`), with temporary writable workspace mounted as isolated ephemeral volumes.
- **Dropped Capabilities:** All Linux capabilities dropped (`--cap-drop=ALL`).
- **Unprivileged Execution:** Scanners run as non-root user (`--user=1000:1000`).
- **Strict Resource Limits:** Bounded memory limits (e.g., 512MB) and CPU quotas.
- **Timeout Enforcement:** Global deadline timers enforce execution bounds and kill lingering containers.

### 3.2 Docker Socket Boundary
- The Docker socket (`/var/run/docker.sock` or `\\.\pipe\docker_engine`) is strictly accessible **only** to the Trusted Scan Worker process.
- The web application (Next.js App Router) never accesses Docker; all jobs are enqueued as durable records in MongoDB.

### 3.3 Secret Redaction & Token Handling
- GitHub access tokens (`gho_*`, `ghp_*`) and credentials are encrypted/stored server-side only in MongoDB sessions.
- Token values are scrubbed from log output and error messages via regex masking (`sanitizeErrorMessage`).
- Secret scanning (Gitleaks) findings have their secret values redacted to `[REDACTED SECRET]` before persistence in MongoDB.
- Request logging middleware automatically strips `Authorization`, `Cookie`, `Set-Cookie`, and session headers.

### 3.4 Authentication & Session Security
- Sessions use opaque, cryptographically random UUIDs (`crypto.randomUUID()`), not self-signed JWTs.
- Sessions are persisted and validated server-side in MongoDB with TTL auto-expiration.
- Session cookies are configured with:
  - `HttpOnly: true` (prevents JavaScript access)
  - `SameSite: 'lax'` (protects against CSRF)
  - `Secure: true` in production environments
  - `Path: '/'`

### 3.5 Anti-Enumeration & User Isolation
- All database queries for scans and findings are strictly scoped to the authenticated `userId`.
- Unauthorized requests to scans owned by other users return `404 Not Found` (never `403 Forbidden`) to prevent attackers from harvesting or enumerating scan IDs.

### 3.6 Input Validation
- All path parameters, query strings, and request bodies are strictly validated using Zod schemas before execution.
- Malformed identifiers, invalid branch names, and payload injection attempts are rejected with `400 Bad Request`.

### 3.7 Rate Limiting
- Built-in sliding window rate limiter protects sensitive endpoints:
  - Scan creation: 10 requests per minute per IP/user.
  - Scan deletion: 10 requests per minute per user.
  - Findings queries: 100 requests per minute per user.
  - Auth endpoints: 100 requests per 15 minutes per IP.
  - General API: 1000 requests per 15 minutes per IP.

### 3.8 Security Headers & Content Security Policy (CSP)
- Responses include hardened HTTP headers:
  - `Content-Security-Policy`: Restricts scripts, styles, frames (`frame-ancestors 'none'`), forms, and base URI.
  - `X-Frame-Options: DENY`: Prevents clickjacking.
  - `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
  - `Strict-Transport-Security`: Enforces HTTPS with `max-age=63072000; includeSubDomains`.
  - `Referrer-Policy: strict-origin-when-cross-origin`.
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
  - `X-Powered-By`: Disabled in Next.js configuration.

### 3.9 Error Response Sanitization
- All API route errors are formatted through `formatErrorResponse`.
- In production, internal error messages, database query details, and stack traces are never leaked to the client.

### 3.10 Dependency Management & CI Auditing
- Continuous Integration enforces dependency vulnerability scanning:
  - `npm audit --omit=dev --audit-level=high` runs on every pull request and push to `main`.
  - Zero critical or high vulnerabilities are permitted in production dependencies.

### 3.11 Data Retention & Cascade Deletion
- Scans and findings are subject to automatic retention cleanup (`SCAN_RETENTION_DAYS`, default: 90 days).
- Per-user scan cap (`MAX_SCANS_PER_USER`, default: 500) auto-prunes oldest terminal scans to prevent database storage exhaustion.
- Deleting a scan automatically cascade-deletes all associated security findings.
