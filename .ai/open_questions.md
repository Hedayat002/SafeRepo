# Open Questions

**Last Updated:** 2026-08-23

---

## Resolved in Phase 00

| ID | Question | Resolution | Date |
|----|----------|------------|------|
| C1 | Scanner network policy — OSV/npm-audit/pip-audit need HTTP but arch says `--network=none` | Staged scanning: code scanners network-disabled containers, dependency scanners in dedicated restricted containers with controlled network (not host-side) | 2026-08-23 |
| C2 | Docker socket security — scanner service needs Docker API access | Dedicated Scanner Runner boundary; socket never exposed to untrusted code | 2026-08-23 |
| H1 | Authentication session strategy — JWT vs server-side sessions | Server-side sessions with MongoDB-backed persistence | 2026-08-23 |

---

## Deferred to Future Phases

> The following items were identified during Phase 00 review. They do NOT block Phase 01 and MUST NOT be implemented without explicit approval.

### Phase 02 — Safe Repository Acquisition

- **Repository size/depth limits:** Exact threshold for maximum repository clone size (e.g., 100MB vs 500MB). Must be decided before implementing repo acquisition.
- **Repository cleanup timing:** Define cleanup-on-startup behavior if the process crashes between clone and cleanup, leaving untrusted code on disk.

### Phase 02 / Phase 06 — Scan Queue

- **Scan queue architecture:** In-memory queue (MVP, no Redis), MongoDB-based queue (simple), or other mechanism for concurrent scan management.
- **Concurrent scan limits:** System-wide and per-user limits for simultaneous scans.

### Phase 03 — Semgrep Integration

- **Semgrep ruleset selection:** Which rulesets to use (`p/default`, `p/security-audit`, `p/owasp-top-ten`, or custom combination). Affects scan quality and time.
- **Scanner Docker image strategy:** Pre-built images from Docker Hub, custom Dockerfiles, or both. Must pin versions for reproducibility.
- **Trivy offline database strategy:** Trivy needs its vulnerability DB pre-loaded in the Docker image for `--network=none` operation.

### Phase 03+ — Scanner Architecture

- **Scanner memory limits per tool:** Semgrep may require more than 512MB on large repos. Make configurable (e.g., Semgrep: 1024m, others: 512m).
- **Scanner versioning and upgrade policy:** Pin scanner tool versions in Dockerfiles. Define upgrade cadence.
- **Deduplication across scanners:** Trivy, OSV, and npm audit may flag the same CVE. Dependency-specific fingerprint strategy needed (package + version + vulnerabilityId).
- **Partial scanner failure handling:** If one scanner fails, should partial results from other scanners still be stored and the scan marked as partially completed?

### Database Design Review

- **`repositories` collection:** Consider adding a dedicated collection to avoid duplicating repo metadata across scans. Enables per-repo views.
- **`findings.fingerprint` unique index:** Consider compound unique index `{ scanId, fingerprint }` to prevent duplicate findings per scan.
- **TTL indexes for scan cleanup:** MongoDB TTL indexes can automate document expiration for scan retention.

### Phase 07 — Frontend

- **Scan status update mechanism:** Polling endpoint, WebSocket, or SSE for real-time scan progress (required by US-06). Must decide before implementing scan status UI.
- **Accessibility (WCAG AA):** AI-OS mandates this. Not yet referenced in SafeRepo NFRs.
- **Loading/error/empty states:** UX flows for these states need definition.
- **Error pages / 404 handling:** Not yet specified for frontend routes.

### Phase 08 — Production Hardening

- **Scan retention policy:** Keep all forever (storage risk), TTL (30/60/90 days), or keep latest N per repo. Affects MongoDB Atlas M0 512MB ceiling.
- **Structured logging NFR:** Pino or similar, with request IDs and sanitized output. AI-OS mandates it but no SafeRepo NFR references it.
- **Rate limiting specification:** Per user? Per IP? Per minute? Needs detailed specification.
- **API DELETE endpoints:** `DELETE /api/v1/scans/:id` and `DELETE /api/v1/users/me` (GDPR). Add to API spec.
- **API documentation endpoint:** Swagger UI at `/docs` as required by AI-OS API_STANDARDS.md.

### Phase 09 — Deployment

- **Production hosting platforms:** Web/API layer and scanner service hosting decisions.
- **MongoDB Atlas M0 storage monitoring:** 512MB ceiling with 100 beta users doing 5 scans/week approaches limit in ~10 weeks.
- **Scanner compute on free VMs:** Fly.io free tier (256MB) too small for Semgrep. Oracle Cloud free ARM (24GB) viable but manual ops.
- **Docker image storage:** Scanner Docker images need registry storage (Docker Hub free, GitHub Container Registry).

### Documentation Cleanup

- **Stale ADRs:** ADR-002 (S3 storage) and ADR-003 (Fastify monolith) reference superseded technology. Should be marked "Superseded."
- **AI-OS standard conflicts:** DATABASE_STANDARDS.md, DOCKER.md, SECURITY_GUIDELINES.md reference Prisma/Postgres defaults. SafeRepo overrides these per approved decisions. Consider documenting the override or updating globally.
- **GitHub App vs OAuth App clarification:** Documentation alternates between these terms. Clarify exact auth mechanism and permissions.

---

## Questions That Do Not Block Any Phase

- Scan cancellation endpoint (nice-to-have, not in MVP requirements)
- Findings export/download format
- Webhook notifications for scan completion
- WebSocket for real-time scan status (alternative: polling)
- Custom seccomp profile for scanner containers (default seccomp is applied by Docker)
- Disk I/O limits for scanner containers (`--device-read-bps`, `--device-write-bps`)
- Dashboard content prioritization (US-16 is "Could" priority)
- Scan completion time success criteria (define during Phase 08)
