# API_SPEC.md — SafeRepo (Proposed)

**Status:** Draft — Endpoint contracts are proposed, not finalized.

**Base:** `http://localhost:3000/api/v1` (local development)

Do not implement APIs until the relevant phase is approved.

---

## API Responsibilities

The SafeRepo API handles:

1. **Authentication** — GitHub OAuth flow, session management
2. **GitHub Integration** — List accessible repositories, fetch repository metadata
3. **Scan Management** — Create scans, track status, retrieve results
4. **Findings** — Query normalized security findings
5. **Health** — Application and database health checks

---

## Proposed API Areas

### Authentication

| Method | Path | Purpose | Phase |
|--------|------|---------|-------|
| GET | /api/v1/auth/github | Initiate GitHub OAuth flow | 01 |
| GET | /api/v1/auth/github/callback | GitHub OAuth callback | 01 |
| GET | /api/v1/auth/me | Get current authenticated user | 01 |
| POST | /api/v1/auth/logout | End session | 01 |

> TBD — Session/token management strategy requires architectural decision.

### GitHub Repositories

| Method | Path | Purpose | Phase |
|--------|------|---------|-------|
| GET | /api/v1/repos | List accessible GitHub repositories | 01 |
| GET | /api/v1/repos/:owner/:name | Get repository metadata | 01 |

> TBD — Pagination, filtering, and caching strategy for repository listing.

### Scans

| Method | Path | Purpose | Phase |
|--------|------|---------|-------|
| POST | /api/v1/scans | Request a new scan | 02 |
| GET | /api/v1/scans | List user's scan history (paginated) | 02 |
| GET | /api/v1/scans/:id | Get scan details and status | 02 |
| GET | /api/v1/scans/:id/findings | Get findings for a scan (paginated, filterable) | 03+ |

> TBD — Scan queue behavior (immediate vs queued), concurrent scan limits, scan cancellation.

### Findings

| Method | Path | Purpose | Phase |
|--------|------|---------|-------|
| GET | /api/v1/scans/:id/findings | Get normalized findings | 03+ |

Expected query parameters (proposed):
- `severity` — Filter by severity (critical, high, medium, low, info)
- `category` — Filter by category (sast, dependency, secret, configuration)
- `scanner` — Filter by scanner (semgrep, trivy, gitleaks, osv, npm-audit, pip-audit)
- `page`, `limit` — Pagination

> TBD — Findings export format, finding detail endpoint, finding suppression/dismissal.

### Health

| Method | Path | Purpose | Phase |
|--------|------|---------|-------|
| GET | /api/health | Application health check | 01 |

---

## Validation

All API inputs will be validated using Zod at the handler level.

- Invalid input → 400 with structured error
- No raw user input reaches the database unvalidated

---

## Error Format (Proposed)

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable description",
    "details": []
  }
}
```

Proposed error codes: `VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`, `SCAN_FAILED`, `SCAN_TIMEOUT`

---

## Authentication

Authentication is via GitHub App (OAuth).

> TBD — Whether to use JWT tokens or server-side sessions. This is an architectural decision for Phase 01.

---

## Rate Limiting

Scan creation will be rate-limited per user to prevent abuse.

> TBD — Rate limit values and implementation strategy.

Response headers (proposed):
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

---

## Pagination (Proposed)

```
?page=1&limit=20  (max limit: 100)
```

Response format:
```json
{
  "data": [],
  "meta": {
    "total": 0,
    "page": 1,
    "limit": 20,
    "pages": 0
  }
}
```

---

## Security

- All endpoints except health and OAuth callback require authentication
- Input validation with Zod on every handler
- Rate limiting on scan creation
- CORS whitelist (configurable via `ALLOWED_ORIGINS`)
- Helmet security headers
- No secrets in response bodies
- No discovered secrets exposed via findings API (redacted at storage time)

---

## Open API Design Questions

> TBD — The following require architectural decisions:

- Authentication mechanism (JWT vs server-side sessions)
- Scan queue vs immediate execution
- Concurrent scan limits per user
- Scan cancellation endpoint
- Findings export/download
- Webhook notifications for scan completion
- WebSocket for real-time scan status updates
