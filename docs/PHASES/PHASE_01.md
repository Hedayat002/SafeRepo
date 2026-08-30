# Phase 01 — Application Foundation

**Status:** Not Started

---

## Objective

Establish the core application infrastructure for SafeRepo: Next.js scaffold, GitHub authentication with server-side sessions, MongoDB connection via Mongoose, project structure, and foundational tests.

Phase 01 produces a working application skeleton that can authenticate users, connect to the database, and serve a basic authenticated page. No scanning functionality is implemented in this phase.

---

## Prerequisites

- Phase 00 review completed and approved ✅
- Scanner network policy decided (C1) ✅
- Docker socket security boundary decided (C2) ✅
- Authentication session strategy decided (H1 — server-side sessions) ✅
- `.env.example` populated (H5) ✅
- MongoDB 7 running locally via `docker-compose up -d`
- GitHub App created with appropriate permissions (or credentials available for local dev)
- Node.js and npm installed locally

---

## Approved Scope

### In Scope

- Next.js 14 App Router project scaffold in `apps/web/`
- TypeScript strict mode configuration
- Tailwind CSS setup
- MongoDB connection via Mongoose (local Docker)
- Mongoose user model (`users` collection)
- GitHub App OAuth authentication flow
- Server-side session management (opaque session ID, Secure/HttpOnly cookie, MongoDB-backed)
- Session expiration and logout/revocation
- GitHub tokens stored server-side only
- Basic authenticated routes: `/` (landing), `/login`, `/dashboard` (protected)
- API routes: `/api/v1/auth/github`, `/api/v1/auth/github/callback`, `/api/v1/auth/me`, `/api/v1/auth/logout`
- API route: `/api/health`
- API route: `/api/v1/repos` (list accessible GitHub repositories — basic)
- API route: `/api/v1/repos/:owner/:name` (repository metadata — basic)
- Zod input validation on all API routes
- Helmet security headers
- CORS configuration (whitelist `ALLOWED_ORIGINS`)
- Basic rate limiting middleware
- Error handling middleware with structured error responses
- ESLint + Prettier configuration
- Vitest configuration
- Unit tests for auth utilities, validation schemas, and session management
- Integration tests for auth API routes (with mocked GitHub)
- Integration tests for health endpoint
- CI workflow (`.github/workflows/ci.yml`): lint, typecheck, test, build

### Out of Scope

- Scanning functionality (Phase 02+)
- Scanner Service / Scanner Runner (Phase 02+)
- Docker container isolation (Phase 02+)
- Dashboard UI beyond basic authenticated placeholder (Phase 07)
- Repository acquisition (Phase 02)
- Findings, scans collections (Phase 02+)
- Production deployment (Phase 09)
- Scan queue (Phase 02/06)

---

## Expected Deliverables

| Deliverable | Location |
|-------------|----------|
| Next.js application scaffold | `apps/web/` |
| Mongoose user model | `apps/web/` (exact path TBD during implementation) |
| GitHub OAuth + session auth | `apps/web/` API routes |
| Health check endpoint | `/api/health` |
| Repository listing endpoint | `/api/v1/repos` |
| Unit tests | `tests/` or colocated |
| Integration tests | `tests/` or colocated |
| CI workflow | `.github/workflows/ci.yml` |
| ESLint + Prettier config | Project root or `apps/web/` |

---

## Security Requirements

- No secrets committed to source code
- `.env` and `.env.local` in `.gitignore`
- Server-side sessions only — no JWT in localStorage
- Session cookies: `Secure`, `HttpOnly`, appropriate `SameSite` policy
- GitHub access tokens stored server-side in session, never sent to client
- Zod validation on all API inputs
- Helmet security headers enabled
- CORS restricted to configured origins
- Rate limiting on authentication endpoints
- Structured error responses that do not leak internal details
- No `console.log` — use structured logger
- No `any` types — TypeScript strict mode
- `npm audit` must pass with 0 critical/high vulnerabilities

---

## Testing Requirements

- **Unit tests:** Auth utilities, session management, Zod schemas, error handling
- **Integration tests:** Auth flow (mocked GitHub OAuth), health endpoint, protected route access (authenticated vs unauthenticated)
- **Framework:** Vitest + Supertest
- **Test DB:** mongodb-memory-server
- **Coverage:** Minimum 80% line coverage for `services/` and `lib/`
- All tests must pass before phase completion
- `npm run build` must succeed without errors

---

## Documentation Requirements

After Phase 01 completion, update:

- `.ai/progress.md` — Record what was built
- `.ai/decisions.md` — Log any implementation decisions made during Phase 01
- `docs/CHANGELOG.md` — Add Phase 01 entries
- `.ai/phase_status.md` — Mark Phase 01 as completed

---

## Review Criteria

Phase 01 is complete when:

- [ ] Next.js application starts and serves pages
- [ ] MongoDB connection established via Mongoose
- [ ] User model created and tested
- [ ] GitHub OAuth authentication flow works (login → callback → session)
- [ ] Server-side session created, stored in MongoDB, accessible via cookie
- [ ] Logout properly terminates session
- [ ] Protected routes reject unauthenticated requests (401)
- [ ] `/api/health` returns `{ status: "ok", db: "connected" }`
- [ ] `/api/v1/repos` returns accessible repositories for authenticated user
- [ ] Zod validation rejects invalid inputs (400)
- [ ] Rate limiting triggers on excessive requests (429)
- [ ] Security headers present in responses
- [ ] CORS rejects unauthorized origins
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Coverage ≥ 80% for services/lib
- [ ] `npm run lint` passes
- [ ] `npm run build` succeeds
- [ ] `npm audit` — 0 critical/high vulnerabilities
- [ ] CI workflow passes
- [ ] No secrets in source code
- [ ] Documentation updated

---

## Stop Condition

After completing Phase 01 implementation and verification:

**STOP.**

Generate a Phase 01 Validation Report.

Do NOT proceed to Phase 02 without explicit human approval.

Do NOT implement scanning, repository acquisition, or Docker isolation.

Wait for human review and approval.
