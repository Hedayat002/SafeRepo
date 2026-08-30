# Change Log

---

### 2026-08-24 — Phase 01: Application Foundation & Authentication Implementation

- **Next.js Scaffold:** Bootstrapped Next.js 14 App Router project in `apps/web/` with TypeScript strict mode, Tailwind CSS, ESLint, and Prettier.
- **Database Layer:** Created Mongoose singleton connection in `apps/web/src/lib/db.ts`, `User` model in `apps/web/src/models/user.ts`, and `Session` model in `apps/web/src/models/session.ts` with TTL auto-expiration index.
- **Authentication Engine:** Built server-side session management (`apps/web/src/lib/session.ts`) utilizing opaque UUIDs, MongoDB persistence, and HttpOnly cookies. GitHub access tokens remain strictly server-side.
- **GitHub App Helpers:** Implemented server-side GitHub App helpers in `apps/web/src/lib/github.ts` using Node built-in fetch.
- **API Routes:** Implemented `GET /api/health`, `GET /api/v1/auth/github`, `GET /api/v1/auth/github/callback`, `GET /api/v1/auth/me`, `POST /api/v1/auth/logout`, `GET /api/v1/repos`, and `GET /api/v1/repos/:owner/:name`.
- **Security & Validation:** Added Zod validation schemas (`lib/schemas.ts`), environment fail-fast validation (`lib/env.ts`), structured logging (`lib/logger.ts`), typed error classes (`lib/errors.ts`), and in-memory rate limiting (`lib/rate-limit.ts`).
- **Frontend Pages:** Implemented root layout, home landing page, login page, and server-side authenticated dashboard.
- **CI & Tests:** Added `.github/workflows/ci.yml` and 11 Vitest test suites.

---

### 2026-08-23 — Phase 00 Approval and Scope Finalization

- Finalized Phase 00 documentation and architecture.
- Finalized ADRs and decision records in `.ai/decisions.md`.
