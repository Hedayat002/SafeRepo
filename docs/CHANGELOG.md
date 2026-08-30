# Changelog — SafeRepo

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.1.0] - 2026-08-24

### Added - Phase 01: Application Foundation & Authentication

- Next.js 14 App Router scaffold in `apps/web/` with TypeScript strict mode and Tailwind CSS.
- MongoDB 7 + Mongoose connection singleton with connection pooling.
- `User` Mongoose model with unique GitHub ID index.
- `Session` Mongoose model with TTL auto-expiration index.
- Server-side session engine with opaque UUID tokens and HttpOnly/Secure cookies.
- GitHub App authentication flow (OAuth initiation, callback, state CSRF verification).
- Safe API endpoints:
  - `GET /api/health` — Health check
  - `GET /api/v1/auth/github` — OAuth start
  - `GET /api/v1/auth/github/callback` — OAuth callback
  - `GET /api/v1/auth/me` — Authenticated user profile
  - `POST /api/v1/auth/logout` — Session revocation
  - `GET /api/v1/repos` — User repository listing
  - `GET /api/v1/repos/:owner/:name` — Single repository metadata
- Security infrastructure: Zod schema validation, fail-fast environment validation, Pino structured logging with PII masking, in-memory rate limiting, and typed API errors.
- Basic frontend pages: Landing (`/`), Login (`/login`), and Protected Dashboard (`/dashboard`).
- CI workflow in `.github/workflows/ci.yml`.
- Unit and integration test suites.
