# ADR-002 — Choose S3-Compatible Storage for Files

**Status:** Accepted  **Date:** 2026-08-07

---

## Context
Need durable, scalable file storage (100MB per file, many files). Local disk doesn't scale, backups hard.

## Decision
Use **S3-compatible storage** (AWS S3 or Supabase Storage). API streams via backend in Phase 1, presigned URLs in Phase 2.

## Consequences
- + Durable 11x9s, + CDN friendly, + presigned direct uploads later
- - Cost per GB, need credentials, latency

## Alternatives
| Option | Why Not |
|--------|---------|
| Local disk | Not scalable, single point failure |
| DB BLOB | Bloats DB, slow |

## Follow-up
- Env: S3_ENDPOINT, BUCKET, KEYS
- Phase 2: direct upload via presigned POST
