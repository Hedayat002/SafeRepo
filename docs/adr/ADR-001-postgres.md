# ADR-001 — Choose MongoDB + Mongoose for Primary Database

**Status:** Accepted (supersedes original ADR-001 PostgreSQL)  **Date:** 2026-08-15  **Deciders:** User, AI Lead

---

## Context
SafeRepo needs to store users, files metadata, shares, and audit logs. The original ADR-001 selected PostgreSQL + Prisma. After further review, the project owner decided on MongoDB as the primary database.

## Decision
We will use **MongoDB 7 + Mongoose ODM** as the primary database, hosted on **MongoDB Atlas**.

## Consequences
- **Positive:** Flexible document schema, horizontal scaling built-in, Atlas provides automated backups and monitoring, Mongoose provides schema validation and middleware, no migration files needed for initial setup
- **Negative:** No native foreign key enforcement (handled at application layer via Mongoose middleware), eventual consistency by default (mitigated by using majority write concern), less mature transaction support than PostgreSQL
- **Risks:** Referential integrity must be carefully managed in application code; cascade deletes must be explicitly implemented in Mongoose hooks

## Alternatives
| Option | Pros | Cons | Why Not |
|--------|------|------|---------|
| PostgreSQL + Prisma | ACID, foreign keys, joins, mature tooling | Rigid schema, requires migrations, more complex scaling | Project owner chose MongoDB |
| SQLite | Simple local dev | No concurrent write scale, no cloud hosting | Need production scale |

## Compliance
- Follows DATABASE_STANDARDS.md
- Follow-up: Create Mongoose schemas in `src/models/`, seed script in `scripts/seed.ts`

---

## Superseded

This ADR supersedes the original ADR-001 which chose PostgreSQL + Prisma. The original decision was made on 2026-08-07 and superseded on 2026-08-15 based on the project owner's decision to use MongoDB.
