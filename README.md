# SafeRepo — Open-Source Security Analysis Platform

> Analyze a GitHub repository's security posture before you run it, depend on it, or trust it.

**Stack:** Next.js + TypeScript + Tailwind CSS + MongoDB + Mongoose + Docker
**Status:** Pre-Phase 00 — Documentation and architecture finalization
**AI-OS:** This project follows `Workspace/AI-OS` global engineering standards.

---

## What Is SafeRepo?

SafeRepo is an open-source security analysis platform designed to help developers understand the security risks in a GitHub repository before they execute or depend on it.

Instead of running scattered CLI tools and interpreting raw scanner output, SafeRepo provides a unified security dashboard with actionable findings across multiple dimensions:

- **Static code analysis** (Semgrep)
- **Dependency vulnerabilities** (Trivy, OSV API, npm audit, pip-audit)
- **Exposed secrets** (Gitleaks)

---

## Problem

Developers routinely clone, install, and run open-source code without understanding its security posture. There is no single tool that provides a unified, actionable view of:

- Code-level security issues
- Vulnerable dependencies
- Exposed secrets and credentials
- Security-relevant configuration problems

Manual review is slow, inconsistent, and often skipped entirely.

---

## Core Flow

```
User → Authenticate (GitHub) → Select Repository → Request Scan
  → SafeRepo acquires repository safely
  → Scans in isolated Docker containers
  → Normalizes findings
  → Stores results in MongoDB
  → Displays security dashboard
```

---

## Key Features (MVP)

- **GitHub Integration** — Connect GitHub account, browse accessible repositories
- **Safe Repository Acquisition** — Clone untrusted repos with depth/size limits
- **Isolated Scanning** — Docker containers with no network, resource limits, timeouts
- **Multiple Scanners** — Semgrep, Trivy, Gitleaks, OSV API, npm audit, pip-audit
- **Normalized Findings** — Unified schema with severity, category, remediation
- **Security Dashboard** — Actionable findings with filtering and remediation guidance
- **Secret Redaction** — Discovered secrets are flagged but never exposed

---

## Security-First Approach

SafeRepo treats every scanned repository as **untrusted input**:

- Never executes repository code, scripts, or lifecycle hooks
- Scanners run in Docker containers with restricted privileges
- No network access for code scanners (`--network=none`)
- CPU, memory, and PID limits enforced
- Timeouts prevent runaway scans
- Ephemeral containers with automatic cleanup
- Secret values from scan results are redacted before storage

---

## Architecture (Local-First)

SafeRepo is designed to be fully functional in a local Docker-based environment. No specific hosting provider is required.

```
Developer Machine
       ↓
SafeRepo Application (Next.js)
       ↓
Docker
├── MongoDB 7 (database)
└── Isolated Scanner Containers (per scan)
       ↓
Security Results → MongoDB → Dashboard
```

Production hosting decisions are deferred to Phase 09.

---

## Project Structure

```
SafeRepo/
├── .ai/                    # AI memory (context, decisions, progress)
├── docs/                   # Product docs (vision, reqs, arch, roadmap)
│   ├── PROJECT_VISION.md
│   ├── REQUIREMENTS.md
│   ├── SYSTEM_ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── USER_STORIES.md
│   ├── DATABASE_DESIGN.md
│   ├── API_SPEC.md
│   ├── DEPLOYMENT.md
│   ├── TESTING_PLAN.md
│   ├── COST_ANALYSIS.md
│   ├── CHANGELOG.md
│   ├── PHASES/             # Phase-specific documentation
│   └── adr/                # Architecture Decision Records
├── apps/
│   └── web/                # Next.js web application
├── services/
│   └── scanner/            # Scanner service
├── packages/               # Shared packages
├── tests/                  # Test suites
├── scripts/                # Utility scripts
├── docker-compose.yml      # Local MongoDB
└── README.md
```

---

## Quick Start (Local)

```bash
cp .env.example .env.local  # fill required variables
docker-compose up -d         # mongodb 7
npm install
npm run dev                  # http://localhost:3000
```

---

## Roadmap

| Phase | Goal | Status |
|-------|------|--------|
| 00 | Project Definition and Architecture | Not Started |
| 01 | Application Foundation | Not Started |
| 02 | Safe Repository Acquisition | Not Started |
| 03 | Semgrep Integration | Not Started |
| 04 | Dependency Vulnerability Scanning | Not Started |
| 05 | Secret Scanning | Not Started |
| 06 | Unified Scan Engine | Not Started |
| 07 | Security Dashboard | Not Started |
| 08 | Production Hardening | Not Started |
| 09 | Deployment and Beta Infrastructure | Not Started |
| 10 | 100-User Beta Testing | Not Started |

See `docs/ROADMAP.md` for details.

---

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/PROJECT_VISION.md` | Product vision and goals |
| `docs/REQUIREMENTS.md` | Functional and non-functional requirements |
| `docs/SYSTEM_ARCHITECTURE.md` | Architecture and tech stack |
| `docs/ROADMAP.md` | Phase plan and milestones |
| `docs/DATABASE_DESIGN.md` | MongoDB data model |
| `docs/API_SPEC.md` | API responsibilities and proposed endpoints |
| `docs/DEPLOYMENT.md` | Deployment architecture and local dev |
| `docs/COST_ANALYSIS.md` | Cost policy and analysis |
| `docs/TESTING_PLAN.md` | Testing strategy |

---

## AI Memory

| File | Purpose |
|------|---------|
| `.ai/context.md` | Project context for AI sessions |
| `.ai/progress.md` | What's been done |
| `.ai/decisions.md` | Why decisions were made |
| `.ai/phase_status.md` | Current phase status |
| `.ai/open_questions.md` | Pending questions |
| `.ai/change_log.md` | Change history |
| `.ai/review_history.md` | Review records |

---

## Database

- **Local:** MongoDB 7 via Docker
- **Production:** MongoDB Atlas
- **ODM:** Mongoose

Not approved for MVP: PostgreSQL, Prisma, Redis.

---

## Open Source

SafeRepo is intended to be open source. See `LICENSE` for details.
