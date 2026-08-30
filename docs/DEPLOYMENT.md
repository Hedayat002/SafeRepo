# DEPLOYMENT.md — SafeRepo

---

## Architecture Principle — Local-First

SafeRepo must be fully functional in a local Docker-based environment.

The core scanning functionality does not depend on any specific hosting provider.

Deployment platform decisions are deferred to Phase 09.

---

## Environments

| Env | URL | Deploy |
|-----|-----|--------|
| local | http://localhost:3000 | `docker-compose up -d` + `npm run dev` |
| staging | TBD (determined in Phase 09) | TBD |
| prod | TBD (determined in Phase 09) | TBD |

---

## Local Dev (Primary Environment)

```bash
cp .env.example .env.local  # fill required variables
docker-compose up -d         # mongodb 7
npm install
npm run dev                  # web http://localhost:3000
```

The local environment must support:

1. Connect to GitHub
2. Select a repository
3. Acquire repository contents safely
4. Scan the repository in an isolated Docker environment
5. Run the approved security scanners
6. Normalize findings
7. Store results in MongoDB
8. Display the repository security status

---

## Docker

`docker-compose.yml` provides:

- **MongoDB 7** for local development database (persistent `mongodata` volume)
- **Isolated scanner containers** for security analysis (ephemeral, per-scan)

Do not add PostgreSQL, Redis, or Prisma infrastructure to Docker Compose.

---

## Deployment Sequence (Phase 09)

Code must be pushed to GitHub before any remote deployment.

```
Final local validation
       ↓
Security and secret review
       ↓
Git repository verification
       ↓
GitHub repository preparation
       ↓
Push approved code to GitHub
       ↓
Verify GitHub repository state
       ↓
Architecture and hosting review
       ↓
Production infrastructure setup
       ↓
Deployment
       ↓
Post-deployment testing
       ↓
Review
       ↓
Human approval
```

Do not deploy to any remote platform before reviewed code is on GitHub.

---

## Hosting — Not Yet Decided

The hosting platform for both the web/API layer and the scanner service will be determined in Phase 09.

**Web/API layer options (to be evaluated):**
- Vercel (option, not mandatory)
- Other hosting platforms

**Scanner service requirements:**
- Must support Docker execution
- Must be evaluated separately from the web/API layer
- Must support isolation, resource limits, timeouts, and cleanup

Do not choose infrastructure solely because it is popular. Choose based on:
- Security
- Isolation
- Reliability
- Cost
- Performance
- Resource requirements
- Maintainability

---

## CI/CD (GitHub Actions)

`.github/workflows/ci.yml`:
- On push: lint, typecheck, test, build
- Deployment triggers: TBD in Phase 09

---

## Env Vars

```
MONGODB_URI=mongodb://admin:password@localhost:27017/saferepo?authSource=admin
GITHUB_APP_ID=your_app_id
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
GITHUB_PRIVATE_KEY=your_private_key
ALLOWED_ORIGINS=http://localhost:3000
```

Never commit `.env` or `.env.local`. Use deployment platform environment variables / GitHub Secrets for production.

---

## Health Checks

- API: GET /api/health → 200 { status: "ok", db: "connected" }

---

## Database

- **Local:** MongoDB 7 via Docker (`docker-compose up -d`)
- **Production:** MongoDB Atlas (free tier M0)
- **ODM:** Mongoose

Not approved for MVP: PostgreSQL, Prisma, Redis.
