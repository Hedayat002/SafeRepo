# Phase 09 — Deployment and Beta Infrastructure

**Status:** Not Started

---

## Objective

Validate the complete production architecture, determine appropriate hosting for both the web/API layer and the scanner service, and prepare the environment for the 100-user beta.

Vercel is an option for the web/API layer. It is NOT mandatory.

Do not deploy anything during this phase without human approval.

---

## Objectives Checklist

- [ ] Validate the complete production architecture
- [ ] Determine appropriate hosting for the web/API layer
- [ ] Determine appropriate hosting for the scanner service
- [ ] Verify MongoDB Atlas configuration
- [ ] Verify GitHub integration
- [ ] Verify secure secret management
- [ ] Verify scanner isolation in production environment
- [ ] Estimate expected infrastructure cost
- [ ] Evaluate free-tier feasibility
- [ ] Decide whether Vercel is appropriate for the web/API layer
- [ ] Decide where the scanner service should run
- [ ] Prepare the 100-user beta environment

---

## Architecture Separation

The eventual production architecture may separate:

```
Web/UI/API Layer
       ↓
Scan Orchestrator
       ↓
Dedicated Isolated Scanner Service
       ↓
Docker / Secure Execution Environment
       ↓
MongoDB Atlas
```

The web/API layer and the scanner service have different requirements:

| Concern | Web/API Layer | Scanner Service |
|---------|--------------|-----------------|
| Execution model | HTTP request/response | Long-running Docker jobs |
| Docker required | No | Yes |
| Network access | Yes (public) | Restricted (no outbound for scanners) |
| Compute profile | Light (API serving) | Heavy (scanning large repos) |
| Hosting options | Many (Vercel, Fly.io, Railway, VPS, etc.) | Requires Docker execution capability |

---

## Hosting Evaluation Criteria

Do not choose infrastructure solely because it is popular.

Evaluate based on:

- **Security** — Can it isolate untrusted code?
- **Isolation** — Does it support Docker with restricted privileges?
- **Reliability** — What is the uptime guarantee?
- **Cost** — Does it fit the ₹0 target? What are free tier limits?
- **Performance** — Does it meet scanning timeout requirements?
- **Resource requirements** — CPU, memory, storage for scanners
- **Maintainability** — How complex is the deployment and operations?

---

## Deployment Sequence

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
Production infrastructure decision (human approval required)
       ↓
Infrastructure setup
       ↓
Deployment
       ↓
Post-deployment testing
       ↓
Review
       ↓
Human approval
```

---

## Steps

### 1. Final Local Validation

- All tests pass (unit, integration, E2E)
- Build succeeds without errors
- No lint or type errors
- Manual smoke test of critical flows
- Full scan pipeline verified locally

### 2. Security and Secret Review

- No secrets in source code
- `.env.example` contains only placeholder keys
- `.env` and `.env.local` are in `.gitignore`
- No credentials committed to git history
- Dependencies audited (`npm audit`)

### 3. Git Repository Verification

- Clean working tree
- All changes committed
- Conventional commit messages
- Branch is up to date

### 4. GitHub Repository Preparation

- GitHub repository exists and is accessible
- Repository settings configured (branch protection, etc.)
- GitHub Actions workflows are present
- Secrets configured in GitHub repository settings

### 5. Push Approved Code to GitHub

- Push reviewed code to the appropriate branch
- Verify CI/CD pipeline passes

### 6. Verify GitHub Repository State

- All branches are in expected state
- CI passes on pushed code
- No unresolved merge conflicts

### 7. Architecture and Hosting Review

- Evaluate scanner workload and security requirements
- Evaluate hosting options for web/API layer
- Evaluate hosting options for scanner service (must support Docker)
- Estimate costs
- Present options with trade-offs
- **Human approval required before proceeding**

### 8. Infrastructure Setup

- Configure chosen hosting platform(s)
- Set up environment variables and secrets
- Configure MongoDB Atlas connection
- Configure GitHub App for production
- Set up monitoring and health checks

### 9. Deployment

- Deploy web/API layer
- Deploy scanner service
- Verify connectivity between components

### 10. Post-Deployment Testing

- Verify application loads correctly
- Test authentication flow
- Test core scanning flow end-to-end
- Verify MongoDB Atlas connectivity
- Check health endpoints
- Verify scanner isolation in production environment

### 11. Review

- Validation report produced
- All deployment steps documented
- Rollback plan documented
- Cost tracking initialized

### 12. Human Approval

- STOP and wait for explicit human approval
- Do not proceed to Phase 10 without approval

---

## Scanner Security Requirements

The scanner execution environment must support:

- Isolation (containers cannot access host or other containers)
- Resource limits (CPU, memory, PIDs)
- Timeouts (configurable per scan)
- Network restrictions (`--network=none` for code scanners)
- Temporary filesystem isolation (read-only mounts)
- Cleanup (ephemeral containers with `--rm`)
- Least privilege (`--cap-drop=ALL`, `--security-opt=no-new-privileges`)
- Secure logging (no secret values in logs)
- Secret redaction in findings

---

## Exit Criteria

- [ ] Production architecture validated
- [ ] Hosting decisions made and approved
- [ ] Code is on GitHub
- [ ] CI/CD passes
- [ ] Deployment succeeds
- [ ] Post-deployment tests pass
- [ ] Scanner isolation verified in production
- [ ] No secrets exposed
- [ ] Cost estimate documented
- [ ] Human approval received

---

## Database

Production database: MongoDB Atlas (configured via `MONGODB_URI` environment variable).

Not approved for MVP: PostgreSQL, Prisma, Redis.
