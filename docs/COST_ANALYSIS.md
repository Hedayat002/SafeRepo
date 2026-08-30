# COST_ANALYSIS.md — SafeRepo

**Last Updated:** 2026-08-22

---

## Cost Policy

Initial target: **₹0 whenever reasonably possible.**

---

## Priorities

1. Local Docker development (free)
2. Open-source scanners (free)
3. Free/open-source tools
4. Free GitHub capabilities
5. MongoDB Atlas free tier (M0: 512MB storage)
6. Free hosting where technically suitable

---

## Do NOT Choose Infrastructure Based On

- Popularity alone
- Convenience at the expense of security
- Assumptions about future scale before validation

## Choose Infrastructure Based On

- Security
- Isolation
- Reliability
- Cost
- Performance
- Resource requirements
- Maintainability

---

## Local Development (₹0)

| Component | Cost | Notes |
|-----------|------|-------|
| Docker | Free | Local MongoDB + scanner isolation |
| MongoDB 7 (Docker) | Free | Local development database |
| Semgrep CLI (OSS) | Free | Static analysis |
| Trivy CLI | Free | Dependency/vulnerability scanning |
| Gitleaks CLI | Free | Secret detection |
| OSV API | Free | Public API, no key required |
| npm audit | Free | Built-in npm feature |
| pip-audit | Free | Open-source CLI tool |
| Next.js | Free | Web framework |
| Node.js | Free | Runtime |
| Git/GitHub | Free | Source control (free tier) |

**Total local development cost: ₹0**

---

## Production (Phase 09 — To Be Evaluated)

Production hosting decisions are deferred to Phase 09.

| Component | Options | Estimated Cost | Notes |
|-----------|---------|---------------|-------|
| MongoDB Atlas | M0 free tier | ₹0 | 512MB storage, shared RAM. Sufficient for ~100 beta users. |
| GitHub Actions | Free tier | ₹0 | 2,000 minutes/month |
| GitHub App | Free | ₹0 | Repository access |
| Web/API hosting | TBD (Phase 09) | TBD | Vercel free tier is one option. Other platforms to be evaluated. |
| Scanner hosting | TBD (Phase 09) | TBD | Requires Docker execution. Must be evaluated separately. |

### Potential Scanner Hosting Options (to evaluate in Phase 09)

| Option | Free Tier | Notes |
|--------|-----------|-------|
| Fly.io | 3 shared-cpu VMs, 256MB RAM | Tight but possible for light scanning |
| Oracle Cloud | Always-free ARM VM (4 OCPU, 24GB RAM) | Generous, good fit |
| Railway | $5/month free credit | Limited |
| Self-hosted VPS | Varies | ₹0 if already available |
| Other | TBD | Evaluate based on requirements |

---

## Cost Risks

| Risk | Scenario | Mitigation |
|------|----------|------------|
| MongoDB Atlas storage overflow | Many scans with large findings | Auto-cleanup old scans, limit findings per scan |
| GitHub API rate limiting | Burst scanning activity | Queue + backoff |
| Scanner compute costs | High scan volume in beta | Rate limit scans per user, evaluate cheapest compute option |

---

## Before Introducing Any Paid Service

1. Explain the requirement
2. Identify a free/open-source alternative
3. Explain limitations
4. Estimate expected cost
5. Wait for explicit human approval

Do not automatically subscribe to paid services, upgrade plans, enable paid cloud resources, or introduce recurring infrastructure costs.
