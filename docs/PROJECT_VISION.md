# PROJECT_VISION.md — SafeRepo

**Version:** 0.2.0  **Date:** 2026-08-22  **Status:** Draft  **Owner:** You

---

## 1. One-Liner

> SafeRepo is an open-source security analysis platform that helps developers safely analyze a GitHub repository and understand its security risks before running or trusting it.

---

## 2. Problem

**Who:** Developers evaluating open-source repositories before adoption or execution.

**Pain:**
- Running or depending on an unknown repository risks malicious code, exposed secrets, vulnerable dependencies
- Security scanners produce scattered, raw CLI output — hard to interpret
- No unified view of a repository's security posture across multiple scan dimensions
- Manual security review is time-consuming and inconsistent

**If not solved:** Developers unknowingly adopt insecure dependencies, execute malicious code, or expose their environments to supply-chain attacks.

---

## 3. Solution

**Core value:** Allow developers to safely analyze a GitHub repository and understand its security risks before running or trusting it.

**Core flow:**

```
User → SafeRepo → GitHub Repository → Isolated Docker Scanner → Security Analysis → MongoDB → Security Status / Dashboard
```

**Key Features (MVP):**
1. Authentication (GitHub App)
2. Connect GitHub and select a repository
3. Safely acquire repository contents
4. Scan in isolated Docker environment (Semgrep, Trivy, Gitleaks, OSV, npm audit, pip-audit)
5. Normalize findings into a unified structure
6. Display actionable security dashboard

**What we will NOT do (MVP):**
- No team workspaces
- No real-time collaboration
- No payments
- No mobile app

---

## 4. Target Users

| Persona | Goal | Pain |
|---------|------|------|
| Developer (evaluating OSS) | Understand security risks of a repo before using it | No unified view of code, dependency, and secret risks |
| Team lead (vetting dependencies) | Approve or reject new dependencies | Manual review is slow and inconsistent |

---

## 5. Success Metrics (post-MVP)

- ~100 beta users providing feedback
- p95 API <300ms
- 0 critical security findings in SafeRepo itself
- Positive user feedback on actionable findings

---

## 6. Constraints

- Budget: ₹0 whenever reasonably possible
- Tech: Next.js, TypeScript, Tailwind CSS, MongoDB, Mongoose
- Local-first: Must be fully functional in a local Docker-based environment
- Deployment platform is secondary — product must work independently of any hosting provider
- Open-source: compatible licenses, minimal dependencies

---

## 7. Vision (2 years)

> The go-to platform for developers to understand the security posture of any open-source repository — before they run it, depend on it, or contribute to it.

---

**Approved:** ☐ Yes ☐ No — Date: _______
