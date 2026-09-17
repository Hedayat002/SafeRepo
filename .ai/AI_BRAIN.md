# SafeRepo Project AI Brain — Agent Entry Point & Routing Protocol

**Repository:** SafeRepo<br>
**Current Baseline Commit (HEAD):** `9fb53b0e9f6f5dacfd86c98851157f7fe7e08c61`<br>
**Current State:** Phase 09 (Production Deployment & Beta Infrastructure) — Uncommitted Work-In-Progress<br>
**Status Authority:** [.ai/phase_status.md](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/phase_status.md)

---

## 1. Mandatory Instructions for AI Agents

All AI agents operating on this repository **MUST** adhere to the following startup protocol:

1. **Read `AI_BRAIN.md` first** (this document).
2. **Read `phase_status.md` second** to discover the authoritative current phase, current accepted step, and next planned operation.
3. **Verify Git status and HEAD** (`git status`, `git rev-parse HEAD`) before proposing or making any changes.
4. **Read ONLY the files relevant to the CURRENT operation.**
5. **Do NOT automatically analyze the entire repository.**
6. **Do NOT reread historical phases (Phases 01–08)** unless explicitly required by the current task.
7. **Use `context.md`** for stable system architecture and security invariants.
8. **Use `decisions.md`** for durable architectural decisions and non-goals.
9. **Use `open_questions.md`** for unresolved issues and deferred work.
10. **Use `review_history.md`** for human review and approval milestones.
11. **Never treat uncommitted WIP as committed.**
12. **Never treat proposed work as approved.**
13. **Never commit or push without explicit human approval.**

> [!IMPORTANT]
> **TOKEN-EFFICIENCY MANDATORY RULE:**
> Do not analyze the entire repository unless the current operation actually requires repository-wide analysis.

---

## 2. Token-Efficiency Startup Protocol

When starting a session or receiving a prompt:

```text
STEP 1: Read .ai/AI_BRAIN.md
STEP 2: Read .ai/phase_status.md
STEP 3: Execute read-only git checks:
        • git status --short
        • git rev-parse HEAD
STEP 4: Determine:
        • Current Phase & Current Step Status
        • Next Authorized Operation
        • Relevant files for that specific operation
STEP 5: Read ONLY the files required for that operation
STEP 6: Implement and verify ONLY the authorized operation
STEP 7: Update the appropriate .ai state files
STEP 8: STOP for human review when the operation requires approval
```

---

## 3. Project AI Brain File Map

| File | Purpose | When to Read |
|---|---|---|
| [`AI_BRAIN.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/AI_BRAIN.md) | Agent routing, startup protocol, and efficiency rules | First file in every session |
| [`phase_status.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/phase_status.md) | Authoritative current phase, step status, and next operation | Second file in every session |
| [`context.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/context.md) | Stable system architecture, security boundaries, and components | When architecture context is needed |
| [`decisions.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/decisions.md) | Durable architectural decision records (ADRs) | When validating architecture choices |
| [`progress.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/progress.md) | Cumulative milestone history and completed work | When reviewing delivered scope |
| [`change_log.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/change_log.md) | Chronological log of meaningful state and code changes | When tracking recent modifications |
| [`review_history.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/review_history.md) | Formal human approval history and gating records | When checking approval status |
| [`open_questions.md`](file:///c:/Users/HP/Downloads/safe/Workspace/Projects/SafeRepo/.ai/open_questions.md) | Unresolved architectural questions and future non-blocking items | When identifying blockers or future scope |

---

## 4. State Consistency Invariant

The following state sources must **NEVER** contradict each other:
- `phase_status.md`
- `progress.md`
- `change_log.md`
- `review_history.md`
- `git rev-parse HEAD`
- `git status`

If any contradiction is detected, **STOP immediately**, do not silently rewrite history, and report the discrepancy to the human reviewer.
