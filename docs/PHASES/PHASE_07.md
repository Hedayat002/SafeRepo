# Phase 07 — Security Dashboard

**Status:** Planning (Awaiting Human Approval)

---

## 1. Phase 07 Objective

Build the **user-facing Security Dashboard** — the primary interface through which authenticated users view, explore, filter, and act on security findings produced by the Unified Scan Engine (Phase 06).

Phase 07 converts SafeRepo from a backend-only scanning service into a complete, interactive security analysis platform by implementing:

1. **Dashboard Home:** Authenticated landing page showing scan history with status indicators, severity summary badges, and a "New Scan" entry point.
2. **Scan Detail View:** Per-scan page showing lifecycle status, timing metadata, severity breakdown chart, scanner execution results, and paginated findings list.
3. **Findings Explorer:** Interactive findings table with client-side and server-side filtering by severity, category, and scanner. Each finding expands to show description, file location, code snippet, vulnerability ID, and remediation guidance.
4. **Severity Breakdown Visualization:** Summary cards and a distribution chart showing critical/high/medium/low/info counts per scan.
5. **New Scan Form:** Repository selection and scan initiation form with real-time validation, integrated with the existing `GET /api/v1/repos` and `POST /api/v1/scans` APIs.
6. **Scan Status Polling:** Automatic poll-based status refresh for in-progress scans using `GET /api/v1/scans/:id` until terminal state is reached.

---

## 2. Functional Requirements Addressed

| ID | Category | Requirement | Implementation in Phase 07 |
|---|---|---|---|
| **FR-15** | Security Dashboard | View repository security findings | Dashboard scan detail page with aggregated findings, severity breakdown, and individual finding details. |
| **FR-16** | Security Dashboard | Filter findings by severity and category | Interactive filtering controls on findings list (severity, category, scanner dropdowns). |
| **FR-17** | Security Dashboard | Review remediation advice | Expandable finding detail panel displaying remediation guidance, vulnerability IDs, and reference links. |
| **FR-18** | Scan History | View past scans | Dashboard home page listing previous scans with status, timestamp, duration, and summary counts. |
| **NFR-04** | Performance | UI p95 response time <300ms | Server Components for initial data load; paginated API queries; lean MongoDB projections. |
| **NFR-05** | Input Validation | Robust validation | Zod validation on new scan form; existing API validation preserved. |
| **NFR-07** | Cost | ₹0 development cost | No new paid dependencies; Tailwind CSS (already installed); no external charting libraries. |
| **NFR-09** | Testing | Automated test suite | ≥90% line coverage on frontend logic modules; critical component rendering tests (react-dom/server); auth boundary tests; ≥65 new test cases. |

---

## 3. Architecture

### 3.1 Rendering Strategy

Phase 07 uses **Next.js App Router** with:
- **React Server Components (RSC)** for authenticated pages that fetch data server-side (`/dashboard`, `/dashboard/scans/[id]`). Server Components read the session cookie, query MongoDB directly, and render HTML without client-side JavaScript for the initial payload.
- **Client Components** (marked with `'use client'`) only where interactive behavior is required: filtering controls, scan status polling, new scan form submission, expandable finding details.

This avoids introducing any client-side data fetching library (no React Query, SWR, or Axios). Interactive mutations use Next.js built-in `fetch` or `useActionState` patterns.

### 3.2 Component Hierarchy

```
app/
├── dashboard/
│   ├── page.tsx                    (RSC) Dashboard home: scan history list
│   ├── layout.tsx                  (RSC) Dashboard shell: nav header, user menu, sign-out
│   ├── new-scan/
│   │   └── page.tsx                (RSC + Client) New scan form
│   └── scans/
│       └── [id]/
│           └── page.tsx            (RSC) Scan detail + findings explorer
│
├── components/
│   ├── dashboard/
│   │   ├── ScanHistoryList.tsx      (RSC) Renders paginated scan cards
│   │   ├── ScanCard.tsx             (RSC) Individual scan summary card
│   │   ├── ScanStatusBadge.tsx      (RSC) Status pill with color coding
│   │   ├── SeveritySummary.tsx      (RSC) Severity count badges (critical/high/medium/low/info)
│   │   ├── SeverityChart.tsx        (Client) Visual severity distribution bar/chart
│   │   ├── ScanDetail.tsx           (RSC) Scan metadata and status display
│   │   ├── ScanPollingWrapper.tsx   (Client) Auto-refreshes scan status until terminal
│   │   ├── FindingsExplorer.tsx     (Client) Interactive findings table with filters
│   │   ├── FindingRow.tsx           (Client) Expandable finding detail row
│   │   ├── FindingsFilter.tsx       (Client) Severity/category/scanner filter controls
│   │   ├── RemediationPanel.tsx     (RSC) Remediation advice display
│   │   ├── NewScanForm.tsx          (Client) Repository selector + scan trigger
│   │   ├── Pagination.tsx           (Client) Page navigation for scan lists and findings
│   │   └── EmptyState.tsx           (RSC) Empty state illustrations
│   └── ui/
│       ├── Badge.tsx                (RSC) Reusable badge component
│       ├── Button.tsx               (RSC) Reusable button component
│       ├── Card.tsx                 (RSC) Reusable card container
│       ├── Select.tsx               (Client) Reusable select dropdown
│       └── Spinner.tsx              (RSC) Loading spinner
```

### 3.3 Data Flow

```
┌────────────────────────────────────────────────────────────┐
│                     Browser (Client)                        │
│                                                            │
│  Dashboard Home ──(navigate)──▶ Scan Detail Page           │
│        │                              │                    │
│  (RSC server fetch)           (RSC server fetch)           │
│        │                              │                    │
│  GET /api/v1/scans            GET /api/v1/scans/:id        │
│  (paginated, user-scoped)     GET /api/v1/scans/:id/findings│
│        │                              │                    │
│        ▼                              ▼                    │
│  Scan History List             Scan Detail + Findings      │
│                                       │                    │
│  ┌─── Client Components ────┐         │                    │
│  │ Polling (in-progress)     │  ┌─────┴─────┐              │
│  │ Filters (severity/cat)    │  │ FindingsExplorer│         │
│  │ Pagination                │  │ (client-side   │         │
│  │ New Scan Form             │  │  filter + API  │         │
│  └───────────────────────────┘  │  pagination)   │         │
│                                 └────────────────┘         │
└────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│              Next.js Server (API Routes)                    │
│                                                            │
│  Existing routes — NO CHANGES:                             │
│  • GET  /api/v1/scans          (paginated, user-scoped)    │
│  • GET  /api/v1/scans/:id      (scan detail, user-scoped)  │
│  • GET  /api/v1/scans/:id/findings (filtered, paginated)   │
│  • POST /api/v1/scans          (queue new scan)            │
│  • GET  /api/v1/repos          (list user repos)           │
│                                                            │
│  All routes enforce authentication + authorization.         │
└────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│                    MongoDB                                  │
│  Collections: users, sessions, scans, findings              │
│  (No schema changes in Phase 07)                           │
└────────────────────────────────────────────────────────────┘
```

---

## 4. API Changes

**Phase 07 requires NO new API routes and NO modifications to existing API routes.**

All data required by the dashboard is already served by existing, tested, and audited endpoints:

| Endpoint | Method | Purpose | Phase Created |
|---|---|---|---|
| `/api/v1/scans` | GET | List user's scan history (paginated, status filter) | Phase 02 |
| `/api/v1/scans` | POST | Queue a new scan | Phase 02 / Phase 06 |
| `/api/v1/scans/:id` | GET | Get scan detail and status | Phase 02 |
| `/api/v1/scans/:id/findings` | GET | Get paginated, filterable findings | Phase 03 |
| `/api/v1/repos` | GET | List user's GitHub repositories | Phase 01 |
| `/api/v1/auth/logout` | POST | Sign out | Phase 01 |
| `/api/v1/auth/github/callback` | GET | OAuth callback | Phase 01 |

The existing API routes already support:
- Pagination (`page`, `per_page`)
- Severity filtering (`severity` query parameter)
- Category filtering (`category` query parameter)
- Scanner filtering (`scanner` query parameter)
- User-scoped authorization (all queries filter by `userId`)

---

## 5. Security Boundaries

### 5.1 Preserved Security Invariants

Phase 07 is a **frontend-only** phase. All security boundaries established in Phases 01–06 remain strictly unchanged:

- **Authentication:** Server-side session validation in RSC pages and API routes (unchanged).
- **Authorization:** All scan and finding queries are scoped by `userId` (unchanged).
- **Docker Socket:** Zero frontend access to Docker (unchanged; Docker control remains exclusively in the Trusted Worker process).
- **Secret Redaction:** Gitleaks findings display `[REDACTED SECRET]` in `codeSnippet` — the backend never stores plaintext secrets, so the frontend cannot leak them.
- **CSRF:** The new scan form uses existing API routes behind session cookie authentication.
- **XSS:** React's default JSX escaping prevents injection. Finding titles, descriptions, and remediation strings are rendered as text, not dangerouslySetInnerHTML.
- **Rate Limiting:** Existing scan creation rate limit applies to the new scan form.
- **Input Validation:** New scan form inputs are validated client-side (immediate feedback) and server-side (Zod, existing `createScanSchema`).

### 5.2 New Security Considerations

- **GitHub Avatar Images:** The dashboard displays user avatars loaded from `avatars.githubusercontent.com`. The existing `next.config.mjs` may need an `images.remotePatterns` entry if Next.js `<Image>` is used. If standard `<img>` tags are used (as in the current Phase 01 placeholder), no config change is needed.
- **Content Security Policy:** No additional CSP headers required — no inline scripts, no external JS, no third-party resources.

---

## 6. Authentication / Authorization Implications

**No changes to the authentication or authorization system.**

- Dashboard pages use the same server-side session validation pattern established in the Phase 01 `dashboard/page.tsx` placeholder: read `saferepo_session` cookie → validate via `getSession()` → lookup `User` → redirect to `/login` if invalid.
- The new dashboard layout component (`dashboard/layout.tsx`) centralizes this auth check so individual dashboard pages don't repeat it.
- All API calls from client components include the session cookie automatically (same-origin fetch with `credentials: 'include'`).

---

## 7. Database Implications

**No schema changes. No new collections. No new indexes. No model modifications.**

Phase 07 is a read-only consumer of data produced by Phases 01–06. All required database fields, indexes, and query patterns already exist:

- `scans` collection: queried by `{ userId, status }`, sorted by `{ createdAt: -1 }`, paginated.
- `findings` collection: queried by `{ scanId }` with optional `{ severity, category, scanner }` filters, sorted by `{ severity: 1, file: 1, line: 1 }`, paginated.
- `users` collection: queried by `_id` for user profile display.

---

## 8. Failure Modes

| Failure | User Experience | Handling |
|---|---|---|
| MongoDB unavailable | Dashboard pages show error state | Server Components catch DB errors; render user-friendly error message with retry guidance. |
| Scan not found / unauthorized | 404 page | Existing API returns 404; dashboard page renders "Scan not found" message. |
| API rate limit exceeded (429) | Form shows rate limit message | New scan form catches 429 response and displays cooldown guidance. |
| GitHub repos API failure | Repo selector shows error | New scan form catches API error and displays fallback manual input option. |
| Polling timeout (scan stuck) | Status badge shows in-progress state | Polling has a maximum iteration count; after limit, displays "Scan may be taking longer than expected" message. |
| Network error during fetch | Component shows error state | Client components use try/catch with user-friendly error messages and retry buttons. |

---

## 9. Concurrency Implications

**No new concurrency concerns introduced by Phase 07.**

- The dashboard is a stateless read-only consumer of MongoDB data.
- Scan status polling uses `setInterval` with a reasonable interval (5 seconds); polling stops on unmount or terminal state.
- Multiple browser tabs viewing the same scan are safe — each independently polls the API.
- The new scan form submits to the existing `POST /api/v1/scans` endpoint, which is already rate-limited and creates scans atomically.

---

## 10. Resource Limits

- **Polling Interval:** 5-second minimum interval for scan status polling. Maximum 120 poll iterations (10 minutes) before stopping with a user message.
- **Findings Page Size:** Default 20 findings per page, maximum 100 (enforced by existing `findingsQuerySchema`).
- **Scan History Page Size:** Default 20 scans per page, maximum 100 (enforced by existing `scansQuerySchema`).
- **No New Server Resources:** Phase 07 adds zero new server-side background processes, timers, or persistent connections.

---

## 11. Timeout Behavior & Polling Specification

### 11.1 Scan Status Polling Specification

The `ScanPollingWrapper` client component manages automatic status refresh for in-progress scans.

#### 11.1.1 Polling Parameters & Constants

| Parameter | Value | Rationale |
|---|---|---|
| `POLL_INTERVAL_MS` | 5000 (5 seconds) | Fixed polling interval; balances user responsiveness with server/DB query load. |
| `MAX_POLL_ITERATIONS` | 120 iterations | Hard stop at ~10 minutes (120 × 5s = 600s); guarantees polling never runs indefinitely. |
| `MAX_CONSECUTIVE_ERRORS` | 10 errors | Circuit breaker threshold; stops polling if the server is persistently unreachable. |
| `WARN_CONSECUTIVE_ERRORS` | 3 errors | Warning threshold; displays non-blocking transient connection warning without halting. |
| `POLL_FETCH_TIMEOUT_MS` | 10000 (10 seconds) | AbortController timeout per poll request to prevent hung socket connections. |

#### 11.1.2 State Classification

- **Non-Terminal States (Polling Active):**
  - `queued`
  - `cloning`
  - `scanning`
  - `normalizing`
- **Terminal States (Polling Stops Immediately):**
  - `completed`
  - `failed`
  - `timed_out`

#### 11.1.3 Polling Lifecycle & Stop Conditions

1. **Start Condition:**
   - Polling initiates ONLY when `ScanPollingWrapper` mounts AND the initial scan status is a non-terminal state (`queued`, `cloning`, `scanning`, `normalizing`).
   - If the scan is already in a terminal state upon initial render, polling is NEVER initiated.
2. **Polling Interval:**
   - Interval is strictly fixed at 5000ms (`POLL_INTERVAL_MS = 5000`).
   - Managed via `setInterval` within a React `useEffect` hook.
   - Each interval tick executes `GET /api/v1/scans/:id` using `fetch` with an associated `AbortController` (10-second timeout).
3. **Stop Conditions (Polling halts immediately if ANY of the following occur):**
   - **Terminal Status Reached:** When the API response contains `status` equal to `completed`, `failed`, or `timed_out`, polling stops immediately (`clearInterval`), and the UI transitions to the final state.
   - **Maximum Iterations Reached (`MAX_POLL_ITERATIONS = 120`):** Polling ceases after 120 ticks (~10 minutes). The interval is cleared and a status notice is displayed: *"Scan may be taking longer than expected. Please refresh the page to check current status."*
   - **Consecutive Error Circuit Breaker (`MAX_CONSECUTIVE_ERRORS = 10`):** After 10 consecutive network errors or non-200 responses, polling ceases. The interval is cleared and an alert is displayed: *"Unable to reach server after multiple attempts. Please check your network connection and refresh."*
   - **Component Unmount:** When the user navigates away or closes the view, the `useEffect` cleanup hook executes immediately.
4. **Cleanup When Component Unmounts:**
   - The React `useEffect` return cleanup function synchronously executes:
     - `clearInterval(timerRef.current)` — eliminates orphaned timer callbacks.
     - `abortControllerRef.current?.abort()` — cancels any in-flight HTTP request.
     - Sets an internal `isMountedRef.current = false` flag to prevent state updates on unmounted component trees.
5. **Transient Error Handling & Recovery:**
   - Network errors, DNS failures, or 5xx responses increment an internal `consecutiveErrors` counter.
   - When `consecutiveErrors >= 3`, a non-intrusive warning notice displays: *"Connection issue detected — retrying..."*
   - Polling continues through transient glitches.
   - Any subsequent successful response (HTTP 200) immediately resets `consecutiveErrors = 0` and dismisses the warning.
6. **Prevention of Uncontrolled Polling Requests:**
   - **In-Flight Request Guard (`isFetchingRef`):** If a network request is still pending when the 5-second interval timer fires, the tick is safely skipped. No duplicate or overlapping network requests can ever be generated.
   - **Hard Iteration Ceiling (`MAX_POLL_ITERATIONS = 120`):** Prevents runaway infinite polling in the browser under all circumstances.
   - **Circuit Breaker (`MAX_CONSECUTIVE_ERRORS = 10`):** Halts polling during server downtime or disconnected networks rather than endlessly polling.
   - **Unmount Cancellation:** Guarantees no polling continues in the background after page navigation.
   - **Non-Terminal Initiation Guard:** Bypasses polling completely if the initial scan state is already terminal.

#### 11.1.4 State Transitions on Terminal Status

| Terminal Status | UI Behavior & State Transition |
|---|---|
| `completed` | Polling stops immediately. Status badge updates to green ("● Completed"). Duration is finalized. Findings section and severity breakdown metrics are unlocked and displayed. |
| `failed` | Polling stops immediately. Status badge updates to red ("✕ Failed"). Error message from `scan.error` is displayed in an alert card. Action provided to retry or return to dashboard. |
| `timed_out` | Polling stops immediately. Status badge updates to orange ("⏱ Timed Out"). Alert displays: *"Scan exceeded maximum execution time (10 minutes)."* Any partial findings captured prior to timeout remain visible with a warning badge. |

### 11.2 API Fetch Timeouts

- **Read operations** (GET scan, GET findings, GET repos): `AbortController` with 10-second timeout.
- **Write operations** (POST scan creation): `AbortController` with 30-second timeout.
- **Timeout handling:** On `AbortError`, the UI displays a user-friendly "Request timed out" message with a retry option.

### 11.3 Server-Side Data Fetching

- RSC data fetches inherit Next.js default timeouts. No custom timeout logic needed — the existing API routes handle their own timeouts.

### 11.4 Loading, Empty, and API-Error State Specification

**Loading States:**

| Context | Loading Indicator |
|---|---|
| Dashboard home (initial page load) | RSC server-side — no client spinner needed (HTML streams complete). |
| Scan detail page (initial load) | RSC server-side — no client spinner needed. |
| Findings pagination (page change) | Inline spinner in findings table body while fetching next page. |
| New scan form (repo list loading) | Spinner inside the repository selector dropdown. |
| New scan form (submission) | Button shows spinner + "Creating scan..." text; button is disabled. |
| Polling tick (background refresh) | No visible spinner — scan detail updates silently. |

**Empty States:**

| Context | Display |
|---|---|
| No scans exist for user | Centered illustration with text: "No scans yet. Analyze your first repository." CTA button linking to `/dashboard/new-scan`. |
| No findings for a completed scan | Message within findings section: "No security findings detected. This repository appears clean." |
| No findings match active filters | Message: "No findings match the selected filters." with a "Clear filters" link. |
| No repositories available | Message in repo selector: "No repositories found. Ensure your GitHub App has access." |

**API Error States:**

| Context | Display |
|---|---|
| Dashboard home — API error | Full-page error card: "Unable to load scan history. Please try again." with retry button. |
| Scan detail — scan not found (404) | Full-page message: "Scan not found. It may have been deleted or you may not have access." |
| Scan detail — server error (500) | Full-page error card with retry button. |
| Findings fetch error | Inline error within findings section with retry button. Scan metadata remains visible. |
| New scan creation error (4xx/5xx) | Inline error message below the form. Form remains interactive for correction/retry. |
| Rate limit exceeded (429) | Inline message: "Too many scan requests. Please wait before trying again." |
| Auth failure (redirect) | Redirect to `/login` — existing behavior, no custom error UI. |

---

## 12. Observability / Logging Requirements

**No new server-side logging required.**

Phase 07 introduces frontend-only changes. All relevant server-side logging (scan lifecycle, API requests, errors) is already implemented in Phases 01–06.

Client-side:
- `console.error` for unrecoverable fetch failures (development only; stripped in production build).
- No client-side telemetry or analytics services (₹0 cost constraint).

---

## 13. Testing Strategy

### 13.1 Testing Architecture & Existing Infrastructure Invariants

Phase 07 introduces React components (`.tsx`), pages, and supporting frontend logic. In strict accordance with the **zero-new-dependency constraint**, Phase 07 executes focused frontend testing using the project's **existing test infrastructure**:

1. **Test Runner:** Vitest running in the existing `environment: 'node'` (`vitest.config.ts`).
2. **Component Rendering Tests (Zero New Dependencies):** React components are tested directly using React's built-in `renderToStaticMarkup` from `react-dom/server` (natively included in `react-dom: ^19.2.8`, already in `package.json`). This renders components to static HTML strings within Node.js, allowing deterministic assertions on HTML structure, CSS tokens, ARIA attributes, labels, and conditional rendering without requiring `jsdom`, `happy-dom`, or `@testing-library/react`.
3. **Frontend Logic & State Machine Tests:** Pure logic modules (`dashboard-utils.ts`, `polling.ts`, `findings-filters.ts`) isolate critical behavioral logic into testable units evaluated with Vitest unit tests.
4. **UI Boundary & Authorization Isolation Tests:** Evaluated against in-memory MongoDB using the project's existing `mongodb-memory-server: ^9.5.0` and `src/test/setup.ts` infrastructure.
5. **No Exhaustive Visual/Component Coverage:** Exhaustive styling edge cases, browser DOM event simulations, and visual diffs are explicitly deferred to Phase 08. Phase 07 focuses strictly on critical behavior, lifecycle state transitions, data correctness, and security invariants.

---

### 13.2 Dashboard Loading, Error, and Empty State Tests

Tested in `apps/web/src/components/__tests__/dashboard-components.test.ts`:

| Component / State | Test Scenario | Verified Assertions |
|---|---|---|
| `<Spinner />` | Loading indicator rendering | Renders valid SVG/CSS spinner classes, accessible `role="status"`, and `aria-label="Loading..."`. |
| `<Button loading={true} />` | Submit button loading state | Renders spinner icon, applies `disabled` attribute, and renders loading label ("Creating scan..."). |
| Findings Table Loading | Page transition loading state | Renders inline skeleton/loading indicator with `aria-busy="true"`. |
| `<EmptyState type="no-scans" />` | Initial user state (0 scans) | Renders empty illustration, "No scans yet. Analyze your first repository.", and CTA link to `/dashboard/new-scan`. |
| `<EmptyState type="no-findings" />` | Clean scan state | Renders clean shield indicator, "No security findings detected. This repository appears clean." |
| `<EmptyState type="no-filter-matches" />` | Filter mismatch state | Renders "No findings match the selected filters." with an active "Clear filters" action button. |
| `<EmptyState type="no-repos" />` | No GitHub repositories | Renders "No repositories found. Ensure your GitHub App has access." with permission guidance. |
| Dashboard Error Card (500) | Server error state | Renders user-friendly error headline, error details, and an interactive "Retry" button. |
| Scan Not Found (404) | Missing or unauthorized scan | Renders "Scan not found or you do not have access." with link back to `/dashboard`. |
| Rate Limit Alert (429) | Scan creation throttled | Renders amber alert card with cooldown guidance ("Too many scan requests. Please wait before trying again."). |
| Network Error Alert | Fetch failure / offline | Renders "Unable to reach server" message with manual retry trigger. |

---

### 13.3 Scan Status Rendering Tests

Tested in `apps/web/src/components/__tests__/dashboard-components.test.ts` and `apps/web/src/lib/__tests__/dashboard-utils.test.ts`:

| Test Group | Target | Verified Assertions |
|---|---|---|
| Status Badge Rendering | `<ScanStatusBadge status={...} />` for all 7 statuses | Renders exact label ("Queued", "Cloning", "Scanning", "Normalizing", "Completed", "Failed", "Timed Out") and correct color tokens (gray, blue, animated blue, green, red, orange). |
| Animated Scanning State | `scanning` & `normalizing` | Verifies presence of animation classes (e.g. `animate-pulse` or spinner icon) indicating active background processing. |
| Terminal Status Detection | `isTerminalStatus(status)` | Returns `true` for `completed`, `failed`, `timed_out`; returns `false` for `queued`, `cloning`, `scanning`, `normalizing`. Returns `false` for null/undefined/invalid values. |
| Status Metadata Mapping | `getStatusDisplay(status)` | Returns `{ label, color, icon }` tuple matching the design specification for all 7 statuses; returns fallback for unrecognized status strings. |

---

### 13.4 Severity & Finding Summary Tests

Tested in `apps/web/src/components/__tests__/dashboard-components.test.ts` and `apps/web/src/lib/__tests__/dashboard-utils.test.ts`:

| Test Group | Target | Verified Assertions |
|---|---|---|
| Summary Component Rendering | `<SeveritySummary summary={...} />` | Renders individual severity count badges for Critical, High, Medium, Low, Info with corresponding color tokens. |
| Zero-Count Handling | Summary with 0 findings in some severities | Badges render zero values correctly without layout collapse or undefined text. |
| Missing / Null Summary | Missing fields or null `scan.summary` | Handles missing fields or null summary objects safely without crashing, falling back to all-zero counts. |
| Severity Count Parsing | `computeSeverityCounts(summary)` | Transforms summary object into an ordered array of `{ severity, count, color }` entries. |
| Percentage Computation | `computeSeverityPercentages(summary)` | Computes accurate proportional percentages (e.g., 20%, 50%, 30%) for distribution charts; provides division-by-zero protection when total finding count is 0 (returns all 0%). |
| Severity Color Mapping | `getSeverityColor(severity, mode)` | Maps each severity level to exact HEX/CSS tokens for both light and dark modes; returns fallback gray for invalid severity strings. |

---

### 13.5 Filter Component & Logic Tests

Tested in `apps/web/src/components/__tests__/dashboard-components.test.ts` and `apps/web/src/lib/__tests__/findings-filters.test.ts`:

| Test Group | Target | Verified Assertions |
|---|---|---|
| Filter Component Rendering | `<FindingsFilter filters={...} />` | Renders severity, category, and scanner `<select>` dropdowns with correct selected options based on active filters. |
| Active Filter Tags | Filter pills / badges | Renders dismissible badge for each active filter; clicking triggers filter removal. |
| Query String Building | `buildFilterQuery(filters)` | Constructs API query parameters (`{ severity, category, scanner }`), omitting unset or 'all' values. |
| URL Param Parsing | `parseFilterParams(searchParams)` | Parses URL search params into typed filter state; validates allowed values against valid enums and ignores malformed inputs. |
| Multi-Filter Composition | Combined filter criteria | Correctly combines multiple active filters (e.g. `severity=high&category=sast&scanner=semgrep`). |
| Filter Reset Behavior | Clearing filters | 'All' selection or reset action clears filter state and returns undefined query parameters. |

---

### 13.6 Pagination Component & Logic Tests

Tested in `apps/web/src/components/__tests__/dashboard-components.test.ts` and `apps/web/src/lib/__tests__/findings-filters.test.ts`:

| Test Group | Target | Verified Assertions |
|---|---|---|
| Pagination Rendering | `<Pagination currentPage={...} totalPages={...} />` | Renders page buttons, current page highlighted with active styling and `aria-current="page"`. |
| Boundary Button States | First and last page limits | "Previous" button has `disabled` attribute on page 1; "Next" button has `disabled` attribute on page `totalPages`. |
| Truncation / Ellipsis | Large page counts (e.g. 10+ pages) | Renders ellipsis (`...`) indicators when page count exceeds maximum visible window. |
| Page Range Math | `getPageRange(currentPage, totalPages, maxVisible)` | Computes accurate window array (e.g., `[1, 2, 3, 4, 5]` or `[1, '...', 4, 5, 6, '...', 10]`). |
| Page Clamping | `clampPage(page, totalPages)` | Clamps out-of-bounds page numbers: `page < 1` clamped to 1; `page > totalPages` clamped to `totalPages`; NaN/invalid defaults to 1. |
| Page Validation | `isValidPage(page, totalPages)` | Validates integer bounds: returns `true` for valid integers within `[1, totalPages]`; `false` otherwise. |

---

### 13.7 Polling Start/Stop Behavior & Lifecycle Tests

Tested in `apps/web/src/lib/__tests__/polling.test.ts`:

| Test Group | Target | Verified Assertions |
|---|---|---|
| Polling Initiation Condition | `shouldStartPolling(status)` | Returns `true` ONLY for non-terminal statuses (`queued`, `cloning`, `scanning`, `normalizing`); returns `false` for `completed`, `failed`, `timed_out`. |
| Terminal Stop Condition | `shouldStopPolling(state)` on terminal status | Returns `{ stop: true, reason: 'terminal_status' }` immediately when scan transitions to `completed`, `failed`, or `timed_out`. |
| Max Iterations Stop Condition | `shouldStopPolling(state)` at iteration 120 | Returns `{ stop: true, reason: 'max_iterations' }` when iteration count reaches `MAX_POLL_ITERATIONS` (120). |
| Error Circuit Breaker Stop | `shouldStopPolling(state)` at 10 errors | Returns `{ stop: true, reason: 'max_errors' }` when `consecutiveErrors` reaches `MAX_CONSECUTIVE_ERRORS` (10). |
| Polling State Reducer | `nextPollState(prevState, response)` | Success: updates status and resets `consecutiveErrors = 0`. Failure: increments `consecutiveErrors`. Warning: sets transient notice at error 3. |
| Uncontrolled Polling Prevention | In-flight request lock (`isFetchingRef`) | Simulates interval firing while fetch is pending; verifies next fetch is skipped so requests never pile up. |
| Unmount Cleanup Lifecycle | `ScanPollingWrapper` unmount | Verifies cleanup contract: `clearInterval(timerRef.current)` and `abortControllerRef.current.abort()` are executed. |
| Constant Invariants | Exported constants | Asserts `POLL_INTERVAL_MS === 5000`, `MAX_POLL_ITERATIONS === 120`, `MAX_CONSECUTIVE_ERRORS === 10`. |

---

### 13.8 Authorization & User-Scoped Data Assumptions at UI Boundary

Tested in `apps/web/src/lib/__tests__/dashboard-auth.test.ts` (using `mongodb-memory-server`):

| Test Group | Target | Verified Assertions |
|---|---|---|
| User-Scoped Scan History | Dashboard scan list query | Inserts scans for User A and User B into MongoDB. Verifies that query with User A's ID strictly returns User A's scans (zero User B scans returned). |
| User-Scoped Scan Detail | Scan detail access | Verifies that requesting a scan belonging to another user returns 404/not found at the data layer, preventing unauthorized access. |
| Finding Ownership Boundary | Findings query scoping | Verifies findings are only queryable when the parent scan belongs to the requesting user. |
| Secret Redaction at UI Boundary | Secret findings in findings table | Queries findings generated by Gitleaks containing simulated tokens. Confirms `codeSnippet` renders `[REDACTED SECRET]` and that raw secrets are never exposed to the UI layer. |
| Empty / Safe Boundary Handling | Non-existent user query | Query with valid ObjectId for a non-existent user returns an empty scan list `{ scans: [], total: 0 }`, not a database or server error. |

---

### 13.9 Measurable Frontend Coverage & Validation Targets

| Metric | Target | Verification Tool |
|---|---|---|
| `src/lib/dashboard-utils.ts` Line Coverage | **≥ 90%** | Vitest coverage report (`npm run test:coverage`) |
| `src/lib/polling.ts` Line Coverage | **≥ 95%** | Vitest coverage report (`npm run test:coverage`) |
| `src/lib/findings-filters.ts` Line Coverage | **≥ 90%** | Vitest coverage report (`npm run test:coverage`) |
| Overall Repository Line Coverage | **≥ 90%** | Vitest coverage report (exceeds 80% threshold in `vitest.config.ts`) |
| New Phase 07 Frontend Test Cases | **≥ 65 total tests** | Test counter in `npm run test` output |
| Critical Component Rendering Tests | **100% pass rate** | `apps/web/src/components/__tests__/dashboard-components.test.ts` |
| Full Test Suite Pass Rate | **100% (344 existing + all new)** | All existing Phase 01–06 tests pass with 0 regressions |
| TypeScript Typecheck | **0 errors** | `npm run typecheck` (`tsc --noEmit`) |
| ESLint Check | **0 errors / 0 warnings** | `npm run lint` (`eslint .`) |
| Production Build | **SUCCESS** | `npm run build` (`next build`) |

---

### 13.10 Scope Partitioning: Deferred to Phase 08 (Production Hardening)

To maintain focus and avoid unnecessary complexity during Phase 07, the following broader testing concerns are explicitly deferred to **Phase 08**:

1. **DOM-Based User Event Simulation:** Full browser DOM emulation using `jsdom` or `happy-dom` with `@testing-library/react` user events (clicking, typing, focus management).
2. **Cross-Browser End-to-End Testing:** Full browser automation across Chrome, Firefox, and WebKit using Playwright.
3. **Visual Regression Testing:** Pixel-by-pixel screenshot comparisons and visual diffing.
4. **Automated Accessibility Auditing:** Automated axe-core a11y tree audits.
5. **Exhaustive Non-Critical Component Coverage:** Visual styling variations, subtle hover states, responsive breakpoint edge cases, and CSS utility coverage for non-critical layout wrappers.

---

## 14. Exact File Change Boundary

### New Files to Create

#### Dashboard Pages
1. `apps/web/src/app/dashboard/layout.tsx` — Dashboard shell layout (auth check, nav, user menu).
2. `apps/web/src/app/dashboard/new-scan/page.tsx` — New scan form page.
3. `apps/web/src/app/dashboard/scans/[id]/page.tsx` — Scan detail and findings explorer page.

#### Reusable UI Components
4. `apps/web/src/components/ui/Badge.tsx` — Severity/status badge.
5. `apps/web/src/components/ui/Button.tsx` — Styled button.
6. `apps/web/src/components/ui/Card.tsx` — Card container.
7. `apps/web/src/components/ui/Select.tsx` — Dropdown select.
8. `apps/web/src/components/ui/Spinner.tsx` — Loading indicator.

#### Dashboard Components
9. `apps/web/src/components/dashboard/ScanHistoryList.tsx` — Paginated scan list.
10. `apps/web/src/components/dashboard/ScanCard.tsx` — Individual scan summary card.
11. `apps/web/src/components/dashboard/ScanStatusBadge.tsx` — Status indicator.
12. `apps/web/src/components/dashboard/SeveritySummary.tsx` — Severity count badges.
13. `apps/web/src/components/dashboard/SeverityChart.tsx` — Severity distribution visualization.
14. `apps/web/src/components/dashboard/ScanDetail.tsx` — Scan metadata display.
15. `apps/web/src/components/dashboard/ScanPollingWrapper.tsx` — Auto-refresh wrapper.
16. `apps/web/src/components/dashboard/FindingsExplorer.tsx` — Interactive findings table.
17. `apps/web/src/components/dashboard/FindingRow.tsx` — Expandable finding row.
18. `apps/web/src/components/dashboard/FindingsFilter.tsx` — Filter controls.
19. `apps/web/src/components/dashboard/RemediationPanel.tsx` — Remediation advice.
20. `apps/web/src/components/dashboard/NewScanForm.tsx` — Repository selector and scan trigger.
21. `apps/web/src/components/dashboard/Pagination.tsx` — Page navigation.
22. `apps/web/src/components/dashboard/EmptyState.tsx` — Empty state display.

#### Utility / Logic Modules
23. `apps/web/src/lib/dashboard-utils.ts` — Severity color/icon mapping, duration formatting, status display helpers, summary computation.
24. `apps/web/src/lib/polling.ts` — Polling state machine: constants, `shouldStartPolling`, `shouldStopPolling`, `nextPollState`.
25. `apps/web/src/lib/findings-filters.ts` — Filter query building, URL param parsing, pagination range computation.

#### Tests
26. `apps/web/src/components/__tests__/dashboard-components.test.ts` — Component rendering tests using `react-dom/server` (status badges for all 7 statuses, severity summaries, loading/error states, empty states, pagination, and filter controls).
27. `apps/web/src/lib/__tests__/dashboard-utils.test.ts` — Unit tests for dashboard utility functions (severity mapping, status helpers, duration formatting, summary computation).
28. `apps/web/src/lib/__tests__/polling.test.ts` — Unit tests for polling state machine (start/stop conditions, state transitions, circuit breaker, iteration cap, unmount cleanup, and uncontrolled polling prevention).
29. `apps/web/src/lib/__tests__/findings-filters.test.ts` — Unit tests for filter logic (URL param parsing, query generation) and pagination computation (range, clamping, bounds).
30. `apps/web/src/lib/__tests__/dashboard-auth.test.ts` — Authorization boundary tests (user-scoped queries, cross-user isolation, and secret redaction at UI boundary).

### Files to Modify

1. `apps/web/src/app/dashboard/page.tsx` — Replace Phase 01 placeholder with full scan history dashboard.
2. `apps/web/src/app/globals.css` — Add dashboard-specific CSS custom properties and utility classes.
3. `apps/web/tailwind.config.ts` — Extend theme with severity color palette tokens.

### Files Explicitly Protected from Modification

The following files MUST NOT be modified in Phase 07:

- `apps/web/package.json` — No new dependencies.
- `package-lock.json` — No lockfile changes.
- `apps/web/src/lib/env.ts` — No new environment variables.
- `apps/web/src/models/*.ts` — No model/schema changes.
- `apps/web/src/app/api/**/*.ts` — No API route changes.
- `apps/web/src/lib/scanner/**/*.ts` — No scanner changes.
- `apps/web/src/lib/auth.ts` — No auth changes.
- `apps/web/src/lib/session.ts` — No session changes.
- `apps/web/src/lib/schemas.ts` — No schema changes.
- `apps/web/src/lib/rate-limit.ts` — No rate limit changes.
- `apps/web/src/lib/errors.ts` — No error handling changes.
- `apps/web/src/lib/github.ts` — No GitHub client changes.
- `apps/web/src/lib/db.ts` — No database connection changes.
- `apps/web/src/types/index.ts` — No type changes (existing types are sufficient).
- `apps/web/next.config.mjs` — No config changes (unless `<Image>` is used for avatars, in which case only `images.remotePatterns` is added).
- `apps/web/vitest.config.ts` — No test config changes (node environment is sufficient for extracted logic tests).
- `apps/web/src/test/setup.ts` — No test setup changes (existing MongoDB setup reused for auth boundary tests).
- `docs/PHASES/PHASE_06.md` — Phase 06 is frozen.

---

## 15. Migration / Backward-Compatibility Requirements

**No migrations required.**

- Phase 07 adds frontend pages and components only.
- No database schema changes.
- No API contract changes.
- The existing Phase 01 dashboard placeholder page (`dashboard/page.tsx`) is replaced in-place with the full implementation. The placeholder explicitly stated: "The security dashboard will be available in Phase 07."
- All existing routes (`/`, `/login`, `/dashboard`, `/api/**`) continue functioning identically.

---

## 16. Rollback Strategy

Phase 07 is a pure frontend addition with no backend changes. Rollback is trivial:

1. `git revert <phase-07-commit>` removes all dashboard UI files.
2. The Phase 01 placeholder dashboard page is restored.
3. All API routes, scanner engine, models, and backend logic remain completely unaffected.
4. No database migration reversal needed.

---

## 17. Explicit Non-Goals

1. **WebSockets / Server-Sent Events (SSE):** Real-time push updates deferred. Polling via `GET /api/v1/scans/:id` is sufficient for MVP (consistent with Phase 06 non-goals).
2. **Client-Side Data Fetching Library:** No React Query, SWR, or Axios. Standard `fetch` and RSC data loading only.
3. **E2E Tests (Playwright):** Deferred to Phase 08 (Production Hardening).
4. **DOM-Based User Event Simulation Tests (jsdom/happy-dom):** Deferred to Phase 08. Phase 07 tests critical component rendering via `react-dom/server` in Node.js, combined with extensive unit and auth boundary suites. Interactive user-event simulation and browser DOM environments are deferred to Phase 08.
5. **Exhaustive Visual / Non-Critical Component Coverage:** Deferred to Phase 08. Phase 07 targets critical frontend behavior, state transitions, and security boundaries. Broad UI hardening, visual regression testing, and non-critical styling variations are deferred to Phase 08.
6. **Dark Mode Toggle:** The app respects `prefers-color-scheme: dark` via existing CSS custom properties. No manual toggle UI.
7. **Repository Detail Pages:** `/repo/:owner/:name` route deferred to a future phase.
8. **Scan Comparison:** Comparing findings across scans is out of scope.
9. **Export/Download Findings:** CSV/PDF export deferred to a future phase.
10. **New Dependencies:** No npm packages added. Tailwind CSS, React, and Next.js (already installed) are sufficient.

---

## 18. Visual Design Specifications

### Color Palette (Severity)

| Severity | Light Mode | Dark Mode | Usage |
|---|---|---|---|
| Critical | `#DC2626` (red-600) | `#EF4444` (red-500) | Badges, chart segments, borders |
| High | `#EA580C` (orange-600) | `#F97316` (orange-500) | Badges, chart segments, borders |
| Medium | `#CA8A04` (yellow-600) | `#EAB308` (yellow-500) | Badges, chart segments, borders |
| Low | `#2563EB` (blue-600) | `#3B82F6` (blue-500) | Badges, chart segments, borders |
| Info | `#6B7280` (gray-500) | `#9CA3AF` (gray-400) | Badges, chart segments, borders |

### Status Indicators

| Status | Color | Icon/Label |
|---|---|---|
| queued | Gray | ○ Queued |
| cloning | Blue | ◌ Cloning |
| scanning | Blue (animated) | ◉ Scanning |
| normalizing | Blue | ◎ Normalizing |
| completed | Green | ● Completed |
| failed | Red | ✕ Failed |
| timed_out | Orange | ⏱ Timed Out |

### Layout

- **Dashboard Shell:** Fixed top navigation bar with SafeRepo logo, user avatar, and sign-out button. Content area below.
- **Responsive Breakpoints:** Mobile-first. Single column on mobile; two-column (sidebar + main) on large screens where appropriate.
- **Cards:** Rounded corners (`rounded-lg`), subtle border (`border border-gray-200 dark:border-gray-800`), hover elevation on interactive cards.
- **Typography:** Inter font (already loaded in `layout.tsx`).

---

## 19. Git Checkpoint Strategy

- **Checkpoint 1 (Planning):** `docs: complete phase 07 planning` (Current document).
- **Checkpoint 2 (UI Foundation):** `feat: implement dashboard layout and ui components` (layout, UI primitives, globals.css, tailwind config).
- **Checkpoint 3 (Dashboard Home):** `feat: implement scan history dashboard` (dashboard page, scan cards, status badges, severity summary, pagination, empty states).
- **Checkpoint 4 (Scan Detail + Findings):** `feat: implement scan detail and findings explorer` (scan detail page, findings explorer, filters, finding rows, remediation panel, severity chart).
- **Checkpoint 5 (New Scan + Polling):** `feat: implement new scan form and status polling` (new scan page, new scan form, polling wrapper).
- **Checkpoint 6 (Verification + Close):** `feat: complete phase 07 security dashboard` (utility tests, validation, phase status update).

---

## 20. Acceptance Criteria (Definition of Done)

Phase 07 is complete when:

**Functional:**
- [ ] Dashboard home page displays authenticated user's scan history with status, severity summary, and timing.
- [ ] Scan detail page displays scan metadata, lifecycle status, severity chart, and paginated findings.
- [ ] Findings explorer supports filtering by severity, category, and scanner.
- [ ] Each finding row expands to show description, file location, code snippet, vulnerability ID, and remediation.
- [ ] New scan form allows selecting a repository and initiating a scan.
- [ ] In-progress scans auto-refresh via polling until terminal state.

**State Handling:**
- [ ] Loading states displayed during data fetching (findings pagination, scan creation, repo loading).
- [ ] Empty states handled for: no scans, no findings, no repos, no filter matches.
- [ ] Error states handled for: API failures (4xx/5xx), network errors, auth failures, not found.
- [ ] Rate limit (429) displays cooldown guidance.

**Polling Behavior:**
- [ ] Polling starts only for non-terminal scan statuses.
- [ ] Polling stops on terminal status (`completed`, `failed`, `timed_out`).
- [ ] Polling stops after `MAX_POLL_ITERATIONS` (120) with user message.
- [ ] Polling stops after `MAX_CONSECUTIVE_ERRORS` (10) with user message.
- [ ] Polling cleanup runs on component unmount (`clearInterval` + `AbortController.abort()`).
- [ ] Overlapping poll requests are prevented (in-flight guard).
- [ ] Consecutive error counter resets on successful response.

**Security:**
- [ ] Secret findings display `[REDACTED SECRET]` — no plaintext secrets anywhere.
- [ ] All scan/finding queries are user-scoped (userId filter verified by auth boundary tests).

**Design:**
- [ ] Dashboard is responsive (mobile and desktop).
- [ ] Dark mode is supported via `prefers-color-scheme`.

**Change Boundary:**
- [ ] No new dependencies added to `package.json`.
- [ ] No API routes modified.
- [ ] No database models or schemas modified.
- [ ] No scanner or queue code modified.

**Validation & Frontend Testing:**
- [ ] `npm run typecheck` passes with 0 errors (`tsc --noEmit`).
- [ ] `npm run lint` passes with 0 errors (`eslint .`).
- [ ] `npm run build` succeeds (Next.js production build with zero errors).
- [ ] `npm run test` passes — all existing 344+ tests AND all new Phase 07 tests pass with 0 failures (100% pass rate).
- [ ] Total new Phase 07 automated tests ≥ 65 test cases.
- [ ] Zero new npm dependencies added to `package.json` or `package-lock.json`.
- [ ] Critical component rendering tests implemented using `react-dom/server` in Node.js environment:
  - [ ] Dashboard loading states tested (`<Spinner />`, submit button loading state, inline loading).
  - [ ] Dashboard error states tested (404 not found, 429 rate limit cooldown, 500 server error, network failure with retry).
  - [ ] Empty states tested (`<EmptyState />` for no-scans, no-findings, no-filter-matches, no-repos).
  - [ ] Scan status rendering tested for all 7 statuses (`queued`, `cloning`, `scanning`, `normalizing`, `completed`, `failed`, `timed_out`).
  - [ ] Severity and finding summaries tested (badges, zero counts, missing fields, percentage calculations).
  - [ ] Filters tested (`<FindingsFilter />` component rendering, URL param parsing, query generation, 'all' filter reset).
  - [ ] Pagination tested (`<Pagination />` component rendering, boundary disabled states, page range math, clamping).
- [ ] Polling lifecycle and state machine tested:
  - [ ] Polling interval confirmed at 5000ms (`POLL_INTERVAL_MS`).
  - [ ] Polling initiates only on non-terminal scan statuses.
  - [ ] Polling stops on terminal status (`completed`, `failed`, `timed_out`).
  - [ ] Polling stops after `MAX_POLL_ITERATIONS` (120 iterations = 10 minutes) with timeout guidance.
  - [ ] Polling stops after `MAX_CONSECUTIVE_ERRORS` (10 errors) with circuit breaker alert.
  - [ ] Polling cleanup on unmount verified (`clearInterval` + `AbortController.abort()`).
  - [ ] Prevention of uncontrolled polling requests verified (in-flight request lock prevents overlapping calls).
  - [ ] Consecutive error counter resets to 0 on successful response.
- [ ] Authorization boundary tested:
  - [ ] Scan queries enforce `{ userId }` filter; User A cannot access User B's scans.
  - [ ] Findings queries enforce parent scan ownership.
  - [ ] Secret redaction verified at UI boundary: findings display `[REDACTED SECRET]` and never leak raw credentials.
  - [ ] Non-existent user query returns empty scan list without database errors.
- [ ] Measurable code coverage targets:
  - [ ] `src/lib/dashboard-utils.ts` achieves ≥ 90% line coverage.
  - [ ] `src/lib/polling.ts` achieves ≥ 95% line coverage.
  - [ ] `src/lib/findings-filters.ts` achieves ≥ 90% line coverage.
  - [ ] Overall repository coverage remains ≥ 90% (exceeding 80% config threshold).
- [ ] Broader UI hardening, Playwright E2E, jsdom user-event simulation, and visual regression tests explicitly reserved for Phase 08.

---

## 21. Human Review Gate

This document requires **explicit human approval** before any implementation begins.

No source code, component, style, or test file may be created or modified until the Phase 07 plan is approved.
