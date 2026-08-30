# USER_STORIES.md — SafeRepo

---

## Story Map

### Epic 1: Authentication

- **US-01:** As a developer, I want to sign in with my GitHub account so I can access SafeRepo using my existing identity.
  - AC: GitHub OAuth flow completes, user record created in MongoDB, session established, redirected to dashboard.

- **US-02:** As a user, I want to log out so my session ends securely.
  - AC: Session terminated, redirected to landing page.

---

### Epic 2: GitHub Integration

- **US-03:** As a user, I want to see a list of my accessible GitHub repositories so I can choose which one to scan.
  - AC: Repositories listed with owner, name, visibility, and last updated. Paginated if many repos.

- **US-04:** As a user, I want to select a specific repository and branch so I can scan exactly what I intend.
  - AC: Repository selected, branch/default branch identified, scan can be initiated.

---

### Epic 3: Repository Scanning

- **US-05:** As a user, I want to start a security scan on a selected repository so I can understand its risks.
  - AC: Scan created with status "queued", repository acquisition begins, user receives scan ID.

- **US-06:** As a user, I want to see the current status of my scan so I know when it will be ready.
  - AC: Scan status displayed (queued → cloning → scanning → normalizing → completed/failed/timed_out). Progress updates visible without page refresh.

- **US-07:** As a user, I want the scan to run in an isolated environment so that malicious repository code cannot harm my system or SafeRepo.
  - AC: Scanners execute in Docker containers with no network, resource limits, timeouts, and automatic cleanup.

---

### Epic 4: Security Findings

- **US-08:** As a user, I want to see a summary of findings after a scan completes so I get a quick overview of the security posture.
  - AC: Summary shows total findings count and breakdown by severity (critical, high, medium, low, info).

- **US-09:** As a user, I want to view detailed findings so I understand each specific security issue.
  - AC: Each finding shows scanner, category, severity, title, description, file, line number (where applicable), and vulnerability ID.

- **US-10:** As a user, I want to filter findings by severity so I can focus on the most critical issues first.
  - AC: Filter by severity (critical, high, medium, low, info). Results update accordingly.

- **US-11:** As a user, I want to filter findings by category so I can focus on specific types of issues (code, dependencies, secrets).
  - AC: Filter by category (sast, dependency, secret, configuration). Results update accordingly.

- **US-12:** As a user, I want to see remediation guidance for each finding so I know how to fix the issue.
  - AC: Findings that have remediation data display suggested fixes. Where no remediation is available, this is clearly indicated.

- **US-13:** As a user, I want to be confident that discovered secrets are not exposed to me in full, so that SafeRepo does not become a vector for secret leakage.
  - AC: Secret findings show file, line, and secret type only. Actual secret values are never displayed or stored.

---

### Epic 5: Scan History

- **US-14:** As a user, I want to see my scan history so I can revisit previous results.
  - AC: Scans listed chronologically with repository name, date, status, and severity summary. Paginated.

- **US-15:** As a user, I want to view a previous scan's results so I can compare security posture over time.
  - AC: Clicking a past scan shows its full findings.

---

### Epic 6: Dashboard

- **US-16:** As a user, I want a dashboard showing my recent scans and overall activity so I have a central view of my security analysis work.
  - AC: Dashboard shows recent scans, quick-scan action, and summary statistics.

---

## Acceptance Tests (E2E)

```gherkin
Feature: Repository Security Scan
  Scenario: Scan a GitHub repository
    Given I am logged in via GitHub
    When I select the repository "example-org/example-repo"
    And I start a scan on the "main" branch
    Then a scan is created with status "queued"
    And the scan progresses through "cloning" → "scanning" → "completed"
    And the results show findings with severity breakdown
    And I can filter findings by "critical" severity
    And secret findings do not expose actual secret values

  Scenario: Scan timeout
    Given I am logged in via GitHub
    When I start a scan on a very large repository
    And the scan exceeds the timeout limit
    Then the scan status changes to "timed_out"
    And partial results (if any) are available
```

---

## Prioritization (MoSCoW)

- **Must:** US-01 through US-13 (auth, GitHub integration, scanning, findings with filtering and remediation)
- **Should:** US-14, US-15 (scan history and comparison)
- **Could:** US-16 (dashboard with summary statistics)
- **Won't (MVP):** Team workspaces, payments, custom scanner rules, PR integration
