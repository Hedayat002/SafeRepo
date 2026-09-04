# Phase 04 — Dependency Vulnerability Scanning

**Status:** Completed (Awaiting Human Approval)

---

## A. Objective & Approved Scope

Implement comprehensive Software Composition Analysis (SCA) and dependency vulnerability scanning across acquired repositories in SafeRepo.

Phase 04 connects repository acquisition (Phase 02) and static code analysis (Phase 03) to a dual-engine dependency analysis pipeline:
1. **Trivy Filesystem Scanner:** Executed inside hardened Stage 1 Docker isolation (`--network=none`, read-only root, dropped capabilities, unprivileged user) using a pre-loaded offline vulnerability database.
2. **OSV API Integration:** Keyless, host-side HTTP batch queries (`https://api.osv.dev/v1/querybatch`) using statically extracted package coordinates (`name`, `version`, `ecosystem`).

Phase 04 normalizes dependency findings into SafeRepo's unified schema, resolves canonical vulnerability identifiers, applies deterministic cross-scanner deduplication, updates scan summary severity counts in MongoDB, and exposes findings via the existing findings query API.

### Scope Boundaries

#### In Scope
- **Ecosystem & Manifest Detection:** Static detection of Node.js (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) and Python (`requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`) manifests without code execution.
- **Trivy Stage 1 Execution:** Hardened containerized scan with `--network=none` against repository files using a pre-populated offline vulnerability database (`TRIVY_DB_PATH`).
- **Trivy Availability State Machine:** Typed handling distinguishing DB availability vs unavailability; explicit scanner error recording without silent skipping; accurate `scan.scanners` accounting.
- **Host-Side OSV Static Query Workflow:** Parsing dependency coordinates from lockfiles and batch-querying the public OSV API over HTTPS via native `fetch` (strictly no repository code or lifecycle scripts executed).
- **Canonical Vulnerability Identifier Resolution:** Resolving aliases to prioritize standard CVE IDs (e.g., `CVE-2021-23337` over `GHSA-35jh-r3h4-6jhm`), preserving all secondary identifiers in metadata.
- **Deterministic Ecosystem-Aware Fingerprinting:** Cross-scanner deduplication hash:
  `sha256("dependency:" + ecosystem.toLowerCase() + ":" + packageName.toLowerCase() + ":" + packageVersion + ":" + canonicalVulnerabilityId.toUpperCase())`
- **Cross-Scanner Deduplication & Merging:** Merging findings across Trivy and OSV when they target the same package, version, and vulnerability, recording contributing scanners in `metadata.scanners` and selecting the highest severity.
- **Partial Failure Semantics:** Resilient execution preserving successful scanner findings when an individual scanner fails or is unavailable.
- **MongoDB Persistence & Summary Aggregation:** Batch persisting normalized dependency findings using the existing `Finding` model and updating parent `Scan` record summary counts.
- **Findings API Integration:** Ensuring findings are retrievable through `GET /api/v1/scans/:id/findings` with existing `category=dependency`, `scanner`, and `severity` filters.

#### Deferred to Future Phases (Explicit Non-Goals)
- **Containerized `npm audit` and `pip-audit`:** **DEFERRED to Phase 06.** SafeRepo currently lacks an egress allowlist/forward proxy in `docker-compose.yml`. Standard Docker bridge networking (`--network=bridge`) is strictly forbidden for untrusted scans, and host-side execution of package manager CLI binaries violates NFR-02.
- **Secret scanning with Gitleaks:** Deferred to Phase 05.
- **Unified multi-scanner orchestrator and queue engine:** Deferred to Phase 06.
- **Dashboard UI visual components:** Deferred to Phase 07.
- **Production deployment & cloud infrastructure:** Deferred to Phase 09.

---

## B. Trivy Stage 1 Security Model & Non-Root Cache Isolation

Trivy operates strictly under **Stage 1 Network-Disabled Isolation** (Decision C1, NFR-02, NFR-03).

### Non-Root Permission & Cache Architecture
Standard Linux containers restrict traversal of `/root` (mode `0700` owned by `root:root`). Under `--user 1000:1000`, an unprivileged process cannot access `/root/.cache/trivy`.

To preserve strict non-root execution (`1000:1000`) without weakening filesystem isolation:
1. A dedicated tmpfs directory is allocated at `/home/scanner`:
   `--tmpfs /home/scanner:rw,noexec,nosuid,size=128m,uid=1000,gid=1000`
2. The offline vulnerability DB is mounted read-only inside the accessible directory:
   `-v <trivyDbPath>:/home/scanner/.cache/trivy/db:ro`
3. Trivy is explicitly configured via environment and CLI flags:
   `-e HOME=/home/scanner`
   `-e TRIVY_CACHE_DIR=/home/scanner/.cache/trivy`
   `--cache-dir /home/scanner/.cache/trivy`
4. Root filesystem remains strictly `--read-only`. Temporary writes are bounded to the unprivileged tmpfs.

### Container Hardening Specifications
```bash
docker run --rm \
  --name saferepo-scan-<scanId>-trivy \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /home/scanner:rw,noexec,nosuid,size=128m,uid=1000,gid=1000 \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --user 1000:1000 \
  --cpus=1 \
  --memory=512m \
  --pids-limit=256 \
  -e HOME=/home/scanner \
  -e TRIVY_CACHE_DIR=/home/scanner/.cache/trivy \
  -v <workspacePath>:/src:ro \
  -v <trivyDbPath>:/home/scanner/.cache/trivy/db:ro \
  -w /src \
  aquasec/trivy:0.59.1 \
  fs --format json --offline-scan --skip-db-update --cache-dir /home/scanner/.cache/trivy --scanners vuln /src
```

### Security Invariants
1. **Network Disabled:** `--network=none` prevents any outbound telemetry, DB download attempts, or data exfiltration.
2. **Read-Only Filesystem:** The container cannot modify its root filesystem or the workspace (`:ro`).
3. **No Code Execution:** Trivy performs static AST and manifest parsing; it never executes repository code, build tools, or package lifecycle scripts.
4. **Docker Socket Isolation (Decision C2):** The Docker socket is never mounted into the container.
5. **Least Privilege:** Drops all Linux capabilities (`--cap-drop=ALL`), sets unprivileged user `1000:1000`, and forbids privilege escalation.

---

## C. Trivy Offline Database State Machine & Typed Result Contract

Operating Trivy under `--network=none` requires a pre-populated vulnerability database.

```
                  ┌───────────────────────────────┐
                  │ Evaluate TRIVY_DB_PATH Config │
                  └───────────────┬───────────────┘
                                  │
                 Is path specified & directory valid?
                                  │
                 ┌────────────────┴────────────────┐
                 ▼ YES                             ▼ NO
  ┌─────────────────────────────┐   ┌─────────────────────────────┐
  │      State: DB Available    │   │    State: DB Unavailable    │
  ├─────────────────────────────┤   ├─────────────────────────────┤
  │ • Mount DB read-only (:ro)  │   │ • Do NOT spawn container    │
  │ • Run Trivy in Stage 1      │   │ • Return typed result:      │
  │ • Return typed result:      │   │   status: "unavailable"     │
  │   status: "success"         │   │   scanner: "trivy"          │
  │ • Add "trivy" to            │   │   reason: "..."             │
  │   scan.scanners             │   │ • Record in scan.error      │
  │ • Findings merged to scan   │   │ • Exclude "trivy" from      │
  │                             │   │   scan.scanners             │
  └─────────────────────────────┘   └─────────────────────────────┘
```

### Discriminated Union Scanner Result Contract
To eliminate ambiguity and prevent exception-driven control flow for expected missing database states:

```typescript
export interface BaseScannerResult {
  scanner: 'semgrep' | 'trivy' | 'osv';
}

export interface ScannerSuccessResult extends BaseScannerResult {
  status: 'success';
  findings: NormalizedFindingInput[];
  durationMs: number;
  rawMatchesCount: number;
}

export interface ScannerUnavailableResult extends BaseScannerResult {
  status: 'unavailable';
  scanner: 'trivy';
  reason: string;
}

export interface ScannerFailedResult extends BaseScannerResult {
  status: 'failed';
  error: string;
  durationMs?: number;
}

export type ScannerResult =
  | ScannerSuccessResult
  | ScannerUnavailableResult
  | ScannerFailedResult;
```

### Operational Rules
1. **Never Silently Skip:** If `TRIVY_DB_PATH` is missing, unconfigured, or invalid, `executeTrivyScan` returns `{ status: 'unavailable', scanner: 'trivy', reason: 'Trivy offline vulnerability database not found at TRIVY_DB_PATH' }`.
2. **Scanner Array Truthfulness:** `"trivy"` is added to `scan.scanners` **if and only if** `result.status === 'success'`.
3. **No False Negatives:** The scan record must never imply that Trivy ran cleanly with 0 findings when the database was absent.
4. **Scan Completion Decoupling:** Scan completion indicates pipeline execution success, NOT whether vulnerabilities were present or absent.

---

## D. Host-Side OSV Static-Coordinate Workflow

The Open Source Vulnerabilities (OSV) API integration runs directly from the host application process (`apps/web`) using native Node.js `fetch`.

```
Acquired Workspace
       │
       ▼
Lockfile / Manifest Extractor (Static JSON / text parse only)
       │
       ▼
Extract Package Coordinates: [ { name: "lodash", version: "4.17.20", ecosystem: "npm" }, ... ]
       │
       ▼
Chunk Queries (Max 100 coordinates per batch)
       │
       ▼
POST https://api.osv.dev/v1/querybatch (Host-side HTTPS, 30s timeout, max 3 retries)
       │
       ▼
OSV Advisory Response Normalization & Canonical CVE Resolution
```

### Security & Compliance Justification
- **Zero Untrusted Code Execution:** The host process only reads static data files (`package-lock.json`, `requirements.txt`, `Pipfile.lock`). It does not invoke package managers (`npm`, `pip`), does not spawn shell processes, and does not evaluate JavaScript or Python files.
- **Least-Data Principle:** Only package coordinates (`name`, `version`, `ecosystem`) are transmitted. No repository source code or proprietary file contents are sent over the network.
- **₹0 Cost & Keyless:** The public OSV API requires no API key or paid subscription.

---

## E. Deferred Scanners: npm audit & pip-audit

### Architectural Blocker
- **Requirement:** `docs/REQUIREMENTS.md` (NFR-02) mandates that dependency advisory scanners execute in dedicated restricted containers with controlled outbound network access and explicit allowlisting.
- **Deficiency:** SafeRepo currently lacks an Egress Allowlist Forward Proxy service in `docker-compose.yml` to constrain container traffic to `registry.npmjs.org` and `pypi.org`.
- **Enforced Constraint:**
  - Standard unrestricted Docker bridge networking (`--network=bridge`) is **prohibited** for untrusted scanning.
  - Direct host-side execution of `npm` or `pip` is **prohibited** due to the risk of untrusted script execution.
- **Status:** `npm audit` and `pip-audit` are officially **DEFERRED** to Phase 06 when an egress allowlist proxy service can be architected and introduced into `docker-compose.yml`.

---

## F. Dependency Ecosystem Detection & Coordinate Extraction

Implemented in `apps/web/src/lib/scanner/ecosystem.ts`:

### Manifest Parsing Strategy (Zero New Dependencies)

| Manifest Format | Ecosystem | Parser Strategy | Exact Version Extraction | Handling of Unresolved Specifiers | Status in Phase 04 |
|---|---|---|---|---|---|
| **`package-lock.json`** | `npm` | Native `JSON.parse` | Reads `packages["node_modules/<name>"].version` (Lockfile v2/v3) or `dependencies[<name>].version` (Lockfile v1). | N/A — Lockfiles guarantee exact resolved versions. | **Supported** |
| **`package.json`** | `npm` | Native `JSON.parse` | Detects ecosystem presence only. | **SKIPPED for OSV query.** Version ranges (`^1.0`, `~2.1`, `*`) are NOT exact versions. Versions are **never invented**. | **Detected only** (Trivy scans in Stage 1) |
| **`yarn.lock`** | `npm` | Non-JSON / YAML format | N/A | Requires external parser library. | **Deferred for OSV** (Trivy scans in Stage 1) |
| **`pnpm-lock.yaml`**| `npm` | YAML format | N/A | Requires YAML parser library (`yaml`). No ad-hoc regex. | **Deferred for OSV** (Trivy scans in Stage 1) |
| **`requirements.txt`**| `pypi` | Native line-by-line UTF-8 text parser | Strict regex: `/^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.\+]+)$/`. Package name PEP 503 normalized (`replace(/[-_.]+/g, '-')`). | Lines with `>=, <=, ~=, >` or unpinned packages are **SKIPPED**. Versions are **never invented**. | **Supported** |
| **`Pipfile.lock`** | `pypi` | Native `JSON.parse` | Reads `default[<name>].version`. Strips leading `==` (`"==2.25.1"` -> `"2.25.1"`). PEP 503 normalized. | Non-exact specifiers skipped. | **Supported** |
| **`pyproject.toml`** | `pypi` | TOML format | N/A | Requires TOML parser library (`@iarna/toml`). No ad-hoc regex. | **Deferred for OSV** (Trivy scans in Stage 1) |
| **`poetry.lock`** | `pypi` | TOML format | N/A | Requires TOML parser library. | **Deferred for OSV** (Trivy scans in Stage 1) |

### Operational Logic
1. Statically reads workspace root using `fs.readdir` and `fs.stat`.
2. Validates that paths do not escape workspace bounds (verifies against directory traversal).
3. If no manifests are found for an ecosystem, scanner execution for that ecosystem is cleanly bypassed with an informational log.
4. In polyglot repositories containing both Node.js and Python manifests, both ecosystem coordinate extractors run.

---

## G. Dependency Finding Normalization

Dependency findings from both Trivy and OSV normalize into SafeRepo's standard `Finding` schema:

| Schema Field | Value / Source |
|---|---|
| `scanId` | Current scan ObjectId |
| `userId` | Scanning user ObjectId |
| `scanner` | `'trivy'` or `'osv'` |
| `category` | `'dependency'` (constant) |
| `severity` | Normalized 5-level severity: `'critical'`, `'high'`, `'medium'`, `'low'`, `'info'` |
| `title` | Vulnerability title or summary (max 120 chars) |
| `description` | Full advisory description or details |
| `file` | Manifest file path relative to workspace root (e.g. `package-lock.json`) |
| `line` | `0` (manifest-level finding) |
| `package` | Name of the vulnerable dependency (e.g. `lodash`) |
| `packageVersion`| Exact vulnerable version detected (e.g. `4.17.20`) |
| `fixedVersion`  | Patched / remediation version if known (e.g. `4.17.21`) |
| `vulnerabilityId`| Canonical vulnerability ID (e.g. `CVE-2021-23337`) |
| `remediation`   | Actionable remediation advice (e.g. `Upgrade lodash to 4.17.21`) |
| `fingerprint`   | Deterministic ecosystem-aware SHA-256 deduplication hash |
| `metadata`      | Raw metadata: `ecosystem`, `aliases`, `scanners: string[]` |

---

## H. Canonical Vulnerability Identifier Resolution

Vulnerability databases frequently refer to the exact same flaw by different identifiers (e.g. OSV reports `GHSA-35jh-r3h4-6jhm`, while Trivy reports `CVE-2021-23337`).

### Resolution Rules
1. Inspect the finding's `aliases` array (from OSV `vuln.aliases` or Trivy `Vulnerability.Aliases`).
2. If any alias matches the standard CVE format (`/^CVE-\d{4}-\d+$/i`), the **CVE ID** is selected as the canonical `vulnerabilityId`.
3. If no CVE alias exists, use the primary vulnerability ID (e.g. `GHSA-...` or `OSV-...`).
4. Retain all original identifiers in `metadata.aliases` for transparency.

---

## I. Dependency Fingerprint Formula

To guarantee deterministic identity and cross-scanner merging across different engines:

```typescript
export function generateDependencyFingerprint(
  ecosystem: string,
  packageName: string,
  packageVersion: string,
  canonicalVulnerabilityId: string
): string {
  const raw =
    'dependency:' +
    ecosystem.trim().toLowerCase() + ':' +
    packageName.trim().toLowerCase() + ':' +
    packageVersion.trim() + ':' +
    canonicalVulnerabilityId.trim().toUpperCase();

  return crypto.createHash('sha256').update(raw).digest('hex');
}
```

### Fingerprint Constraints
- **Must NOT contain `file`:** Manifest path naming differences across tools (e.g., coordinate lookups vs filesystem paths) must not prevent duplicate merging.
- **Must NOT contain `scanner`:** Including scanner name prevents merging Trivy and OSV duplicates for the same package.
- **Phase 03 Semgrep Contract Preservation:** The existing SAST fingerprint formula (`generateFindingFingerprint('semgrep', ruleId, file, line, message)`) remains 100% untouched.

---

## J. Cross-Scanner Deduplication Mechanics

During the normalization phase, findings are processed through an in-memory `Map<string, NormalizedFindingInput>` keyed by `fingerprint`.

```
Trivy Finding ──┐
                ├──► In-Memory Map keyed by Fingerprint ──► Unified Finding Record
OSV Finding   ──┘
```

### Merge Precedence Rules
When a new finding matches an existing `fingerprint`:
1. **Contributing Scanners:** Append the new scanner to `metadata.scanners` (e.g. `['trivy', 'osv']`).
2. **Severity Precedence:** Retain the highest severity according to precedence rank:
   `critical` (5) > `high` (4) > `medium` (3) > `low` (2) > `info` (1).
3. **Remediation Enrichment:** If the existing finding lacks `fixedVersion` or `remediation`, merge from the new finding.
4. **Alias Union:** Compute the union of `metadata.aliases` across both sources.

---

## K. Partial Scanner Failure Semantics

SafeRepo follows an isolated fault-tolerance model across scanners:

| Scenario | Semgrep | Trivy | OSV | Resulting Scan Status | Scan Error Field | Scanners Array |
|---|---|---|---|---|---|---|
| **All Pass** | Pass | Pass | Pass | `completed` | `null` | `['semgrep', 'trivy', 'osv']` |
| **Trivy DB Missing** | Pass | Unavailable | Pass | `completed` | `"Warning: Trivy unavailable (DB missing)"` | `['semgrep', 'osv']` |
| **OSV Network Blip** | Pass | Pass | Failed | `completed` | `"Warning: OSV query failed (timeout)"` | `['semgrep', 'trivy']` |
| **Only One Runs & Fails**| Failed | Unavailable | Failed | `failed` | `"Scan failed: All scanners failed"` | `[]` |
| **Scan Timeout (>300s)**| Any | Any | Any | `timed_out` | `"Scan exceeded maximum duration of 300s"` | Scanners completed before timeout |

### Key Rule
A partial scanner failure or unconfigured tool never purges or aborts findings generated by other successful scanners.

---

## L. Scan Status & Metadata Semantics

- **Status Transitions:**
  `queued` → `cloning` → `scanning` → `normalizing` → `completed` (or `failed` / `timed_out`).
- **`scan.scanners`:** Contains strictly the names of scanners that executed to completion (`status === 'success'`).
- **`scan.error`:** Null on clean runs; contains explicit warning strings on partial failures; contains fatal error message on failed scans.
- **`scan.metadata.scannerErrors`:** Array of typed scanner error objects:
  ```json
  [
    {
      "scanner": "trivy",
      "status": "unavailable",
      "reason": "Trivy vulnerability database not found at TRIVY_DB_PATH"
    }
  ]
  ```

---

## M. Resource Limits, Timeouts & Workspace Isolation

| Parameter | Limit | Enforcement Mechanism |
|---|---|---|
| **Overall Scan Timeout** | 300 seconds | Aborts pipeline, marks `timed_out`, purges partial artifacts |
| **Trivy Container Timeout** | 180 seconds | `setTimeout` with `docker kill` and `SIGKILL` |
| **OSV HTTP Request Timeout**| 30 seconds per batch | `AbortController` signal on native `fetch` |
| **Trivy Memory Limit** | 512MB (`--memory=512m`) | Docker cgroup limit |
| **Trivy CPU Limit** | 1.0 CPU (`--cpus=1`) | Docker cgroup limit |
| **Trivy PID Limit** | 256 (`--pids-limit=256`) | Docker cgroup limit |
| **Stdout Stream Limit** | 10MB | Stream byte counter throws `OutputSizeExceededError` |
| **Workspace Mount** | Read-Only (`-v <path>:/src:ro`) | Docker bind mount option |
| **Workspace Cleanup** | Post-scan | Guaranteed in `processScanPipeline` `finally` block |

---

## N. Testing & Coverage Requirements

### Unit Tests
1. **`ecosystem.test.ts`:**
   - Detects Node.js (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).
   - Detects Python (`requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`).
   - Coordinate extraction: verified for `package-lock.json`, `requirements.txt`, and `Pipfile.lock`.
   - Rejection of unresolved version ranges: `package.json` ranges and unpinned `requirements.txt` lines are skipped from OSV coordinates.
   - Handles polyglot repositories (both present).
   - Handles empty workspaces (both absent).
   - Verifies symlink and path traversal protection.
2. **`trivy.test.ts`:**
   - Docker CLI argument construction (`--network=none`, `--read-only`, non-root tmpfs `/home/scanner`, caps dropped).
   - Availability state machine (valid path vs missing path returns typed `ScannerUnavailableResult`).
   - Trivy vulnerability JSON output parser.
   - Severity mapping from Trivy levels to SafeRepo 5-level model.
3. **`osv.test.ts`:**
   - Coordinate extraction from `package-lock.json`, `requirements.txt`, and `Pipfile.lock`.
   - Batch query chunking (100 items per chunk).
   - Canonical CVE alias resolution.
   - Mocked HTTP responses, error handling, and timeout behavior.
4. **`normalizer.test.ts`:**
   - `generateDependencyFingerprint` deterministic hash verification.
   - Cross-scanner deduplication logic (merging overlapping Trivy and OSV matches).
   - Precedence rule for merged severity.
   - Confirmation that Phase 03 Semgrep SAST fingerprinting is unaffected.

### Integration Tests
1. **`acquisition.test.ts`:**
   - Multi-scanner orchestration pipeline combining Semgrep, Trivy, and OSV.
   - DB persistence of dependency findings with compound index validation.
   - Scan summary computation with combined SAST + dependency severity counts.
   - Partial failure handling and warning metadata persistence.
2. **Findings API Verification:**
   - Querying `GET /api/v1/scans/:id/findings?category=dependency`.
   - Querying `GET /api/v1/scans/:id/findings?scanner=trivy` and `scanner=osv`.
   - Verification that cross-tenant access is rejected with 404/403.

### Quality & Coverage Gates
- Minimum **80% line coverage** across new scanner modules in `apps/web/src/lib/scanner/`.
- `npm run typecheck` passes with 0 errors.
- `npm run lint` passes with 0 warnings/errors.
- `npm run build` succeeds cleanly.

---

## O. Review Criteria & Definition of Done

Phase 04 is complete when:
- [x] Ecosystem detector accurately identifies Node.js and Python manifests.
- [x] OSV coordinates are extracted only from exact-resolved manifests (`package-lock.json`, pinned `requirements.txt`, `Pipfile.lock`); unresolved version ranges are skipped without inventing versions.
- [x] Trivy executes inside Stage 1 Docker container with `--network=none` and non-root `/home/scanner` cache when DB is available.
- [x] Trivy unavailable state is typed (`ScannerUnavailableResult`) and explicitly recorded when DB is missing, without silent skipping or throwing exceptions.
- [x] OSV API queries successfully retrieve advisories using static coordinates via host-side HTTPS.
- [x] Canonical vulnerability IDs prioritize CVE IDs over ecosystem-specific aliases.
- [x] Dependency fingerprints use the ecosystem-aware formula and exclude file paths and scanner names.
- [x] Overlapping findings from Trivy and OSV are deduplicated into unified records in MongoDB.
- [x] Scan summary metrics accurately combine SAST and dependency finding counts.
- [x] `GET /api/v1/scans/:id/findings?category=dependency` returns paginated, filtered findings.
- [x] Phase 03 Semgrep implementation and fingerprints remain 100% unmodified and passing.
- [x] All unit and integration tests pass with ≥ 80% line coverage.
- [x] `npm run typecheck`, `npm run lint`, and `npm run build` pass with 0 errors.
- [x] Phase 04 Validation Report generated and submitted for human approval.
