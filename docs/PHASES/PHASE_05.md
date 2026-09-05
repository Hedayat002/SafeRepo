# Phase 05 — Secret Scanning (Gitleaks)

**Status:** Completed (Awaiting Human Review)

---

## A. Objective & Approved Scope

Implement comprehensive static secret detection across acquired repositories in SafeRepo using Gitleaks executed inside hardened Stage 1 Docker isolation.

Phase 05 extends the multi-scanner scanning pipeline (connecting Semgrep SAST and Trivy/OSV dependency vulnerability analysis) with secret detection:
1. **Hardened Stage 1 Docker Execution:** Executes Gitleaks inside ephemeral container isolation (`--network=none`, `--read-only` root filesystem, `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, unprivileged user `1000:1000`, dropped capabilities, resource limits, execution timeouts).
2. **Process-Boundary Redaction:** Explicitly enforces native Gitleaks redaction via `--redact`, suppressing raw secret values directly at the container output boundary.
3. **Sensitive Raw Output Protection:** Stdout and stderr are treated as sensitive streams; output is parsed strictly in memory with zero logging, zero exception echoing, and zero disk caching of raw findings.
4. **Strict Normalization Redaction:** Normalized findings scrub raw `Secret` and `Match` fields, replace `codeSnippet` with `[REDACTED SECRET]`, and format descriptions generically.
5. **Deterministic Severity Policy:** Fully documented rule-based severity categorization (`critical`, `high`, `medium`, `low`, `info`).
6. **Deterministic Fingerprint:** Namespaced `secret:` hash strictly excluding secret values, preserving uniqueness without leakage risk.
7. **Fault-Isolated Pipeline Integration:** Integrated as Scanner 4 in `processScanPipeline` in `apps/web/src/lib/scanner/acquisition.ts`. Partial failure never discards Semgrep, Trivy, or OSV findings.
8. **Findings API Integration:** Queryable via `GET /api/v1/scans/:id/findings` with `category=secret` and `scanner=gitleaks`.

---

## B. Docker Stage 1 Isolation & Process-Boundary Redaction

Gitleaks executes strictly under **Stage 1 Network-Disabled Isolation** (Decision C1, Decision C2, NFR-02, NFR-03).

### Container CLI Specification
```bash
docker run --rm \
  --name saferepo-scan-<scanId>-gitleaks \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --user 1000:1000 \
  --cpus=1 \
  --memory=512m \
  --pids-limit=256 \
  -e HOME=/tmp \
  -v <workspacePath>:/src:ro \
  -w /src \
  zricethezav/gitleaks:v8.24.0 \
  dir /src \
  --report-format json \
  --report-path - \
  --redact \
  --no-banner \
  --no-color
```

### Security Invariants
1. **Native Process-Boundary Redaction (`--redact`):** Gitleaks redacts secret values in its report output directly inside the container before streaming to host stdout.
2. **Network Disabled (`--network=none`):** Zero network connectivity. Gitleaks evaluates its built-in offline ruleset (>150 secret types) without external requests or telemetry.
3. **Read-Only Root Filesystem (`--read-only`):** The container cannot modify its root filesystem or the workspace (`:ro`).
4. **Unprivileged Execution (`--user 1000:1000`):** Runs as unprivileged non-root user matching host standard.
5. **Docker Socket Isolation (Decision C2):** Docker daemon access is isolated to the Scanner Runner boundary. `/var/run/docker.sock` is never mounted into the container.
6. **Resource Limits:** Capped at 1 CPU core, 512MB RAM, 256 PIDs, 180s hard execution timeout, and 10MB maximum stdout buffer.

---

## C. Sensitive Raw Output Handling

Gitleaks container `stdout` and `stderr` are classified as **Sensitive Scanner Output**:
- **Zero Logging:** Logger never records raw stdout or stderr. Only operational metadata (`scanId`, `scanner`, `exitCode`, `durationMs`, `matchesCount`) is logged.
- **Zero Exception Echoing:** Non-zero exit codes throw generic operational errors (`Gitleaks execution failed (exit code 2)`) without concatenating stderr.
- **Zero Persistence of Raw Output:** Raw JSON is never saved to disk, never cached, and never stored in MongoDB. Output is parsed in memory via `JSON.parse` in a scoped block.
- **Sanitized Error Metadata:** Operational failures recorded in `scan.metadata.scannerErrors` contain only generic sanitized strings.

---

## D. Exit-Code Semantics

Gitleaks exit codes are handled explicitly:
- **`0` (Clean Scan):** Scan completed with 0 leaks detected. Output is empty or `[]`. Added to `scan.scanners`.
- **`1` (Finding-Positive):** Scan completed and leaks were detected. Findings are parsed, normalized, and redacted. Handled as `status: 'success'` and **added to `scan.scanners`**.
- **`> 1` (Operational Error):** Fatal configuration or runtime error. Handled as `status: 'failed'` and excluded from `scan.scanners`.
- **Timeout:** Killed with `SIGKILL` after 180s; handled as failure.

---

## E. Deterministic Severity Policy

SafeRepo enforces an explicit, deterministic rule-based severity policy:

| Severity | Category / Secret Types | Matching Criteria (`ruleId` or `tags`) |
|---|---|---|
| **`critical`** | Cryptographic Private Keys | `ruleId` matching: `private-key`, `rsa-private-key`, `ssh-private-key`, `pgp-private-key`, `dsa-private-key`, `ec-private-key`, `openssh-private-key`, `putty-private-key`, `jwt-secret`<br/>OR `tags`: `'key'`, `'private-key'`, `'crypto'` |
| **`critical`** | Cloud Admin Credentials | `ruleId` matching: `aws-access-token`, `aws-secret-access-key`, `gcp-service-account-key`, `gcp-api-key`, `azure-client-secret`, `azure-storage-key`, `digitalocean-token`, `linode-token`<br/>OR `tags`: `'cloud'`, `'infrastructure'` |
| **`critical`** | Database Connection Strings | `ruleId` matching: `mongodb-uri`, `postgres-uri`, `mysql-uri`, `redis-uri`, `database-password`<br/>OR `tags`: `'database'` |
| **`critical`** | High-Privilege SaaS / Auth | `ruleId` matching: `stripe-secret-key`, `okta-api-token`, `vault-token`, `auth0-secret`<br/>OR `tags`: `'auth'`, `'payment'` |
| **`high`** | Developer & VCS Tokens | `ruleId` matching: `github-pat`, `github-app-token`, `gitlab-pat`, `bitbucket-token`, `npm-access-token`, `pypi-api-token`, `dockerhub-token` |
| **`high`** | Collaboration & Messaging | `ruleId` matching: `slack-token`, `slack-bot-token`, `slack-webhook-url`, `discord-bot-token`, `discord-webhook-url`, `telegram-bot-token` |
| **`high`** | Transactional API Keys | `ruleId` matching: `sendgrid-api-key`, `twilio-api-key`, `mailgun-api-key`, `postmark-api-key` |
| **`high`** | Hardcoded Passwords | `ruleId` matching: `password-in-url`, `hardcoded-password`, `generic-api-key` |
| **`high`** | Deterministic Fallback | Any detected secret not matching `critical`, `medium`, or `low` |
| **`medium`** | Webhooks & Client Keys | `ruleId` matching: `generic-webhook`, `incoming-webhook`, `stripe-publishable-key`, `firebase-api-key`, `google-maps-api-key`, `mapbox-api-key`, `sentry-dsn`<br/>OR `tags`: `'publishable'`, `'client-side'`, `'dsn'` |
| **`low`** | High-Entropy Strings | `ruleId` matching: `generic-high-entropy-string`, `entropy-match` |
| **`info`** | Test Placeholders | `ruleId` matching: `example-token`, `test-credential`, `mock-secret` |

---

## F. Strict Fingerprint Policy

Secret finding fingerprints use a deterministic, normalized SHA-256 hash:

$$\text{sha256}(\text{"secret:"} + \text{normalizedRuleId} + \text{":"} + \text{normalizedFilePath} + \text{":"} + \text{normalizedLine} + \text{":"} + \text{normalizedColumn})$$

- **Normalization:**
  - File path: container prefix (`/src/`) stripped, backslashes converted to forward slashes, trimmed, lowercased.
  - Rule ID: trimmed, lowercased (fallback: `'generic-secret'`).
  - Line & Column: non-negative integers $\ge 0$ (default `0` if invalid).
- **Security Invariant:** Plaintext secret values, raw Match, and code snippets are **STRICTLY PROHIBITED** from the fingerprint.

---

## G. Secret Redaction Invariants

- `codeSnippet`: Always set to `"[REDACTED SECRET]"`.
- `description`: Set to generic string `${Description || RuleID} detected in source code.`.
- `metadata`: `rawFinding.Secret` and `rawFinding.Match` are strictly omitted. Only safe metadata (`ruleId`, `secretType`, `entropy`, `commit`, `author`, `date`, `tags`, `scanners`) is recorded.
- Persisted MongoDB `Finding` documents contain zero plaintext secret values.

---

## H. Multi-Scanner Pipeline Integration & Fault Isolation

In `apps/web/src/lib/scanner/acquisition.ts`:
- Orchestrates:
  - Scanner 1: Semgrep SAST
  - Scanner 2: Trivy SCA Filesystem
  - Scanner 3: OSV Dependency Advisories
  - Scanner 4: Gitleaks Secret Scanner
- Findings are aggregated: `[...semgrepFindings, ...dependencyFindings, ...gitleaksFindings]`.
- Summary metrics combine counts across all categories (`sast`, `dependency`, `secret`).
- Scanners array accurately accounts for successful executions: `['semgrep', 'trivy', 'osv', 'gitleaks']`.
- Partial failure semantics: If Gitleaks fails, Semgrep, Trivy, and OSV findings are preserved.

---

## I. Verification & Quality Gates

### Automated Test Suite
- **24 Test Files, 327 Tests Passing (100% Pass Rate).**
- `npm run test` passes with 0 failures.
- `npm run typecheck` passes with 0 errors.
- `npm run lint` passes with 0 errors.
- `npm run build` succeeds cleanly.

### Code Coverage Metrics
- `apps/web/src/lib/scanner/gitleaks.ts`: **98.66% line coverage**
- `apps/web/src/lib/scanner/normalizer.ts`: **97.36% line coverage**
- `apps/web/src/lib/scanner/acquisition.ts`: **90.55% line coverage**
- Entire codebase: **94.43% line coverage** (Threshold $\ge 80\%$).
