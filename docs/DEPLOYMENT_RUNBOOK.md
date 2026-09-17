# SafeRepo Production Operations & Deployment Runbook

**Document Role:** Authoritative operational manual for provisioning, deploying, validating, operating, and recovering the SafeRepo production stack on a beta host.<br>
**Target Environment:** Single-Host 100-User Beta (Ubuntu 24.04 LTS)<br>
**Baseline Git Checkpoint:** `9fb53b0e9f6f5dacfd86c98851157f7fe7e08c61`<br>
**Application Release Baseline:** SafeRepo `v0.9.0` (Node 24.19.0 LTS, Next.js 16.3.3 Standalone, MongoDB 7)

---

## 1. Purpose & Scope

This runbook provides human operators with the end-to-end operational procedures required to deploy, configure, verify, maintain, and recover SafeRepo safely on a beta production host.

### Scope
- Provisioning and hardening an Ubuntu 24.04 LTS host for single-host beta operation.
- Configuring the dual-tier container architecture (Web + Worker + Database + Ingress).
- Managing production environment variables, secret boundaries, and rotation procedures.
- Executing deterministic pre-flight configuration validation and automated HTTP smoke testing.
- Performing ongoing operational maintenance, log analysis, and backup verification.
- Executing disaster recovery, emergency incident response, and rollback procedures.
- Enforcing architectural boundaries between the single-host beta and future GA production.

---

## 2. SafeRepo Production Architecture

SafeRepo employs a decoupled, multi-tier architecture that isolates internet-facing web traffic from untrusted code scanning workloads:

```text
                                  PUBLIC INTERNET
                                         │
                                   [Ports 80/443]
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Caddy Reverse Proxy (saferepo-caddy: caddy:2.9.1-alpine)                        │
│ • Sole public ingress point; terminates TLS 1.3 / HTTPS                         │
│ • Reverse proxies to internal Web tier on web-net                               │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ (HTTP :3000 over web-net)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Web / API Application Tier (saferepo-web: saferepo-web:0.9.0)                   │
│ • Stateless Next.js 16.3.3 Standalone server (Node 24.19.0 Alpine)              │
│ • Runs as unprivileged system user (nextjs, UID 1001)                           │
│ • Port 3000 is internal-only (UNPUBLISHED to host)                              │
│ • Strictly ZERO access to /var/run/docker.sock or Docker CLI                    │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                                         ▼ (backend-net)
┌─────────────────────────────────────────────────────────────────────────────────┐
│ MongoDB Database (saferepo-mongo: mongo:7.0.18-jammy or MongoDB Atlas)          │
│ • Stores users, sessions, scans, and normalized findings                        │
│ • Port 27017 is internal-only (UNPUBLISHED to host)                             │
│ • Persistent volume: mongodata:/data/db                                         │
└────────────────────────────────────────▲────────────────────────────────────────┘
                                         │ (Claims scan jobs via atomic queue)
                                         │ (backend-net)
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Trusted Scan Worker (saferepo-worker: saferepo-worker:0.9.0)                    │
│ • Background Node 24 polling worker process outside Next.js request loop        │
│ • Runs as unprivileged user (workeruser, UID 1001)                              │
│ • Isolated ephemeral workspaces (/tmp/saferepo-workspaces, permissions 0700)   │
│ • Minimal client tools only: docker-cli, git (NO Docker daemon installed)       │
│ • NO direct /var/run/docker.sock mount                                          │
│ • Connects via DOCKER_HOST=tcp://docker-proxy:2375 over worker-proxy-net        │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ (Docker API over worker-proxy-net)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Restricted Docker Socket Proxy (saferepo-docker-proxy: v0.1.1)                  │
│ • Sole service mounting /var/run/docker.sock (read-only inode mount)            │
│ • Port 2375 is private to worker-proxy-net (UNPUBLISHED to host)                │
│ • Enforces API restrictions: CONTAINERS=1, POST=1, PING=1                       │
│ • Blocks dangerous APIs: VOLUMES=0, NETWORKS=0, EXEC=0, BUILD=0, SECRETS=0      │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ (Spawns ephemeral child containers)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Ephemeral Stage 1 Scanner Sandboxes                                             │
│ • semgrep/semgrep:1.100.0 (SAST)                                                │
│ • aquasec/trivy:0.59.1 (SCA Lockfile Scanner)                                   │
│ • zricethezav/gitleaks:v8.24.0 (Secret Scanner)                                 │
│ • Invariants: --network=none, --read-only, --cap-drop=ALL, 512MB RAM cap        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Architectural Security Invariants
1. **Web Tier Isolation:** The `web` container has strictly **ZERO** access to `/var/run/docker.sock`, contains no Docker CLI client, and has no network route to `worker-proxy-net`. A compromised web container cannot execute Docker commands or reach the Docker socket proxy.
2. **Worker Socket Mediation:** The `worker` container does **NOT** mount `/var/run/docker.sock` directly. It communicates with the Docker API exclusively over the internal `worker-proxy-net` via `DOCKER_HOST=tcp://docker-proxy:2375`.
3. **Sole Socket Mount:** `docker-proxy` is the **ONLY** service in the entire Compose stack that mounts `/var/run/docker.sock`.
4. **Network Exposure Restrictions:** `caddy` is the sole ingress layer publishing host ports (80 and 443). `web` (3000), `worker`, `docker-proxy` (2375), and `mongo` (27017) are private to internal bridge networks and are **never** published to the host or external internet.
5. **Defense-in-Depth Beta Boundary (Important Limitation):** The Docker socket proxy (`tecnativa/docker-socket-proxy`) acts as a HTTP URL path and HTTP verb filter. **It does NOT inspect or sanitize JSON request bodies** sent to `POST /containers/create`. Consequently, it cannot inspect container creation parameters (such as `HostConfig` privilege flags or host bind mounts). Therefore, the socket proxy is a **defense-in-depth mitigation** for the local/single-host beta architecture, **NOT a complete security boundary**.
6. **GA Target Architecture:** For multi-tenant production (Phase 10+ GA), the approved architecture requires a **Dedicated Isolated Worker VM/Host** with its own independent Docker daemon, physically and network-separated from the Web/API server and production database.

---

## 3. Prerequisites

### Host System Requirements (Ubuntu 24.04 LTS Baseline)

The following matrix distinguishes the practical baseline for the single-host 100-user beta from the recommended production baseline:

| Requirement | Minimum Practical Beta Baseline (100 Users) | Recommended Production Baseline |
|---|---|---|
| **Operating System** | Ubuntu 24.04 LTS (x86_64) | Ubuntu 24.04 LTS (x86_64) |
| **CPU** | 2 vCPUs | 4 vCPUs |
| **RAM** | 4 GB RAM | 8 GB RAM (or 4 GB Web + 8 GB Worker VM) |
| **Storage** | 40 GB SSD (NVMe preferred) | 80 GB NVMe SSD |
| **Network** | 100 Mbps, Static Public IPv4 | 1 Gbps, Static Public IPv4 + IPv6 |
| **Docker Engine** | Docker Engine `24.x` or `26.x`+ | Docker Engine `26.x`+ |
| **Docker Compose** | Compose Plugin `v2.20`+ | Compose Plugin `v2.26`+ |
| **Node.js (Host)** | Node.js `24.19.0` LTS (for host CLI validation) | Node.js `24.19.0` LTS |

---

## 4. Host Preparation

Execute these commands as a user with `sudo` privileges on a clean Ubuntu 24.04 LTS host.

### 4.1 System Updates & Essential Packages
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw fail2ban unattended-upgrades apt-transport-https ca-certificates gnupg
```

### 4.2 Unattended Security Updates
Enable automatic security updates for the host OS:
```bash
sudo systemctl enable --now unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 4.3 Firewall (UFW) Hardening
Configure defensive firewall rules so that only necessary ports are accessible:
```bash
# Default policies: block all incoming, allow outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow administrative SSH, and public HTTP/HTTPS for Caddy
sudo ufw allow 22/tcp comment 'SSH Administration'
sudo ufw allow 80/tcp comment 'Caddy HTTP Ingress'
sudo ufw allow 443/tcp comment 'Caddy HTTPS Ingress'

# Enable firewall
sudo ufw --force enable
sudo ufw status verbose
```

> [!CAUTION]
> Always verify SSH (port 22) is allowed before enabling UFW to prevent losing remote administrative access.

### 4.4 SSH Hardening
Update `/etc/ssh/sshd_config.d/50-saferepo-hardening.conf` or `/etc/ssh/sshd_config`:
```text
PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
MaxAuthTries 4
```
Reload the SSH daemon:
```bash
sudo systemctl reload ssh
```

### 4.5 Install Official Docker Engine & Compose Plugin
```bash
# Register Docker official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Register Docker APT repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker packages
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable Docker service
sudo systemctl enable --now docker
```

### 4.6 Deployer User & Filesystem Permissions
Create a dedicated non-login system deployer user and prepare the application directory:
```bash
# Create dedicated unprivileged deployer user
sudo adduser --system --group --shell /bin/bash saferepo
sudo usermod -aG docker saferepo

# Allocate application directory with restricted ownership
sudo mkdir -p /opt/saferepo
sudo chown -R saferepo:saferepo /opt/saferepo
sudo chmod 750 /opt/saferepo
```

---

## 5. Repository & Application Deployment

Log in as the `saferepo` user to perform application deployments:
```bash
su - saferepo
cd /opt/saferepo
```

### 5.1 Clone SafeRepo & Verify Git Baseline
Clone the repository and verify the commit hash against the approved Git baseline:
```bash
git clone https://github.com/<ORG>/saferepo.git .
git checkout main

# Verify the commit matches the audited checkpoint
git rev-parse HEAD
# Must match: 9fb53b0e9f6f5dacfd86c98851157f7fe7e08c61 or the authorized release tag
```

### 5.2 Deployment Workflow Summary
1. Obtain the approved SafeRepo release on the server.
2. Verify the exact Git revision.
3. Configure `.env.production` server-side with `0600` permissions.
4. Run pre-flight configuration validation (`validate-production.ts`).
5. Pre-cache pinned scanner container images.
6. Build or pull approved production images.
7. Launch the stack via `docker compose -f docker-compose.prod.yml up -d`.
8. Verify health via `/api/health` and automated smoke testing (`smoke-test.ts`).

> [!IMPORTANT]
> Never commit `.env.production` to Git. Production secrets must remain exclusively on the host server.

---

## 6. Environment & Secrets Management

SafeRepo loads configuration exclusively from server-side environment variables. Real production credentials must never be committed to Git, placed into Dockerfiles, or embedded into container image layers.

### 6.1 Create Production Environment File
Create `/opt/saferepo/.env.production` with strict read/write restrictions:
```bash
touch /opt/saferepo/.env.production
chmod 600 /opt/saferepo/.env.production
```

### 6.2 Production Environment Schema
Populate `/opt/saferepo/.env.production` using the schema below (replace all placeholder values with generated production values):

```env
# Runtime Configuration
NODE_ENV=production
PORT=3000
HOSTNAME=0.0.0.0
NEXT_TELEMETRY_DISABLED=1

# Application Ingress URLs (Replace with your actual production domain)
NEXT_PUBLIC_APP_URL=https://<YOUR_DOMAIN>
ALLOWED_ORIGINS=https://<YOUR_DOMAIN>

# Database Connection (Choice A: Atlas or Choice B: Local Container)
# Choice A: MongoDB Atlas (Recommended):
# MONGODB_URI=mongodb+srv://saferepo_app:<STRONG_DB_PASSWORD>@<CLUSTER>.mongodb.net/saferepo?retryWrites=true&w=majority
# Choice B: Local Mongo Container:
MONGODB_URI=mongodb://mongo:27017/saferepo

# Session Authentication (Generate using: openssl rand -base64 32)
SESSION_SECRET=REPLACE_WITH_MINIMUM_32_CHAR_CRYPTOGRAPHIC_SECRET_KEY

# GitHub App Integration (From GitHub App Developer Settings)
GITHUB_APP_ID=123456
GITHUB_CLIENT_ID=Iv1.xxxxxxxxxxxxxxxx
GITHUB_CLIENT_SECRET=REPLACE_WITH_REAL_GITHUB_APP_CLIENT_SECRET

# Operational Limits & Retention Policies
SCAN_RETENTION_DAYS=90
MAX_SCANS_PER_USER=500
MAX_CONCURRENT_SCANS=1
SCAN_TIMEOUT_SECONDS=300

# Scanner Engine Container Images (Strictly Pinned)
SEMGREP_IMAGE=semgrep/semgrep:1.100.0
TRIVY_IMAGE=aquasec/trivy:0.59.1
GITLEAKS_IMAGE=zricethezav/gitleaks:v8.24.0
OSV_API_URL=https://api.osv.dev/v1/querybatch
```

### 6.3 Security Hygiene Guidelines
- **Server-Side Only:** `.env.production` must reside only on the production host filesystem with `0600` permissions.
- **Zero Secrets in Git:** Version control must contain zero secrets, API keys, or private certificates.
- **Zero Secrets in Dockerfiles / Images:** Never use `ENV` or `ARG` to pass secrets during Docker builds. SafeRepo builds production assets with inert placeholder variables.
- **Zero Secrets in Logs:** Pino logging filters and masks authentication headers, cookies, and tokens.
- **No AI Agent Access:** AI coding assistants or automated agents must never be supplied with real production credentials.

### 6.4 Conceptual Secret Rotation Procedures
1. **GitHub App Client Secret:**
   - Navigate to GitHub App settings -> Generate new client secret.
   - Update `GITHUB_CLIENT_SECRET` in `/opt/saferepo/.env.production`.
   - Restart the web tier: `docker compose -f docker-compose.prod.yml restart web`.
   - Confirm successful login via OAuth callback.
   - Revoke the old client secret in GitHub App settings.
2. **Session Encryption Secret:**
   - Generate a fresh 32-byte secret: `openssl rand -base64 32`.
   - Update `SESSION_SECRET` in `/opt/saferepo/.env.production`.
   - Restart the web tier: `docker compose -f docker-compose.prod.yml restart web`.
   - *Note: Rotating `SESSION_SECRET` invalidates active user sessions, requiring users to log in again.*
3. **Database Credentials:**
   - Create a new database user in MongoDB Atlas with `readWrite` permissions on `saferepo`.
   - Update `MONGODB_URI` in `/opt/saferepo/.env.production`.
   - Restart web and worker services: `docker compose -f docker-compose.prod.yml restart web worker`.
   - Verify health via `/api/health`.
   - Delete the old database user in MongoDB Atlas.

---

## 7. MongoDB Production Setup

SafeRepo supports two database architectures for the 100-user beta:

### Option A: MongoDB Atlas (Managed Cloud Database — Recommended)
1. **Cluster Provisioning:** Provision a cluster in the cloud region closest to your host. Select an appropriate tier (e.g. M0 free tier for initial testing, M10+ dedicated cluster for production beta) according to your project's storage and throughput requirements. Consult the MongoDB Atlas portal for current instance specifications.
2. **Least-Privilege Database User:**
   - In Atlas -> **Database Access** -> **Add New Database User**.
   - Create a user `saferepo_app`.
   - Grant **Built-in Role:** `readWrite` specifically on the `saferepo` database only.
   - Do **NOT** grant cluster administration or Atlas admin privileges.
3. **Network Allowlist:**
   - In Atlas -> **Network Access** -> **Add IP Address**.
   - Add the **static public IP of your production VPS host** (`<VPS_STATIC_IP>/32`).
   - **Never permit `0.0.0.0/0` (allow access from anywhere).**
4. **Connection String:**
   - Copy the SRV connection string into `MONGODB_URI` in `/opt/saferepo/.env.production`:
     `mongodb+srv://saferepo_app:<PASSWORD>@<CLUSTER>.mongodb.net/saferepo?retryWrites=true&w=majority`
5. **Backups & Monitoring:** Atlas automatically performs continuous snapshots and point-in-time recovery. Monitor connection counts and query latency in Atlas Cloud Monitoring.

### Option B: Self-Hosted MongoDB 7 (Single-Host Container)
The provided `docker-compose.prod.yml` includes an internal `mongo:7.0.18-jammy` service.
- **Network Isolation:** The container attaches only to internal `backend-net`. Port 27017 is **NOT published to the host**.
- **Data Persistence:** Database files are persisted in the named Docker volume `mongodata:/data/db`.
- **Manual Backups:** Backups must be scheduled using `mongodump` as detailed in Section 16.
- **Security Rule:** Self-hosted MongoDB must remain private to `backend-net`. Never add a `ports: ["27017:27017"]` mapping.

---

## 8. GitHub App Configuration

SafeRepo integrates with GitHub for user authentication and shallow cloning of target repositories.

### 8.1 Registering the Production GitHub App
In your GitHub Organization or User settings, navigate to **Settings** -> **Developer settings** -> **GitHub Apps** -> **New GitHub App**:

1. **GitHub App name:** `SafeRepo Production` (or your organizational name).
2. **Homepage URL:** `https://<YOUR_DOMAIN>`
3. **Callback URL:** `https://<YOUR_DOMAIN>/api/v1/auth/github/callback`
4. **Expire user authorization tokens:** Checked (recommended for security).
5. **Webhook:** Unchecked / Inactive (SafeRepo operates on user-initiated scans and does not require incoming webhooks for beta).

### 8.2 Least-Privilege Permissions
Configure strictly the minimum permissions required by SafeRepo:

| Category | Permission Name | Access Level | Operational Purpose |
|---|---|---|---|
| **Repository permissions** | `Contents` | **Read-only** | Shallow cloning and archive retrieval of source code for security scanning. |
| **Repository permissions** | `Metadata` | **Read-only** | Listing user-accessible repositories in the dashboard. |
| **Account permissions** | `Email addresses` | **Read-only** | Associating authenticated GitHub identity with scan history. |

> [!IMPORTANT]
> Grant **ZERO** write permissions. Do **NOT** grant pull request, commit, issue, administration, or workflow permissions.

Record the generated **App ID**, **Client ID**, and generate a **Client Secret** to configure in `/opt/saferepo/.env.production`.

---

## 9. Production Stack & Container Images

SafeRepo services are defined in `docker-compose.prod.yml`:

| Service Name | Container Name | Image Reference | Network Attachments | Security Controls |
|---|---|---|---|---|
| **`caddy`** | `saferepo-caddy` | `caddy:2.9.1-alpine` | `public-net`, `web-net` | Non-root, TLS 1.3 termination, host ports 80/443 |
| **`web`** | `saferepo-web` | `saferepo-web:0.9.0` | `web-net`, `backend-net` | Non-root `nextjs` (UID 1001), port 3000 internal, zero Docker access |
| **`worker`** | `saferepo-worker` | `saferepo-worker:0.9.0` | `backend-net`, `worker-proxy-net` | Non-root `workeruser` (UID 1001), workspace `0700`, no daemon |
| **`docker-proxy`** | `saferepo-docker-proxy` | `tecnativa/docker-socket-proxy:0.1.1` | `worker-proxy-net` | `/var/run/docker.sock:ro`, port 2375 internal, API filtering |
| **`mongo`** | `saferepo-mongo` | `mongo:7.0.18-jammy` | `backend-net` | Port 27017 internal, persistent volume `mongodata` |

### Pinned Scanner Images
The scan worker orchestrates three pinned scanner images to perform isolated analysis:
1. **SAST:** `semgrep/semgrep:1.100.0`
2. **SCA:** `aquasec/trivy:0.59.1`
3. **Secrets:** `zricethezav/gitleaks:v8.24.0`

### Preloading Scanner Images
To prevent on-demand pull delays and network timeouts during scan execution, pre-cache all scanner images using the provided scripts:
- **Linux / Bash:** `./scripts/preload-scanners.sh`
- **Windows / PowerShell:** `powershell -ExecutionPolicy Bypass -File scripts/preload-scanners.ps1`

*Note: These scripts pull images and inspect metadata only; they do not execute scanner containers. Scanner versions are pinned and must not be changed without validation.*

---

## 10. Configuration Validation

SafeRepo provides an automated, read-only pre-flight validation utility (`scripts/validate-production.ts`) that verifies the environment before containers are started.

### Validation Scope
- **Deterministic Read-Only Checks:** Operates without modifying files or making network requests.
- **Compose Configuration Validation:** Confirms syntax, service definitions, network bindings, and resource constraints.
- **Security Invariants:** Enforces that Web has zero Docker socket mounts, Worker has no direct socket mount, Docker proxy is read-only, and container ports are properly restricted.
- **Image & Runtime Expectations:** Validates Dockerfiles for non-root users, verifies scanner image pinning, and checks `.env.production` schema conformance.

### Running Validation
Execute the following non-destructive commands on the host:
```bash
# 1. Validate Docker Compose YAML syntax and variable interpolation
docker compose -f docker-compose.prod.yml --env-file .env.production config -q

# 2. Run SafeRepo pre-flight validation auditor
npx --prefix apps/web tsx scripts/validate-production.ts
```

**Expected Result:**
```text
SUMMARY: 49 PASSED  │  0 WARNINGS  │  0 FAILED
```
*Do not proceed with deployment if any check reports a failure.*

---

## 11. Ordered Production Deployment Procedure

Follow these steps in exact sequential order:

```text
Step 1: Host Readiness
   ↓
Step 2: Repository / Release Verification
   ↓
Step 3: Environment Configuration
   ↓
Step 4: Configuration Validation
   ↓
Step 5: Production Image Build
   ↓
Step 6: Scanner Image Preload
   ↓
Step 7: Production Stack Startup
   ↓
Step 8: Health Verification
   ↓
Step 9: HTTP Smoke Test
   ↓
Step 10: Operational Verification
```

### Step 1: Host Readiness
Confirm Ubuntu 24.04 LTS host is updated, UFW firewall is active (ports 22, 80, 443 only), and Docker Engine is running:
```bash
sudo ufw status verbose
sudo systemctl status docker --no-pager
```

### Step 2: Repository / Release Verification
Verify that the repository working tree is on the audited release baseline:
```bash
cd /opt/saferepo
git rev-parse HEAD
# Confirm matches: 9fb53b0e9f6f5dacfd86c98851157f7fe7e08c61
```

### Step 3: Environment Configuration
Ensure `/opt/saferepo/.env.production` exists with permissions `0600` and contains valid production values:
```bash
ls -la /opt/saferepo/.env.production
# Permissions must be: -rw------- (0600)
```

### Step 4: Configuration Validation
Execute Compose syntax validation and the pre-flight auditor:
```bash
docker compose -f docker-compose.prod.yml --env-file .env.production config -q
npx --prefix apps/web tsx scripts/validate-production.ts
```

### Step 5: Production Image Build
Build the production Next.js Web and Scan Worker container images locally:
```bash
docker compose -f docker-compose.prod.yml build
```
Verify non-root execution:
```bash
docker image inspect saferepo-web:0.9.0 --format '{{.Config.User}}'
# Must return: nextjs

docker image inspect saferepo-worker:0.9.0 --format '{{.Config.User}}'
# Must return: workeruser
```

### Step 6: Scanner Image Preload
Pre-cache the three pinned scanner images to the local Docker engine:
```bash
./scripts/preload-scanners.sh
```
*Confirm output reports: `SUMMARY: 3/3 PASSED | 0 FAILED`.*

### Step 7: Production Stack Startup
Start all Compose services in detached mode:
```bash
docker compose -f docker-compose.prod.yml --env-file .env.production up -d
```

### Step 8: Health Verification
Check that containers are healthy and verify the internal health endpoint:
```bash
docker compose -f docker-compose.prod.yml ps
curl -i http://localhost:3000/api/health
```

### Step 9: HTTP Smoke Test
Execute the automated smoke test suite to verify HTTP contracts, security headers, and network isolation:
```bash
SMOKE_BASE_URL="http://localhost:3000" npx --prefix apps/web tsx scripts/smoke-test.ts
```
*Confirm output reports: `SUMMARY: 23 PASSED | 0 WARNINGS | 0 FAILED`.*

### Step 10: Operational Verification
Verify from an external host that only ports 80 and 443 are reachable, and inspect initial application logs:
```bash
docker compose -f docker-compose.prod.yml logs --tail=50
```

---

## 12. Health & Smoke Testing

### 12.1 Health Check Endpoint (`/api/health`)
SafeRepo exposes a lightweight, unauthenticated health endpoint at `GET /api/health`.

**Verification Command:**
```bash
curl -i http://localhost:3000/api/health
```

**Expected JSON Response:**
```json
{
  "status": "ok",
  "db": "connected",
  "timestamp": "2026-09-16T12:00:00.000Z",
  "version": "0.1.0",
  "queue": {
    "pending": 0
  },
  "uptime": 42
}
```

**Response Field Explanations:**
- `status`: Service status indicator (`"ok"` when MongoDB is reachable, `"error"` if database connection fails). HTTP status code is `200` for `"ok"`, `503` for `"error"`.
- `db`: Database connectivity state (`"connected"` or `"disconnected"`).
- `timestamp`: ISO 8601 UTC timestamp of the health check evaluation.
- `version`: Application semantic version loaded from root `package.json` (`"0.1.0"`).
- `queue.pending`: Integer count of scans currently awaiting execution in the atomic queue with status `"queued"`.
- `uptime`: Node.js process runtime in integer seconds (`Math.floor(process.uptime())`).

### 12.2 Automated HTTP Smoke Test Suite (`scripts/smoke-test.ts`)
SafeRepo includes an automated HTTP smoke test suite that verifies live container contracts and infrastructure invariants.

**Execution Command:**
```bash
SMOKE_BASE_URL="http://localhost:3000" npx --prefix apps/web tsx scripts/smoke-test.ts
```

**Configurable Options:**
- `SMOKE_BASE_URL`: Base target URL to test (default: `http://localhost:3000`). For testing through Caddy ingress, set to `http://localhost` or `https://<YOUR_DOMAIN>`.
- `SMOKE_TIMEOUT_MS`: Request timeout in milliseconds (default: `8000` ms). Employs `AbortController` to guarantee tests fail fast rather than hanging indefinitely.
- `SMOKE_SKIP_INFRA`: Optional flag (`1` or `true`) to bypass local Compose manifest inspection when executing remotely.

**Automated Validations Performed:**
1. **Health Endpoint:** Validates 200 OK status, `application/json` content-type, full response schema conformance, and checks that zero database credentials or secrets leak in the payload.
2. **Security Headers:** Validates headers defined in `next.config.mjs`:
   - `X-Frame-Options: DENY` (anti-clickjacking)
   - `X-Content-Type-Options: nosniff` (MIME-type sniffing prevention)
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...`
   - `Strict-Transport-Security` (validated on HTTPS targets per RFC 6797)
   - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
   - `X-Powered-By` suppression (`poweredByHeader: false`)
3. **Request Tracing:** Verifies that incoming `x-request-id` headers are handled cleanly and that no authentication tokens, session secrets, or sensitive headers are reflected in responses.
4. **Error Response Sanitization:** Queries a non-existent route (`/api/__saferepo_smoke_test_nonexistent__`) and verifies:
   - Returns client error `404 Not Found`
   - Zero internal JavaScript runtime stack traces are exposed (`node_modules`, `webpack://`, etc.)
   - Zero database URIs (`mongodb://`) or secret tokens leak into error bodies
5. **Infrastructure Invariants:** Inspects `docker-compose.prod.yml` to confirm:
   - Only `caddy` publishes host ports (80 and 443)
   - `web` port 3000 is internal-only (no host port publication)
   - `mongo` port 27017 is internal-only (no host port publication)
   - `docker-proxy` port 2375 is internal-only (no host port publication)
   - `web` has zero Docker socket mounts
   - `worker` has zero direct Docker socket mounts
   - `docker-proxy` is the sole service mounting `/var/run/docker.sock` and is strictly `:ro`

---

## 13. Caddy & Domain TLS Configuration

Caddy serves as the public ingress gateway and automated TLS termination layer for SafeRepo.

### 13.1 Existing Caddy Configuration
In the provided `docker-compose.prod.yml`, Caddy publishes host ports 80 and 443:
```yaml
ports:
  - "80:80"
  - "443:443"
command: ["caddy", "reverse-proxy", "--from", ":80", "--to", "web:3000"]
```
By default, `--from :80` operates over plain HTTP on port 80. This configuration is suitable for local testing, staging, or environments behind an upstream cloud load balancer.

### 13.2 Configuring Production Domain TLS
To enable automatic HTTPS on a public production host with a custom domain:
1. Ensure your public DNS provider has an **A record** (and optional **AAAA record**) pointing `<YOUR_DOMAIN>` to the host VPS static public IP.
2. In `docker-compose.prod.yml`, update the `caddy` command:
   ```yaml
   command: ["caddy", "reverse-proxy", "--from", "<YOUR_DOMAIN>", "--to", "web:3000"]
   ```
3. Restart Caddy to obtain certificates and initiate TLS termination:
   ```bash
   docker compose -f docker-compose.prod.yml restart caddy
   ```

### 13.3 TLS Behavior & Certificate Management
- **Automatic Certificate Provisioning:** Caddy automatically negotiates and issues certificates via Let's Encrypt or ZeroSSL using ACME HTTP-01 and TLS-ALPN-01 challenges.
- **Automatic HTTP-to-HTTPS Redirection:** When configured with a domain name, Caddy listens on port 443 for HTTPS and automatically redirects incoming port 80 HTTP traffic to HTTPS.
- **Certificate Storage:** Certificates and ACME account keys are persisted across container restarts in the named Docker volume `caddy_data:/data`.
- **Zero Maintenance:** Caddy monitors certificate validity and automatically renews certificates approximately 30 days prior to expiration.

---

## 14. Firewall & Network Security

### Expected Exposure Topology

| Service | Protocol / Port | Network Exposure | Access Rule |
|---|---|---|---|
| **Caddy (HTTP)** | TCP 80 | **PUBLIC** | Open to internet (redirects to HTTPS) |
| **Caddy (HTTPS)** | TCP 443 | **PUBLIC** | Open to internet (TLS 1.3 termination) |
| **SSH** | TCP 22 | **RESTRICTED** | Open to administrator IPs only |
| **Next.js Web** | TCP 3000 | **PRIVATE** | Internal to `web-net` and `backend-net` only |
| **MongoDB** | TCP 27017 | **PRIVATE** | Internal to `backend-net` only |
| **Docker Socket Proxy** | TCP 2375 | **PRIVATE** | Internal to `worker-proxy-net` only |

### External Port Verification
Verify from an external machine that private service ports are inaccessible:
```bash
nmap -p 80,443,3000,2375,27017 <SERVER_IP>
```
**Expected Scan Results:**
- Port 80: **OPEN** (Caddy)
- Port 443: **OPEN** (Caddy)
- Port 3000: **FILTERED / CLOSED** (Web unexposed)
- Port 2375: **FILTERED / CLOSED** (Proxy unexposed)
- Port 27017: **FILTERED / CLOSED** (Mongo unexposed)

> [!CAUTION]
> The Docker socket proxy (port 2375) must NEVER be published to the host or external internet. Exposing port 2375 allows arbitrary container operations on the host.

---

## 15. Logging & Observability

SafeRepo uses Pino structured JSON logging with built-in PII and credential redaction.

### Viewing Container Logs
```bash
# Tail all container logs
docker compose -f docker-compose.prod.yml logs -f --tail=100

# View Web application and API access logs
docker compose -f docker-compose.prod.yml logs -f web

# View Scan Worker queue and execution logs
docker compose -f docker-compose.prod.yml logs -f worker

# View Caddy ingress access and TLS logs
docker compose -f docker-compose.prod.yml logs -f caddy
```

### Request Tracing with `X-Request-Id`
Every API request processed by SafeRepo is assigned a unique `X-Request-Id` (UUID v4) via middleware.
- The request ID is attached to the response headers.
- The request ID is included in structured log output.
- To correlate a user report with internal server logs:
  ```bash
  docker compose -f docker-compose.prod.yml logs web | grep '<REQUEST_ID>'
  ```

### Observability Scope
SafeRepo does not require an external centralized logging platform for the beta. All diagnostics are accessible via Docker logging drivers and `docker compose logs`. If an external log aggregator (e.g. Datadog, Grafana Loki) is introduced in GA, configure it at the Docker daemon level without altering application code.

---

## 16. Backup & Disaster Recovery

### Definitions
- **Backup:** Creating a point-in-time snapshot or compressed archive of persistent application data (MongoDB).
- **Restore:** Reconstructing database records and indexes from an archive into a running database.
- **Rollback:** Reverting application code and container images to a previously verified stable checkpoint.

### 16.1 Automated MongoDB Backup Script
For self-hosted MongoDB deployments, create `/opt/saferepo/scripts/backup.sh` (owned by `saferepo`, permissions `chmod 700`):

```bash
#!/usr/bin/env bash
# SafeRepo Automated Database Backup
set -euo pipefail

BACKUP_DIR="/opt/saferepo/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "${BACKUP_DIR}"

# Execute mongodump from internal container
docker compose -f /opt/saferepo/docker-compose.prod.yml exec -T mongo \
  mongodump --archive --gzip > "${BACKUP_DIR}/saferepo_${TIMESTAMP}.archive.gz"

# Retain 14 days of backups; prune older archives
find "${BACKUP_DIR}" -type f -name "saferepo_*.archive.gz" -mtime +14 -delete
```

Configure a daily cron job (`crontab -e` under the `saferepo` user):
```text
0 2 * * * /opt/saferepo/scripts/backup.sh > /dev/null 2>&1
```

### 16.2 Restore Testing Procedure
Regularly verify that backups can be restored on a staging or test host:
```bash
cat saferepo_<TIMESTAMP>.archive.gz | docker compose -f docker-compose.prod.yml exec -T mongo \
  mongorestore --archive --gzip --drop
```

### 16.3 Configuration & Image Recovery
- **Environment Recovery:** Store an encrypted, offline backup of `/opt/saferepo/.env.production` in an organizational password manager or secrets vault.
- **Image Recovery:** Docker images are tagged deterministically (`saferepo-web:0.9.0`, `saferepo-worker:0.9.0`) and can be re-built directly from the repository baseline.

---

## 17. Deployment Verification Checklist

Before accepting user traffic on the beta host, complete this checklist:

- [ ] **Host Secure:** Ubuntu 24.04 LTS updated, unattended security upgrades active.
- [ ] **Firewall Configured:** UFW active; default deny incoming; only ports 22, 80, and 443 permitted.
- [ ] **Docker Installed:** Official Docker Engine and Compose plugin installed and enabled.
- [ ] **Environment Configured:** `/opt/saferepo/.env.production` present with permissions `0600`.
- [ ] **Secrets Protected:** Zero real credentials committed to Git or embedded into Docker images.
- [ ] **Compose Config Valid:** `docker compose config -q` passes without error or warnings.
- [ ] **Pre-Flight Validation Passes:** `validate-production.ts` returns 49/49 PASSED.
- [ ] **Scanner Images Preloaded:** Semgrep, Trivy, and Gitleaks pre-cached via script.
- [ ] **Application Images Built:** `saferepo-web:0.9.0` and `saferepo-worker:0.9.0` built cleanly.
- [ ] **Containers Healthy:** `docker compose ps` shows all 5 services healthy and running.
- [ ] **Health Endpoint Passes:** `GET /api/health` returns `200 OK` with `"status": "ok"` and `"db": "connected"`.
- [ ] **Smoke Test Suite Passes:** `smoke-test.ts` returns 23/23 PASSED.
- [ ] **Ports Verified:** Ports 3000, 2375, and 27017 verified unexposed to external traffic via port scan.
- [ ] **Docker Socket Isolation Verified:** Web has 0 socket mounts; proxy is sole `:ro` socket mount.
- [ ] **Logs Reviewed:** `docker compose logs` shows clean startup with zero error loops.
- [ ] **Rollback Information Available:** Previous stable commit hash and backup archive verified.

---

## 18. Rollback Procedure

If a new deployment introduces unexpected regressions or operational failures, a human operator should execute this safe rollback procedure:

1. **Stop Current Stack:**
   ```bash
   cd /opt/saferepo
   docker compose -f docker-compose.prod.yml down
   ```
2. **Revert Working Tree to Previous Approved Commit / Tag:**
   ```bash
   git checkout <PREVIOUS_STABLE_COMMIT_HASH>
   ```
3. **Rebuild Application Images from Stable Baseline:**
   ```bash
   docker compose -f docker-compose.prod.yml build
   ```
4. **Relaunch Production Stack:**
   ```bash
   docker compose -f docker-compose.prod.yml --env-file .env.production up -d
   ```
5. **Verify Operational Health:**
   ```bash
   docker compose -f docker-compose.prod.yml ps
   curl -i http://localhost:3000/api/health
   SMOKE_BASE_URL="http://localhost:3000" npx --prefix apps/web tsx scripts/smoke-test.ts
   ```

---

## 19. Incident Response Basics

| Symptom | Probable Cause | Diagnostic Command | Immediate Remedy |
|---|---|---|---|
| **Web 503 / "db disconnected"** | MongoDB unreachable, crashed, or Atlas IP allowlist blocked | `docker compose -f docker-compose.prod.yml logs web` | Check `mongo` container status or verify host VPS public IP in Atlas Network Access allowlist. |
| **Scans stuck in "queued"** | Worker crashed, stopped, or atomic queue lock held | `docker compose -f docker-compose.prod.yml logs worker` | Restart worker (`docker compose restart worker`); verify worker can reach MongoDB. |
| **Worker Docker connection error** | Docker proxy down or socket permission denied | `docker compose -f docker-compose.prod.yml logs docker-proxy` | Verify host `/var/run/docker.sock` exists and is accessible; restart `docker-proxy`. |
| **TLS Certificate Error** | Caddy DNS misconfiguration or Let's Encrypt rate limit | `docker compose -f docker-compose.prod.yml logs caddy` | Verify public DNS A record matches server public IP; ensure ports 80/443 are open in UFW. |
| **High Host Disk Usage** | Ephemeral workspaces not pruned | `du -sh /tmp/saferepo-workspaces` | Run manual prune of workspaces older than 24 hours; check worker workspace cleanup logs. |
| **Suspected Secret Exposure** | Credential committed or leaked in logs | Inspect git history and container logs | Immediately revoke credential at provider (GitHub, Atlas); generate new secret and update `.env.production`. |

---

## 20. Non-Negotiable Production Security Rules

1. **Never commit secrets to Git** or include credentials in Dockerfile `ENV`/`ARG` build instructions.
2. **Never expose MongoDB (port 27017) or Docker Socket Proxy (port 2375) to the public internet.**
3. **Never mount `/var/run/docker.sock` into the Web container** or any container processing public HTTP requests.
4. **Never give the Web container Docker CLI or daemon access.**
5. **Never run production application containers as root** (`UID 1001` enforced for both `nextjs` and `workeruser`).
6. **Never place real production secrets into image layers.**
7. **Never run production security scans from arbitrary, unpinned, or untrusted container images.**
8. **Always review and validate changes locally** using pre-flight tools before applying them to the production server.

---

## 21. Beta vs. GA Security Posture Boundary

| Dimension | Phase 09 Beta Architecture (Single-Host) | Phase 10+ GA Production Architecture (Multi-Host) |
|---|---|---|
| **Host Topology** | Single Ubuntu 24.04 VPS hosting all 5 Compose services | Decoupled: Managed Web Host + Dedicated Scan Worker Host |
| **Docker Socket Isolation** | Mediated via `tecnativa/docker-socket-proxy` | Dedicated Worker VM with native, isolated Docker daemon |
| **Security Boundary** | Defense-in-depth (URL/method filtering only) | Physical/Hypervisor VM isolation boundary |
| **Blast Radius** | Host-level defense-in-depth | Contained entirely within ephemeral Worker VM |
| **Database** | Mongo 7 Container or Atlas M0/M10 | MongoDB Atlas Dedicated Cluster (M10+) with VPC Peering |
| **Scalability** | Vertical host scaling | Horizontal scaling of worker VMs based on queue depth |

> [!IMPORTANT]
> The single-host Docker socket proxy architecture is approved strictly as a defense-in-depth mechanism for controlled beta testing. It does not provide hypervisor-level isolation. GA production requires migration to the Dedicated Isolated Worker VM model.
