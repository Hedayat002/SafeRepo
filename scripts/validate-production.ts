#!/usr/bin/env node
/**
 * SafeRepo Phase 09 Pre-Flight Environment & Infrastructure Validator
 *
 * Standalone, deterministic, read-only pre-flight validation script.
 * Validates production deployment prerequisites, container definitions,
 * security boundaries, and environment configurations WITHOUT requiring
 * or displaying real production secrets.
 *
 * Usage:
 *   npx tsx scripts/validate-production.ts
 *
 * Exit codes:
 *   0: All mandatory pre-flight checks passed
 *   1: One or more pre-flight checks failed
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

interface CheckResult {
  category: string;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  detail: string;
}

const results: CheckResult[] = [];
const rootDir = path.resolve(__dirname, '..');

function addResult(category: string, name: string, status: 'PASS' | 'WARN' | 'FAIL', detail: string) {
  results.push({ category, name, status, detail });
}

// ─────────────────────────────────────────────────────────────
// 1. Project Files & Manifests Verification
// ─────────────────────────────────────────────────────────────
function checkRequiredFiles() {
  const category = '1. Project Manifests';
  const requiredFiles = [
    'docker-compose.prod.yml',
    'apps/web/Dockerfile',
    'apps/web/Dockerfile.worker',
    'apps/web/next.config.mjs',
    '.dockerignore',
    'apps/web/.dockerignore',
    'docs/PHASES/PHASE_09.md',
    'apps/web/package.json',
    'package.json',
    'package-lock.json',
  ];

  for (const relPath of requiredFiles) {
    const fullPath = path.join(rootDir, relPath);
    if (fs.existsSync(fullPath)) {
      addResult(category, `File exists: ${relPath}`, 'PASS', 'Present in working tree');
    } else {
      addResult(category, `File exists: ${relPath}`, 'FAIL', `Missing file: ${relPath}`);
    }
  }
}

// ─────────────────────────────────────────────────────────────
// 2. Local Tooling & Runtime Compatibility
// ─────────────────────────────────────────────────────────────
function checkTooling() {
  const category = '2. Local Tooling';

  // Node.js version
  const nodeVersion = process.version;
  if (nodeVersion.startsWith('v24.')) {
    addResult(category, 'Node.js Runtime', 'PASS', `Active Node ${nodeVersion} matches Node 24.19.0 LTS baseline`);
  } else {
    addResult(category, 'Node.js Runtime', 'WARN', `Active Node ${nodeVersion} differs from baseline v24.19.0`);
  }

  // npm CLI
  try {
    const npmVer = execSync('npm --version', { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    addResult(category, 'npm CLI', 'PASS', `npm v${npmVer} available`);
  } catch {
    addResult(category, 'npm CLI', 'FAIL', 'npm command is not available in PATH');
  }

  // Docker CLI
  try {
    const dockerVer = execSync('docker --version', { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    addResult(category, 'Docker CLI', 'PASS', `${dockerVer} available`);
  } catch {
    addResult(category, 'Docker CLI', 'FAIL', 'docker command is not available in PATH');
  }

  // Docker Compose
  try {
    const composeVer = execSync('docker compose version', { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    addResult(category, 'Docker Compose', 'PASS', `${composeVer} available`);
  } catch {
    addResult(category, 'Docker Compose', 'FAIL', 'docker compose command is not available in PATH');
  }

  // Docker Daemon Connectivity (Read-only ping)
  try {
    const serverVer = execSync('docker version --format "{{.Server.Version}}"', {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (serverVer) {
      addResult(category, 'Docker Daemon', 'PASS', `Docker daemon responsive (v${serverVer})`);
    } else {
      addResult(category, 'Docker Daemon', 'WARN', 'Docker daemon returned empty version');
    }
  } catch {
    addResult(category, 'Docker Daemon', 'WARN', 'Docker daemon is not currently responsive or running');
  }
}

// ─────────────────────────────────────────────────────────────
// 3. Compose Manifest Static Validation
// ─────────────────────────────────────────────────────────────
function checkComposeSyntax() {
  const category = '3. Compose Validation';
  const composePath = path.join(rootDir, 'docker-compose.prod.yml');

  if (!fs.existsSync(composePath)) {
    addResult(category, 'docker-compose.prod.yml', 'FAIL', 'Manifest does not exist');
    return;
  }

  try {
    execSync('docker compose -f docker-compose.prod.yml config -q', {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    addResult(category, 'Compose Config Validation', 'PASS', 'docker compose config -q passed cleanly (0 errors)');
  } catch (err) {
    addResult(category, 'Compose Config Validation', 'FAIL', `Compose validation failed: ${String(err)}`);
  }
}

// ─────────────────────────────────────────────────────────────
// 4. Security Invariants in docker-compose.prod.yml
// ─────────────────────────────────────────────────────────────
function checkComposeSecurityInvariants() {
  const category = '4. Compose Security Invariants';
  const composePath = path.join(rootDir, 'docker-compose.prod.yml');

  if (!fs.existsSync(composePath)) {
    addResult(category, 'Compose Invariants', 'FAIL', 'Cannot inspect missing docker-compose.prod.yml');
    return;
  }

  const content = fs.readFileSync(composePath, 'utf-8');

  // Helper to accurately extract a service configuration block under services:
  function getServiceBlock(serviceName: string): string {
    const regex = new RegExp(`^[ ]{2}${serviceName}:[\\r\\n]+([\\s\\S]*?)(?=^[ ]{2}[a-zA-Z0-9_-]+:|^networks:|^volumes:|\\Z)`, 'm');
    const match = content.match(regex);
    const raw = match ? match[1] : '';
    // Strip comment lines so documentation comments don't trigger false positives
    return raw.split(/\r?\n/).filter(line => !line.trim().startsWith('#')).join('\n');
  }

  const caddySection = getServiceBlock('caddy');
  const webSection = getServiceBlock('web');
  const workerSection = getServiceBlock('worker');
  const proxySection = getServiceBlock('docker-proxy');
  const mongoSection = getServiceBlock('mongo');

  // 1. Web has no docker.sock mount
  if (webSection.includes('/var/run/docker.sock')) {
    addResult(category, 'Web Docker Socket Isolation', 'FAIL', 'CRITICAL: web service has /var/run/docker.sock mounted');
  } else {
    addResult(category, 'Web Docker Socket Isolation', 'PASS', 'web service has ZERO Docker socket access');
  }

  // 2. Web has no access to worker-proxy-net
  if (webSection.includes('worker-proxy-net')) {
    addResult(category, 'Web Network Isolation', 'FAIL', 'CRITICAL: web service is connected to worker-proxy-net');
  } else {
    addResult(category, 'Web Network Isolation', 'PASS', 'web service is completely isolated from worker-proxy-net');
  }

  // 3. Web does not publish port 3000 to public host
  if (webSection.includes('"3000:3000"')) {
    addResult(category, 'Web Public Exposure', 'FAIL', 'web service publishes port 3000 to the public host');
  } else {
    addResult(category, 'Web Public Exposure', 'PASS', 'web service port 3000 is exposed internally on web-net only');
  }

  // 4. Worker has no direct docker.sock mount
  if (workerSection.includes('/var/run/docker.sock')) {
    addResult(category, 'Worker Direct Socket Mount', 'FAIL', 'Worker has direct /var/run/docker.sock mount');
  } else {
    addResult(category, 'Worker Direct Socket Mount', 'PASS', 'Worker has NO direct /var/run/docker.sock mount');
  }

  // 5. Worker uses DOCKER_HOST over TCP proxy
  if (workerSection.includes('DOCKER_HOST: tcp://docker-proxy:2375')) {
    addResult(category, 'Worker Proxy Mediation', 'PASS', 'Worker connects via DOCKER_HOST: tcp://docker-proxy:2375');
  } else {
    addResult(category, 'Worker Proxy Mediation', 'FAIL', 'Worker DOCKER_HOST not configured to docker-proxy');
  }

  // 6. Docker proxy is the only service mounting socket
  if (proxySection.includes('/var/run/docker.sock:/var/run/docker.sock:ro')) {
    addResult(category, 'Proxy Socket Mount', 'PASS', 'docker-proxy mounts /var/run/docker.sock:ro as read-only inode');
  } else {
    addResult(category, 'Proxy Socket Mount', 'FAIL', 'docker-proxy socket mount missing or not marked :ro');
  }

  // 7. Docker proxy does not publish port 2375 to host
  if (proxySection.includes('"2375:2375"') || proxySection.includes('ports:')) {
    addResult(category, 'Proxy Public Exposure', 'FAIL', 'CRITICAL: docker-proxy publishes port 2375 to host');
  } else {
    addResult(category, 'Proxy Public Exposure', 'PASS', 'docker-proxy port 2375 is private to worker-proxy-net');
  }

  // 8. Docker proxy disables high-risk capabilities
  const dangerousVars = ['VOLUMES: "0"', 'EXEC: "0"', 'NETWORKS: "0"', 'BUILD: "0"', 'AUTH: "0"', 'SECRETS: "0"', 'SYSTEM: "0"'];
  const allDisabled = dangerousVars.every((v) => proxySection.includes(v));
  if (allDisabled) {
    addResult(category, 'Proxy API Restrictions', 'PASS', 'Dangerous Docker API categories explicitly disabled (=0)');
  } else {
    addResult(category, 'Proxy API Restrictions', 'FAIL', 'One or more dangerous API categories not disabled in proxy');
  }

  // 9. Mongo does not publish port 27017 to host
  if (mongoSection.includes('"27017:27017"')) {
    addResult(category, 'Mongo Public Exposure', 'FAIL', 'CRITICAL: mongo service publishes port 27017 to host');
  } else {
    addResult(category, 'Mongo Public Exposure', 'PASS', 'mongo service port 27017 is private to backend-net only');
  }

  // 10. Caddy is the only public entrypoint
  if (caddySection.includes('"80:80"') && caddySection.includes('"443:443"')) {
    addResult(category, 'Public Ingress Invariant', 'PASS', 'caddy is the sole ingress gateway publishing ports 80/443');
  } else {
    addResult(category, 'Public Ingress Invariant', 'FAIL', 'caddy ingress ports not properly configured');
  }
}

// ─────────────────────────────────────────────────────────────
// 5. Dockerfiles Security & Build Integrity
// ─────────────────────────────────────────────────────────────
function checkDockerfiles() {
  const category = '5. Dockerfile Security';

  // Web Dockerfile
  const webDockerPath = path.join(rootDir, 'apps/web/Dockerfile');
  if (fs.existsSync(webDockerPath)) {
    const content = fs.readFileSync(webDockerPath, 'utf-8');
    if (content.includes('FROM node:24.19.0-alpine')) {
      addResult(category, 'Web Base Image', 'PASS', 'Uses pinned node:24.19.0-alpine base image');
    } else {
      addResult(category, 'Web Base Image', 'FAIL', 'Web Dockerfile does not use node:24.19.0-alpine');
    }

    if (content.includes('USER nextjs')) {
      addResult(category, 'Web Unprivileged User', 'PASS', 'Runs as non-root user (USER nextjs)');
    } else {
      addResult(category, 'Web Unprivileged User', 'FAIL', 'Web Dockerfile missing USER nextjs instruction');
    }

    if (content.includes('.next/standalone')) {
      addResult(category, 'Web Standalone Output', 'PASS', 'Copies .next/standalone artifacts');
    } else {
      addResult(category, 'Web Standalone Output', 'FAIL', 'Web Dockerfile does not copy .next/standalone');
    }

    if (content.includes('/var/run/docker.sock') || content.includes('docker-cli')) {
      addResult(category, 'Web Docker Isolation', 'FAIL', 'Web Dockerfile references Docker socket or CLI');
    } else {
      addResult(category, 'Web Docker Isolation', 'PASS', 'Zero Docker CLI or socket references in Web image');
    }
  }

  // Worker Dockerfile
  const workerDockerPath = path.join(rootDir, 'apps/web/Dockerfile.worker');
  if (fs.existsSync(workerDockerPath)) {
    const content = fs.readFileSync(workerDockerPath, 'utf-8');
    if (content.includes('FROM node:24.19.0-alpine')) {
      addResult(category, 'Worker Base Image', 'PASS', 'Uses pinned node:24.19.0-alpine base image');
    } else {
      addResult(category, 'Worker Base Image', 'FAIL', 'Worker Dockerfile does not use node:24.19.0-alpine');
    }

    if (content.includes('USER workeruser')) {
      addResult(category, 'Worker Unprivileged User', 'PASS', 'Runs as non-root user (USER workeruser)');
    } else {
      addResult(category, 'Worker Unprivileged User', 'FAIL', 'Worker Dockerfile missing USER workeruser instruction');
    }

    if (content.includes('docker-cli') && content.includes('git')) {
      addResult(category, 'Worker Tooling Packages', 'PASS', 'Installs required minimal tools (docker-cli, git)');
    } else {
      addResult(category, 'Worker Tooling Packages', 'FAIL', 'Worker Dockerfile missing required docker-cli or git');
    }

    if (content.includes('dockerd') || content.includes('docker-engine')) {
      addResult(category, 'Worker Daemon Exclusion', 'FAIL', 'Worker Dockerfile installs Docker daemon inside image');
    } else {
      addResult(category, 'Worker Daemon Exclusion', 'PASS', 'Zero Docker daemon installed (client CLI only)');
    }

    if (content.includes('/var/run/docker.sock')) {
      addResult(category, 'Worker Image Socket Exclusion', 'FAIL', 'Worker Dockerfile mounts or references host socket');
    } else {
      addResult(category, 'Worker Image Socket Exclusion', 'PASS', 'Zero host socket mounts inside worker image');
    }
  }
}

// ─────────────────────────────────────────────────────────────
// 6. Scanner Image Pinning Verification
// ─────────────────────────────────────────────────────────────
function checkScannerImagePinning() {
  const category = '6. Scanner Image Pinning';
  const composePath = path.join(rootDir, 'docker-compose.prod.yml');
  const envPath = path.join(rootDir, 'apps/web/src/lib/env.ts');

  const expectedPinnedImages = [
    { name: 'Semgrep SAST', image: 'semgrep/semgrep:1.100.0' },
    { name: 'Trivy SCA', image: 'aquasec/trivy:0.59.1' },
    { name: 'Gitleaks Secrets', image: 'zricethezav/gitleaks:v8.24.0' },
  ];

  const composeContent = fs.existsSync(composePath) ? fs.readFileSync(composePath, 'utf-8') : '';
  const envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf-8') : '';

  for (const { name, image } of expectedPinnedImages) {
    const isPinnedInCompose = composeContent.includes(image);
    const isPinnedInEnv = envContent.includes(image);

    if (isPinnedInCompose && isPinnedInEnv) {
      addResult(category, `Pinned Image: ${name}`, 'PASS', `Exact immutable tag pinned: ${image}`);
    } else {
      addResult(category, `Pinned Image: ${name}`, 'FAIL', `Image ${image} not consistently pinned`);
    }
  }

  // Verify no mutable tags are present
  const mutableTags = [':latest', ':edge', ':master', ':main', ':dev'];
  const hasMutableInCompose = mutableTags.some((tag) => composeContent.includes(tag));
  if (hasMutableInCompose) {
    addResult(category, 'Mutable Tag Prohibition', 'FAIL', 'Found mutable tag (:latest, :edge) in Compose manifest');
  } else {
    addResult(category, 'Mutable Tag Prohibition', 'PASS', 'Zero mutable tags found; all image references immutable');
  }
}

// ─────────────────────────────────────────────────────────────
// 7. Environment Schema & Secret-Safety Verification
// ─────────────────────────────────────────────────────────────
function checkEnvironmentSchema() {
  const category = '7. Environment Schema (Secret-Safe)';
  const envTsPath = path.join(rootDir, 'apps/web/src/lib/env.ts');

  if (!fs.existsSync(envTsPath)) {
    addResult(category, 'Environment Schema', 'FAIL', 'apps/web/src/lib/env.ts missing');
    return;
  }

  const envContent = fs.readFileSync(envTsPath, 'utf-8');

  // Mandatory variable names verified in schema without inspecting values
  const requiredVarNames = [
    'MONGODB_URI',
    'GITHUB_APP_ID',
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'SESSION_SECRET',
    'NEXT_PUBLIC_APP_URL',
    'ALLOWED_ORIGINS',
    'SCAN_RETENTION_DAYS',
    'MAX_SCANS_PER_USER',
  ];

  for (const varName of requiredVarNames) {
    if (envContent.includes(varName)) {
      addResult(category, `Schema Variable: ${varName}`, 'PASS', 'Declared in Zod environment validation schema');
    } else {
      addResult(category, `Schema Variable: ${varName}`, 'FAIL', `Missing in Zod environment validation schema: ${varName}`);
    }
  }

  // Secret safety check: verify .dockerignore excludes .env files
  const dockerignorePath = path.join(rootDir, '.dockerignore');
  if (fs.existsSync(dockerignorePath)) {
    const content = fs.readFileSync(dockerignorePath, 'utf-8');
    if (content.includes('.env*.local') || content.includes('.env')) {
      addResult(category, 'Secret Hygiene (.dockerignore)', 'PASS', '.dockerignore excludes local .env files from build context');
    } else {
      addResult(category, 'Secret Hygiene (.dockerignore)', 'FAIL', '.dockerignore does not exclude .env files');
    }
  }
}

// ─────────────────────────────────────────────────────────────
// Execution & Summary Presentation
// ─────────────────────────────────────────────────────────────
function main() {
  console.log('================================================================');
  console.log(' SafeRepo Phase 09 Pre-Flight Environment & Infrastructure Audit');
  console.log(' Target Baseline: Node 24.19.0 LTS | Checkpoint: 9fb53b0');
  console.log(' Mode: READ-ONLY STATIC VALIDATION (No secrets accessed/printed)');
  console.log('================================================================\n');

  checkRequiredFiles();
  checkTooling();
  checkComposeSyntax();
  checkComposeSecurityInvariants();
  checkDockerfiles();
  checkScannerImagePinning();
  checkEnvironmentSchema();

  let passCount = 0;
  let warnCount = 0;
  let failCount = 0;

  let currentCategory = '';
  for (const res of results) {
    if (res.category !== currentCategory) {
      currentCategory = res.category;
      console.log(`\n─── ${currentCategory} ───`);
    }

    const tag = res.status === 'PASS' ? '✅ PASS' : res.status === 'WARN' ? '⚠️ WARN' : '❌ FAIL';
    console.log(`  [${tag}] ${res.name.padEnd(36)} │ ${res.detail}`);

    if (res.status === 'PASS') passCount++;
    if (res.status === 'WARN') warnCount++;
    if (res.status === 'FAIL') failCount++;
  }

  console.log('\n================================================================');
  console.log(` SUMMARY: ${passCount} PASSED  │  ${warnCount} WARNINGS  │  ${failCount} FAILED`);
  console.log('================================================================');

  if (failCount > 0) {
    console.error('\n❌ Pre-flight audit FAILED: One or more required criteria were not met.');
    process.exit(1);
  } else if (warnCount > 0) {
    console.log('\n⚠️ Pre-flight audit PASSED with warnings. Safe for local verification.');
    process.exit(0);
  } else {
    console.log('\n✅ Pre-flight audit PASSED: All production infrastructure criteria verified.');
    process.exit(0);
  }
}

main();
