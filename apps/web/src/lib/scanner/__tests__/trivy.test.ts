import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import {
  executeTrivyScan,
  validateTrivyDb,
  mapTrivySeverity,
  resolveCanonicalVulnerabilityId,
  normalizeTrivyTargetPath,
  validateAndNormalizeTrivyTargetPath,
  parseTrivyJsonOutput,
} from '../trivy';
import * as runnerModule from '../runner';
import { buildStage1DockerArgs, ScannerTimeoutError, OutputSizeExceededError } from '../runner';

describe('Trivy Stage 1 Scanner Integration', () => {
  let tempDbDir: string;

  beforeEach(async () => {
    vi.restoreAllMocks();
    tempDbDir = await fs.mkdtemp(path.join(os.tmpdir(), 'saferepo-trivy-db-'));
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDbDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  /**
   * Helper to populate a fully valid Trivy offline database (both trivy.db and metadata.json).
   */
  async function createValidTrivyDb(dir: string): Promise<void> {
    await fs.writeFile(path.join(dir, 'trivy.db'), 'binary bbolt database content');
    await fs.writeFile(
      path.join(dir, 'metadata.json'),
      JSON.stringify({ Version: 2, NextUpdate: '2026-10-01T00:00:00Z', DownloadedAt: '2026-09-01T00:00:00Z' })
    );
  }

  describe('Database State Machine (validateTrivyDb)', () => {
    it('returns valid: false when dbPath is undefined or empty', async () => {
      const result1 = await validateTrivyDb(undefined);
      expect(result1.valid).toBe(false);
      expect(result1.reason).toContain('Trivy offline vulnerability database not found at TRIVY_DB_PATH');

      const result2 = await validateTrivyDb('   ');
      expect(result2.valid).toBe(false);
      expect(result2.reason).toContain('Trivy offline vulnerability database not found at TRIVY_DB_PATH');
    });

    it('returns valid: false when dbPath directory does not exist', async () => {
      const nonExistent = path.join(tempDbDir, 'does-not-exist');
      const result = await validateTrivyDb(nonExistent);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Trivy offline vulnerability database not found at TRIVY_DB_PATH');
    });

    it('returns valid: false when dbPath is a file rather than a directory', async () => {
      const filePath = path.join(tempDbDir, 'some-file.txt');
      await fs.writeFile(filePath, 'not a dir');
      const result = await validateTrivyDb(filePath);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Trivy offline vulnerability database not found at TRIVY_DB_PATH');
    });

    it('returns valid: false when directory exists but contains no database files', async () => {
      // Empty directory
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('trivy.db');
    });

    it('returns valid: false when directory contains only trivy.db but is missing metadata.json', async () => {
      await fs.writeFile(path.join(tempDbDir, 'trivy.db'), 'fake db binary');
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('metadata.json');
    });

    it('returns valid: false when directory contains only metadata.json but is missing trivy.db', async () => {
      await fs.writeFile(path.join(tempDbDir, 'metadata.json'), JSON.stringify({ Version: 2 }));
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('trivy.db');
    });

    it('returns valid: false when trivy.db is an empty 0-byte file', async () => {
      await fs.writeFile(path.join(tempDbDir, 'trivy.db'), '');
      await fs.writeFile(path.join(tempDbDir, 'metadata.json'), JSON.stringify({ Version: 2 }));
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('trivy.db');
    });

    it('returns valid: false when metadata.json contains invalid JSON', async () => {
      await fs.writeFile(path.join(tempDbDir, 'trivy.db'), 'fake db binary');
      await fs.writeFile(path.join(tempDbDir, 'metadata.json'), 'not valid json');
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('metadata.json');
    });

    it('returns valid: false when metadata.json has non-positive Version', async () => {
      await fs.writeFile(path.join(tempDbDir, 'trivy.db'), 'fake db binary');
      await fs.writeFile(path.join(tempDbDir, 'metadata.json'), JSON.stringify({ Version: 0 }));
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('metadata.json');
    });

    it('returns valid: true when directory contains both valid trivy.db and valid metadata.json', async () => {
      await createValidTrivyDb(tempDbDir);
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('returns valid: false when directory is unreadable', async () => {
      vi.spyOn(fs, 'access').mockRejectedValueOnce(new Error('EACCES: permission denied'));
      await createValidTrivyDb(tempDbDir);
      const result = await validateTrivyDb(tempDbDir);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Trivy offline vulnerability database not found at TRIVY_DB_PATH');
    });
  });

  describe('Stage 1 Hardened Docker CLI Construction for Trivy', () => {
    it('constructs hardened Docker CLI arguments matching all security invariants', () => {
      const workspacePath = path.resolve('/tmp/workspace');
      const dbPath = path.resolve('/tmp/trivy-db');

      const args = buildStage1DockerArgs({
        containerName: 'saferepo-scan-123-trivy',
        workspacePath,
        image: 'aquasec/trivy:0.59.1',
        memoryLimit: '512m',
        commandArgs: [
          'fs',
          '--format', 'json',
          '--offline-scan',
          '--skip-db-update',
          '--cache-dir', '/home/scanner/.cache/trivy',
          '--scanners', 'vuln',
          '/src',
        ],
        homeTmpfs: '/home/scanner:rw,noexec,nosuid,size=128m,uid=1000,gid=1000',
        extraEnv: {
          HOME: '/home/scanner',
          TRIVY_CACHE_DIR: '/home/scanner/.cache/trivy',
        },
        extraMounts: [
          {
            source: dbPath,
            target: '/home/scanner/.cache/trivy/db',
            readonly: true,
          },
        ],
      });

      // Ephemeral & name
      expect(args).toContain('run');
      expect(args).toContain('--rm');
      expect(args).toContain('--name');
      expect(args).toContain('saferepo-scan-123-trivy');

      // Network & filesystem
      expect(args).toContain('--network=none');
      expect(args).toContain('--read-only');

      // Non-root tmpfs & cache
      expect(args).toContain('--tmpfs');
      expect(args).toContain('/tmp:rw,noexec,nosuid,size=64m');
      expect(args).toContain('/home/scanner:rw,noexec,nosuid,size=128m,uid=1000,gid=1000');

      // Security flags
      expect(args).toContain('--security-opt=no-new-privileges');
      expect(args).toContain('--cap-drop=ALL');
      expect(args).toContain('--user');
      expect(args).toContain('1000:1000');

      // Resource limits
      expect(args).toContain('--cpus=1');
      expect(args).toContain('--memory');
      expect(args).toContain('512m');
      expect(args).toContain('--pids-limit=256');

      // Environment variables
      expect(args).toContain('-e');
      expect(args).toContain('HOME=/home/scanner');
      expect(args).toContain('TRIVY_CACHE_DIR=/home/scanner/.cache/trivy');

      // Mounts
      expect(args).toContain('-v');
      expect(args).toContain(`${workspacePath}:/src:ro`);
      expect(args).toContain(`${dbPath}:/home/scanner/.cache/trivy/db:ro`);

      // Working dir & Image
      expect(args).toContain('-w');
      expect(args).toContain('/src');
      expect(args).toContain('aquasec/trivy:0.59.1');

      // Command
      expect(args).toContain('fs');
      expect(args).toContain('--format');
      expect(args).toContain('json');
      expect(args).toContain('--offline-scan');
      expect(args).toContain('--skip-db-update');
      expect(args).toContain('--cache-dir');
      expect(args).toContain('/home/scanner/.cache/trivy');
      expect(args).toContain('--scanners');
      expect(args).toContain('vuln');
    });

    it('preserves Semgrep compatibility when homeTmpfs and extraMounts are omitted', () => {
      const args = buildStage1DockerArgs({
        containerName: 'saferepo-scan-semgrep',
        workspacePath: '/tmp/workspace',
        image: 'semgrep/semgrep:1.100.0',
        memoryLimit: '512m',
        commandArgs: ['semgrep', 'scan'],
      });

      expect(args).toContain('/home/semgrep:rw,noexec,nosuid,size=32m');
      expect(args).toContain('XDG_CACHE_HOME=/tmp/cache');
      expect(args).toContain('SEMGREP_SETTINGS_FILE=/tmp/settings.yaml');
    });
  });

  describe('executeTrivyScan Execution Flow', () => {
    it('returns typed unavailable result when DB is missing without spawning Docker', async () => {
      const runDockerSpy = vi.spyOn(runnerModule, 'runDockerScanner');

      const result = await executeTrivyScan({
        scanId: 'scan-test-unavail',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: path.join(tempDbDir, 'missing-db'),
      });

      expect(result.status).toBe('unavailable');
      if (result.status === 'unavailable') {
        expect(result.scanner).toBe('trivy');
        expect(result.reason).toContain('Trivy offline vulnerability database not found at TRIVY_DB_PATH');
      }

      // Docker MUST NOT be spawned
      expect(runDockerSpy).not.toHaveBeenCalled();
    });

    it('executes Trivy and parses findings when DB is valid and runner succeeds', async () => {
      await createValidTrivyDb(tempDbDir);

      const mockTrivyJson = JSON.stringify({
        SchemaVersion: 2,
        Results: [
          {
            Target: 'package-lock.json',
            Class: 'lang-pkgs',
            Type: 'npm',
            Vulnerabilities: [
              {
                VulnerabilityID: 'CVE-2021-23337',
                PkgName: 'lodash',
                InstalledVersion: '4.17.20',
                FixedVersion: '4.17.21',
                Severity: 'HIGH',
                Title: 'Command Injection in lodash',
                Description: 'This affects versions of lodash prior to 4.17.21',
                Aliases: ['GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337'],
              },
            ],
          },
        ],
      });

      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: mockTrivyJson,
        stderr: '',
        exitCode: 0,
        durationMs: 1200,
      });

      const result = await executeTrivyScan({
        scanId: 'scan-test-success',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: tempDbDir,
      });

      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.scanner).toBe('trivy');
        expect(result.rawMatchesCount).toBe(1);
        expect(result.durationMs).toBe(1200);

        const finding = result.findings[0]!;
        expect(finding.canonicalId).toBe('CVE-2021-23337');
        expect(finding.package).toBe('lodash');
        expect(finding.packageVersion).toBe('4.17.20');
        expect(finding.fixedVersion).toBe('4.17.21');
        expect(finding.severity).toBe('high');
        expect(finding.target).toBe('package-lock.json');
        expect(finding.remediation).toBe('Upgrade lodash to 4.17.21');
        expect(finding.aliases).toContain('CVE-2021-23337');
        expect(finding.aliases).toContain('GHSA-35jh-r3h4-6jhm');
      }
    });

    it('returns failed result when Trivy exits with non-zero code', async () => {
      await createValidTrivyDb(tempDbDir);

      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: '',
        stderr: 'Fatal: DB corrupted',
        exitCode: 2,
        durationMs: 400,
      });

      const result = await executeTrivyScan({
        scanId: 'scan-test-fail-code',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: tempDbDir,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.scanner).toBe('trivy');
        expect(result.error).toContain('Trivy exited with non-zero exit code 2');
        expect(result.error).toContain('Fatal: DB corrupted');
      }
    });

    it('returns failed result when Trivy times out (ScannerTimeoutError)', async () => {
      await createValidTrivyDb(tempDbDir);

      vi.spyOn(runnerModule, 'runDockerScanner').mockRejectedValueOnce(
        new ScannerTimeoutError('Trivy container timed out after 180000ms')
      );

      const result = await executeTrivyScan({
        scanId: 'scan-test-timeout',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: tempDbDir,
        timeoutMs: 180_000,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.scanner).toBe('trivy');
        expect(result.error).toContain('Trivy scan timed out after 180000ms');
      }
    });

    it('returns failed result when Trivy stdout exceeds buffer limit (OutputSizeExceededError)', async () => {
      await createValidTrivyDb(tempDbDir);

      vi.spyOn(runnerModule, 'runDockerScanner').mockRejectedValueOnce(
        new OutputSizeExceededError('Scanner stdout exceeded maximum buffer limit')
      );

      const result = await executeTrivyScan({
        scanId: 'scan-test-size-exceeded',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: tempDbDir,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.scanner).toBe('trivy');
        expect(result.error).toContain('Scanner stdout exceeded maximum buffer limit');
      }
    });

    it('returns failed result when Docker runner encounters unexpected spawn failure', async () => {
      await createValidTrivyDb(tempDbDir);

      vi.spyOn(runnerModule, 'runDockerScanner').mockRejectedValueOnce(
        new Error('docker: daemon is not running')
      );

      const result = await executeTrivyScan({
        scanId: 'scan-test-spawn-fail',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: tempDbDir,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.scanner).toBe('trivy');
        expect(result.error).toContain('docker: daemon is not running');
      }
    });

    it('returns failed result when Trivy stdout is malformed JSON', async () => {
      await createValidTrivyDb(tempDbDir);

      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: '{ malformed json ...',
        stderr: '',
        exitCode: 0,
        durationMs: 600,
      });

      const result = await executeTrivyScan({
        scanId: 'scan-test-bad-json',
        userId: 'user-123',
        workspacePath: '/tmp/workspace',
        trivyDbPath: tempDbDir,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.scanner).toBe('trivy');
        expect(result.error).toContain('Failed to parse Trivy output: Invalid JSON');
      }
    });
  });

  describe('Helpers & Data Normalization', () => {
    describe('mapTrivySeverity', () => {
      it('maps all Trivy severities to SafeRepo standard 5-level severity', () => {
        expect(mapTrivySeverity('CRITICAL')).toBe('critical');
        expect(mapTrivySeverity('HIGH')).toBe('high');
        expect(mapTrivySeverity('MEDIUM')).toBe('medium');
        expect(mapTrivySeverity('LOW')).toBe('low');
        expect(mapTrivySeverity('UNKNOWN')).toBe('info');
        expect(mapTrivySeverity('INFO')).toBe('info');
        expect(mapTrivySeverity(undefined)).toBe('medium');
        expect(mapTrivySeverity('CUSTOM')).toBe('medium');
      });
    });

    describe('resolveCanonicalVulnerabilityId', () => {
      it('prioritizes CVE ID from aliases over GHSA ID', () => {
        const canonical = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', [
          'CVE-2021-23337',
        ]);
        expect(canonical).toBe('CVE-2021-23337');
      });

      it('retains primary CVE ID if already a CVE', () => {
        const canonical = resolveCanonicalVulnerabilityId('CVE-2023-1234', ['GHSA-abcd-1234']);
        expect(canonical).toBe('CVE-2023-1234');
      });

      it('falls back to primary ID if no CVE alias exists', () => {
        const canonical = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', ['OSV-2021-123']);
        expect(canonical).toBe('GHSA-35JH-R3H4-6JHM');
      });
    });

    describe('validateAndNormalizeTrivyTargetPath', () => {
      it('accepts valid manifest paths within /src mount', () => {
        expect(validateAndNormalizeTrivyTargetPath('/src/package-lock.json')).toBe('package-lock.json');
        expect(validateAndNormalizeTrivyTargetPath('package-lock.json')).toBe('package-lock.json');
        expect(validateAndNormalizeTrivyTargetPath('/src/apps/web/package-lock.json')).toBe(
          'apps/web/package-lock.json'
        );
        expect(validateAndNormalizeTrivyTargetPath('apps/web/package-lock.json')).toBe(
          'apps/web/package-lock.json'
        );
      });

      it('strictly REJECTS path traversal attempts and absolute external paths', () => {
        expect(validateAndNormalizeTrivyTargetPath('../../etc/passwd')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('../../../etc/passwd')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('/etc/shadow')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('/src/../../etc/passwd')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('/src/apps/../../etc/passwd')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('C:\\Windows\\System32')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('/src')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('/src/..')).toBeNull();
      });

      it('rejects empty or undefined target strings', () => {
        expect(validateAndNormalizeTrivyTargetPath(undefined)).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('')).toBeNull();
        expect(validateAndNormalizeTrivyTargetPath('   ')).toBeNull();
      });

      it('ensures normalizeTrivyTargetPath alias exhibits identical rejection behavior', () => {
        expect(normalizeTrivyTargetPath('/src/package-lock.json')).toBe('package-lock.json');
        expect(normalizeTrivyTargetPath('../../etc/passwd')).toBeNull();
        expect(normalizeTrivyTargetPath('/etc/shadow')).toBeNull();
      });
    });

    describe('parseTrivyJsonOutput', () => {
      it('parses valid results and strictly skips results with rejected target paths', () => {
        const output = JSON.stringify({
          SchemaVersion: 2,
          Results: [
            {
              Target: '/src/package-lock.json',
              Vulnerabilities: [
                {
                  VulnerabilityID: 'GHSA-1234',
                  PkgName: 'axios',
                  InstalledVersion: '0.21.1',
                  FixedVersion: '0.21.2',
                  Severity: 'CRITICAL',
                  Title: 'SSRF in axios',
                  Aliases: ['CVE-2020-28168'],
                },
              ],
            },
            {
              // Security test: Traversal target MUST be completely rejected and produce 0 findings
              Target: '../../etc/passwd',
              Vulnerabilities: [
                {
                  VulnerabilityID: 'CVE-2020-0001',
                  PkgName: 'injected-evil',
                  InstalledVersion: '1.0.0',
                  Severity: 'HIGH',
                },
              ],
            },
            {
              // Security test: Absolute external path MUST be completely rejected and produce 0 findings
              Target: '/etc/shadow',
              Vulnerabilities: [
                {
                  VulnerabilityID: 'CVE-2020-0002',
                  PkgName: 'shadow-evil',
                  InstalledVersion: '1.0.0',
                  Severity: 'CRITICAL',
                },
              ],
            },
            {
              Target: '/src/requirements.txt',
              Vulnerabilities: [
                {
                  VulnerabilityID: 'CVE-2023-9999',
                  PkgName: 'cryptography',
                  InstalledVersion: '3.4.7',
                  Severity: 'MEDIUM',
                },
              ],
            },
          ],
        });

        const findings = parseTrivyJsonOutput(output, '/workspace');
        // Only the 2 valid targets (/src/package-lock.json and /src/requirements.txt) should produce findings
        expect(findings).toHaveLength(2);

        // First finding
        expect(findings[0]!.package).toBe('axios');
        expect(findings[0]!.canonicalId).toBe('CVE-2020-28168');
        expect(findings[0]!.severity).toBe('critical');
        expect(findings[0]!.target).toBe('package-lock.json');
        expect(findings[0]!.fixedVersion).toBe('0.21.2');
        expect(findings[0]!.remediation).toBe('Upgrade axios to 0.21.2');

        // Second finding
        expect(findings[1]!.package).toBe('cryptography');
        expect(findings[1]!.canonicalId).toBe('CVE-2023-9999');
        expect(findings[1]!.target).toBe('requirements.txt');
        expect(findings[1]!.fixedVersion).toBeUndefined();
        expect(findings[1]!.remediation).toBe('No fixed version available for CVE-2023-9999');

        // Ensure no evil finding with ../../etc/passwd or /etc/shadow exists
        const packages = findings.map((f) => f.package);
        expect(packages).not.toContain('injected-evil');
        expect(packages).not.toContain('shadow-evil');
      });

      it('returns empty array when Results is empty or absent', () => {
        expect(parseTrivyJsonOutput('{"Results": []}', '/workspace')).toEqual([]);
        expect(parseTrivyJsonOutput('{}', '/workspace')).toEqual([]);
      });
    });

    describe('Runner Configuration & Security Flags Enforcement', () => {
      it('invokes runDockerScanner with exact non-root and Stage 1 parameters', async () => {
        await createValidTrivyDb(tempDbDir);

        const spy = vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
          stdout: '{"Results": []}',
          stderr: '',
          exitCode: 0,
          durationMs: 500,
        });

        await executeTrivyScan({
          scanId: 'scan-exact-opts',
          userId: 'user-exact',
          workspacePath: '/tmp/workspace',
          trivyDbPath: tempDbDir,
          image: 'aquasec/trivy:0.59.1',
          timeoutMs: 180_000,
          memoryLimit: '512m',
        });

        expect(spy).toHaveBeenCalledWith(
          expect.objectContaining({
            scanId: 'scan-exact-opts',
            scannerName: 'trivy',
            workspacePath: '/tmp/workspace',
            image: 'aquasec/trivy:0.59.1',
            timeoutMs: 180_000,
            memoryLimit: '512m',
            homeTmpfs: '/home/scanner:rw,noexec,nosuid,size=128m,uid=1000,gid=1000',
            extraEnv: {
              HOME: '/home/scanner',
              TRIVY_CACHE_DIR: '/home/scanner/.cache/trivy',
            },
            extraMounts: [
              {
                source: path.resolve(tempDbDir),
                target: '/home/scanner/.cache/trivy/db',
                readonly: true,
              },
            ],
            commandArgs: [
              'fs',
              '--format', 'json',
              '--offline-scan',
              '--skip-db-update',
              '--cache-dir', '/home/scanner/.cache/trivy',
              '--scanners', 'vuln',
              '/src',
            ],
          })
        );
      });
    });
  });
});
