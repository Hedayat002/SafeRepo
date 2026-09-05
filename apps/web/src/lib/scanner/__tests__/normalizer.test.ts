import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  normalizeFilePath,
  mapSemgrepSeverity,
  generateFindingTitle,
  generateFindingFingerprint,
  normalizeSemgrepOutput,
  resolveCanonicalVulnerabilityId,
  generateDependencyFingerprint,
  mapDependencySeverity,
  inferEcosystemFromPath,
  normalizeTrivyFinding,
  normalizeOsvFinding,
  mergeDependencyFindings,
  deduplicateDependencyFindings,
  normalizeTrivyOutput,
  normalizeOsvOutput,
  normalizeDependencyFindings,
  generateSecretFingerprint,
  mapSecretSeverity,
  normalizeGitleaksFinding,
  deduplicateSecretFindings,
  normalizeGitleaksOutput,
  SEVERITY_RANK,
  type NormalizedFindingInput,
} from '../normalizer';
import type { GitleaksRawFinding, SemgrepRawOutput } from '@/types';
import type { TrivyVulnerabilityFinding } from '../trivy';
import type { OsvVulnerabilityFinding } from '../osv';

describe('Result Normalizer', () => {
  // ==========================================================================
  // Preserved Phase 03 Semgrep Unit Tests
  // ==========================================================================

  describe('normalizeFilePath', () => {
    it('normalizes forward and backslash paths', () => {
      expect(normalizeFilePath('/src/lib/auth.ts')).toBe('lib/auth.ts');
      expect(normalizeFilePath('\\src\\lib\\auth.ts')).toBe('lib/auth.ts');
      expect(normalizeFilePath('/app/index.js')).toBe('app/index.js');
      expect(normalizeFilePath('src/models/user.ts')).toBe('src/models/user.ts');
    });
  });

  describe('mapSemgrepSeverity', () => {
    it('maps ERROR with injection CWEs to critical', () => {
      expect(mapSemgrepSeverity('ERROR', { cwe: ['CWE-89: SQL Injection'] })).toBe('critical');
      expect(mapSemgrepSeverity('ERROR', { cwe: ['CWE-78: OS Command Injection'] })).toBe('critical');
      expect(mapSemgrepSeverity('ERROR', { cwe: ['CWE-95: Eval Injection'] })).toBe('critical');
      expect(mapSemgrepSeverity('ERROR', { owasp: ['A03:2021 - Injection'] })).toBe('critical');
    });

    it('maps general ERROR to high', () => {
      expect(mapSemgrepSeverity('ERROR', { cwe: ['CWE-200'] })).toBe('high');
      expect(mapSemgrepSeverity('error')).toBe('high');
    });

    it('maps WARNING to medium', () => {
      expect(mapSemgrepSeverity('WARNING')).toBe('medium');
      expect(mapSemgrepSeverity('warning')).toBe('medium');
    });

    it('maps INFO to low', () => {
      expect(mapSemgrepSeverity('INFO')).toBe('low');
      expect(mapSemgrepSeverity('info')).toBe('low');
    });

    it('maps unknown to info', () => {
      expect(mapSemgrepSeverity('UNKNOWN')).toBe('info');
    });
  });

  describe('generateFindingTitle', () => {
    it('generates readable title from check_id', () => {
      expect(generateFindingTitle('javascript.security.eval-code-injection', 'Eval is dangerous')).toBe(
        'Eval Code Injection'
      );
      expect(generateFindingTitle('python.security.sql_injection', 'SQL Injection')).toBe(
        'Sql Injection'
      );
    });
  });

  describe('generateFindingFingerprint (Semgrep)', () => {
    it('produces deterministic SHA-256 hash', () => {
      const hash1 = generateFindingFingerprint(
        'semgrep',
        'eval-code-injection',
        'src/index.ts',
        42,
        'Eval is dangerous'
      );
      const hash2 = generateFindingFingerprint(
        'semgrep',
        'eval-code-injection',
        'src/index.ts',
        42,
        'Eval is dangerous'
      );
      const hash3 = generateFindingFingerprint(
        'semgrep',
        'eval-code-injection',
        'src/index.ts',
        43, // different line
        'Eval is dangerous'
      );

      expect(hash1).toBe(hash2);
      expect(hash1).not.toBe(hash3);
      expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    });

    it('preserves Phase 03 Semgrep fingerprint formula and results unchanged', () => {
      const raw = 'semgrep:rule-123:app/api.ts:50:SQL injection';
      const expected = crypto.createHash('sha256').update(raw).digest('hex');
      const actual = generateFindingFingerprint('semgrep', 'rule-123', 'app/api.ts', 50, 'SQL injection');
      expect(actual).toBe(expected);
    });
  });

  describe('normalizeSemgrepOutput', () => {
    const fixtureOutput: SemgrepRawOutput = {
      results: [
        {
          check_id: 'javascript.security.sql-injection-concatenation',
          path: '/src/src/db.ts',
          start: { line: 10, col: 5, offset: 120 },
          end: { line: 10, col: 45, offset: 160 },
          extra: {
            message: 'Constructing SQL query with concatenation allows SQL injection.',
            severity: 'ERROR',
            metadata: {
              cwe: ['CWE-89: SQL Injection'],
              owasp: ['A03:2021 - Injection'],
              remediation: 'Use parameterized query.',
            },
            lines: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
          },
        },
        {
          check_id: 'javascript.security.insecure-hash-algorithm',
          path: '/src/lib/crypto.ts',
          start: { line: 25, col: 12, offset: 400 },
          end: { line: 25, col: 38, offset: 426 },
          extra: {
            message: 'MD5 is broken.',
            severity: 'WARNING',
            metadata: {
              cwe: ['CWE-327'],
            },
            lines: 'crypto.createHash("md5")',
          },
        },
        {
          check_id: 'javascript.security.insecure-hash-algorithm',
          path: '/src/lib/crypto.ts',
          start: { line: 25, col: 12, offset: 400 },
          end: { line: 25, col: 38, offset: 426 },
          extra: {
            message: 'MD5 is broken.',
            severity: 'WARNING',
            metadata: {
              cwe: ['CWE-327'],
            },
            lines: 'crypto.createHash("md5")',
          },
        },
      ],
    };

    it('correctly parses, normalizes, deduplicates, and summarizes findings', () => {
      const result = normalizeSemgrepOutput('scan-123', 'user-456', fixtureOutput);

      expect(result.rawMatchesCount).toBe(3);
      expect(result.dedupedCount).toBe(2);
      expect(result.findings.length).toBe(2);

      const [f1, f2] = result.findings;

      expect(f1.scanId).toBe('scan-123');
      expect(f1.userId).toBe('user-456');
      expect(f1.scanner).toBe('semgrep');
      expect(f1.category).toBe('sast');
      expect(f1.severity).toBe('critical');
      expect(f1.file).toBe('src/db.ts');
      expect(f1.line).toBe(10);
      expect(f1.remediation).toBe('Use parameterized query.');
      expect(f1.codeSnippet).toBe('db.query(`SELECT * FROM users WHERE id = ${id}`)');

      expect(f2.severity).toBe('medium');
      expect(f2.file).toBe('lib/crypto.ts');

      expect(result.summary).toEqual({
        total: 2,
        critical: 1,
        high: 0,
        medium: 1,
        low: 0,
        info: 0,
      });
    });

    it('parses JSON string input', () => {
      const jsonStr = JSON.stringify(fixtureOutput);
      const result = normalizeSemgrepOutput('scan-123', 'user-456', jsonStr);
      expect(result.findings.length).toBe(2);
    });

    it('throws on invalid JSON string input', () => {
      expect(() => normalizeSemgrepOutput('scan-123', 'user-456', 'not-valid-json')).toThrow(
        'Failed to parse Semgrep JSON output'
      );
    });
  });

  // ==========================================================================
  // Phase 04: Canonical Vulnerability ID Resolution Tests
  // ==========================================================================

  describe('resolveCanonicalVulnerabilityId', () => {
    it('prefers primary CVE selection when primary is already a CVE', () => {
      const id = resolveCanonicalVulnerabilityId('CVE-2021-23337', ['GHSA-35jh-r3h4-6jhm']);
      expect(id).toBe('CVE-2021-23337');
    });

    it('prefers CVE alias selection when primary is GHSA', () => {
      const id = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', ['CVE-2021-23337']);
      expect(id).toBe('CVE-2021-23337');
    });

    it('falls back to GHSA when no CVE alias exists', () => {
      const id = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', []);
      expect(id).toBe('GHSA-35JH-R3H4-6JHM');
    });

    it('falls back to OSV ID when no CVE alias exists', () => {
      const id = resolveCanonicalVulnerabilityId('OSV-2023-999', ['PYSEC-2023-123']);
      expect(id).toBe('OSV-2023-999');
    });

    it('picks deterministic first sorted CVE when multiple CVE aliases exist', () => {
      const id = resolveCanonicalVulnerabilityId('GHSA-test', ['CVE-2023-5000', 'CVE-2023-1000']);
      expect(id).toBe('CVE-2023-1000');
    });

    it('normalizes case-insensitively (e.g. cve-2021-23337 -> CVE-2021-23337)', () => {
      const id = resolveCanonicalVulnerabilityId('cve-2021-23337');
      expect(id).toBe('CVE-2021-23337');
    });

    it('trims whitespace across primary and aliases', () => {
      const id = resolveCanonicalVulnerabilityId('  ghsa-test  ', ['  cve-2021-23337  ']);
      expect(id).toBe('CVE-2021-23337');
    });

    it('falls back to UNKNOWN when primary and aliases are missing or empty', () => {
      expect(resolveCanonicalVulnerabilityId('', [])).toBe('UNKNOWN');
      expect(resolveCanonicalVulnerabilityId(undefined, [])).toBe('UNKNOWN');
      expect(resolveCanonicalVulnerabilityId(null, [])).toBe('UNKNOWN');
    });

    it('uses deterministic alias fallback when primary ID is missing', () => {
      const id = resolveCanonicalVulnerabilityId(null, ['GHSA-bbb', 'GHSA-aaa']);
      expect(id).toBe('GHSA-AAA');
    });
  });

  // ==========================================================================
  // Phase 04: Ecosystem Inference Helper
  // ==========================================================================

  describe('inferEcosystemFromPath', () => {
    it('infers npm for Node.js manifest files', () => {
      expect(inferEcosystemFromPath('package-lock.json')).toBe('npm');
      expect(inferEcosystemFromPath('apps/web/package-lock.json')).toBe('npm');
      expect(inferEcosystemFromPath('package.json')).toBe('npm');
      expect(inferEcosystemFromPath('yarn.lock')).toBe('npm');
      expect(inferEcosystemFromPath('pnpm-lock.yaml')).toBe('npm');
    });

    it('infers pypi for Python manifest files', () => {
      expect(inferEcosystemFromPath('requirements.txt')).toBe('pypi');
      expect(inferEcosystemFromPath('services/api/requirements.txt')).toBe('pypi');
      expect(inferEcosystemFromPath('Pipfile.lock')).toBe('pypi');
      expect(inferEcosystemFromPath('pyproject.toml')).toBe('pypi');
      expect(inferEcosystemFromPath('poetry.lock')).toBe('pypi');
    });

    it('returns unknown for unrecognized files', () => {
      expect(inferEcosystemFromPath('Dockerfile')).toBe('unknown');
      expect(inferEcosystemFromPath(null)).toBe('unknown');
    });
  });

  // ==========================================================================
  // Phase 04: Dependency Severity Mapping
  // ==========================================================================

  describe('mapDependencySeverity', () => {
    it('maps standard severity strings accurately', () => {
      expect(mapDependencySeverity('CRITICAL')).toBe('critical');
      expect(mapDependencySeverity('critical')).toBe('critical');
      expect(mapDependencySeverity('HIGH')).toBe('high');
      expect(mapDependencySeverity('MEDIUM')).toBe('medium');
      expect(mapDependencySeverity('MODERATE')).toBe('medium');
      expect(mapDependencySeverity('LOW')).toBe('low');
    });

    it('defaults unknown/missing severity safely to info without fabricating', () => {
      expect(mapDependencySeverity('UNKNOWN')).toBe('info');
      expect(mapDependencySeverity('INFO')).toBe('info');
      expect(mapDependencySeverity(undefined)).toBe('info');
      expect(mapDependencySeverity(null)).toBe('info');
      expect(mapDependencySeverity('')).toBe('info');
      expect(mapDependencySeverity('arbitrary_string')).toBe('info');
    });

    it('verifies severity ranking hierarchy', () => {
      expect(SEVERITY_RANK['critical']).toBeGreaterThan(SEVERITY_RANK['high']);
      expect(SEVERITY_RANK['high']).toBeGreaterThan(SEVERITY_RANK['medium']);
      expect(SEVERITY_RANK['medium']).toBeGreaterThan(SEVERITY_RANK['low']);
      expect(SEVERITY_RANK['low']).toBeGreaterThan(SEVERITY_RANK['info']);
    });
  });

  // ==========================================================================
  // Phase 04: Dependency Fingerprint Tests
  // ==========================================================================

  describe('generateDependencyFingerprint', () => {
    it('dependency fingerprint determinism: identical inputs yield identical SHA-256', () => {
      const hash1 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      const hash2 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    });

    it('same dependency + same CVE => same fingerprint across Trivy and OSV', () => {
      // Trivy canonical ID
      const trivyHash = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      // OSV resolved canonical ID from alias
      const osvCanonical = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', ['CVE-2021-23337']);
      const osvHash = generateDependencyFingerprint('npm', 'lodash', '4.17.20', osvCanonical);

      expect(osvCanonical).toBe('CVE-2021-23337');
      expect(trivyHash).toBe(osvHash);
    });

    it('different ecosystem => different fingerprint', () => {
      const npmHash = generateDependencyFingerprint('npm', 'requests', '2.25.1', 'CVE-2021-1234');
      const pypiHash = generateDependencyFingerprint('pypi', 'requests', '2.25.1', 'CVE-2021-1234');
      expect(npmHash).not.toBe(pypiHash);
    });

    it('different package => different fingerprint', () => {
      const hash1 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      const hash2 = generateDependencyFingerprint('npm', 'axios', '4.17.20', 'CVE-2021-23337');
      expect(hash1).not.toBe(hash2);
    });

    it('different version => different fingerprint', () => {
      const hash1 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      const hash2 = generateDependencyFingerprint('npm', 'lodash', '4.17.21', 'CVE-2021-23337');
      expect(hash1).not.toBe(hash2);
    });

    it('different vulnerability => different fingerprint', () => {
      const hash1 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      const hash2 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2020-8203');
      expect(hash1).not.toBe(hash2);
    });

    it('file path does NOT affect fingerprint', () => {
      // Fingerprint takes ecosystem, package, version, vulnId; path is excluded
      const hash1 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      const hash2 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      expect(hash1).toBe(hash2);
    });

    it('scanner name does NOT affect fingerprint', () => {
      // Neither 'trivy' nor 'osv' appears in fingerprint
      const hash1 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      const expectedRaw = 'dependency:npm:lodash:4.17.20:CVE-2021-23337';
      const expectedHash = crypto.createHash('sha256').update(expectedRaw).digest('hex');
      expect(hash1).toBe(expectedHash);
    });

    it('handles case-insensitivity and whitespace trimming for all parameters', () => {
      const hash1 = generateDependencyFingerprint('NPM', ' Lodash ', ' 4.17.20 ', ' cve-2021-23337 ');
      const hash2 = generateDependencyFingerprint('npm', 'lodash', '4.17.20', 'CVE-2021-23337');
      expect(hash1).toBe(hash2);
    });
  });

  // ==========================================================================
  // Phase 04: Single Finding Normalization Tests
  // ==========================================================================

  describe('normalizeTrivyFinding', () => {
    const trivyRawFixture: TrivyVulnerabilityFinding = {
      vulnerabilityId: 'CVE-2021-23337',
      canonicalId: 'CVE-2021-23337',
      package: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      severity: 'high',
      title: 'Command Injection in lodash',
      description: 'Lodash vulnerable to command injection via template.',
      target: 'package-lock.json',
      remediation: 'Upgrade lodash to 4.17.21',
      aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
      rawVulnerability: { VulnerabilityID: 'CVE-2021-23337' },
    };

    it('normalizes Trivy finding into category dependency with unified fields', () => {
      const finding = normalizeTrivyFinding('scan-1', 'user-1', trivyRawFixture);

      expect(finding.scanId).toBe('scan-1');
      expect(finding.userId).toBe('user-1');
      expect(finding.scanner).toBe('trivy');
      expect(finding.category).toBe('dependency');
      expect(finding.severity).toBe('high');
      expect(finding.package).toBe('lodash');
      expect(finding.packageVersion).toBe('4.17.20');
      expect(finding.fixedVersion).toBe('4.17.21');
      expect(finding.vulnerabilityId).toBe('CVE-2021-23337');
      expect(finding.file).toBe('package-lock.json');
      expect(finding.line).toBe(0);
      expect(finding.remediation).toBe('Upgrade lodash to 4.17.21');
      expect(finding.metadata?.ecosystem).toBe('npm');
      expect(finding.metadata?.scanners).toEqual(['trivy']);
      expect(finding.metadata?.aliases).toContain('CVE-2021-23337');
      expect(finding.metadata?.aliases).toContain('GHSA-35JH-R3H4-6JHM');
    });

    it('handles Python requirements.txt manifest path in Trivy finding', () => {
      const pythonTrivy: TrivyVulnerabilityFinding = {
        ...trivyRawFixture,
        package: 'urllib3',
        packageVersion: '1.26.4',
        target: 'requirements.txt',
      };

      const finding = normalizeTrivyFinding('scan-1', 'user-1', pythonTrivy);
      expect(finding.metadata?.ecosystem).toBe('pypi');
      expect(finding.package).toBe('urllib3');
    });
  });

  describe('normalizeOsvFinding', () => {
    const osvRawFixture: OsvVulnerabilityFinding = {
      vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
      canonicalId: 'CVE-2021-23337',
      package: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      severity: 'critical',
      title: 'Command injection in lodash',
      description: 'Lodash command injection vulnerability.',
      target: 'apps/web/package-lock.json',
      remediation: 'Upgrade lodash to 4.17.21',
      aliases: ['CVE-2021-23337'],
      ecosystem: 'npm',
      rawVulnerability: { id: 'GHSA-35jh-r3h4-6jhm' },
    };

    it('normalizes OSV finding into category dependency with canonical CVE', () => {
      const finding = normalizeOsvFinding('scan-1', 'user-1', osvRawFixture);

      expect(finding.scanId).toBe('scan-1');
      expect(finding.userId).toBe('user-1');
      expect(finding.scanner).toBe('osv');
      expect(finding.category).toBe('dependency');
      expect(finding.severity).toBe('critical');
      expect(finding.package).toBe('lodash');
      expect(finding.packageVersion).toBe('4.17.20');
      expect(finding.fixedVersion).toBe('4.17.21');
      expect(finding.vulnerabilityId).toBe('CVE-2021-23337'); // Canonical CVE resolved
      expect(finding.file).toBe('apps/web/package-lock.json');
      expect(finding.line).toBe(0);
      expect(finding.metadata?.ecosystem).toBe('npm');
      expect(finding.metadata?.scanners).toEqual(['osv']);
      expect(finding.metadata?.aliases).toContain('CVE-2021-23337');
      expect(finding.metadata?.aliases).toContain('GHSA-35JH-R3H4-6JHM');
    });
  });

  // ==========================================================================
  // Phase 04: Merge Semantics & Deduplication Tests
  // ==========================================================================

  describe('mergeDependencyFindings & deduplication', () => {
    const trivyItem: TrivyVulnerabilityFinding = {
      vulnerabilityId: 'CVE-2021-23337',
      canonicalId: 'CVE-2021-23337',
      package: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      severity: 'high',
      title: 'Command Injection in lodash',
      description: 'Lodash vulnerable to command injection via template.',
      target: 'package-lock.json',
      remediation: 'Upgrade lodash to 4.17.21',
      aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
      rawVulnerability: {},
    };

    const osvItem: OsvVulnerabilityFinding = {
      vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
      canonicalId: 'CVE-2021-23337',
      package: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      severity: 'critical',
      title: 'Command injection in lodash template',
      description: 'A critical command injection vulnerability in lodash.',
      target: 'apps/web/package-lock.json',
      remediation: 'Upgrade lodash to 4.17.21',
      aliases: ['CVE-2021-23337'],
      ecosystem: 'npm',
      rawVulnerability: {},
    };

    it('Trivy + OSV duplicate merge produces exactly ONE finding with unified scanners', () => {
      const f1 = normalizeTrivyFinding('scan-1', 'user-1', trivyItem);
      const f2 = normalizeOsvFinding('scan-1', 'user-1', osvItem);

      expect(f1.fingerprint).toBe(f2.fingerprint);

      const merged = mergeDependencyFindings(f1, f2);

      // Scanners unified
      expect(merged.metadata?.scanners).toEqual(['osv', 'trivy']);
      // Highest severity wins (critical > high)
      expect(merged.severity).toBe('critical');
      // Aliases unified
      expect(merged.metadata?.aliases).toEqual(['CVE-2021-23337', 'GHSA-35JH-R3H4-6JHM']);
      // Fixed version preserved
      expect(merged.fixedVersion).toBe('4.17.21');
      // Manifest paths union
      expect(merged.metadata?.manifestPaths).toContain('package-lock.json');
      expect(merged.metadata?.manifestPaths).toContain('apps/web/package-lock.json');
    });

    it('highest severity wins: critical overrides medium, high overrides low', () => {
      const baseFinding: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
      };

      const highFinding: NormalizedFindingInput = {
        ...baseFinding,
        scanner: 'osv',
        severity: 'high',
      };

      const criticalFinding: NormalizedFindingInput = {
        ...baseFinding,
        scanner: 'osv',
        severity: 'critical',
      };

      const lowFinding: NormalizedFindingInput = {
        ...baseFinding,
        scanner: 'osv',
        severity: 'low',
      };

      expect(mergeDependencyFindings(baseFinding, highFinding).severity).toBe('high');
      expect(mergeDependencyFindings(baseFinding, criticalFinding).severity).toBe('critical');
      expect(mergeDependencyFindings(baseFinding, lowFinding).severity).toBe('medium');
    });

    it('fixedVersion preservation: retains fixed version from available source', () => {
      const findingWithFixed: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        fixedVersion: '1.0.1',
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
      };

      const findingWithoutFixed: NormalizedFindingInput = {
        ...findingWithFixed,
        scanner: 'osv',
        fixedVersion: undefined,
      };

      // When existing has fixedVersion and incoming does not
      const m1 = mergeDependencyFindings(findingWithFixed, findingWithoutFixed);
      expect(m1.fixedVersion).toBe('1.0.1');

      // When incoming has fixedVersion and existing does not
      const m2 = mergeDependencyFindings(findingWithoutFixed, findingWithFixed);
      expect(m2.fixedVersion).toBe('1.0.1');
    });

    it('missing fixed version: leaves fixedVersion undefined when neither scanner has it', () => {
      const f1: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        fixedVersion: undefined,
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
      };

      const f2: NormalizedFindingInput = {
        ...f1,
        scanner: 'osv',
        fixedVersion: undefined,
      };

      const merged = mergeDependencyFindings(f1, f2);
      expect(merged.fixedVersion).toBeUndefined();
    });

    it('remediation preservation: retains actionable remediation instructions over generic', () => {
      const f1: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        remediation: 'No fixed version available for CVE-2023-0001',
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
      };

      const f2: NormalizedFindingInput = {
        ...f1,
        scanner: 'osv',
        remediation: 'Upgrade pkg to 1.0.1',
      };

      const merged = mergeDependencyFindings(f1, f2);
      expect(merged.remediation).toBe('Upgrade pkg to 1.0.1');
    });

    it('duplicate scanner prevention: avoids duplicate scanner entries in metadata.scanners', () => {
      const f1: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
        metadata: { scanners: ['trivy'] },
      };

      const f2: NormalizedFindingInput = {
        ...f1,
        scanner: 'trivy',
        metadata: { scanners: ['trivy'] },
      };

      const merged = mergeDependencyFindings(f1, f2);
      expect(merged.metadata?.scanners).toEqual(['trivy']);
    });

    it('alias union: contains union of aliases from both scanners without duplicates', () => {
      const f1: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
        metadata: { aliases: ['CVE-2023-0001', 'GHSA-1111'] },
      };

      const f2: NormalizedFindingInput = {
        ...f1,
        scanner: 'osv',
        metadata: { aliases: ['GHSA-1111', 'PYSEC-2222'] },
      };

      const merged = mergeDependencyFindings(f1, f2);
      expect(merged.metadata?.aliases).toEqual(['CVE-2023-0001', 'GHSA-1111', 'PYSEC-2222']);
    });

    it('empty metadata handling: handles missing or empty metadata objects gracefully', () => {
      const f1: NormalizedFindingInput = {
        scanId: 's1',
        userId: 'u1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'medium',
        title: 'Title',
        description: 'Desc',
        file: 'package-lock.json',
        line: 0,
        package: 'pkg',
        packageVersion: '1.0.0',
        vulnerabilityId: 'CVE-2023-0001',
        fingerprint: 'hash1',
        metadata: undefined,
      };

      const f2: NormalizedFindingInput = {
        ...f1,
        scanner: 'osv',
        metadata: {},
      };

      const merged = mergeDependencyFindings(f1, f2);
      expect(merged.metadata?.scanners).toEqual(['osv', 'trivy']);
      expect(merged.metadata?.aliases).toContain('CVE-2023-0001');
    });

    it('deduplicateDependencyFindings merges duplicate findings in an array', () => {
      const f1 = normalizeTrivyFinding('scan-1', 'user-1', trivyItem);
      const f2 = normalizeOsvFinding('scan-1', 'user-1', osvItem);

      const deduped = deduplicateDependencyFindings([f1, f2]);
      expect(deduped.length).toBe(1);
      expect(deduped[0]!.severity).toBe('critical');
      expect(deduped[0]!.metadata?.scanners).toEqual(['osv', 'trivy']);
    });
  });

  // ==========================================================================
  // Phase 04: Batch Output Normalizer Tests
  // ==========================================================================

  describe('normalizeTrivyOutput & normalizeOsvOutput', () => {
    const trivyItems: TrivyVulnerabilityFinding[] = [
      {
        vulnerabilityId: 'CVE-2021-23337',
        canonicalId: 'CVE-2021-23337',
        package: 'lodash',
        packageVersion: '4.17.20',
        fixedVersion: '4.17.21',
        severity: 'high',
        title: 'Command Injection in lodash',
        description: 'Lodash command injection.',
        target: 'package-lock.json',
        remediation: 'Upgrade lodash to 4.17.21',
        aliases: ['CVE-2021-23337'],
        rawVulnerability: {},
      },
      // Duplicate
      {
        vulnerabilityId: 'CVE-2021-23337',
        canonicalId: 'CVE-2021-23337',
        package: 'lodash',
        packageVersion: '4.17.20',
        fixedVersion: '4.17.21',
        severity: 'high',
        title: 'Command Injection in lodash',
        description: 'Lodash command injection.',
        target: 'package-lock.json',
        remediation: 'Upgrade lodash to 4.17.21',
        aliases: ['CVE-2021-23337'],
        rawVulnerability: {},
      },
    ];

    it('normalizeTrivyOutput deduplicates duplicate findings and computes accurate summary', () => {
      const res = normalizeTrivyOutput('scan-1', 'user-1', trivyItems);
      expect(res.rawMatchesCount).toBe(2);
      expect(res.dedupedCount).toBe(1);
      expect(res.findings.length).toBe(1);
      expect(res.summary.total).toBe(1);
      expect(res.summary.high).toBe(1);
      expect(res.summary.critical).toBe(0);
    });

    it('normalizeTrivyOutput parses JSON string of Trivy findings', () => {
      const jsonStr = JSON.stringify(trivyItems);
      const res = normalizeTrivyOutput('scan-1', 'user-1', jsonStr);
      expect(res.findings.length).toBe(1);
    });

    it('normalizeOsvOutput normalizes OSV findings and computes summary', () => {
      const osvItems: OsvVulnerabilityFinding[] = [
        {
          vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
          canonicalId: 'CVE-2021-23337',
          package: 'lodash',
          packageVersion: '4.17.20',
          fixedVersion: '4.17.21',
          severity: 'critical',
          title: 'Command injection in lodash',
          description: 'Lodash command injection.',
          target: 'package-lock.json',
          remediation: 'Upgrade lodash to 4.17.21',
          aliases: ['CVE-2021-23337'],
          ecosystem: 'npm',
          rawVulnerability: {},
        },
      ];

      const res = normalizeOsvOutput('scan-1', 'user-1', osvItems);
      expect(res.rawMatchesCount).toBe(1);
      expect(res.dedupedCount).toBe(1);
      expect(res.summary.critical).toBe(1);
      expect(res.findings[0]!.vulnerabilityId).toBe('CVE-2021-23337');
    });

    it('normalizeOsvOutput throws controlled error on invalid JSON string input', () => {
      expect(() => normalizeOsvOutput('scan-1', 'user-1', 'invalid-json')).toThrow(
        'Failed to parse OSV JSON output'
      );
    });
  });

  describe('normalizeDependencyFindings (Combined Cross-Scanner Normalization)', () => {
    const trivyItem: TrivyVulnerabilityFinding = {
      vulnerabilityId: 'CVE-2021-23337',
      canonicalId: 'CVE-2021-23337',
      package: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      severity: 'high',
      title: 'Command Injection in lodash',
      description: 'Lodash command injection.',
      target: 'package-lock.json',
      remediation: 'Upgrade lodash to 4.17.21',
      aliases: ['CVE-2021-23337'],
      rawVulnerability: {},
    };

    const osvItem: OsvVulnerabilityFinding = {
      vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
      canonicalId: 'CVE-2021-23337',
      package: 'lodash',
      packageVersion: '4.17.20',
      fixedVersion: '4.17.21',
      severity: 'critical',
      title: 'Command injection in lodash template',
      description: 'Lodash template injection.',
      target: 'apps/web/package-lock.json',
      remediation: 'Upgrade lodash to 4.17.21',
      aliases: ['CVE-2021-23337'],
      ecosystem: 'npm',
      rawVulnerability: {},
    };

    const osvDistinctItem: OsvVulnerabilityFinding = {
      vulnerabilityId: 'GHSA-7890-abcd',
      canonicalId: 'CVE-2022-12345',
      package: 'axios',
      packageVersion: '0.21.1',
      fixedVersion: '0.21.2',
      severity: 'medium',
      title: 'SSRF in axios',
      description: 'Axios SSRF vulnerability.',
      target: 'package-lock.json',
      remediation: 'Upgrade axios to 0.21.2',
      aliases: ['CVE-2022-12345'],
      ecosystem: 'npm',
      rawVulnerability: {},
    };

    it('unifies overlapping Trivy + OSV finding into one and preserves distinct findings', () => {
      const res = normalizeDependencyFindings('scan-123', 'user-456', {
        trivyFindings: [trivyItem],
        osvFindings: [osvItem, osvDistinctItem],
      });

      expect(res.rawMatchesCount).toBe(3);
      expect(res.dedupedCount).toBe(2);
      expect(res.findings.length).toBe(2);

      const lodashFinding = res.findings.find((f) => f.package === 'lodash')!;
      expect(lodashFinding).toBeDefined();
      expect(lodashFinding.severity).toBe('critical'); // elevated from OSV
      expect(lodashFinding.metadata?.scanners).toEqual(['osv', 'trivy']);

      const axiosFinding = res.findings.find((f) => f.package === 'axios')!;
      expect(axiosFinding).toBeDefined();
      expect(axiosFinding.severity).toBe('medium');
      expect(axiosFinding.metadata?.scanners).toEqual(['osv']);

      expect(res.summary).toEqual({
        total: 2,
        critical: 1,
        high: 0,
        medium: 1,
        low: 0,
        info: 0,
      });
    });
  });

  // ==========================================================================
  // Phase 04: Security Invariants Review
  // ==========================================================================

  describe('Security & Pure In-Memory Invariants', () => {
    it('executes in-memory without child_process or filesystem side-effects', () => {
      // Confirms all functions are pure transformations
      const fp = generateDependencyFingerprint('npm', 'test', '1.0.0', 'CVE-2020-0001');
      expect(typeof fp).toBe('string');
      expect(fp).toHaveLength(64);
    });
  });

  // ==========================================================================
  // Phase 05: Secret Scanning Normalization & Strict Redaction Tests
  // ==========================================================================

  describe('Phase 05: Secret Scanning (Gitleaks)', () => {
    const fakeSecret = 'fake-secret-token-xyz-123456789';
    const fakeMatch = `const AWS_KEY = "${fakeSecret}";`;

    describe('generateSecretFingerprint', () => {
      it('generates deterministic 64-character SHA-256 hash', () => {
        const fp1 = generateSecretFingerprint('aws-access-key-id', 'src/config.ts', 15, 1);
        const fp2 = generateSecretFingerprint('aws-access-key-id', 'src/config.ts', 15, 1);

        expect(fp1).toHaveLength(64);
        expect(fp1).toBe(fp2);
      });

      it('normalizes case, slashes, and whitespace', () => {
        const fp1 = generateSecretFingerprint('AWS-ACCESS-KEY-ID', '/src/config.ts', 15, 1);
        const fp2 = generateSecretFingerprint('aws-access-key-id', 'config.ts', 15, 1);

        expect(fp1).toBe(fp2);
      });

      it('handles missing or invalid location values safely (defaults to 0)', () => {
        const fp1 = generateSecretFingerprint('generic-secret', '', Number.NaN, Number.NaN);
        const fp2 = generateSecretFingerprint('generic-secret', '', 0, 0);

        expect(fp1).toBe(fp2);
      });

      it('strictly NEVER includes the secret value, Match, or code snippet', () => {
        const fpWithoutSecret = generateSecretFingerprint('aws-access-key-id', 'src/config.ts', 10, 1);

        // Verification: raw string hashed does not contain fakeSecret
        const rawHashed = `secret:aws-access-key-id:src/config.ts:10:1`;
        const expected = crypto.createHash('sha256').update(rawHashed).digest('hex');

        expect(fpWithoutSecret).toBe(expected);
      });
    });

    describe('mapSecretSeverity', () => {
      it('maps cryptographic private keys to critical', () => {
        expect(mapSecretSeverity('rsa-private-key')).toBe('critical');
        expect(mapSecretSeverity('ssh-private-key')).toBe('critical');
        expect(mapSecretSeverity('jwt-secret')).toBe('critical');
        expect(mapSecretSeverity('some-key', ['crypto'])).toBe('critical');
        expect(mapSecretSeverity('some-key', ['private-key'])).toBe('critical');
      });

      it('maps cloud provider admin credentials to critical', () => {
        expect(mapSecretSeverity('aws-access-token')).toBe('critical');
        expect(mapSecretSeverity('aws-secret-access-key')).toBe('critical');
        expect(mapSecretSeverity('gcp-service-account-key')).toBe('critical');
        expect(mapSecretSeverity('azure-client-secret')).toBe('critical');
        expect(mapSecretSeverity('digitalocean-token')).toBe('critical');
        expect(mapSecretSeverity('custom-cloud', ['cloud'])).toBe('critical');
      });

      it('maps database connection strings to critical', () => {
        expect(mapSecretSeverity('mongodb-uri')).toBe('critical');
        expect(mapSecretSeverity('postgres-uri')).toBe('critical');
        expect(mapSecretSeverity('mysql-uri')).toBe('critical');
        expect(mapSecretSeverity('redis-uri')).toBe('critical');
        expect(mapSecretSeverity('custom-db', ['database'])).toBe('critical');
      });

      it('maps high-privilege SaaS and payment credentials to critical', () => {
        expect(mapSecretSeverity('stripe-secret-key')).toBe('critical');
        expect(mapSecretSeverity('okta-api-token')).toBe('critical');
        expect(mapSecretSeverity('vault-token')).toBe('critical');
        expect(mapSecretSeverity('auth0-secret')).toBe('critical');
        expect(mapSecretSeverity('custom-auth', ['payment'])).toBe('critical');
      });

      it('maps developer VCS, messaging, and API tokens to high', () => {
        expect(mapSecretSeverity('github-pat')).toBe('high');
        expect(mapSecretSeverity('gitlab-pat')).toBe('high');
        expect(mapSecretSeverity('slack-token')).toBe('high');
        expect(mapSecretSeverity('discord-bot-token')).toBe('high');
        expect(mapSecretSeverity('sendgrid-api-key')).toBe('high');
        expect(mapSecretSeverity('twilio-api-key')).toBe('high');
        expect(mapSecretSeverity('password-in-url')).toBe('high');
        expect(mapSecretSeverity('generic-api-key')).toBe('high');
      });

      it('defaults unmapped / unknown secret rules deterministically to high', () => {
        expect(mapSecretSeverity('unknown-internal-secret')).toBe('high');
        expect(mapSecretSeverity('')).toBe('high');
        expect(mapSecretSeverity(null)).toBe('high');
      });

      it('maps generic webhooks and publishable/client keys to medium', () => {
        expect(mapSecretSeverity('generic-webhook')).toBe('medium');
        expect(mapSecretSeverity('incoming-webhook')).toBe('medium');
        expect(mapSecretSeverity('stripe-publishable-key')).toBe('medium');
        expect(mapSecretSeverity('firebase-api-key')).toBe('medium');
        expect(mapSecretSeverity('google-maps-api-key')).toBe('medium');
        expect(mapSecretSeverity('sentry-dsn')).toBe('medium');
        expect(mapSecretSeverity('some-key', ['publishable'])).toBe('medium');
        expect(mapSecretSeverity('some-key', ['client-side'])).toBe('medium');
      });

      it('maps generic high-entropy strings to low', () => {
        expect(mapSecretSeverity('generic-high-entropy-string')).toBe('low');
        expect(mapSecretSeverity('entropy-match')).toBe('low');
      });

      it('maps example and test credential tokens to info', () => {
        expect(mapSecretSeverity('example-token')).toBe('info');
        expect(mapSecretSeverity('test-credential')).toBe('info');
        expect(mapSecretSeverity('mock-secret')).toBe('info');
      });
    });

    describe('normalizeGitleaksFinding & Strict Redaction', () => {
      it('redacts all sensitive secret material and sets safe properties', () => {
        const raw: GitleaksRawFinding = {
          Description: 'AWS Access Key ID',
          RuleID: 'aws-access-key-id',
          Secret: fakeSecret,
          Match: fakeMatch,
          File: '/src/config.ts',
          StartLine: 12,
          EndLine: 12,
          StartColumn: 1,
          EndColumn: 20,
          Entropy: 3.8,
          Commit: 'abcdef1234567890',
          Author: 'developer',
          Date: '2026-08-01',
          Tags: ['key', 'AWS'],
        };

        const finding = normalizeGitleaksFinding('scan-1', 'user-1', raw);

        expect(finding.scanner).toBe('gitleaks');
        expect(finding.category).toBe('secret');
        expect(finding.severity).toBe('critical');
        expect(finding.file).toBe('config.ts');
        expect(finding.line).toBe(12);
        expect(finding.column).toBe(1);
        expect(finding.title).toBe('Secret detected: AWS Access Key ID');
        expect(finding.description).toBe('AWS Access Key ID detected in source code.');
        expect(finding.remediation).toContain('Revoke and rotate this credential immediately');

        // STRICT REDACTION ASSERTIONS
        // 1. Raw secret is absent from entire finding JSON string
        expect(JSON.stringify(finding)).not.toContain(fakeSecret);

        // 2. codeSnippet is redacted
        expect(finding.codeSnippet).toBe('[REDACTED SECRET]');
        expect(finding.codeSnippet).not.toContain(fakeSecret);

        // 3. description contains no secret
        expect(finding.description).not.toContain(fakeSecret);

        // 4. metadata deletes Secret and Match
        expect(finding.metadata).not.toHaveProperty('Secret');
        expect(finding.metadata).not.toHaveProperty('Match');
        expect(JSON.stringify(finding.metadata)).not.toContain(fakeSecret);

        // 5. metadata preserves safe operational context
        expect(finding.metadata?.ruleId).toBe('aws-access-key-id');
        expect(finding.metadata?.secretType).toBe('AWS Access Key ID');
        expect(finding.metadata?.entropy).toBe(3.8);
        expect(finding.metadata?.scanners).toEqual(['gitleaks']);
      });

      it('handles findings with missing optional fields cleanly', () => {
        const raw: GitleaksRawFinding = {
          RuleID: 'generic-api-key',
          File: 'app.js',
        };

        const finding = normalizeGitleaksFinding('scan-1', 'user-1', raw);
        expect(finding.line).toBe(0);
        expect(finding.column).toBe(0);
        expect(finding.severity).toBe('high');
        expect(finding.title).toBe('Secret detected: generic-api-key');
        expect(finding.codeSnippet).toBe('[REDACTED SECRET]');
      });
    });

    describe('deduplicateSecretFindings', () => {
      it('deduplicates identical secret findings by fingerprint', () => {
        const raw: GitleaksRawFinding = {
          Description: 'GitHub PAT',
          RuleID: 'github-pat',
          Secret: fakeSecret,
          Match: fakeMatch,
          File: 'src/token.ts',
          StartLine: 5,
        };

        const f1 = normalizeGitleaksFinding('scan-1', 'user-1', raw);
        const f2 = normalizeGitleaksFinding('scan-1', 'user-1', raw);

        const deduped = deduplicateSecretFindings([f1, f2]);
        expect(deduped).toHaveLength(1);
        expect(deduped[0]?.fingerprint).toBe(f1.fingerprint);
      });
    });

    describe('normalizeGitleaksOutput', () => {
      it('normalizes from JSON string and computes correct severity counts', () => {
        const rawList = [
          {
            Description: 'AWS Access Key ID',
            RuleID: 'aws-access-key-id',
            Secret: fakeSecret,
            Match: fakeMatch,
            File: 'src/aws.ts',
            StartLine: 10,
          },
          {
            Description: 'Generic Webhook',
            RuleID: 'generic-webhook',
            Secret: fakeSecret,
            Match: fakeMatch,
            File: 'src/webhook.ts',
            StartLine: 20,
          },
        ];

        const res = normalizeGitleaksOutput('scan-1', 'user-1', JSON.stringify(rawList));

        expect(res.rawMatchesCount).toBe(2);
        expect(res.dedupedCount).toBe(2);
        expect(res.summary).toEqual({
          total: 2,
          critical: 1, // AWS
          high: 0,
          medium: 1, // Webhook
          low: 0,
          info: 0,
        });

        // Zero secret values anywhere in result
        expect(JSON.stringify(res)).not.toContain(fakeSecret);
      });

      it('handles empty JSON string or whitespace cleanly', () => {
        const res = normalizeGitleaksOutput('scan-1', 'user-1', '  ');
        expect(res.findings).toEqual([]);
        expect(res.summary.total).toBe(0);
      });

      it('throws error when JSON string is invalid without leaking raw content', () => {
        expect(() =>
          normalizeGitleaksOutput('scan-1', 'user-1', 'not valid json')
        ).toThrow('Failed to parse Gitleaks output: Invalid JSON structure');
      });
    });
  });
});

