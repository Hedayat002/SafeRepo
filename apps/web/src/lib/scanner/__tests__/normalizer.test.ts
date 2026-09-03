import { describe, it, expect } from 'vitest';
import {
  normalizeFilePath,
  mapSemgrepSeverity,
  generateFindingTitle,
  generateFindingFingerprint,
  normalizeSemgrepOutput,
} from '../normalizer';
import type { SemgrepRawOutput } from '@/types';

describe('Result Normalizer', () => {
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

  describe('generateFindingFingerprint', () => {
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
        // Duplicate entry with same fingerprint
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
      expect(f1.severity).toBe('critical'); // CWE-89 maps to critical
      expect(f1.file).toBe('src/db.ts');
      expect(f1.line).toBe(10);
      expect(f1.remediation).toBe('Use parameterized query.');
      expect(f1.codeSnippet).toBe('db.query(`SELECT * FROM users WHERE id = ${id}`)');

      expect(f2.severity).toBe('medium'); // WARNING maps to medium
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
});
