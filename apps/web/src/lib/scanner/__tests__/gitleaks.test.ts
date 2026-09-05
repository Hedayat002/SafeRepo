import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  executeGitleaksScan,
  buildGitleaksCommandArgs,
  parseGitleaksJsonOutput,
} from '../gitleaks';
import * as runnerModule from '../runner';
import { ScannerTimeoutError, OutputSizeExceededError } from '../runner';

describe('Gitleaks Secret Scanner Integration', () => {
  const fakeSecret = 'fake-secret-token-xyz-123456789';
  const fakeMatch = `const API_KEY = "${fakeSecret}";`;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('Command Arguments Construction', () => {
    it('constructs hardened CLI arguments with native process-boundary redaction', () => {
      const args = buildGitleaksCommandArgs();

      expect(args).toContain('dir');
      expect(args).toContain('/src');
      expect(args).toContain('--report-format');
      expect(args).toContain('json');
      expect(args).toContain('--report-path');
      expect(args).toContain('-');
      expect(args).toContain('--redact');
      expect(args).toContain('--no-banner');
      expect(args).toContain('--no-color');
    });
  });

  describe('Output Parsing (parseGitleaksJsonOutput)', () => {
    it('returns empty array when stdout is empty or whitespace', () => {
      expect(parseGitleaksJsonOutput('')).toEqual([]);
      expect(parseGitleaksJsonOutput('   \n  ')).toEqual([]);
    });

    it('parses valid JSON array of findings', () => {
      const mockJson = JSON.stringify([
        {
          Description: 'AWS Access Key ID',
          StartLine: 12,
          EndLine: 12,
          StartColumn: 1,
          EndColumn: 20,
          Secret: fakeSecret,
          Match: fakeMatch,
          File: '/src/config.ts',
          RuleID: 'aws-access-key-id',
          Entropy: 3.5,
          Tags: ['key', 'AWS'],
        },
      ]);

      const findings = parseGitleaksJsonOutput(mockJson);
      expect(findings.length).toBe(1);
      expect(findings[0]?.RuleID).toBe('aws-access-key-id');
      expect(findings[0]?.StartLine).toBe(12);
    });

    it('throws sanitized error when stdout contains invalid JSON without echoing raw content', () => {
      const invalidJson = `Invalid JSON content containing ${fakeSecret}`;

      let caughtError: Error | null = null;
      try {
        parseGitleaksJsonOutput(invalidJson);
      } catch (err) {
        caughtError = err as Error;
      }

      expect(caughtError).not.toBeNull();
      expect(caughtError?.message).toBe(
        'Failed to parse Gitleaks output: Invalid JSON structure'
      );
      // Ensure the error message NEVER contains raw secret content
      expect(caughtError?.message).not.toContain(fakeSecret);
    });

    it('throws error when JSON is an object instead of an array', () => {
      const jsonObject = JSON.stringify({ error: 'something' });

      expect(() => parseGitleaksJsonOutput(jsonObject)).toThrow(
        'Failed to parse Gitleaks output: Expected JSON array'
      );
    });
  });

  describe('Scanner Execution (executeGitleaksScan)', () => {
    it('passes hardened Stage 1 container options to runDockerScanner', async () => {
      const spy = vi
        .spyOn(runnerModule, 'runDockerScanner')
        .mockResolvedValueOnce({
          stdout: '[]',
          stderr: '',
          exitCode: 0,
          durationMs: 400,
        });

      await executeGitleaksScan({
        scanId: 'scan-test-1',
        userId: 'user-test-1',
        workspacePath: '/tmp/test-workspace',
      });

      expect(spy).toHaveBeenCalledTimes(1);
      const callArgs = spy.mock.calls[0]?.[0];
      expect(callArgs?.scannerName).toBe('gitleaks');
      expect(callArgs?.workspacePath).toBe('/tmp/test-workspace');
      expect(callArgs?.homeTmpfs).toContain('uid=1000,gid=1000');
      expect(callArgs?.extraEnv).toEqual({ HOME: '/tmp' });
      expect(callArgs?.commandArgs).toContain('--redact');
    });

    it('handles exit code 0 (clean scan with 0 leaks) as success', async () => {
      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: '[]',
        stderr: '',
        exitCode: 0,
        durationMs: 350,
      });

      const result = await executeGitleaksScan({
        scanId: 'scan-clean',
        userId: 'user-1',
        workspacePath: '/tmp/workspace',
      });

      expect(result.status).toBe('success');
      if (result.status !== 'success') throw new Error('Expected success');
      expect(result.findings).toEqual([]);
      expect(result.rawMatchesCount).toBe(0);
      expect(result.durationMs).toBe(350);
    });

    it('handles exit code 1 (findings detected) as success and normalizes findings with redaction', async () => {
      const mockFindings = [
        {
          Description: 'AWS Access Key ID',
          StartLine: 15,
          StartColumn: 5,
          Secret: fakeSecret,
          Match: fakeMatch,
          File: '/src/services/aws.ts',
          RuleID: 'aws-access-key-id',
          Entropy: 3.8,
          Tags: ['key', 'AWS'],
        },
      ];

      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: JSON.stringify(mockFindings),
        stderr: '',
        exitCode: 1, // Exit code 1 means leaks were found
        durationMs: 800,
      });

      const result = await executeGitleaksScan({
        scanId: 'scan-with-secrets',
        userId: 'user-1',
        workspacePath: '/tmp/workspace',
      });

      expect(result.status).toBe('success');
      if (result.status !== 'success') throw new Error('Expected success');
      expect(result.findings.length).toBe(1);
      expect(result.rawMatchesCount).toBe(1);

      const finding = result.findings[0]!;
      expect(finding.scanner).toBe('gitleaks');
      expect(finding.category).toBe('secret');
      expect(finding.severity).toBe('critical'); // AWS is mapped to critical
      expect(finding.file).toBe('services/aws.ts');
      expect(finding.line).toBe(15);
      expect(finding.column).toBe(5);

      // Strict Redaction verification:
      expect(JSON.stringify(finding)).not.toContain(fakeSecret);
      expect(finding.codeSnippet).toBe('[REDACTED SECRET]');
      expect(finding.metadata).not.toHaveProperty('Secret');
      expect(finding.metadata).not.toHaveProperty('Match');
    });

    it('handles exit code > 1 as scanner failure with sanitized error message', async () => {
      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: '',
        stderr: `Fatal error mentioning ${fakeSecret}`,
        exitCode: 2,
        durationMs: 200,
      });

      const result = await executeGitleaksScan({
        scanId: 'scan-fatal',
        userId: 'user-1',
        workspacePath: '/tmp/workspace',
      });

      expect(result.status).toBe('failed');
      if (result.status !== 'failed') throw new Error('Expected failed');
      expect(result.error).toBe('Gitleaks execution failed (exit code 2)');
      // Stderr with sensitive values must NOT be in error message
      expect(result.error).not.toContain(fakeSecret);
    });

    it('handles ScannerTimeoutError cleanly', async () => {
      vi.spyOn(runnerModule, 'runDockerScanner').mockRejectedValueOnce(
        new ScannerTimeoutError('Scanner execution timed out after 180s')
      );

      const result = await executeGitleaksScan({
        scanId: 'scan-timeout',
        userId: 'user-1',
        workspacePath: '/tmp/workspace',
        timeoutMs: 180_000,
      });

      expect(result.status).toBe('failed');
      if (result.status !== 'failed') throw new Error('Expected failed');
      expect(result.error).toContain('timed out after 180000ms');
    });

    it('handles OutputSizeExceededError cleanly', async () => {
      vi.spyOn(runnerModule, 'runDockerScanner').mockRejectedValueOnce(
        new OutputSizeExceededError('Scanner output exceeded maximum allowed size of 10.0 MB')
      );

      const result = await executeGitleaksScan({
        scanId: 'scan-oversize',
        userId: 'user-1',
        workspacePath: '/tmp/workspace',
      });

      expect(result.status).toBe('failed');
      if (result.status !== 'failed') throw new Error('Expected failed');
      expect(result.error).toContain('Scanner output exceeded maximum allowed size');
    });

    it('handles malformed JSON output on exit code 1 as failure', async () => {
      vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
        stdout: 'not-valid-json',
        stderr: '',
        exitCode: 1,
        durationMs: 300,
      });

      const result = await executeGitleaksScan({
        scanId: 'scan-malformed',
        userId: 'user-1',
        workspacePath: '/tmp/workspace',
      });

      expect(result.status).toBe('failed');
      if (result.status !== 'failed') throw new Error('Expected failed');
      expect(result.error).toContain('Failed to parse Gitleaks output');
    });
  });
});
