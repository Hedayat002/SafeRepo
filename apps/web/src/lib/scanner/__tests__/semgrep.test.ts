import { describe, it, expect, vi } from 'vitest';
import { executeSemgrepScan, getDefaultRulesPath } from '../semgrep';
import * as runnerModule from '../runner';

describe('Semgrep Scanner Wrapper', () => {
  it('resolves default rules path', () => {
    const rulesPath = getDefaultRulesPath();
    expect(rulesPath).toContain('rules');
    expect(rulesPath).toContain('semgrep');
  });

  it('executes semgrep scan and normalizes output when runner succeeds', async () => {
    const mockRawOutput = JSON.stringify({
      results: [
        {
          check_id: 'javascript.security.eval-code-injection',
          path: '/src/src/eval.ts',
          start: { line: 5, col: 1, offset: 50 },
          end: { line: 5, col: 20, offset: 70 },
          extra: {
            message: 'Dynamic code execution via eval()',
            severity: 'ERROR',
            metadata: {
              cwe: ['CWE-95: Eval Injection'],
              owasp: ['A03:2021 - Injection'],
            },
            lines: 'eval(userInput)',
          },
        },
      ],
    });

    vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
      stdout: mockRawOutput,
      stderr: '',
      exitCode: 1, // Semgrep returns 1 when findings are present
      durationMs: 1500,
    });

    const result = await executeSemgrepScan({
      scanId: 'scan-test-1',
      userId: 'user-test-1',
      workspacePath: '/tmp/workspace',
    });

    expect(result.durationMs).toBe(1500);
    expect(result.normalization.findings.length).toBe(1);
    expect(result.normalization.summary.total).toBe(1);
    expect(result.normalization.summary.critical).toBe(1);
    expect(result.normalization.findings[0].vulnerabilityId).toBe(
      'javascript.security.eval-code-injection'
    );
  });

  it('throws when runner exits with fatal error code >= 2 without valid JSON', async () => {
    vi.spyOn(runnerModule, 'runDockerScanner').mockResolvedValueOnce({
      stdout: '',
      stderr: 'Fatal: invalid configuration in /rules',
      exitCode: 2,
      durationMs: 500,
    });

    await expect(
      executeSemgrepScan({
        scanId: 'scan-test-fail',
        userId: 'user-test-fail',
        workspacePath: '/tmp/workspace',
      })
    ).rejects.toThrow('Semgrep execution failed (exit code 2)');
  });
});
