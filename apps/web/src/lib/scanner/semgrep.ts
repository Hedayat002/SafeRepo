import path from 'path';
import { runDockerScanner } from './runner';
import { normalizeSemgrepOutput, type NormalizationResult } from './normalizer';
import { logger } from '@/lib/logger';
import { env } from '@/lib/env';

export interface ExecuteSemgrepScanOptions {
  scanId: string;
  userId: string;
  workspacePath: string;
  rulesPath?: string;
  timeoutMs?: number;
  memoryLimit?: string;
}

export interface ExecuteSemgrepScanResult {
  normalization: NormalizationResult;
  durationMs: number;
  rawStdoutLength: number;
}

/**
 * Resolves the default offline Semgrep rules directory.
 */
export function getDefaultRulesPath(): string {
  // Points to apps/web/src/lib/scanner/rules/semgrep
  return path.resolve(process.cwd(), 'src/lib/scanner/rules/semgrep');
}

/**
 * Executes a Semgrep SAST scan inside a hardened Stage 1 Docker container
 * and normalizes the results.
 */
export async function executeSemgrepScan(
  options: ExecuteSemgrepScanOptions
): Promise<ExecuteSemgrepScanResult> {
  const {
    scanId,
    userId,
    workspacePath,
    rulesPath = getDefaultRulesPath(),
    timeoutMs = env.SEMGREP_TIMEOUT_MS,
    memoryLimit = env.SEMGREP_MEMORY_LIMIT,
  } = options;

  logger.info({ scanId, workspacePath, rulesPath }, 'Starting Semgrep scan execution');

  // Command arguments for Semgrep inside container
  const commandArgs = [
    'semgrep',
    'scan',
    '--json',
    '--config', '/rules',
    '--no-git-ignore',
    '--disable-version-check',
    '--metrics=off',
    '/src',
  ];

  const runnerResult = await runDockerScanner({
    scanId,
    scannerName: 'semgrep',
    workspacePath,
    rulesPath,
    commandArgs,
    timeoutMs,
    memoryLimit,
  });

  const { stdout, stderr, exitCode, durationMs } = runnerResult;

  // Semgrep exits with 0 (no findings or clean) or 1 (findings detected)
  // Non-zero exit code >= 2 indicates a fatal syntax / configuration error
  if (exitCode > 1 && !stdout.trim().startsWith('{')) {
    logger.error(
      { scanId, exitCode, stderr },
      'Semgrep scanner failed with non-zero exit code'
    );
    throw new Error(`Semgrep execution failed (exit code ${exitCode}): ${stderr || 'Unknown error'}`);
  }

  // Parse and normalize JSON output
  const normalization = normalizeSemgrepOutput(scanId, userId, stdout);

  logger.info(
    {
      scanId,
      totalFindings: normalization.summary.total,
      critical: normalization.summary.critical,
      high: normalization.summary.high,
      medium: normalization.summary.medium,
      low: normalization.summary.low,
      info: normalization.summary.info,
      durationMs,
    },
    'Semgrep scan completed and normalized successfully'
  );

  return {
    normalization,
    durationMs,
    rawStdoutLength: stdout.length,
  };
}
