import { spawn, type ChildProcess } from 'child_process';
import path from 'path';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { AppError } from '@/lib/errors';

/**
 * Custom error thrown when scanner exceeds execution time limit.
 */
export class ScannerTimeoutError extends AppError {
  constructor(message = 'Scanner execution timed out') {
    super(message, {
      code: 'SCAN_TIMEOUT',
      statusCode: 408,
    });
    this.name = 'ScannerTimeoutError';
  }
}

/**
 * Custom error thrown when scanner output exceeds maximum byte limit.
 */
export class OutputSizeExceededError extends AppError {
  constructor(message = 'Scanner stdout exceeded maximum buffer limit') {
    super(message, {
      code: 'OUTPUT_SIZE_EXCEEDED',
      statusCode: 413,
    });
    this.name = 'OutputSizeExceededError';
  }
}

export interface DockerVolumeMount {
  source: string;
  target: string;
  readonly?: boolean;
}

export interface RunDockerScannerOptions {
  scanId: string;
  scannerName: string;
  workspacePath: string;
  rulesPath?: string;
  image?: string;
  commandArgs?: string[];
  timeoutMs?: number;
  memoryLimit?: string;
  maxStdoutBytes?: number;
  homeTmpfs?: string;
  extraEnv?: Record<string, string>;
  extraMounts?: DockerVolumeMount[];
}

export interface RunDockerScannerResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
}

/**
 * Forcefully terminates a running Docker container by name.
 */
export async function killDockerContainer(containerName: string): Promise<void> {
  return new Promise((resolve) => {
    logger.warn({ containerName }, 'Issuing docker kill to container');
    const killProcess = spawn('docker', ['kill', containerName], {
      shell: false,
      env: process.env,
    });

    killProcess.on('close', () => {
      resolve();
    });

    killProcess.on('error', (err: Error) => {
      logger.warn({ err: err.message, containerName }, 'Failed to issue docker kill');
      resolve();
    });
  });
}

/**
 * Builds deterministic, hardened Stage 1 Docker CLI arguments.
 */
export function buildStage1DockerArgs(options: {
  containerName: string;
  workspacePath: string;
  rulesPath?: string;
  image: string;
  memoryLimit: string;
  commandArgs: string[];
  homeTmpfs?: string;
  extraEnv?: Record<string, string>;
  extraMounts?: DockerVolumeMount[];
}): string[] {
  const {
    containerName,
    workspacePath,
    rulesPath,
    image,
    memoryLimit,
    commandArgs,
    homeTmpfs,
    extraEnv,
    extraMounts,
  } = options;

  // Resolve absolute paths
  const resolvedWorkspace = path.resolve(workspacePath);

  const args: string[] = [
    'run',
    '--rm',
    '--name', containerName,
    '--network=none',
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
  ];

  // User home tmpfs
  if (homeTmpfs) {
    args.push('--tmpfs', homeTmpfs);
  } else {
    // Default Semgrep home tmpfs
    args.push('--tmpfs', '/home/semgrep:rw,noexec,nosuid,size=32m');
  }

  args.push(
    '--security-opt=no-new-privileges',
    '--cap-drop=ALL',
    '--user', '1000:1000',
    '--cpus=1',
    '--memory', memoryLimit,
    '--pids-limit=256'
  );

  // Environment variables
  if (extraEnv) {
    for (const [key, val] of Object.entries(extraEnv)) {
      args.push('-e', `${key}=${val}`);
    }
  } else {
    // Default Semgrep environment
    args.push(
      '-e', 'XDG_CACHE_HOME=/tmp/cache',
      '-e', 'SEMGREP_SETTINGS_FILE=/tmp/settings.yaml'
    );
  }

  // Workspace mount (always read-only)
  args.push('-v', `${resolvedWorkspace}:/src:ro`);

  if (rulesPath) {
    const resolvedRules = path.resolve(rulesPath);
    args.push('-v', `${resolvedRules}:/rules:ro`);
  }

  // Additional read-only mounts (e.g. Trivy DB)
  if (extraMounts) {
    for (const m of extraMounts) {
      const resolved = path.resolve(m.source);
      const mode = m.readonly ?? true ? 'ro' : 'rw';
      args.push('-v', `${resolved}:${m.target}:${mode}`);
    }
  }

  args.push('-w', '/src');
  args.push(image);
  args.push(...commandArgs);

  return args;
}

/**
 * Executes a security scanner inside a Stage 1 hardened ephemeral Docker container.
 *
 * Enforces:
 * - Stage 1 security isolation flags
 * - Hard timeout with automatic docker kill
 * - Maximum stdout byte stream limit to protect host memory
 * - Non-root least-privileged execution
 */
export async function runDockerScanner(
  options: RunDockerScannerOptions
): Promise<RunDockerScannerResult> {
  const {
    scanId,
    scannerName,
    workspacePath,
    rulesPath,
    image = env.SEMGREP_IMAGE,
    commandArgs = [
      'semgrep',
      'scan',
      '--json',
      '--config', '/rules',
      '--no-git-ignore',
      '--disable-version-check',
      '--metrics=off',
      '/src',
    ],
    timeoutMs = env.SEMGREP_TIMEOUT_MS,
    memoryLimit = env.SEMGREP_MEMORY_LIMIT,
    maxStdoutBytes = env.MAX_SCANNER_STDOUT_BYTES,
    homeTmpfs,
    extraEnv,
    extraMounts,
  } = options;

  const containerName = `saferepo-scan-${scanId}-${scannerName}`;
  const startTime = Date.now();

  const dockerArgs = buildStage1DockerArgs({
    containerName,
    workspacePath,
    rulesPath,
    image,
    memoryLimit,
    commandArgs,
    homeTmpfs,
    extraEnv,
    extraMounts,
  });

  logger.info(
    { scanId, scanner: scannerName, containerName, image },
    'Spawning hardened Docker scanner container'
  );

  return new Promise<RunDockerScannerResult>((resolve, reject) => {
    let childProcess: ChildProcess | null = null;
    let stdoutBuffer = '';
    let stderrBuffer = '';
    let totalStdoutBytes = 0;
    let isTerminated = false;
    let timer: NodeJS.Timeout | null = null;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    };

    // 1. Timeout Controller
    timer = setTimeout(async () => {
      if (isTerminated) return;
      isTerminated = true;
      cleanup();

      logger.error(
        { scanId, scanner: scannerName, timeoutMs },
        'Scanner execution exceeded timeout limit'
      );

      await killDockerContainer(containerName);

      if (childProcess) {
        try {
          childProcess.kill('SIGKILL');
        } catch {
          // ignore
        }
      }

      reject(new ScannerTimeoutError(`Scanner execution timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    let proc: ChildProcess;
    try {
      // 2. Spawn Docker CLI directly without shell
      proc = spawn('docker', dockerArgs, {
        shell: false,
        env: process.env,
      });
      childProcess = proc;
    } catch (err) {
      cleanup();
      reject(err);
      return;
    }

    // 3. Stream reader for stdout with buffer size limit
    proc.stdout?.on('data', (chunk: Buffer) => {
      if (isTerminated) return;
      totalStdoutBytes += chunk.length;

      if (totalStdoutBytes > maxStdoutBytes) {
        isTerminated = true;
        cleanup();

        logger.error(
          { scanId, scanner: scannerName, totalStdoutBytes, maxStdoutBytes },
          'Scanner stdout exceeded maximum allowed byte limit'
        );

        proc.stdout?.destroy();
        proc.stderr?.destroy();

        void killDockerContainer(containerName).finally(() => {
          try {
            proc.kill('SIGKILL');
          } catch {
            // ignore
          }
          reject(
            new OutputSizeExceededError(
              `Scanner output exceeded maximum allowed size of ${(maxStdoutBytes / 1024 / 1024).toFixed(1)} MB`
            )
          );
        });
        return;
      }

      stdoutBuffer += chunk.toString('utf-8');
    });

    let totalStderrBytes = 0;

    // 4. Stream reader for stderr with buffer size limit
    proc.stderr?.on('data', (chunk: Buffer) => {
      if (isTerminated) return;
      totalStderrBytes += chunk.length;

      if (totalStderrBytes > maxStdoutBytes) {
        isTerminated = true;
        cleanup();

        logger.error(
          { scanId, scanner: scannerName, totalStderrBytes, maxStdoutBytes },
          'Scanner stderr exceeded maximum allowed byte limit'
        );

        proc.stdout?.destroy();
        proc.stderr?.destroy();

        void killDockerContainer(containerName).finally(() => {
          try {
            proc.kill('SIGKILL');
          } catch {
            // ignore
          }
          reject(
            new OutputSizeExceededError(
              `Scanner stderr exceeded maximum allowed size of ${(maxStdoutBytes / 1024 / 1024).toFixed(1)} MB`
            )
          );
        });
        return;
      }

      stderrBuffer += chunk.toString('utf-8');
    });

    proc.on('error', (err: Error) => {
      if (isTerminated) return;
      isTerminated = true;
      cleanup();
      logger.error({ scanId, scanner: scannerName, error: err.message }, 'Docker spawn process error');
      reject(err);
    });

    proc.on('close', (code: number | null) => {
      if (isTerminated) return;
      isTerminated = true;
      cleanup();

      const durationMs = Date.now() - startTime;
      const exitCode = code ?? 0;

      logger.info(
        { scanId, scanner: scannerName, exitCode, durationMs, stdoutBytes: totalStdoutBytes },
        'Docker scanner container exited'
      );

      resolve({
        stdout: stdoutBuffer,
        stderr: stderrBuffer,
        exitCode,
        durationMs,
      });
    });
  });
}
