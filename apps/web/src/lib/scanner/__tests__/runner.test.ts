import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';
import { Readable } from 'stream';
import path from 'path';

vi.mock('child_process', () => ({
  spawn: vi.fn(),
}));

import { spawn, type ChildProcess } from 'child_process';
import {
  buildStage1DockerArgs,
  ScannerTimeoutError,
  OutputSizeExceededError,
  killDockerContainer,
  runDockerScanner,
} from '../runner';

const mockSpawn = vi.mocked(spawn);

function createMockChildProcess(): ChildProcess {
  const stdout = new Readable({ read() {} });
  const stderr = new Readable({ read() {} });

  const proc = Object.assign(new EventEmitter(), {
    stdout,
    stderr,
    stdin: null,
    stdio: [null, stdout, stderr, null, null],
    killed: false,
    pid: 12345,
    kill: vi.fn(),
    send: vi.fn(),
    disconnect: vi.fn(),
    unref: vi.fn(),
    ref: vi.fn(),
    exitCode: null,
    signalCode: null,
    spawnargs: [],
    spawnfile: '',
    connected: false,
  }) as unknown as ChildProcess;

  return proc;
}

describe('Scanner Runner (Docker Stage 1 Isolation)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('builds compliant Stage 1 Docker CLI arguments', () => {
    const workspacePath = path.resolve('/tmp/test-workspace');
    const rulesPath = path.resolve('/tmp/test-rules');

    const args = buildStage1DockerArgs({
      containerName: 'saferepo-scan-123-semgrep',
      workspacePath,
      rulesPath,
      image: 'semgrep/semgrep:1.100.0',
      memoryLimit: '512m',
      commandArgs: ['semgrep', 'scan', '--json', '/src'],
    });

    expect(args).toContain('run');
    expect(args).toContain('--rm');
    expect(args).toContain('--name');
    expect(args).toContain('saferepo-scan-123-semgrep');
    expect(args).toContain('--network=none');
    expect(args).toContain('--read-only');
    expect(args).toContain('--tmpfs');
    expect(args).toContain('/tmp:rw,noexec,nosuid,size=64m');
    expect(args).toContain('/home/semgrep:rw,noexec,nosuid,size=32m');
    expect(args).toContain('--security-opt=no-new-privileges');
    expect(args).toContain('--cap-drop=ALL');
    expect(args).toContain('--user');
    expect(args).toContain('1000:1000');
    expect(args).toContain('--cpus=1');
    expect(args).toContain('--memory');
    expect(args).toContain('512m');
    expect(args).toContain('--pids-limit=256');

    // Mounts
    expect(args).toContain('-v');
    expect(args).toContain(`${workspacePath}:/src:ro`);
    expect(args).toContain(`${rulesPath}:/rules:ro`);
    expect(args).toContain('-w');
    expect(args).toContain('/src');

    // Image & command
    expect(args).toContain('semgrep/semgrep:1.100.0');
    expect(args).toContain('semgrep');
    expect(args).toContain('scan');
  });

  it('builds Stage 1 Docker args without rulesPath', () => {
    const args = buildStage1DockerArgs({
      containerName: 'test-no-rules',
      workspacePath: '/tmp/workspace',
      image: 'semgrep/semgrep:1.100.0',
      memoryLimit: '512m',
      commandArgs: ['semgrep', 'scan'],
    });

    const hasRulesMount = args.some((a) => a.includes(':/rules:ro'));
    expect(hasRulesMount).toBe(false);
    expect(args).toContain('--network=none');
    expect(args).toContain('--read-only');
  });

  it('instantiates custom error classes correctly', () => {
    const timeoutErr = new ScannerTimeoutError('Test timeout');
    expect(timeoutErr.statusCode).toBe(408);
    expect(timeoutErr.code).toBe('SCAN_TIMEOUT');
    expect(timeoutErr.message).toBe('Test timeout');

    const outputErr = new OutputSizeExceededError('Test buffer overflow');
    expect(outputErr.statusCode).toBe(413);
    expect(outputErr.code).toBe('OUTPUT_SIZE_EXCEEDED');
    expect(outputErr.message).toBe('Test buffer overflow');
  });

  describe('killDockerContainer', () => {
    it('resolves when docker kill process closes', async () => {
      const mockProc = createMockChildProcess();
      mockSpawn.mockReturnValue(mockProc);

      const promise = killDockerContainer('test-container');
      mockProc.emit('close', 0);

      await expect(promise).resolves.toBeUndefined();
      expect(mockSpawn).toHaveBeenCalledWith(
        'docker',
        ['kill', 'test-container'],
        expect.objectContaining({ shell: false })
      );
    });

    it('resolves even when docker kill emits error', async () => {
      const mockProc = createMockChildProcess();
      mockSpawn.mockReturnValue(mockProc);

      const promise = killDockerContainer('test-container');
      mockProc.emit('error', new Error('docker not found'));

      await expect(promise).resolves.toBeUndefined();
    });
  });

  describe('runDockerScanner', () => {
    const baseOptions = {
      scanId: 'test-scan',
      scannerName: 'semgrep',
      workspacePath: '/tmp/workspace',
      timeoutMs: 60000,
      memoryLimit: '512m',
      maxStdoutBytes: 10_000_000,
      image: 'semgrep/semgrep:1.100.0',
      commandArgs: ['semgrep', 'scan', '--json', '/src'],
    };

    it('resolves with stdout, stderr, and exitCode on success', async () => {
      const mockProc = createMockChildProcess();
      mockSpawn.mockReturnValue(mockProc);

      const promise = runDockerScanner(baseOptions);

      mockProc.stdout?.emit('data', Buffer.from('{"results":[]}'));
      mockProc.stderr?.emit('data', Buffer.from('some warning'));
      mockProc.emit('close', 0);

      const result = await promise;
      expect(result.stdout).toBe('{"results":[]}');
      expect(result.stderr).toBe('some warning');
      expect(result.exitCode).toBe(0);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('resolves with non-zero exit code when findings present', async () => {
      const mockProc = createMockChildProcess();
      mockSpawn.mockReturnValue(mockProc);

      const promise = runDockerScanner(baseOptions);

      mockProc.stdout?.emit('data', Buffer.from('{"results":[{"check_id":"test"}]}'));
      mockProc.emit('close', 1);

      const result = await promise;
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain('results');
    });

    it('treats null exit code as 0', async () => {
      const mockProc = createMockChildProcess();
      mockSpawn.mockReturnValue(mockProc);

      const promise = runDockerScanner(baseOptions);
      mockProc.emit('close', null);

      const result = await promise;
      expect(result.exitCode).toBe(0);
    });

    it('rejects with ScannerTimeoutError when timeout expires', async () => {
      const runProc = createMockChildProcess();
      const killProc = createMockChildProcess();
      mockSpawn
        .mockReturnValueOnce(runProc)
        .mockReturnValueOnce(killProc);

      const promise = runDockerScanner({
        ...baseOptions,
        timeoutMs: 50,
      });

      // Wait for timeout to fire (50ms) + buffer
      await new Promise((r) => setTimeout(r, 120));

      // Kill container process completes
      killProc.emit('close', 0);

      await expect(promise).rejects.toBeInstanceOf(ScannerTimeoutError);
    }, 5000);

    it('rejects with OutputSizeExceededError when stdout exceeds limit', async () => {
      const runProc = createMockChildProcess();
      const killProc = createMockChildProcess();
      mockSpawn
        .mockReturnValueOnce(runProc)
        .mockReturnValueOnce(killProc);

      const promise = runDockerScanner({
        ...baseOptions,
        maxStdoutBytes: 100,
      });

      // Emit chunk exceeding the byte limit
      runProc.stdout?.emit('data', Buffer.alloc(200, 'x'));

      // Kill container process completes, triggering .finally() reject
      killProc.emit('close', 0);

      await expect(promise).rejects.toBeInstanceOf(OutputSizeExceededError);
    });

    it('rejects with OutputSizeExceededError when stderr exceeds limit', async () => {
      const runProc = createMockChildProcess();
      const killProc = createMockChildProcess();
      mockSpawn
        .mockReturnValueOnce(runProc)
        .mockReturnValueOnce(killProc);

      const promise = runDockerScanner({
        ...baseOptions,
        maxStdoutBytes: 100,
      });

      // Emit stderr chunk exceeding the byte limit
      runProc.stderr?.emit('data', Buffer.alloc(200, 'e'));

      // Kill container process completes
      killProc.emit('close', 0);

      await expect(promise).rejects.toBeInstanceOf(OutputSizeExceededError);
    });

    it('rejects on Docker process error event', async () => {
      const mockProc = createMockChildProcess();
      mockSpawn.mockReturnValue(mockProc);

      const promise = runDockerScanner(baseOptions);
      mockProc.emit('error', new Error('Docker daemon not running'));

      await expect(promise).rejects.toThrow('Docker daemon not running');
    });

    it('rejects when spawn throws synchronously', async () => {
      mockSpawn.mockImplementation(() => {
        throw new Error('spawn ENOENT');
      });

      await expect(runDockerScanner(baseOptions)).rejects.toThrow('spawn ENOENT');
    });
  });
});
