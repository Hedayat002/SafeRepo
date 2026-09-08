import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import {
  enqueueScanJob,
  claimNextScanJob,
  updateScanHeartbeat,
  transitionScanStatus,
  reconcileStaleScans,
  checkAndHandleScanCancellation,
  createScanWorker,
  type ScanWorker,
} from '../queue';
import * as runnerModule from '../runner';
import * as workspaceModule from '../workspace';

describe('Phase 06 — Queue, Worker & Reconciliation Sweeper', () => {
  const userId = new mongoose.Types.ObjectId();
  const activeWorkers: ScanWorker[] = [];

  beforeEach(async () => {
    await Scan.deleteMany({});
    await Finding.deleteMany({});
    vi.clearAllMocks();
  });

  afterEach(async () => {
    // Clean up any active workers to avoid open handles
    for (const worker of activeWorkers) {
      if (worker.isRunning()) {
        await worker.stop(500);
      }
    }
    activeWorkers.length = 0;
    vi.restoreAllMocks();
  });

  describe('enqueueScanJob', () => {
    it('creates a scan in queued status with empty summary', async () => {
      const scan = await enqueueScanJob({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'queued-app',
        repositoryUrl: 'https://github.com/safe-org/queued-app',
        branch: 'main',
      });

      expect(scan._id).toBeDefined();
      expect(scan.status).toBe('queued');
      expect(scan.summary.total).toBe(0);
      expect(scan.workerId).toBeNull();
      expect(scan.heartbeatAt).toBeNull();
    });
  });

  describe('claimNextScanJob', () => {
    it('atomically claims the oldest queued job in FIFO order', async () => {
      // Create first scan
      const scan1 = await enqueueScanJob({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'repo-1',
        repositoryUrl: 'https://github.com/safe-org/repo-1',
        branch: 'main',
      });

      // Artificial delay to ensure distinct createdAt timestamps
      await new Promise((r) => setTimeout(r, 50));

      // Create second scan
      const scan2 = await enqueueScanJob({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'repo-2',
        repositoryUrl: 'https://github.com/safe-org/repo-2',
        branch: 'main',
      });

      // Claim job
      const claimed = await claimNextScanJob('worker-test-1');
      expect(claimed).not.toBeNull();
      expect(claimed?._id.toString()).toBe(scan1._id.toString());
      expect(claimed?.status).toBe('cloning');
      expect(claimed?.workerId).toBe('worker-test-1');
      expect(claimed?.heartbeatAt).toBeInstanceOf(Date);
      expect(claimed?.startedAt).toBeInstanceOf(Date);

      // Next claim should get repo-2
      const claimed2 = await claimNextScanJob('worker-test-2');
      expect(claimed2?._id.toString()).toBe(scan2._id.toString());

      // Next claim should return null (queue empty)
      const claimed3 = await claimNextScanJob('worker-test-1');
      expect(claimed3).toBeNull();
    });

    it('returns null when queue has no queued scans', async () => {
      const claimed = await claimNextScanJob('worker-empty');
      expect(claimed).toBeNull();
    });
  });

  describe('updateScanHeartbeat', () => {
    it('updates heartbeat when workerId matches and status is active', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'heartbeat-app',
        repositoryUrl: 'https://github.com/safe-org/heartbeat-app',
        branch: 'main',
        status: 'scanning',
        workerId: 'worker-hb-1',
        heartbeatAt: new Date(Date.now() - 10_000),
      });

      const updated = await updateScanHeartbeat(scan._id.toString(), 'worker-hb-1');
      expect(updated).toBe(true);

      const refreshed = await Scan.findById(scan._id);
      expect(refreshed?.heartbeatAt!.getTime()).toBeGreaterThan(scan.heartbeatAt!.getTime());
    });

    it('fails to update heartbeat if lease lost (different workerId)', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'heartbeat-app',
        repositoryUrl: 'https://github.com/safe-org/heartbeat-app',
        branch: 'main',
        status: 'scanning',
        workerId: 'worker-hb-1',
        heartbeatAt: new Date(),
      });

      const updated = await updateScanHeartbeat(scan._id.toString(), 'wrong-worker');
      expect(updated).toBe(false);
    });

    it('fails to update heartbeat if scan is already completed or failed', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'heartbeat-app',
        repositoryUrl: 'https://github.com/safe-org/heartbeat-app',
        branch: 'main',
        status: 'completed',
        workerId: 'worker-hb-1',
        heartbeatAt: new Date(),
      });

      const updated = await updateScanHeartbeat(scan._id.toString(), 'worker-hb-1');
      expect(updated).toBe(false);
    });
  });

  describe('transitionScanStatus', () => {
    it('transitions status atomically when workerId and fromStatus match', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'status-app',
        repositoryUrl: 'https://github.com/safe-org/status-app',
        branch: 'main',
        status: 'cloning',
        workerId: 'worker-trans-1',
      });

      const transitioned = await transitionScanStatus(
        scan._id.toString(),
        'worker-trans-1',
        'cloning',
        'scanning',
        { commitSha: 'abc1234' }
      );

      expect(transitioned).not.toBeNull();
      expect(transitioned?.status).toBe('scanning');
      expect(transitioned?.commitSha).toBe('abc1234');
      expect(transitioned?.heartbeatAt).toBeInstanceOf(Date);
    });

    it('rejects transition if fromStatus does not match', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'status-app',
        repositoryUrl: 'https://github.com/safe-org/status-app',
        branch: 'main',
        status: 'cloning',
        workerId: 'worker-trans-1',
      });

      const transitioned = await transitionScanStatus(
        scan._id.toString(),
        'worker-trans-1',
        'scanning', // Mismatched fromStatus
        'normalizing'
      );

      expect(transitioned).toBeNull();
    });
  });

  describe('reconcileStaleScans (Reconciliation Sweeper)', () => {
    it('detects and marks abandoned scans as failed with orphan cleanup', async () => {
      const staleDate = new Date(Date.now() - 400_000); // Expired beyond 360s stale timeout

      const staleScan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'stale-app',
        repositoryUrl: 'https://github.com/safe-org/stale-app',
        branch: 'main',
        status: 'scanning',
        workerId: 'crashed-worker-999',
        heartbeatAt: staleDate,
        workspacePath: 'tmp/workspaces/stale-scan-123',
      });

      // Insert orphaned partial findings
      await Finding.create({
        scanId: staleScan._id,
        userId,
        category: 'sast',
        scanner: 'semgrep',
        vulnerabilityId: 'test-rule',
        title: 'Test finding',
        description: 'Test description',
        severity: 'high',
        file: 'src/index.ts',
        line: 1,
        fingerprint: 'fp-stale-1',
      });

      const killSpy = vi.spyOn(runnerModule, 'killDockerContainer').mockResolvedValue();
      const cleanSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      const reconciledCount = await reconcileStaleScans();

      expect(reconciledCount).toBe(1);

      // Verify scan finalized as failed
      const updatedScan = await Scan.findById(staleScan._id);
      expect(updatedScan?.status).toBe('failed');
      expect(updatedScan?.error).toContain('terminated unexpectedly');
      expect(updatedScan?.completedAt).toBeInstanceOf(Date);

      // Verify deterministic container kill calls
      expect(killSpy).toHaveBeenCalledWith(`saferepo-scan-${staleScan._id}-semgrep`);
      expect(killSpy).toHaveBeenCalledWith(`saferepo-scan-${staleScan._id}-trivy`);
      expect(killSpy).toHaveBeenCalledWith(`saferepo-scan-${staleScan._id}-gitleaks`);

      // Verify workspace cleaned
      expect(cleanSpy).toHaveBeenCalledWith('tmp/workspaces/stale-scan-123');

      // Verify partial findings purged
      const remainingFindings = await Finding.find({ scanId: staleScan._id });
      expect(remainingFindings).toHaveLength(0);
    });

    it('does not touch healthy scans whose heartbeat is recent', async () => {
      await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'healthy-app',
        repositoryUrl: 'https://github.com/safe-org/healthy-app',
        branch: 'main',
        status: 'scanning',
        workerId: 'healthy-worker-1',
        heartbeatAt: new Date(), // Active heartbeat
      });

      const reconciledCount = await reconcileStaleScans();
      expect(reconciledCount).toBe(0);
    });
  });

  describe('createScanWorker Lifecycle', () => {
    it('claims and executes jobs, respecting concurrency limit', async () => {
      await enqueueScanJob({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'worker-test-app',
        repositoryUrl: 'https://github.com/safe-org/worker-test-app',
        branch: 'main',
      });

      let executedScanId: string | null = null;
      let executionWorkerId: string | null = null;

      const worker = createScanWorker(async (scan, workerId) => {
        executedScanId = scan._id.toString();
        executionWorkerId = workerId;
        // Simulate quick scan execution
        await transitionScanStatus(scan._id.toString(), workerId, 'cloning', 'completed');
      });
      activeWorkers.push(worker);

      await worker.start();
      expect(worker.isRunning()).toBe(true);

      // Wait a moment for the immediate poll to execute
      await new Promise((r) => setTimeout(r, 200));

      expect(executedScanId).not.toBeNull();
      expect(executionWorkerId).toBe(worker.workerId);

      await worker.stop(500);
      expect(worker.isRunning()).toBe(false);
    });
  });

  describe('checkAndHandleScanCancellation & Cancellation in Worker', () => {
    it('cancels active scan when cancelRequested is true', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'cancel-app',
        repositoryUrl: 'https://github.com/safe-org/cancel-app',
        branch: 'main',
        status: 'scanning',
        workerId: 'worker-cancel-1',
        cancelRequested: true,
      });

      const cancelled = await checkAndHandleScanCancellation(scan._id.toString(), 'worker-cancel-1');
      expect(cancelled).toBe(true);

      const refreshed = await Scan.findById(scan._id);
      expect(refreshed?.status).toBe('failed');
      expect(refreshed?.error).toBe('Scan cancelled by user');
      expect(refreshed?.completedAt).not.toBeNull();
    });

    it('returns false and leaves scan untouched when cancelRequested is false', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'not-cancelled',
        repositoryUrl: 'https://github.com/safe-org/not-cancelled',
        branch: 'main',
        status: 'scanning',
        workerId: 'worker-cancel-1',
        cancelRequested: false,
      });

      const cancelled = await checkAndHandleScanCancellation(scan._id.toString(), 'worker-cancel-1');
      expect(cancelled).toBe(false);

      const refreshed = await Scan.findById(scan._id);
      expect(refreshed?.status).toBe('scanning');
      expect(refreshed?.error).toBeNull();
    });

    it('returns false when workerId does not match', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'other-worker-app',
        repositoryUrl: 'https://github.com/safe-org/other-worker-app',
        branch: 'main',
        status: 'scanning',
        workerId: 'worker-original',
        cancelRequested: true,
      });

      const cancelled = await checkAndHandleScanCancellation(scan._id.toString(), 'different-worker');
      expect(cancelled).toBe(false);

      const refreshed = await Scan.findById(scan._id);
      expect(refreshed?.status).toBe('scanning');
    });

    it('purges partial findings and cleans workspace upon cancellation', async () => {
      const killDockerSpy = vi.spyOn(runnerModule, 'killDockerContainer').mockResolvedValue();
      const cleanWorkspaceSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'cleanup-cancelled',
        repositoryUrl: 'https://github.com/safe-org/cleanup-cancelled',
        branch: 'main',
        status: 'scanning',
        workerId: 'worker-cleanup',
        cancelRequested: true,
        workspacePath: '/tmp/saferepo/cancel-test',
      });

      await Finding.create({
        scanId: scan._id,
        userId,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'high',
        title: 'Partial Finding',
        description: 'Should be purged',
        file: 'test.js',
        line: 1,
        fingerprint: new mongoose.Types.ObjectId().toString(),
      });

      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(1);

      const cancelled = await checkAndHandleScanCancellation(scan._id.toString(), 'worker-cleanup');
      expect(cancelled).toBe(true);

      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(0);
      expect(cleanWorkspaceSpy).toHaveBeenCalledWith('/tmp/saferepo/cancel-test');
      expect(killDockerSpy).toHaveBeenCalled();
    });

    it('worker abortSignal triggers when heartbeat detects cancellation', async () => {
      const scan = await enqueueScanJob({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'worker-cancel-test',
        repositoryUrl: 'https://github.com/safe-org/worker-cancel-test',
        branch: 'main',
      });

      let observedAbort = false;

      const worker = createScanWorker(async (claimedScan, workerId, abortSignal) => {
        abortSignal?.addEventListener('abort', () => {
          observedAbort = true;
        });

        // Set cancelRequested while scan is executing
        await Scan.updateOne({ _id: claimedScan._id }, { $set: { cancelRequested: true } });

        // Trigger check
        await checkAndHandleScanCancellation(claimedScan._id.toString(), workerId);
      });
      activeWorkers.push(worker);

      await worker.start();
      await new Promise((r) => setTimeout(r, 200));

      const finalScan = await Scan.findById(scan._id);
      expect(finalScan?.status).toBe('failed');
      expect(finalScan?.error).toBe('Scan cancelled by user');
      expect(observedAbort).toBeDefined();

      await worker.stop(500);
    });
  });
});
