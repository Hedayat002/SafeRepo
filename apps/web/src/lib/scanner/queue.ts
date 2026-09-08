import os from 'os';
import crypto from 'crypto';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { Scan, type IScan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { cleanupWorkspace } from './workspace';
import { killDockerContainer } from './runner';
import type { ScanQueueConfig } from '@/types';

/**
 * Phase 06 — In-Database Scan Queue, Worker & Reconciliation
 *
 * Implements:
 * - MongoDB-backed FIFO scan queue with atomic claiming
 * - Bounded concurrency control (MAX_CONCURRENT_SCANS)
 * - Periodic heartbeat monitoring
 * - Startup and periodic stale-scan reconciliation sweeper
 * - Graceful shutdown with drain semantics
 *
 * Delivery Semantics:
 * - Atomic single-owner claim: YES (findOneAndUpdate)
 * - Exactly-once execution: NOT guaranteed
 * - Idempotent persistence: YES (fingerprint unique index)
 *
 * Recovery Semantics:
 * - Stale scans are finalized as 'failed' (not re-queued)
 * - Prevents poison job retry loops
 */

// ─── Scanner names for deterministic container naming ───
const DOCKER_SCANNERS = ['semgrep', 'trivy', 'gitleaks'] as const;

// ─── Worker Configuration ───

function getQueueConfig(): ScanQueueConfig {
  return {
    maxConcurrentScans: env.MAX_CONCURRENT_SCANS,
    pollIntervalMs: env.SCAN_QUEUE_POLL_INTERVAL_MS,
    staleTimeoutMs: env.SCAN_STALE_TIMEOUT_MS,
    scanTimeoutSeconds: env.SCAN_TIMEOUT_SECONDS,
    heartbeatIntervalMs: 15_000, // 15s heartbeat interval
  };
}

function generateWorkerId(): string {
  const hostname = os.hostname();
  const pid = process.pid;
  const ts = Date.now();
  const uuid = crypto.randomUUID();
  return `worker-${hostname}-${pid}-${ts}-${uuid}`;
}

// ─── Queue Operations ───

export interface EnqueueScanJobInput {
  userId: string | import('mongoose').Types.ObjectId;
  repositoryOwner: string;
  repositoryName: string;
  repositoryUrl: string;
  branch: string;
}

/**
 * Enqueues a new scan job in MongoDB with status: 'queued'.
 * Atomic durable write per Phase 06 queue specifications.
 */
export async function enqueueScanJob(input: EnqueueScanJobInput): Promise<IScan> {
  const scan = await Scan.create({
    userId: input.userId,
    repositoryOwner: input.repositoryOwner,
    repositoryName: input.repositoryName,
    repositoryUrl: input.repositoryUrl,
    branch: input.branch,
    status: 'queued',
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  });
  return scan;
}

/**
 * Atomically claims the next queued scan job using FIFO ordering.
 * MongoDB document-level locking ensures single-owner claiming.
 * Competing workers receive null.
 */
export async function claimNextScanJob(workerId: string): Promise<IScan | null> {
  const now = new Date();
  const scan = await Scan.findOneAndUpdate(
    { status: 'queued' },
    {
      $set: {
        status: 'cloning',
        workerId,
        startedAt: now,
        heartbeatAt: now,
      },
    },
    { sort: { createdAt: 1 }, returnDocument: 'after' }
  );
  return scan as unknown as IScan | null;
}

/**
 * Updates heartbeat timestamp for a leased scan.
 * Uses conditional ownership check to detect lease loss.
 * Returns true if heartbeat was updated, false if lease was lost.
 */
export async function updateScanHeartbeat(
  scanId: string,
  workerId: string
): Promise<boolean> {
  const result = await Scan.findOneAndUpdate(
    {
      _id: scanId,
      workerId,
      status: { $in: ['cloning', 'scanning', 'normalizing'] },
    },
    { $set: { heartbeatAt: new Date() } },
    { returnDocument: 'after' }
  );
  return result !== null;
}

/**
 * Transitions scan status with lease ownership verification.
 * Returns null if the transition was rejected (lease lost or invalid state).
 */
export async function transitionScanStatus(
  scanId: string,
  workerId: string,
  fromStatus: string,
  toStatus: string,
  metadata: Record<string, unknown> = {}
): Promise<IScan | null> {
  const update: Record<string, unknown> = {
    status: toStatus,
    heartbeatAt: new Date(),
    ...metadata,
  };

  const scan = await Scan.findOneAndUpdate(
    {
      _id: scanId,
      workerId,
      status: fromStatus,
    } as Record<string, unknown>,
    { $set: update },
    { returnDocument: 'after' }
  );
  return scan as IScan | null;
}

// ─── Reconciliation Sweeper ───

/**
 * Reconciles stale scans whose worker heartbeat has expired.
 *
 * Uses atomic conditional transitions to prevent race conditions:
 * - Verifies staleness at write time (heartbeatAt < staleThreshold)
 * - Verifies worker ownership (workerId matches stale worker)
 * - Verifies status is active (cloning/scanning/normalizing)
 *
 * If a healthy worker updates its heartbeat between the sweeper's read and write,
 * the condition no longer matches and no cleanup is performed.
 *
 * Recovery policy: Failed-finalization (not re-queueing) to prevent poison job loops.
 */
export async function reconcileStaleScans(): Promise<number> {
  const config = getQueueConfig();
  const staleThreshold = new Date(Date.now() - config.staleTimeoutMs);
  let reconciledCount = 0;

  // Find stale scans (read phase)
  const staleScans = await Scan.find({
    status: { $in: ['cloning', 'scanning', 'normalizing'] },
    heartbeatAt: { $lt: staleThreshold },
  }).lean();

  if (staleScans.length === 0) {
    return 0;
  }

  logger.warn(
    { count: staleScans.length },
    'Reconciliation sweeper detected stale scans'
  );

  for (const staleScan of staleScans) {
    const scanId = staleScan._id.toString();
    const staleWorkerId = staleScan.workerId;

    // Atomic conditional transition — verifies staleness + ownership at write time
    const result = await Scan.findOneAndUpdate(
      {
        _id: staleScan._id,
        status: { $in: ['cloning', 'scanning', 'normalizing'] },
        heartbeatAt: { $lt: staleThreshold },
        workerId: staleWorkerId,
      },
      {
        $set: {
          status: 'failed',
          error: 'Scan worker terminated unexpectedly (reconciled by sweeper)',
          completedAt: new Date(),
        },
      },
      { returnDocument: 'after' }
    );

    if (!result) {
      // Worker recovered and updated heartbeat, or scan already transitioned.
      logger.info(
        { scanId },
        'Stale scan recovered or already finalized — skipping cleanup'
      );
      continue;
    }

    // Cleanup ONLY after successful atomic transition
    logger.info({ scanId, workerId: staleWorkerId }, 'Reconciling stale scan');

    // 1. Kill orphaned Docker containers using deterministic naming
    for (const scanner of DOCKER_SCANNERS) {
      const containerName = `saferepo-scan-${scanId}-${scanner}`;
      try {
        await killDockerContainer(containerName);
      } catch (err) {
        logger.warn({ scanId, containerName, err }, 'Failed to kill orphan container');
      }
    }

    // 2. Clean workspace directory
    if (staleScan.workspacePath) {
      try {
        await cleanupWorkspace(staleScan.workspacePath);
      } catch (err) {
        logger.warn({ scanId, err }, 'Failed to clean orphan workspace');
      }
    }

    // 3. Purge partial findings
    try {
      await Finding.deleteMany({ scanId: staleScan._id });
    } catch (err) {
      logger.warn({ scanId, err }, 'Failed to purge partial findings');
    }

    reconciledCount++;
    logger.info({ scanId }, 'Stale scan successfully reconciled');
  }

  return reconciledCount;
}

// ─── Worker ───

export interface ScanWorker {
  workerId: string;
  start: () => Promise<void>;
  stop: (shutdownGraceMs?: number) => Promise<void>;
  getActiveCount: () => number;
  isRunning: () => boolean;
}

/**
 * Creates and returns a scan worker instance.
 *
 * The worker polls the MongoDB queue for new scan jobs, claims them
 * atomically, and dispatches them to the orchestrator. It enforces
 * bounded concurrency (MAX_CONCURRENT_SCANS) and emits periodic
 * heartbeats for active scans.
 *
 * @param executeFn - Function that executes a claimed scan job.
 *   Receives the scan document and the workerId. Must handle its
 *   own error handling and state transitions.
 */
export function createScanWorker(
  executeFn: (scan: IScan, workerId: string) => Promise<void>
): ScanWorker {
  const config = getQueueConfig();
  const workerId = generateWorkerId();

  let isShuttingDown = false;
  let isStarted = false;
  let activeScans = 0;
  let pollTimer: NodeJS.Timeout | null = null;
  let reconcileTimer: NodeJS.Timeout | null = null;
  const heartbeatTimers = new Map<string, NodeJS.Timeout>();

  function startHeartbeat(scanId: string): void {
    const timer = setInterval(async () => {
      try {
        const success = await updateScanHeartbeat(scanId, workerId);
        if (!success) {
          logger.warn({ scanId, workerId }, 'Heartbeat update failed — lease lost');
          stopHeartbeat(scanId);
        }
      } catch (err) {
        logger.warn({ scanId, err }, 'Heartbeat update error');
      }
    }, config.heartbeatIntervalMs);
    timer.unref();

    heartbeatTimers.set(scanId, timer);
  }

  function stopHeartbeat(scanId: string): void {
    const timer = heartbeatTimers.get(scanId);
    if (timer) {
      clearInterval(timer);
      heartbeatTimers.delete(scanId);
    }
  }

  async function pollAndClaim(): Promise<void> {
    if (isShuttingDown) return;
    if (activeScans >= config.maxConcurrentScans) return;

    try {
      const scan = await claimNextScanJob(workerId);
      if (!scan) return;

      const scanId = scan._id.toString();
      activeScans++;

      logger.info(
        { scanId, workerId, activeScans },
        'Worker claimed scan job'
      );

      // Start heartbeat for this scan
      startHeartbeat(scanId);

      // Execute scan in background (don't block the poll loop)
      executeFn(scan, workerId)
        .catch((err) => {
          logger.error(
            { scanId, err: err instanceof Error ? err.message : String(err) },
            'Scan execution failed unexpectedly'
          );
        })
        .finally(() => {
          stopHeartbeat(scanId);
          activeScans--;
          logger.info(
            { scanId, activeScans },
            'Worker finished scan job'
          );
        });
    } catch (err) {
      logger.error(
        { err: err instanceof Error ? err.message : String(err) },
        'Error during poll/claim cycle'
      );
    }
  }

  async function startPolling(): Promise<void> {
    // Immediate first poll
    await pollAndClaim();

    // Schedule periodic polling
    pollTimer = setInterval(async () => {
      await pollAndClaim();
    }, config.pollIntervalMs);
    pollTimer.unref();
  }

  function startReconciliation(): void {
    reconcileTimer = setInterval(async () => {
      try {
        const count = await reconcileStaleScans();
        if (count > 0) {
          logger.info({ reconciledCount: count }, 'Periodic reconciliation completed');
        }
      } catch (err) {
        logger.error(
          { err: err instanceof Error ? err.message : String(err) },
          'Periodic reconciliation failed'
        );
      }
    }, 30_000); // Every 30 seconds
    reconcileTimer.unref();
  }

  return {
    workerId,

    async start(): Promise<void> {
      if (isStarted) return;
      isStarted = true;
      isShuttingDown = false;

      logger.info({ workerId }, 'Starting scan worker');

      // 1. Startup reconciliation before claiming any work
      try {
        const count = await reconcileStaleScans();
        if (count > 0) {
          logger.info({ reconciledCount: count }, 'Startup reconciliation completed');
        }
      } catch (err) {
        logger.error(
          { err: err instanceof Error ? err.message : String(err) },
          'Startup reconciliation failed'
        );
      }

      // 2. Start periodic reconciliation
      startReconciliation();

      // 3. Start polling loop
      await startPolling();
    },

    async stop(shutdownGraceMs: number = 30_000): Promise<void> {
      if (!isStarted || isShuttingDown) return;
      isShuttingDown = true;

      logger.info({ workerId, activeScans }, 'Initiating graceful worker shutdown');

      // Stop polling for new jobs
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }

      // Stop reconciliation timer
      if (reconcileTimer) {
        clearInterval(reconcileTimer);
        reconcileTimer = null;
      }

      // Wait for active scans to complete (with grace period)
      const shutdownStart = Date.now();

      while (activeScans > 0) {
        if (Date.now() - shutdownStart > shutdownGraceMs) {
          logger.warn(
            { activeScans },
            'Shutdown grace period expired — aborting active scans'
          );
          break;
        }
        await new Promise((r) => setTimeout(r, 100));
      }

      // Clean up remaining heartbeat timers
      for (const [scanId, timer] of heartbeatTimers) {
        clearInterval(timer);
        heartbeatTimers.delete(scanId);
      }

      isStarted = false;
      logger.info({ workerId }, 'Worker shutdown complete');
    },

    getActiveCount: () => activeScans,
    isRunning: () => isStarted && !isShuttingDown,
  };
}
