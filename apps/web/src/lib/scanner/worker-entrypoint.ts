import { connectDB } from '@/lib/db';
import { logger } from '@/lib/logger';
import { createScanWorker } from './queue';
import { executeOrchestratedScan } from './orchestrator';

/**
 * SafeRepo Trusted Scan Worker Entrypoint.
 *
 * Standalone Node.js process running outside the Next.js request lifecycle.
 * Exclusive trust boundary for Docker scanner execution.
 *
 * Usage:
 *   npx tsx src/lib/scanner/worker-entrypoint.ts
 *   npm run worker
 */
async function main(): Promise<void> {
  logger.info('Initializing SafeRepo Trusted Scan Worker...');

  // 1. Connect to MongoDB
  try {
    await connectDB();
    logger.info('Connected to MongoDB database');
  } catch (err) {
    logger.error({ err }, 'Failed to connect to MongoDB — exiting worker');
    process.exit(1);
  }

  // 2. Instantiate worker with orchestrator execution handler
  const worker = createScanWorker(async (scan, workerId) => {
    logger.info({ scanId: scan._id.toString(), workerId }, 'Dispatching scan to orchestrator');
    await executeOrchestratedScan(scan._id.toString(), workerId);
  });

  // 3. Register graceful shutdown handlers
  let isShuttingDown = false;
  async function shutdown(signal: string): Promise<void> {
    if (isShuttingDown) return;
    isShuttingDown = true;
    logger.info({ signal }, 'Received termination signal — shutting down worker');
    try {
      await worker.stop();
      logger.info('Worker shutdown completed cleanly');
      process.exit(0);
    } catch (err) {
      logger.error({ err }, 'Error during worker shutdown');
      process.exit(1);
    }
  }

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  // 4. Start worker (runs startup reconciliation, then enters polling loop)
  try {
    await worker.start();
    logger.info({ workerId: worker.workerId }, 'Scan worker loop active and waiting for jobs');
  } catch (err) {
    logger.error({ err }, 'Worker loop encountered fatal error');
    process.exit(1);
  }
}

// Only invoke main when run directly as a script
if (require.main === module || process.argv[1]?.includes('worker-entrypoint')) {
  main().catch((err) => {
    logger.error({ err }, 'Unhandled rejection in worker entrypoint');
    process.exit(1);
  });
}

export { main };
