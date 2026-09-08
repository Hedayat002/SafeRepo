import { NextResponse } from 'next/server';
import { isDBConnected, connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import type { HealthResponse } from '@/types';
import packageInfo from '../../../../package.json';

/**
 * GET /api/health
 *
 * Application health check endpoint.
 * No authentication required.
 * Returns service status, MongoDB connectivity, application version,
 * pending queue depth, and process uptime.
 */
export async function GET(): Promise<NextResponse<HealthResponse>> {
  try {
    await connectDB();
  } catch {
    // Connection attempt failed — report disconnected
  }

  const dbConnected = isDBConnected();
  let pendingCount = 0;

  if (dbConnected) {
    try {
      pendingCount = await Scan.countDocuments({ status: 'queued' });
    } catch {
      pendingCount = 0;
    }
  }

  const response: HealthResponse = {
    status: dbConnected ? 'ok' : 'error',
    db: dbConnected ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
    version: packageInfo.version ?? '0.1.0',
    queue: {
      pending: pendingCount,
    },
    uptime: Math.floor(process.uptime()),
  };

  return NextResponse.json(response, {
    status: dbConnected ? 200 : 503,
  });
}
