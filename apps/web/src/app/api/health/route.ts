import { NextResponse } from 'next/server';
import { isDBConnected, connectDB } from '@/lib/db';
import type { HealthResponse } from '@/types';

/**
 * GET /api/health
 *
 * Application health check endpoint.
 * No authentication required.
 */
export async function GET(): Promise<NextResponse<HealthResponse>> {
  try {
    await connectDB();
  } catch {
    // Connection attempt failed — report disconnected
  }

  const dbConnected = isDBConnected();

  const response: HealthResponse = {
    status: dbConnected ? 'ok' : 'error',
    db: dbConnected ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(response, {
    status: dbConnected ? 200 : 503,
  });
}
