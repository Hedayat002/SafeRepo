import { NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { destroySession, getSessionIdFromCookies, clearSessionCookie } from '@/lib/session';
import { formatErrorResponse } from '@/lib/errors';
import { logger } from '@/lib/logger';

/**
 * POST /api/v1/auth/logout
 *
 * Destroys the server-side session and clears the session cookie.
 * Returns 401 if not authenticated.
 */
export async function POST(): Promise<NextResponse> {
  try {
    await requireAuth();

    const sessionId = await getSessionIdFromCookies();
    if (sessionId) {
      await destroySession(sessionId);
    }

    await clearSessionCookie();

    logger.info('User logged out');

    return NextResponse.json({ message: 'Logged out' });
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
