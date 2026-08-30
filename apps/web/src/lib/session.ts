import { randomUUID } from 'crypto';
import { cookies } from 'next/headers';
import { Session } from '@/models/session';
import { connectDB } from '@/lib/db';
import { logger } from '@/lib/logger';

/**
 * Server-side session management.
 *
 * - Opaque UUID session IDs (not JWT)
 * - MongoDB-backed persistence with TTL auto-expiration
 * - HttpOnly, Secure, SameSite=Lax cookies
 * - Immediate revocation on logout
 * - GitHub access tokens stored server-side only
 */

const SESSION_COOKIE_NAME = 'saferepo_session';

function getSessionMaxAgeMs(): number {
  return Number(process.env.SESSION_MAX_AGE_MS) || 86_400_000; // 24 hours
}

function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

/**
 * Create a new server-side session.
 * Returns the opaque session ID to be stored in a cookie.
 */
export async function createSession(
  userId: string,
  githubAccessToken: string
): Promise<string> {
  await connectDB();

  const sessionId = randomUUID();
  const maxAge = getSessionMaxAgeMs();
  const expiresAt = new Date(Date.now() + maxAge);

  await Session.create({
    sessionId,
    userId,
    githubAccessToken,
    expiresAt,
  });

  logger.info({ userId }, 'Session created');
  return sessionId;
}

/**
 * Retrieve a valid (non-expired) session by session ID.
 * Returns null if session doesn't exist or is expired.
 */
export async function getSession(
  sessionId: string
): Promise<{
  sessionId: string;
  userId: string;
  githubAccessToken: string;
  expiresAt: Date;
} | null> {
  await connectDB();

  const session = await Session.findOne({
    sessionId,
    expiresAt: { $gt: new Date() },
  }).lean();

  if (!session) {
    return null;
  }

  return {
    sessionId: session.sessionId,
    userId: session.userId.toString(),
    githubAccessToken: session.githubAccessToken,
    expiresAt: session.expiresAt,
  };
}

/**
 * Destroy a single session (logout).
 */
export async function destroySession(sessionId: string): Promise<void> {
  await connectDB();
  await Session.deleteOne({ sessionId });
  logger.info('Session destroyed');
}

/**
 * Destroy all sessions for a user (logout everywhere).
 */
export async function destroyAllUserSessions(userId: string): Promise<void> {
  await connectDB();
  const result = await Session.deleteMany({ userId });
  logger.info({ userId, count: result.deletedCount }, 'All user sessions destroyed');
}

/**
 * Set the session cookie on a response.
 */
export async function setSessionCookie(sessionId: string): Promise<void> {
  const maxAge = getSessionMaxAgeMs();

  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: isProduction(),
    sameSite: 'lax',
    path: '/',
    maxAge: Math.floor(maxAge / 1000), // cookies use seconds
  });
}

/**
 * Clear the session cookie.
 */
export async function clearSessionCookie(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isProduction(),
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

/**
 * Read the session ID from the request cookies.
 */
export async function getSessionIdFromCookies(): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get(SESSION_COOKIE_NAME)?.value;
}

export { SESSION_COOKIE_NAME };
