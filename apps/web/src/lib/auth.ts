import { getSession, getSessionIdFromCookies } from '@/lib/session';
import { User, type IUser } from '@/models/user';
import { UnauthorizedError } from '@/lib/errors';
import { connectDB } from '@/lib/db';
import { logger } from '@/lib/logger';

/**
 * Authentication middleware.
 *
 * Reads the session cookie, validates the session in MongoDB,
 * and returns the authenticated user and session data.
 *
 * Throws UnauthorizedError (401) if not authenticated.
 * All authentication validation happens server-side.
 */

export interface AuthContext {
  user: IUser;
  githubAccessToken: string;
}

export async function requireAuth(): Promise<AuthContext> {
  const sessionId = await getSessionIdFromCookies();

  if (!sessionId) {
    logger.debug('No session cookie found');
    throw new UnauthorizedError();
  }

  const session = await getSession(sessionId);

  if (!session) {
    logger.debug('Session not found or expired');
    throw new UnauthorizedError();
  }

  await connectDB();
  const user = await User.findById(session.userId);

  if (!user) {
    logger.warn({ userId: session.userId }, 'Session references non-existent user');
    throw new UnauthorizedError();
  }

  return {
    user,
    githubAccessToken: session.githubAccessToken,
  };
}
