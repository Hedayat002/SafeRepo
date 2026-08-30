import { NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { formatErrorResponse } from '@/lib/errors';
import type { AuthenticatedUser } from '@/types';

/**
 * GET /api/v1/auth/me
 *
 * Returns the authenticated user's profile.
 * Never returns githubAccessToken or session internals.
 * Returns 401 if not authenticated.
 */
export async function GET(): Promise<NextResponse> {
  try {
    const { user } = await requireAuth();

    const profile: AuthenticatedUser = {
      id: user._id.toString(),
      username: user.username,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
    };

    return NextResponse.json({ user: profile });
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
