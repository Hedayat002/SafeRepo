import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { getSession } from '@/lib/session';
import { User } from '@/models/user';
import { connectDB } from '@/lib/db';

/**
 * Protected Dashboard page.
 *
 * Server-side auth check — reads session cookie, validates in MongoDB.
 * Redirects to /login if not authenticated.
 * Basic placeholder for Phase 01 — full dashboard is Phase 07.
 */
export default async function DashboardPage() {
  // Server-side auth check
  const cookieStore = await cookies();
  const sessionId = cookieStore.get('saferepo_session')?.value;

  if (!sessionId) {
    redirect('/login');
  }

  const session = await getSession(sessionId);
  if (!session) {
    redirect('/login');
  }

  await connectDB();
  const user = await User.findById(session.userId);
  if (!user) {
    redirect('/login');
  }

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <header className="flex items-center justify-between mb-8">
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              {user.avatarUrl && (
                /* eslint-disable-next-line @next/next/no-img-element */
                <img
                  src={user.avatarUrl}
                  alt={`${user.username}'s avatar`}
                  className="w-8 h-8 rounded-full"
                />
              )}
              <span className="text-sm font-medium">{user.username}</span>
            </div>
            <form action="/api/v1/auth/logout" method="POST">
              <button
                type="submit"
                className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                Sign out
              </button>
            </form>
          </div>
        </header>

        <div className="rounded-lg border border-gray-200 dark:border-gray-800 p-8 text-center">
          <p className="text-gray-600 dark:text-gray-400">
            Welcome, <strong>{user.displayName ?? user.username}</strong>.
            The security dashboard will be available in Phase 07.
          </p>
        </div>
      </div>
    </main>
  );
}
