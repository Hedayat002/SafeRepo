import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { getSession } from '@/lib/session';
import { User } from '@/models/user';
import { connectDB } from '@/lib/db';

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
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
    <div className="min-h-screen bg-gray-50/50 dark:bg-black flex flex-col">
      {/* Fixed top navigation bar */}
      <header className="sticky top-0 z-30 border-b border-gray-200 bg-white/80 backdrop-blur dark:border-gray-800 dark:bg-gray-900/80">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Link
              href="/dashboard"
              className="flex items-center gap-2 text-lg font-bold text-gray-900 dark:text-gray-100 hover:opacity-90 transition-opacity"
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-600 text-white font-bold text-sm">
                S
              </span>
              <span>SafeRepo</span>
            </Link>

            <nav className="hidden sm:flex items-center gap-4 text-sm font-medium">
              <Link
                href="/dashboard"
                className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100 transition-colors"
              >
                Scan History
              </Link>
              <Link
                href="/dashboard/new-scan"
                className="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100 transition-colors"
              >
                New Scan
              </Link>
            </nav>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              {user.avatarUrl && (
                /* eslint-disable-next-line @next/next/no-img-element */
                <img
                  src={user.avatarUrl}
                  alt={`${user.username}'s avatar`}
                  className="w-7 h-7 rounded-full border border-gray-200 dark:border-gray-700"
                />
              )}
              <span className="hidden md:inline text-xs font-medium text-gray-700 dark:text-gray-300">
                {user.displayName ?? user.username}
              </span>
            </div>

            <form action="/api/v1/auth/logout" method="POST">
              <button
                type="submit"
                className="rounded-md px-2.5 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-100 transition-colors"
              >
                Sign out
              </button>
            </form>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}
