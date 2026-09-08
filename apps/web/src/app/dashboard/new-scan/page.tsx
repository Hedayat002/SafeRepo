import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { getSession } from '@/lib/session';
import { getUserRepos } from '@/lib/github';
import { NewScanForm, type RepoOption } from '@/components/dashboard/NewScanForm';

export default async function NewScanPage() {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get('saferepo_session')?.value;

  if (!sessionId) {
    redirect('/login');
  }

  const session = await getSession(sessionId);
  if (!session) {
    redirect('/login');
  }

  let repos: RepoOption[] = [];

  try {
    const { repos: ghRepos } = await getUserRepos(
      session.githubAccessToken,
      1,
      50
    );
    repos = ghRepos.map((r) => ({
      id: r.id,
      name: r.name,
      fullName: r.full_name,
      owner: r.owner.login,
      defaultBranch: r.default_branch,
    }));
  } catch {
    // Graceful fallback to client fetching or manual input
    repos = [];
  }

  return (
    <div className="max-w-2xl mx-auto flex flex-col gap-6">
      <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
        <Link
          href="/dashboard"
          className="hover:text-gray-900 dark:hover:text-gray-100 transition-colors"
        >
          ← Back to Scan History
        </Link>
      </div>

      <NewScanForm initialRepos={repos} />
    </div>
  );
}
