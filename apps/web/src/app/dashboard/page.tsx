import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { getSession } from '@/lib/session';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import type { ScanResponseData } from '@/types';
import { ScanHistoryList } from '@/components/dashboard/ScanHistoryList';

export default async function DashboardPage({
  searchParams,
}: {
  searchParams?: Promise<{ page?: string }>;
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

  const params = await searchParams;
  const rawPage = params?.page ? parseInt(params.page, 10) : 1;
  const page = !isNaN(rawPage) && rawPage > 0 ? rawPage : 1;
  const perPage = 20;
  const skip = (page - 1) * perPage;

  let scans: ScanResponseData[] = [];
  let total = 0;
  let dbError: string | null = null;

  try {
    await connectDB();

    const [dbScans, totalCount] = await Promise.all([
      Scan.find({ userId: session.userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(perPage)
        .lean(),
      Scan.countDocuments({ userId: session.userId }),
    ]);

    total = totalCount;
    scans = dbScans.map((s) => ({
      id: s._id.toString(),
      userId: s.userId.toString(),
      repositoryOwner: s.repositoryOwner,
      repositoryName: s.repositoryName,
      repositoryUrl: s.repositoryUrl,
      branch: s.branch,
      commitSha: s.commitSha,
      status: s.status,
      scanners: s.scanners,
      summary: s.summary,
      error: s.error,
      startedAt: s.startedAt ? s.startedAt.toISOString() : null,
      completedAt: s.completedAt ? s.completedAt.toISOString() : null,
      duration: s.duration,
      createdAt: s.createdAt.toISOString(),
      updatedAt: s.updatedAt.toISOString(),
    }));
  } catch (err: unknown) {
    dbError =
      err instanceof Error
        ? err.message
        : 'Failed to retrieve scan history from database';
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-gray-200 dark:border-gray-800">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            Security Scans
          </h1>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Monitor vulnerability scans, security findings, and remediation status.
          </p>
        </div>

        <Link
          href="/dashboard/new-scan"
          className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 shadow-sm transition-colors"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M12 4v16m8-8H4"
            />
          </svg>
          New Security Scan
        </Link>
      </div>

      {dbError ? (
        <div
          role="alert"
          className="rounded-lg border border-red-200 bg-red-50 p-6 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
        >
          <h3 className="font-semibold text-base mb-1">
            Unable to load scan history
          </h3>
          <p className="text-xs mb-4">{dbError}</p>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1.5 text-xs font-semibold underline"
          >
            Retry
          </Link>
        </div>
      ) : (
        <ScanHistoryList
          scans={scans}
          total={total}
          page={page}
          perPage={perPage}
        />
      )}
    </div>
  );
}
