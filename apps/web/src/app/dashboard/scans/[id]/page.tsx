import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { getSession } from '@/lib/session';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { scanIdParamSchema } from '@/lib/schemas';
import type { FindingResponseData, ScanResponseData } from '@/types';
import { ScanDetail } from '@/components/dashboard/ScanDetail';
import { ScanPollingWrapper } from '@/components/dashboard/ScanPollingWrapper';
import { FindingsExplorer } from '@/components/dashboard/FindingsExplorer';
import { isTerminalStatus } from '@/lib/dashboard-utils';

export default async function ScanDetailPage(props: {
  params: Promise<{ id: string }>;
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

  const params = await props.params;
  const parseResult = scanIdParamSchema.safeParse(params);

  if (!parseResult.success) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-6 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
        <h2 className="text-base font-semibold mb-1">Invalid Scan Identifier</h2>
        <p className="text-xs mb-4">The provided scan ID is malformed.</p>
        <Link href="/dashboard" className="text-xs font-semibold underline">
          ← Return to Dashboard
        </Link>
      </div>
    );
  }

  const { id } = parseResult.data;

  await connectDB();

  // Enforce anti-enumeration & user authorization at the query level
  const dbScan = await Scan.findOne({ _id: id, userId: session.userId }).lean();

  if (!dbScan) {
    return (
      <div className="rounded-lg border border-gray-200 bg-white p-8 text-center shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <svg
          className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-600 mb-3"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100">
          Scan Not Found
        </h2>
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400 max-w-sm mx-auto mb-6">
          The requested scan could not be located, or you do not have permission to inspect it.
        </p>
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-700 transition-colors"
        >
          ← Return to Scan History
        </Link>
      </div>
    );
  }

  const scan: ScanResponseData = {
    id: dbScan._id.toString(),
    userId: dbScan.userId.toString(),
    repositoryOwner: dbScan.repositoryOwner,
    repositoryName: dbScan.repositoryName,
    repositoryUrl: dbScan.repositoryUrl,
    branch: dbScan.branch,
    commitSha: dbScan.commitSha,
    status: dbScan.status,
    scanners: dbScan.scanners,
    summary: dbScan.summary,
    error: dbScan.error,
    startedAt: dbScan.startedAt ? dbScan.startedAt.toISOString() : null,
    completedAt: dbScan.completedAt ? dbScan.completedAt.toISOString() : null,
    duration: dbScan.duration,
    createdAt: dbScan.createdAt.toISOString(),
    updatedAt: dbScan.updatedAt.toISOString(),
  };

  // Initial findings query
  const perPage = 20;
  const [dbFindings, totalFindings] = await Promise.all([
    Finding.find({ scanId: dbScan._id })
      .sort({ severity: 1, file: 1, line: 1 })
      .skip(0)
      .limit(perPage)
      .lean(),
    Finding.countDocuments({ scanId: dbScan._id }),
  ]);

  const findings: FindingResponseData[] = dbFindings.map((f) => ({
    id: f._id.toString(),
    scanId: f.scanId.toString(),
    scanner: f.scanner,
    category: f.category,
    severity: f.severity,
    title: f.title,
    description: f.description,
    file: f.file,
    line: f.line,
    endLine: f.endLine,
    column: f.column,
    endColumn: f.endColumn,
    codeSnippet: f.codeSnippet,
    package: f.package,
    packageVersion: f.packageVersion,
    fixedVersion: f.fixedVersion,
    vulnerabilityId: f.vulnerabilityId,
    remediation: f.remediation,
    fingerprint: f.fingerprint,
    metadata: f.metadata,
    createdAt: f.createdAt.toISOString(),
  }));

  const isTerminal = isTerminalStatus(scan.status);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
        <Link
          href="/dashboard"
          className="hover:text-gray-900 dark:hover:text-gray-100 transition-colors inline-flex items-center gap-1"
        >
          ← Back to Scan History
        </Link>
        <span className="font-mono text-gray-400">ID: {scan.id}</span>
      </div>

      <ScanPollingWrapper scanId={scan.id} initialStatus={scan.status}>
        <ScanDetail scan={scan} />

        {/* If scan is actively progressing, render progress banner */}
        {!isTerminal && (
          <div className="rounded-lg border border-blue-200 bg-blue-50/50 p-6 text-center dark:border-blue-900 dark:bg-blue-950/20">
            <div className="inline-flex items-center gap-3">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-blue-500" />
              </span>
              <span className="text-sm font-semibold text-blue-900 dark:text-blue-200 capitalize">
                Scan is currently {scan.status}...
              </span>
            </div>
            <p className="mt-2 text-xs text-blue-700 dark:text-blue-300 max-w-md mx-auto">
              SafeRepo is analyzing repository source code and dependencies.
              Findings will update automatically when scanning finishes.
            </p>
          </div>
        )}

        {/* Findings Explorer (rendered for terminal scans, or if findings already exist) */}
        {(isTerminal || findings.length > 0) && (
          <FindingsExplorer
            scanId={scan.id}
            initialFindings={findings}
            initialTotal={totalFindings}
            initialPage={1}
            initialPerPage={perPage}
          />
        )}
      </ScanPollingWrapper>
    </div>
  );
}
