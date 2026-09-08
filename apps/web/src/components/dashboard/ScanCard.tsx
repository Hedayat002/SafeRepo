import React from 'react';
import Link from 'next/link';
import type { ScanResponseData } from '@/types';
import { ScanStatusBadge } from './ScanStatusBadge';
import { SeveritySummary } from './SeveritySummary';
import { formatDuration, formatRelativeTime } from '@/lib/dashboard-utils';

export interface ScanCardProps {
  scan: ScanResponseData;
}

export function ScanCard({ scan }: ScanCardProps) {
  const shortSha = scan.commitSha ? scan.commitSha.slice(0, 7) : null;
  const relativeTime = formatRelativeTime(scan.createdAt);
  const durationStr = formatDuration(scan.duration);

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm transition-all hover:border-gray-300 hover:shadow dark:border-gray-800 dark:bg-gray-900 dark:hover:border-gray-700">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-3">
          <Link
            href={`/dashboard/scans/${scan.id}`}
            className="text-base font-semibold text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 transition-colors"
          >
            {scan.repositoryOwner}/{scan.repositoryName}
          </Link>
          <div className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 font-mono">
              <svg
                className="w-3 h-3 text-gray-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207"
                />
              </svg>
              {scan.branch}
            </span>
            {shortSha && (
              <span className="font-mono text-gray-400 dark:text-gray-500">
                @{shortSha}
              </span>
            )}
          </div>
        </div>
        <div>
          <ScanStatusBadge status={scan.status} />
        </div>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-gray-100 dark:border-gray-800 text-xs text-gray-500 dark:text-gray-400">
        <div>
          <SeveritySummary summary={scan.summary} />
        </div>
        <div className="flex items-center gap-4 text-xs">
          <span>Started: {relativeTime}</span>
          <span>Duration: {durationStr}</span>
        </div>
      </div>
    </div>
  );
}
