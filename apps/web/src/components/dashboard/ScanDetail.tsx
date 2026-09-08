import React from 'react';
import type { ScanResponseData } from '@/types';
import { ScanStatusBadge } from './ScanStatusBadge';
import { SeverityChart } from './SeverityChart';
import { formatDuration, formatRelativeTime } from '@/lib/dashboard-utils';

export interface ScanDetailProps {
  scan: ScanResponseData;
}

export function ScanDetail({ scan }: ScanDetailProps) {
  const shortSha = scan.commitSha ? scan.commitSha.slice(0, 7) : null;
  const startedAtStr = scan.startedAt
    ? formatRelativeTime(scan.startedAt)
    : 'Not started';
  const durationStr = formatDuration(scan.duration);

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header Card */}
      <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {scan.repositoryOwner}/{scan.repositoryName}
              </h1>
              <ScanStatusBadge status={scan.status} />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-gray-500 dark:text-gray-400">
              <span className="font-mono bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">
                branch: {scan.branch}
              </span>
              {shortSha && (
                <span className="font-mono bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">
                  commit: {shortSha}
                </span>
              )}
              {scan.repositoryUrl && (
                <a
                  href={scan.repositoryUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 dark:text-blue-400 hover:underline inline-flex items-center gap-1"
                >
                  GitHub Repository ↗
                </a>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs border-t md:border-t-0 md:border-l border-gray-200 dark:border-gray-800 pt-4 md:pt-0 md:pl-6">
            <div>
              <span className="text-gray-400 dark:text-gray-500 block">
                Started
              </span>
              <span className="font-medium text-gray-800 dark:text-gray-200">
                {startedAtStr}
              </span>
            </div>
            <div>
              <span className="text-gray-400 dark:text-gray-500 block">
                Duration
              </span>
              <span className="font-medium text-gray-800 dark:text-gray-200">
                {durationStr}
              </span>
            </div>
            <div>
              <span className="text-gray-400 dark:text-gray-500 block">
                Total Findings
              </span>
              <span className="font-bold text-base text-gray-900 dark:text-gray-100">
                {scan.summary?.total ?? 0}
              </span>
            </div>
          </div>
        </div>

        {/* Scanner engines badge list */}
        <div className="mt-4 pt-4 border-t border-gray-100 dark:border-gray-800 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-gray-500 dark:text-gray-400">
            Security Scanners:
          </span>
          {scan.scanners.map((scanner) => (
            <span
              key={scanner}
              className="px-2 py-0.5 rounded-md bg-gray-100 dark:bg-gray-800 font-mono text-gray-700 dark:text-gray-300"
            >
              {scanner}
            </span>
          ))}
        </div>
      </div>

      {/* Terminal Error Alerts if Failed or Timed Out */}
      {scan.status === 'failed' && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
        >
          <div className="flex items-center gap-2 font-semibold">
            <svg
              className="h-5 w-5 text-red-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            Scan Execution Failed
          </div>
          <p className="mt-1 text-xs">
            {scan.error || 'An unexpected failure occurred while analyzing the repository.'}
          </p>
        </div>
      )}

      {scan.status === 'timed_out' && (
        <div
          role="alert"
          className="rounded-lg border border-orange-200 bg-orange-50 p-4 text-sm text-orange-800 dark:border-orange-900 dark:bg-orange-950/40 dark:text-orange-300"
        >
          <div className="flex items-center gap-2 font-semibold">
            <svg
              className="h-5 w-5 text-orange-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            Scan Execution Timed Out
          </div>
          <p className="mt-1 text-xs">
            The scan exceeded the maximum execution duration (10 minutes).
            Partial findings captured before timeout are displayed below.
          </p>
        </div>
      )}

      {/* Severity Distribution Card */}
      <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-800 dark:bg-gray-900">
        <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Severity Breakdown
        </h2>
        <SeverityChart summary={scan.summary} />
      </div>
    </div>
  );
}
