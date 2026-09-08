import React from 'react';
import type { FindingResponseData } from '@/types';

export interface RemediationPanelProps {
  finding: FindingResponseData;
  className?: string;
}

export function RemediationPanel({ finding, className = '' }: RemediationPanelProps) {
  const hasDependencyDetails = Boolean(
    finding.package || finding.packageVersion || finding.fixedVersion
  );

  return (
    <div
      className={`rounded-lg border border-blue-100 bg-blue-50/50 p-4 text-xs dark:border-blue-950 dark:bg-blue-950/20 ${className}`}
    >
      <div className="flex items-center gap-2 mb-2 font-semibold text-blue-900 dark:text-blue-300">
        <svg
          className="w-4 h-4 text-blue-600 dark:text-blue-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="2"
            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        Remediation Guidance
      </div>

      {finding.remediation ? (
        <p className="text-gray-700 dark:text-gray-300 leading-relaxed whitespace-pre-line mb-3">
          {finding.remediation}
        </p>
      ) : (
        <p className="text-gray-500 dark:text-gray-400 italic mb-3">
          No automated remediation text available. Review the code at the identified location and apply security best practices.
        </p>
      )}

      {hasDependencyDetails && (
        <div className="pt-2 border-t border-blue-200/60 dark:border-blue-900/60 flex flex-wrap gap-4 text-gray-700 dark:text-gray-300">
          {finding.package && (
            <div>
              <span className="text-gray-400 dark:text-gray-500">Package: </span>
              <span className="font-mono font-medium">{finding.package}</span>
            </div>
          )}
          {finding.packageVersion && (
            <div>
              <span className="text-gray-400 dark:text-gray-500">Current Version: </span>
              <span className="font-mono text-red-600 dark:text-red-400 font-medium">
                {finding.packageVersion}
              </span>
            </div>
          )}
          {finding.fixedVersion && (
            <div>
              <span className="text-gray-400 dark:text-gray-500">Fixed In: </span>
              <span className="font-mono text-green-600 dark:text-green-400 font-medium">
                {finding.fixedVersion}
              </span>
            </div>
          )}
        </div>
      )}

      <div className="mt-2 pt-2 border-t border-blue-200/60 dark:border-blue-900/60 flex items-center justify-between text-gray-500 dark:text-gray-400">
        <span>Vulnerability ID: <strong className="font-mono text-gray-800 dark:text-gray-200">{finding.vulnerabilityId}</strong></span>
        <span>Scanner: <span className="font-mono capitalize">{finding.scanner}</span></span>
      </div>
    </div>
  );
}
