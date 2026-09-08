import React from 'react';
import Link from 'next/link';

export interface EmptyStateProps {
  type?: 'no-scans' | 'no-findings' | 'no-filter-matches' | 'no-repos' | 'custom';
  title?: string;
  description?: string;
  action?: React.ReactNode;
  onReset?: () => void;
  className?: string;
}

export function EmptyState({
  type = 'custom',
  title,
  description,
  action,
  onReset,
  className = '',
}: EmptyStateProps) {
  let defaultIcon: React.ReactNode = null;
  let defaultTitle = title;
  let defaultDescription = description;
  let defaultAction = action;

  switch (type) {
    case 'no-scans':
      defaultTitle = defaultTitle ?? 'No scans yet';
      defaultDescription =
        defaultDescription ??
        'Analyze your first repository to uncover vulnerabilities, dependencies, and secrets.';
      defaultIcon = (
        <svg
          className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-600"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
          />
        </svg>
      );
      defaultAction = defaultAction ?? (
        <Link
          href="/dashboard/new-scan"
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 transition-colors"
        >
          Start New Scan
        </Link>
      );
      break;

    case 'no-findings':
      defaultTitle = defaultTitle ?? 'No security findings detected';
      defaultDescription =
        defaultDescription ??
        'This repository appears clean. No vulnerabilities, security weaknesses, or secret leaks were identified.';
      defaultIcon = (
        <svg
          className="mx-auto h-12 w-12 text-green-500 dark:text-green-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
          />
        </svg>
      );
      break;

    case 'no-filter-matches':
      defaultTitle = defaultTitle ?? 'No findings match the selected filters';
      defaultDescription =
        defaultDescription ??
        'Try broadening your search or resetting active severity, category, or scanner filters.';
      defaultIcon = (
        <svg
          className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-600"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"
          />
        </svg>
      );
      if (onReset && !defaultAction) {
        defaultAction = (
          <button
            type="button"
            onClick={onReset}
            className="inline-flex items-center gap-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3.5 py-1.5 text-xs font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            Clear filters
          </button>
        );
      }
      break;

    case 'no-repos':
      defaultTitle = defaultTitle ?? 'No repositories found';
      defaultDescription =
        defaultDescription ??
        'Ensure your GitHub App has access to your organization or personal repositories.';
      defaultIcon = (
        <svg
          className="mx-auto h-12 w-12 text-orange-400 dark:text-orange-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth="1.5"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
      );
      break;

    default:
      break;
  }

  return (
    <div
      className={`rounded-lg border border-dashed border-gray-300 dark:border-gray-800 p-8 text-center ${className}`}
    >
      {defaultIcon && <div className="mb-4">{defaultIcon}</div>}
      {defaultTitle && (
        <h4 className="text-base font-semibold text-gray-900 dark:text-gray-100">
          {defaultTitle}
        </h4>
      )}
      {defaultDescription && (
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 max-w-md mx-auto">
          {defaultDescription}
        </p>
      )}
      {defaultAction && <div className="mt-6">{defaultAction}</div>}
    </div>
  );
}
