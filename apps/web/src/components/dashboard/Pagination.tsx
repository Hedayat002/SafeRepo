import React from 'react';
import Link from 'next/link';
import { getPageRange } from '@/lib/findings-filters';

export interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange?: (page: number) => void;
  createPageUrl?: (page: number) => string;
  className?: string;
}

export function Pagination({
  currentPage,
  totalPages,
  onPageChange,
  createPageUrl,
  className = '',
}: PaginationProps) {
  if (totalPages <= 1) {
    return null;
  }

  const pages = getPageRange(currentPage, totalPages);
  const isFirst = currentPage <= 1;
  const isLast = currentPage >= totalPages;

  const renderPageItem = (p: number | '...', index: number) => {
    if (p === '...') {
      return (
        <span
          key={`ellipsis-${index}`}
          className="px-3 py-1.5 text-xs text-gray-500 dark:text-gray-400"
          aria-hidden="true"
        >
          ...
        </span>
      );
    }

    const isActive = p === currentPage;
    const itemClasses = isActive
      ? 'bg-blue-600 text-white font-semibold'
      : 'bg-white text-gray-700 hover:bg-gray-50 border-gray-300 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700 dark:hover:bg-gray-700';

    if (createPageUrl) {
      return (
        <Link
          key={p}
          href={createPageUrl(p)}
          aria-current={isActive ? 'page' : undefined}
          className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${itemClasses}`}
        >
          {p}
        </Link>
      );
    }

    return (
      <button
        key={p}
        type="button"
        onClick={() => onPageChange?.(p)}
        aria-current={isActive ? 'page' : undefined}
        className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${itemClasses}`}
      >
        {p}
      </button>
    );
  };

  const prevButton = createPageUrl ? (
    <Link
      href={createPageUrl(Math.max(1, currentPage - 1))}
      aria-disabled={isFirst}
      tabIndex={isFirst ? -1 : undefined}
      className={`px-2.5 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 transition-colors ${
        isFirst
          ? 'pointer-events-none opacity-40'
          : 'hover:bg-gray-50 dark:hover:bg-gray-700'
      }`}
    >
      Previous
    </Link>
  ) : (
    <button
      type="button"
      disabled={isFirst}
      aria-disabled={isFirst}
      onClick={() => onPageChange?.(currentPage - 1)}
      className="px-2.5 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
    >
      Previous
    </button>
  );

  const nextButton = createPageUrl ? (
    <Link
      href={createPageUrl(Math.min(totalPages, currentPage + 1))}
      aria-disabled={isLast}
      tabIndex={isLast ? -1 : undefined}
      className={`px-2.5 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 transition-colors ${
        isLast
          ? 'pointer-events-none opacity-40'
          : 'hover:bg-gray-50 dark:hover:bg-gray-700'
      }`}
    >
      Next
    </Link>
  ) : (
    <button
      type="button"
      disabled={isLast}
      aria-disabled={isLast}
      onClick={() => onPageChange?.(currentPage + 1)}
      className="px-2.5 py-1.5 text-xs font-medium rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
    >
      Next
    </button>
  );

  return (
    <nav
      aria-label="Pagination"
      className={`flex items-center justify-between gap-2 ${className}`}
    >
      <div>{prevButton}</div>
      <div className="flex items-center gap-1">
        {pages.map((p, idx) => renderPageItem(p, idx))}
      </div>
      <div>{nextButton}</div>
    </nav>
  );
}
