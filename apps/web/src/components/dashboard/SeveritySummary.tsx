import React from 'react';
import type { ScanSummary } from '@/types';
import {
  computeSeverityCounts,
  getSeverityBadgeClasses,
} from '@/lib/dashboard-utils';

export interface SeveritySummaryProps {
  summary?: Partial<ScanSummary> | null;
  className?: string;
  showZeroCounts?: boolean;
}

export function SeveritySummary({
  summary,
  className = '',
  showZeroCounts = true,
}: SeveritySummaryProps) {
  const items = computeSeverityCounts(summary);

  const displayedItems = showZeroCounts
    ? items
    : items.filter((item) => item.count > 0);

  if (displayedItems.length === 0) {
    return (
      <span className="text-xs text-gray-500 dark:text-gray-400">
        No findings
      </span>
    );
  }

  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className}`}>
      {displayedItems.map((item) => {
        const badgeClasses = getSeverityBadgeClasses(item.severity);
        return (
          <span
            key={item.severity}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border ${badgeClasses}`}
          >
            <span>{item.label}:</span>
            <span className="font-bold">{item.count}</span>
          </span>
        );
      })}
    </div>
  );
}
