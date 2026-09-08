import React from 'react';
import type { ScanSummary } from '@/types';
import { computeSeverityPercentages } from '@/lib/dashboard-utils';

export interface SeverityChartProps {
  summary?: Partial<ScanSummary> | null;
  className?: string;
}

export function SeverityChart({ summary, className = '' }: SeverityChartProps) {
  const items = computeSeverityPercentages(summary);
  const total = items.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className={`flex flex-col gap-3 ${className}`}>
      {/* Visual Proportional Bar */}
      <div className="h-3 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800 flex">
        {total === 0 ? (
          <div
            className="h-full w-full bg-gray-200 dark:bg-gray-700"
            title="No findings detected"
          />
        ) : (
          items.map((item) => {
            if (item.count === 0) return null;
            return (
              <div
                key={item.severity}
                style={{
                  width: `${(item.count / total) * 100}%`,
                  backgroundColor: item.color,
                }}
                className="h-full transition-all duration-300"
                title={`${item.label}: ${item.count} (${item.percentage}%)`}
              />
            );
          })
        )}
      </div>

      {/* Legend with counts and percentages */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
        {items.map((item) => (
          <div
            key={item.severity}
            className="flex items-center gap-1.5 p-1.5 rounded border border-gray-100 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-800/30"
          >
            <span
              className="h-2.5 w-2.5 rounded-full flex-shrink-0"
              style={{ backgroundColor: item.color }}
              aria-hidden="true"
            />
            <span className="text-gray-600 dark:text-gray-400 truncate">
              {item.label}:
            </span>
            <span className="font-semibold text-gray-900 dark:text-gray-100 ml-auto">
              {item.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
