import React from 'react';
import type { ScanStatus } from '@/types';
import { getStatusDisplay, getStatusBadgeClasses } from '@/lib/dashboard-utils';

export interface ScanStatusBadgeProps {
  status: ScanStatus | string;
  className?: string;
}

export function ScanStatusBadge({ status, className = '' }: ScanStatusBadgeProps) {
  const display = getStatusDisplay(status);
  const badgeClasses = getStatusBadgeClasses(status);
  const normalized = status.toLowerCase();
  const isAnimated = normalized === 'scanning' || normalized === 'normalizing';

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${badgeClasses} ${className}`}
    >
      {isAnimated ? (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500" />
        </span>
      ) : (
        <span aria-hidden="true" className="font-semibold text-xs">
          {display.icon}
        </span>
      )}
      <span>{display.label}</span>
    </span>
  );
}
