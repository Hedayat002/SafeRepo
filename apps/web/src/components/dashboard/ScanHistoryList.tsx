import React from 'react';
import type { ScanResponseData } from '@/types';
import { ScanCard } from './ScanCard';
import { EmptyState } from './EmptyState';
import { Pagination } from './Pagination';

export interface ScanHistoryListProps {
  scans: ScanResponseData[];
  total: number;
  page: number;
  perPage: number;
}

export function ScanHistoryList({
  scans,
  total,
  page,
  perPage,
}: ScanHistoryListProps) {
  if (scans.length === 0) {
    return <EmptyState type="no-scans" />;
  }

  const totalPages = Math.ceil(total / perPage);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-3">
        {scans.map((scan) => (
          <ScanCard key={scan.id} scan={scan} />
        ))}
      </div>

      {totalPages > 1 && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-800">
          <Pagination
            currentPage={page}
            totalPages={totalPages}
            createPageUrl={(p) => `/dashboard?page=${p}`}
          />
        </div>
      )}
    </div>
  );
}
