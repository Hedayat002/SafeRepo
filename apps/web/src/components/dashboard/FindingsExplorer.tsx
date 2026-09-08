'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import type { FindingResponseData } from '@/types';
import type { FindingsFilterState } from '@/lib/findings-filters';
import { buildFilterQuery } from '@/lib/findings-filters';
import { FindingsFilter } from './FindingsFilter';
import { FindingRow } from './FindingRow';
import { EmptyState } from './EmptyState';
import { Pagination } from './Pagination';
import { Spinner } from '@/components/ui/Spinner';

export interface FindingsExplorerProps {
  scanId: string;
  initialFindings: FindingResponseData[];
  initialTotal: number;
  initialPage: number;
  initialPerPage: number;
}

export function FindingsExplorer({
  scanId,
  initialFindings,
  initialTotal,
  initialPage,
  initialPerPage,
}: FindingsExplorerProps) {
  const [findings, setFindings] = useState<FindingResponseData[]>(initialFindings);
  const [total, setTotal] = useState(initialTotal);
  const [page, setPage] = useState(initialPage);
  const [perPage] = useState(initialPerPage);
  const [filters, setFilters] = useState<FindingsFilterState>({
    severity: 'all',
    category: 'all',
    scanner: 'all',
    page: 1,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);
  const isInitialMount = useRef(true);

  const fetchFindings = useCallback(
    async (targetFilters: FindingsFilterState, targetPage: number) => {
      // Abort any in-flight request
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      const controller = new AbortController();
      abortControllerRef.current = controller;

      setIsLoading(true);
      setError(null);

      try {
        const queryObj = buildFilterQuery({
          ...targetFilters,
          page: targetPage,
        });

        const queryParams = new URLSearchParams(queryObj);
        queryParams.set('per_page', String(perPage));
        queryParams.set('page', String(targetPage));

        const res = await fetch(
          `/api/v1/scans/${scanId}/findings?${queryParams.toString()}`,
          {
            signal: controller.signal,
            headers: { Accept: 'application/json' },
            credentials: 'include',
          }
        );

        if (!res.ok) {
          throw new Error(`Failed to load findings (HTTP ${res.status})`);
        }

        const json = await res.json();
        setFindings(json.data ?? []);
        setTotal(json.meta?.total ?? 0);
        setPage(targetPage);
      } catch (err: unknown) {
        if (err instanceof Error && err.name === 'AbortError') {
          return; // Ignore intentional aborts
        }
        setError(
          err instanceof Error
            ? err.message
            : 'An unexpected error occurred while loading findings.'
        );
      } finally {
        setIsLoading(false);
      }
    },
    [scanId, perPage]
  );

  // Fetch when filters or page change, skipping initial mount since server rendered initial findings
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false;
      return;
    }

    fetchFindings(filters, filters.page ?? 1);

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [filters, fetchFindings]);

  const handleFilterChange = (newFilters: FindingsFilterState) => {
    setFilters(newFilters);
  };

  const handleResetFilters = () => {
    setFilters({
      severity: 'all',
      category: 'all',
      scanner: 'all',
      page: 1,
    });
  };

  const handlePageChange = (newPage: number) => {
    setFilters((prev) => ({ ...prev, page: newPage }));
  };

  const totalPages = Math.ceil(total / perPage);
  const hasActiveFilters = Boolean(
    (filters.severity && filters.severity !== 'all') ||
      (filters.category && filters.category !== 'all') ||
      (filters.scanner && filters.scanner !== 'all')
  );

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-800 dark:bg-gray-900 flex flex-col gap-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100">
            Security Findings Explorer
          </h2>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
            Showing {findings.length} of {total} findings
          </p>
        </div>

        {isLoading && (
          <div className="flex items-center gap-2 text-xs text-blue-600 dark:text-blue-400">
            <Spinner size="sm" label="Updating findings..." />
            <span>Updating...</span>
          </div>
        )}
      </div>

      {/* Filter Controls */}
      <FindingsFilter
        filters={filters}
        onFilterChange={handleFilterChange}
        onReset={handleResetFilters}
      />

      {/* Error state */}
      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-200 bg-red-50 p-4 text-xs text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300 flex items-center justify-between"
        >
          <span>{error}</span>
          <button
            type="button"
            onClick={() => fetchFindings(filters, page)}
            className="font-medium underline hover:text-red-950 dark:hover:text-red-100"
          >
            Retry
          </button>
        </div>
      )}

      {/* Findings Content */}
      <div className="rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
        {isLoading && findings.length === 0 ? (
          <div className="p-12 text-center">
            <Spinner size="lg" label="Loading security findings..." />
            <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
              Retrieving findings...
            </p>
          </div>
        ) : findings.length === 0 ? (
          <div className="p-8">
            {hasActiveFilters ? (
              <EmptyState
                type="no-filter-matches"
                onReset={handleResetFilters}
              />
            ) : (
              <EmptyState type="no-findings" />
            )}
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-gray-800">
            {findings.map((finding) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="pt-2">
          <Pagination
            currentPage={page}
            totalPages={totalPages}
            onPageChange={handlePageChange}
          />
        </div>
      )}
    </div>
  );
}
