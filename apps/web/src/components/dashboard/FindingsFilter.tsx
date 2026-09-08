'use client';

import React from 'react';
import type { FindingCategory, FindingScanner, FindingSeverity } from '@/types';
import type { FindingsFilterState } from '@/lib/findings-filters';
import { Select } from '@/components/ui/Select';

export interface FindingsFilterProps {
  filters: FindingsFilterState;
  onFilterChange: (filters: FindingsFilterState) => void;
  onReset?: () => void;
  className?: string;
}

const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

const CATEGORY_OPTIONS = [
  { value: 'all', label: 'All Categories' },
  { value: 'sast', label: 'SAST' },
  { value: 'dependency', label: 'Dependency' },
  { value: 'secret', label: 'Secret' },
  { value: 'configuration', label: 'Configuration' },
  { value: 'license', label: 'License' },
];

const SCANNER_OPTIONS = [
  { value: 'all', label: 'All Scanners' },
  { value: 'semgrep', label: 'Semgrep' },
  { value: 'trivy', label: 'Trivy' },
  { value: 'gitleaks', label: 'Gitleaks' },
  { value: 'osv', label: 'OSV' },
  { value: 'npm-audit', label: 'npm-audit' },
  { value: 'pip-audit', label: 'pip-audit' },
];

export function FindingsFilter({
  filters,
  onFilterChange,
  onReset,
  className = '',
}: FindingsFilterProps) {
  const hasActiveFilters = Boolean(
    (filters.severity && filters.severity !== 'all') ||
      (filters.category && filters.category !== 'all') ||
      (filters.scanner && filters.scanner !== 'all')
  );

  const handleSeverityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      severity: e.target.value as FindingSeverity | 'all',
      page: 1, // reset page on filter change
    });
  };

  const handleCategoryChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      category: e.target.value as FindingCategory | 'all',
      page: 1,
    });
  };

  const handleScannerChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      scanner: e.target.value as FindingScanner | 'all',
      page: 1,
    });
  };

  return (
    <div className={`flex flex-col gap-3 ${className}`}>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Select
          label="Filter by Severity"
          options={SEVERITY_OPTIONS}
          value={filters.severity ?? 'all'}
          onChange={handleSeverityChange}
        />
        <Select
          label="Filter by Category"
          options={CATEGORY_OPTIONS}
          value={filters.category ?? 'all'}
          onChange={handleCategoryChange}
        />
        <Select
          label="Filter by Scanner"
          options={SCANNER_OPTIONS}
          value={filters.scanner ?? 'all'}
          onChange={handleScannerChange}
        />
      </div>

      {hasActiveFilters && (
        <div className="flex items-center justify-between text-xs pt-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-gray-500 dark:text-gray-400">Active filters:</span>
            {filters.severity && filters.severity !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300 font-medium">
                Severity: {filters.severity}
                <button
                  type="button"
                  onClick={() =>
                    onFilterChange({ ...filters, severity: 'all', page: 1 })
                  }
                  className="hover:text-blue-900 dark:hover:text-white"
                  aria-label="Remove severity filter"
                >
                  ×
                </button>
              </span>
            )}
            {filters.category && filters.category !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300 font-medium">
                Category: {filters.category}
                <button
                  type="button"
                  onClick={() =>
                    onFilterChange({ ...filters, category: 'all', page: 1 })
                  }
                  className="hover:text-blue-900 dark:hover:text-white"
                  aria-label="Remove category filter"
                >
                  ×
                </button>
              </span>
            )}
            {filters.scanner && filters.scanner !== 'all' && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300 font-medium">
                Scanner: {filters.scanner}
                <button
                  type="button"
                  onClick={() =>
                    onFilterChange({ ...filters, scanner: 'all', page: 1 })
                  }
                  className="hover:text-blue-900 dark:hover:text-white"
                  aria-label="Remove scanner filter"
                >
                  ×
                </button>
              </span>
            )}
          </div>

          {onReset && (
            <button
              type="button"
              onClick={onReset}
              className="text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100 underline text-xs"
            >
              Reset all
            </button>
          )}
        </div>
      )}
    </div>
  );
}
