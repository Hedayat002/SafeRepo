import type { FindingCategory, FindingScanner, FindingSeverity } from '@/types';

/**
 * UI filter state for security findings.
 */
export interface FindingsFilterState {
  severity?: FindingSeverity | 'all';
  category?: FindingCategory | 'all';
  scanner?: FindingScanner | 'all';
  page?: number;
}

const VALID_SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_CATEGORIES: readonly string[] = ['sast', 'dependency', 'secret', 'configuration', 'license'];
const VALID_SCANNERS: readonly string[] = ['semgrep', 'trivy', 'gitleaks', 'osv', 'npm-audit', 'pip-audit'];

/**
 * Constructs a query parameters object from UI filter state, omitting unset or 'all' values.
 */
export function buildFilterQuery(
  filters: FindingsFilterState
): Record<string, string> {
  const query: Record<string, string> = {};

  if (filters.severity && filters.severity !== 'all') {
    query.severity = filters.severity;
  }
  if (filters.category && filters.category !== 'all') {
    query.category = filters.category;
  }
  if (filters.scanner && filters.scanner !== 'all') {
    query.scanner = filters.scanner;
  }
  if (filters.page && filters.page > 1) {
    query.page = String(filters.page);
  }

  return query;
}

/**
 * Parses search parameters into a strongly-typed findings filter state.
 */
export function parseFilterParams(
  searchParams: URLSearchParams | Record<string, string | string[] | undefined>
): FindingsFilterState {
  const getParam = (key: string): string | undefined => {
    if (searchParams instanceof URLSearchParams) {
      return searchParams.get(key) ?? undefined;
    }
    const val = searchParams[key];
    if (Array.isArray(val)) return val[0];
    return val ?? undefined;
  };

  const rawSeverity = getParam('severity')?.toLowerCase();
  const rawCategory = getParam('category')?.toLowerCase();
  const rawScanner = getParam('scanner')?.toLowerCase();
  const rawPage = getParam('page');

  const severity: FindingSeverity | 'all' =
    rawSeverity && VALID_SEVERITIES.includes(rawSeverity)
      ? (rawSeverity as FindingSeverity)
      : 'all';

  const category: FindingCategory | 'all' =
    rawCategory && VALID_CATEGORIES.includes(rawCategory)
      ? (rawCategory as FindingCategory)
      : 'all';

  const scanner: FindingScanner | 'all' =
    rawScanner && VALID_SCANNERS.includes(rawScanner)
      ? (rawScanner as FindingScanner)
      : 'all';

  const parsedPage = rawPage ? parseInt(rawPage, 10) : 1;
  const page = !isNaN(parsedPage) && parsedPage > 0 ? parsedPage : 1;

  return { severity, category, scanner, page };
}

/**
 * Generates an array of page numbers and ellipsis tokens for pagination controls.
 */
export function getPageRange(
  currentPage: number,
  totalPages: number,
  maxVisible: number = 5
): (number | '...')[] {
  if (totalPages <= 0) return [];
  if (totalPages === 1) return [1];

  const current = clampPage(currentPage, totalPages);

  // If total pages is small, show all pages directly
  if (totalPages <= maxVisible + 2) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }

  const pages: (number | '...')[] = [];
  const sidePages = Math.floor((maxVisible - 2) / 2);

  let startPage = Math.max(2, current - sidePages);
  let endPage = Math.min(totalPages - 1, current + sidePages);

  if (current <= sidePages + 1) {
    endPage = maxVisible;
  } else if (current >= totalPages - sidePages) {
    startPage = totalPages - maxVisible + 1;
  }

  pages.push(1);

  if (startPage > 2) {
    pages.push('...');
  }

  for (let i = startPage; i <= endPage; i++) {
    if (i > 1 && i < totalPages) {
      pages.push(i);
    }
  }

  if (endPage < totalPages - 1) {
    pages.push('...');
  }

  pages.push(totalPages);

  return pages;
}

/**
 * Clamps a page number into the valid interval [1, totalPages].
 */
export function clampPage(
  page: number | string | null | undefined,
  totalPages: number
): number {
  const safeTotal = Math.max(1, totalPages);
  if (page === null || page === undefined) return 1;

  const numeric = typeof page === 'number' ? page : parseInt(String(page), 10);
  if (isNaN(numeric) || numeric < 1) {
    return 1;
  }
  if (numeric > safeTotal) {
    return safeTotal;
  }
  return numeric;
}

/**
 * Validates whether a page value represents a valid page within bounds.
 */
export function isValidPage(
  page: number | string | null | undefined,
  totalPages: number
): boolean {
  if (page === null || page === undefined || totalPages < 1) return false;
  const numeric = typeof page === 'number' ? page : Number(page);
  if (!Number.isInteger(numeric)) return false;
  return numeric >= 1 && numeric <= totalPages;
}
