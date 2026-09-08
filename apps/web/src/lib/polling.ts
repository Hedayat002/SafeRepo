import type { ScanStatus } from '@/types';
import { isTerminalStatus } from './dashboard-utils';

/**
 * Polling interval in milliseconds (5 seconds).
 */
export const POLL_INTERVAL_MS = 5000;

/**
 * Maximum number of polling attempts before timing out (~10 minutes total).
 */
export const MAX_POLL_ITERATIONS = 120;

/**
 * Consecutive error threshold before circuit breaker triggers polling halt.
 */
export const MAX_CONSECUTIVE_ERRORS = 10;

/**
 * Consecutive error threshold before displaying non-blocking warning notice.
 */
export const WARN_CONSECUTIVE_ERRORS = 3;

/**
 * Timeout in milliseconds for individual poll fetch requests (10 seconds).
 */
export const POLL_FETCH_TIMEOUT_MS = 10000;

/**
 * Immutable polling state representation.
 */
export interface PollState {
  status: ScanStatus | string;
  iteration: number;
  consecutiveErrors: number;
  uiMessage: string | null;
  isTerminal: boolean;
}

/**
 * Determines whether polling should initially start given the scan status.
 * Starts ONLY for active, non-terminal scans.
 */
export function shouldStartPolling(status: string | null | undefined): boolean {
  if (!status) return false;
  const normalized = status.toLowerCase();
  const validNonTerminal: string[] = ['queued', 'cloning', 'scanning', 'normalizing'];
  return validNonTerminal.includes(normalized);
}

/**
 * Evaluates whether polling must cease based on current state.
 */
export function shouldStopPolling(state: {
  status?: string | null;
  iteration: number;
  consecutiveErrors: number;
}): { stop: boolean; reason?: 'terminal_status' | 'max_iterations' | 'max_errors' } {
  if (isTerminalStatus(state.status)) {
    return { stop: true, reason: 'terminal_status' };
  }

  if (state.iteration >= MAX_POLL_ITERATIONS) {
    return { stop: true, reason: 'max_iterations' };
  }

  if (state.consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
    return { stop: true, reason: 'max_errors' };
  }

  return { stop: false };
}

/**
 * Creates the initial state for polling.
 */
export function createInitialPollState(initialStatus: ScanStatus | string): PollState {
  const terminal = isTerminalStatus(initialStatus);
  return {
    status: initialStatus,
    iteration: 0,
    consecutiveErrors: 0,
    uiMessage: null,
    isTerminal: terminal,
  };
}

/**
 * Pure state reducer determining the next poll state from fetch results.
 */
export function nextPollState(
  prevState: PollState,
  result: { status?: ScanStatus | string; error?: string | null }
): PollState {
  const nextIteration = prevState.iteration + 1;

  // Handle request error case
  if (result.error !== undefined && result.error !== null) {
    const nextErrors = prevState.consecutiveErrors + 1;

    if (nextErrors >= MAX_CONSECUTIVE_ERRORS) {
      return {
        ...prevState,
        iteration: nextIteration,
        consecutiveErrors: nextErrors,
        isTerminal: true,
        uiMessage:
          'Unable to reach server after multiple attempts. Please check your network connection and refresh.',
      };
    }

    if (nextIteration >= MAX_POLL_ITERATIONS) {
      return {
        ...prevState,
        iteration: nextIteration,
        consecutiveErrors: nextErrors,
        isTerminal: true,
        uiMessage:
          'Scan may be taking longer than expected. Please refresh the page to check current status.',
      };
    }

    return {
      ...prevState,
      iteration: nextIteration,
      consecutiveErrors: nextErrors,
      uiMessage:
        nextErrors >= WARN_CONSECUTIVE_ERRORS
          ? 'Connection issue detected — retrying...'
          : prevState.uiMessage,
    };
  }

  // Successful response case
  const nextStatus = result.status ?? prevState.status;
  const terminal = isTerminalStatus(nextStatus);

  if (terminal) {
    let finalMessage: string | null = null;
    if (nextStatus.toLowerCase() === 'failed') {
      finalMessage = 'Scan failed.';
    } else if (nextStatus.toLowerCase() === 'timed_out') {
      finalMessage = 'Scan exceeded maximum execution time (10 minutes).';
    }

    return {
      status: nextStatus,
      iteration: nextIteration,
      consecutiveErrors: 0,
      uiMessage: finalMessage,
      isTerminal: true,
    };
  }

  if (nextIteration >= MAX_POLL_ITERATIONS) {
    return {
      status: nextStatus,
      iteration: nextIteration,
      consecutiveErrors: 0,
      uiMessage:
        'Scan may be taking longer than expected. Please refresh the page to check current status.',
      isTerminal: true,
    };
  }

  return {
    status: nextStatus,
    iteration: nextIteration,
    consecutiveErrors: 0,
    uiMessage: null,
    isTerminal: false,
  };
}
