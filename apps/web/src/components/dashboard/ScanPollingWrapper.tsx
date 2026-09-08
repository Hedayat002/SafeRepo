'use client';

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import type { ScanStatus } from '@/types';
import {
  POLL_INTERVAL_MS,
  POLL_FETCH_TIMEOUT_MS,
  createInitialPollState,
  nextPollState,
  shouldStartPolling,
  shouldStopPolling,
  type PollState,
} from '@/lib/polling';

export interface ScanPollingWrapperProps {
  scanId: string;
  initialStatus: ScanStatus | string;
  onStatusChange?: (status: ScanStatus | string) => void;
  children?: React.ReactNode;
}

export function ScanPollingWrapper({
  scanId,
  initialStatus,
  onStatusChange,
  children,
}: ScanPollingWrapperProps) {
  const router = useRouter();
  const [pollState, setPollState] = useState<PollState>(() =>
    createInitialPollState(initialStatus)
  );

  const isFetchingRef = useRef(false);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const isMountedRef = useRef(true);

  const checkStatus = useCallback(async () => {
    // Prevent overlapping concurrent requests
    if (isFetchingRef.current) {
      return;
    }

    // Stop if already stopped
    if (shouldStopPolling(pollState).stop) {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      return;
    }

    isFetchingRef.current = true;
    const controller = new AbortController();
    abortControllerRef.current = controller;

    // 10s fetch timeout
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, POLL_FETCH_TIMEOUT_MS);

    try {
      const res = await fetch(`/api/v1/scans/${scanId}`, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
        credentials: 'include',
      });

      clearTimeout(timeoutId);

      if (!isMountedRef.current) return;

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const json = await res.json();
      const newStatus = json.data?.status;

      setPollState((prev) => {
        const next = nextPollState(prev, { status: newStatus });
        if (next.status !== prev.status) {
          onStatusChange?.(next.status);
          if (next.isTerminal) {
            // Refresh server components to pull latest findings and metadata
            router.refresh();
          }
        }
        return next;
      });
    } catch (err: unknown) {
      clearTimeout(timeoutId);
      if (!isMountedRef.current) return;

      if (err instanceof Error && err.name === 'AbortError') {
        // Request timed out or cancelled
      }

      setPollState((prev) =>
        nextPollState(prev, {
          error: err instanceof Error ? err.message : 'Network error',
        })
      );
    } finally {
      isFetchingRef.current = false;
      abortControllerRef.current = null;
    }
  }, [scanId, pollState, onStatusChange, router]);

  useEffect(() => {
    isMountedRef.current = true;

    // Only start polling if initial status is non-terminal
    if (!shouldStartPolling(initialStatus)) {
      return;
    }

    // Interval tick every 5000ms
    timerRef.current = setInterval(() => {
      checkStatus();
    }, POLL_INTERVAL_MS);

    return () => {
      isMountedRef.current = false;
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
    };
  }, [initialStatus, checkStatus]);

  return (
    <div className="flex flex-col gap-3">
      {/* Notice Banner if transient or terminal polling notice is active */}
      {pollState.uiMessage && (
        <div
          role="status"
          className={`rounded-lg p-3 text-xs flex items-center justify-between ${
            pollState.isTerminal
              ? 'bg-amber-50 text-amber-900 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-900'
              : 'bg-blue-50 text-blue-800 border border-blue-200 dark:bg-blue-950/40 dark:text-blue-300 dark:border-blue-900'
          }`}
        >
          <span>{pollState.uiMessage}</span>
          {pollState.isTerminal && (
            <button
              type="button"
              onClick={() => router.refresh()}
              className="font-medium underline hover:text-amber-950 dark:hover:text-amber-100 ml-2"
            >
              Refresh Page
            </button>
          )}
        </div>
      )}

      {children}
    </div>
  );
}
