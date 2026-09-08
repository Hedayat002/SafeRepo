import { describe, it, expect } from 'vitest';
import {
  POLL_INTERVAL_MS,
  MAX_POLL_ITERATIONS,
  MAX_CONSECUTIVE_ERRORS,
  WARN_CONSECUTIVE_ERRORS,
  POLL_FETCH_TIMEOUT_MS,
  shouldStartPolling,
  shouldStopPolling,
  createInitialPollState,
  nextPollState,
  type PollState,
} from '../polling';

describe('polling module', () => {
  describe('constants', () => {
    it('enforces approved timing and iteration constraints', () => {
      expect(POLL_INTERVAL_MS).toBe(5000);
      expect(MAX_POLL_ITERATIONS).toBe(120);
      expect(MAX_CONSECUTIVE_ERRORS).toBe(10);
      expect(WARN_CONSECUTIVE_ERRORS).toBe(3);
      expect(POLL_FETCH_TIMEOUT_MS).toBe(10000);
    });
  });

  describe('shouldStartPolling', () => {
    it('returns true for active non-terminal scan states', () => {
      expect(shouldStartPolling('queued')).toBe(true);
      expect(shouldStartPolling('cloning')).toBe(true);
      expect(shouldStartPolling('scanning')).toBe(true);
      expect(shouldStartPolling('normalizing')).toBe(true);
      expect(shouldStartPolling('QUEUED')).toBe(true);
    });

    it('returns false for terminal scan states', () => {
      expect(shouldStartPolling('completed')).toBe(false);
      expect(shouldStartPolling('failed')).toBe(false);
      expect(shouldStartPolling('timed_out')).toBe(false);
      expect(shouldStartPolling('COMPLETED')).toBe(false);
    });

    it('returns false for null, undefined, or empty values', () => {
      expect(shouldStartPolling(null)).toBe(false);
      expect(shouldStartPolling(undefined)).toBe(false);
      expect(shouldStartPolling('')).toBe(false);
      expect(shouldStartPolling('unknown_state')).toBe(false);
    });
  });

  describe('shouldStopPolling', () => {
    it('halts immediately when a terminal status is present', () => {
      expect(
        shouldStopPolling({ status: 'completed', iteration: 5, consecutiveErrors: 0 })
      ).toEqual({ stop: true, reason: 'terminal_status' });

      expect(
        shouldStopPolling({ status: 'failed', iteration: 2, consecutiveErrors: 0 })
      ).toEqual({ stop: true, reason: 'terminal_status' });

      expect(
        shouldStopPolling({ status: 'timed_out', iteration: 10, consecutiveErrors: 0 })
      ).toEqual({ stop: true, reason: 'terminal_status' });
    });

    it('halts when maximum poll iterations is reached (120)', () => {
      expect(
        shouldStopPolling({ status: 'scanning', iteration: 120, consecutiveErrors: 0 })
      ).toEqual({ stop: true, reason: 'max_iterations' });

      expect(
        shouldStopPolling({ status: 'scanning', iteration: 125, consecutiveErrors: 0 })
      ).toEqual({ stop: true, reason: 'max_iterations' });
    });

    it('halts when consecutive error threshold is reached (10)', () => {
      expect(
        shouldStopPolling({ status: 'scanning', iteration: 15, consecutiveErrors: 10 })
      ).toEqual({ stop: true, reason: 'max_errors' });

      expect(
        shouldStopPolling({ status: 'scanning', iteration: 15, consecutiveErrors: 12 })
      ).toEqual({ stop: true, reason: 'max_errors' });
    });

    it('continues when under all limits and status is non-terminal', () => {
      expect(
        shouldStopPolling({ status: 'scanning', iteration: 20, consecutiveErrors: 2 })
      ).toEqual({ stop: false });
      expect(
        shouldStopPolling({ status: 'cloning', iteration: 0, consecutiveErrors: 0 })
      ).toEqual({ stop: false });
    });
  });

  describe('createInitialPollState', () => {
    it('initializes non-terminal scan state correctly', () => {
      const state = createInitialPollState('scanning');
      expect(state).toEqual({
        status: 'scanning',
        iteration: 0,
        consecutiveErrors: 0,
        uiMessage: null,
        isTerminal: false,
      });
    });

    it('initializes terminal scan state with isTerminal true', () => {
      const state = createInitialPollState('completed');
      expect(state).toEqual({
        status: 'completed',
        iteration: 0,
        consecutiveErrors: 0,
        uiMessage: null,
        isTerminal: true,
      });
    });
  });

  describe('nextPollState', () => {
    const initialState: PollState = {
      status: 'scanning',
      iteration: 1,
      consecutiveErrors: 0,
      uiMessage: null,
      isTerminal: false,
    };

    it('updates status and resets consecutive errors on successful response', () => {
      const stateWithErrors: PollState = {
        ...initialState,
        consecutiveErrors: 2,
      };

      const next = nextPollState(stateWithErrors, { status: 'normalizing' });
      expect(next.status).toBe('normalizing');
      expect(next.iteration).toBe(2);
      expect(next.consecutiveErrors).toBe(0);
      expect(next.isTerminal).toBe(false);
      expect(next.uiMessage).toBeNull();
    });

    it('transitions to terminal when completed status is received', () => {
      const next = nextPollState(initialState, { status: 'completed' });
      expect(next.status).toBe('completed');
      expect(next.isTerminal).toBe(true);
      expect(next.consecutiveErrors).toBe(0);
      expect(next.uiMessage).toBeNull();
    });

    it('transitions to terminal when failed status is received', () => {
      const next = nextPollState(initialState, { status: 'failed' });
      expect(next.status).toBe('failed');
      expect(next.isTerminal).toBe(true);
      expect(next.uiMessage).toBe('Scan failed.');
    });

    it('transitions to terminal when timed_out status is received', () => {
      const next = nextPollState(initialState, { status: 'timed_out' });
      expect(next.status).toBe('timed_out');
      expect(next.isTerminal).toBe(true);
      expect(next.uiMessage).toContain('Scan exceeded maximum execution time');
    });

    it('increments consecutive errors and displays warning at 3 errors', () => {
      let state = initialState;

      // Error 1
      state = nextPollState(state, { error: 'Network timeout' });
      expect(state.consecutiveErrors).toBe(1);
      expect(state.uiMessage).toBeNull();
      expect(state.isTerminal).toBe(false);

      // Error 2
      state = nextPollState(state, { error: 'Network timeout' });
      expect(state.consecutiveErrors).toBe(2);
      expect(state.uiMessage).toBeNull();

      // Error 3: warning threshold
      state = nextPollState(state, { error: 'Network timeout' });
      expect(state.consecutiveErrors).toBe(3);
      expect(state.uiMessage).toBe('Connection issue detected — retrying...');
      expect(state.isTerminal).toBe(false);
    });

    it('triggers circuit breaker and stops polling after 10 consecutive errors', () => {
      let state: PollState = {
        ...initialState,
        consecutiveErrors: 9,
      };

      state = nextPollState(state, { error: 'Server down 503' });
      expect(state.consecutiveErrors).toBe(10);
      expect(state.isTerminal).toBe(true);
      expect(state.uiMessage).toContain('Unable to reach server after multiple attempts');
    });

    it('stops polling when reaching max iterations (120) with success response', () => {
      const stateAt119: PollState = {
        ...initialState,
        iteration: 119,
      };

      const next = nextPollState(stateAt119, { status: 'scanning' });
      expect(next.iteration).toBe(120);
      expect(next.isTerminal).toBe(true);
      expect(next.uiMessage).toContain('Scan may be taking longer than expected');
    });

    it('stops polling when reaching max iterations (120) with error response', () => {
      const stateAt119: PollState = {
        ...initialState,
        iteration: 119,
      };

      const next = nextPollState(stateAt119, { error: 'timeout' });
      expect(next.iteration).toBe(120);
      expect(next.isTerminal).toBe(true);
      expect(next.uiMessage).toContain('Scan may be taking longer than expected');
    });
  });
});
