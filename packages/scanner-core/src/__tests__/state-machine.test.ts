import { describe, it, expect } from 'vitest';
import { ScanStateMachine } from '../state-machine.js';
import { ScanStatus } from '@securityscan/contracts';

describe('ScanStateMachine', () => {
  it('starts in CREATED state', () => {
    const sm = new ScanStateMachine();
    expect(sm.status).toBe(ScanStatus.CREATED);
  });

  it('allows valid transitions', () => {
    const sm = new ScanStateMachine();
    sm.transition(ScanStatus.VALIDATING);
    expect(sm.status).toBe(ScanStatus.VALIDATING);
    sm.transition(ScanStatus.QUEUED);
    expect(sm.status).toBe(ScanStatus.QUEUED);
  });

  it('throws on invalid transition', () => {
    const sm = new ScanStateMachine();
    expect(() => sm.transition(ScanStatus.COMPLETED)).toThrow('Invalid state transition');
  });

  it('allows cancellation from any active state', () => {
    const sm = new ScanStateMachine();
    sm.transition(ScanStatus.VALIDATING);
    sm.transition(ScanStatus.QUEUED);
    sm.transition(ScanStatus.DISCOVERING);
    sm.transition(ScanStatus.CANCELLED);
    expect(sm.status).toBe(ScanStatus.CANCELLED);
  });

  it('detects terminal states', () => {
    const sm = new ScanStateMachine(ScanStatus.COMPLETED);
    expect(sm.isTerminal()).toBe(true);
  });

  it('detects active states', () => {
    const sm = new ScanStateMachine();
    expect(sm.isActive()).toBe(false); // CREATED is not active
    sm.transition(ScanStatus.VALIDATING);
    expect(sm.isActive()).toBe(true);
  });

  it('does not allow transitions from terminal states', () => {
    const sm = new ScanStateMachine(ScanStatus.FAILED);
    expect(sm.canTransition(ScanStatus.QUEUED)).toBe(false);
    expect(() => sm.transition(ScanStatus.QUEUED)).toThrow();
  });

  it('runs through full happy path', () => {
    const sm = new ScanStateMachine();
    const path = [
      ScanStatus.VALIDATING, ScanStatus.QUEUED, ScanStatus.DISCOVERING,
      ScanStatus.CRAWLING, ScanStatus.PASSIVE_ANALYSIS, ScanStatus.ACTIVE_TESTING,
      ScanStatus.API_TESTING, ScanStatus.VERIFYING, ScanStatus.EVIDENCE_COLLECTION,
      ScanStatus.REPORTING, ScanStatus.COMPLETED,
    ];
    for (const status of path) {
      expect(sm.canTransition(status)).toBe(true);
      sm.transition(status);
    }
    expect(sm.status).toBe(ScanStatus.COMPLETED);
    expect(sm.isTerminal()).toBe(true);
  });
});
