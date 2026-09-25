import { describe, it, expect } from 'vitest';
import {
  ScanStatus,
  AuthorizationState,
  ScanProfile,
  Severity,
  Confidence,
  FindingStatus,
} from '../enums.js';
import { SCAN_STATE_TRANSITIONS } from '../types/scan.js';

describe('ScanStatus', () => {
  it('has all expected states', () => {
    expect(ScanStatus.CREATED).toBe('CREATED');
    expect(ScanStatus.VALIDATING).toBe('VALIDATING');
    expect(ScanStatus.QUEUED).toBe('QUEUED');
    expect(ScanStatus.DISCOVERING).toBe('DISCOVERING');
    expect(ScanStatus.CRAWLING).toBe('CRAWLING');
    expect(ScanStatus.PASSIVE_ANALYSIS).toBe('PASSIVE_ANALYSIS');
    expect(ScanStatus.ACTIVE_TESTING).toBe('ACTIVE_TESTING');
    expect(ScanStatus.API_TESTING).toBe('API_TESTING');
    expect(ScanStatus.VERIFYING).toBe('VERIFYING');
    expect(ScanStatus.EVIDENCE_COLLECTION).toBe('EVIDENCE_COLLECTION');
    expect(ScanStatus.REPORTING).toBe('REPORTING');
    expect(ScanStatus.COMPLETED).toBe('COMPLETED');
    expect(ScanStatus.FAILED).toBe('FAILED');
    expect(ScanStatus.CANCELLED).toBe('CANCELLED');
    expect(ScanStatus.TIMEOUT).toBe('TIMEOUT');
  });
});

describe('ScanProfile', () => {
  it('supports all 10 production profiles', () => {
    expect(ScanProfile.PASSIVE).toBe('PASSIVE');
    expect(ScanProfile.QUICK).toBe('QUICK');
    expect(ScanProfile.WEB_STANDARD).toBe('WEB_STANDARD');
    expect(ScanProfile.API_STANDARD).toBe('API_STANDARD');
    expect(ScanProfile.AUTHENTICATED).toBe('AUTHENTICATED');
    expect(ScanProfile.AUTHORIZATION).toBe('AUTHORIZATION');
    expect(ScanProfile.FULL_ASSESSMENT).toBe('FULL_ASSESSMENT');
    expect(ScanProfile.CICD).toBe('CICD');
    expect(ScanProfile.PRODUCTION_SAFE).toBe('PRODUCTION_SAFE');
    expect(ScanProfile.SECURITY_LAB).toBe('SECURITY_LAB');
  });

  it('supports backward-compatibility aliases', () => {
    expect(ScanProfile.LIGHT).toBe(ScanProfile.QUICK);
    expect(ScanProfile.STANDARD).toBe(ScanProfile.WEB_STANDARD);
    expect(ScanProfile.AGGRESSIVE).toBe(ScanProfile.FULL_ASSESSMENT);
  });
});

describe('SCAN_STATE_TRANSITIONS', () => {
  it('terminal states have no transitions', () => {
    expect(SCAN_STATE_TRANSITIONS[ScanStatus.COMPLETED]).toEqual([]);
    expect(SCAN_STATE_TRANSITIONS[ScanStatus.FAILED]).toEqual([]);
    expect(SCAN_STATE_TRANSITIONS[ScanStatus.CANCELLED]).toEqual([]);
    expect(SCAN_STATE_TRANSITIONS[ScanStatus.TIMEOUT]).toEqual([]);
  });

  it('CREATED can transition to VALIDATING or CANCELLED', () => {
    const transitions = SCAN_STATE_TRANSITIONS[ScanStatus.CREATED];
    expect(transitions).toContain(ScanStatus.VALIDATING);
    expect(transitions).toContain(ScanStatus.CANCELLED);
  });

  it('every active state can transition to CANCELLED', () => {
    const activeStates = [
      ScanStatus.CREATED,
      ScanStatus.VALIDATING,
      ScanStatus.QUEUED,
      ScanStatus.DISCOVERING,
      ScanStatus.CRAWLING,
      ScanStatus.PASSIVE_ANALYSIS,
      ScanStatus.ACTIVE_TESTING,
      ScanStatus.API_TESTING,
      ScanStatus.VERIFYING,
      ScanStatus.EVIDENCE_COLLECTION,
      ScanStatus.REPORTING,
    ];
    for (const state of activeStates) {
      expect(SCAN_STATE_TRANSITIONS[state]).toContain(ScanStatus.CANCELLED);
    }
  });
});

describe('AuthorizationState', () => {
  it('has all expected values', () => {
    expect(AuthorizationState.PENDING).toBe('PENDING');
    expect(AuthorizationState.AUTHORIZED).toBe('AUTHORIZED');
    expect(AuthorizationState.EXPIRED).toBe('EXPIRED');
    expect(AuthorizationState.REVOKED).toBe('REVOKED');
  });
});
