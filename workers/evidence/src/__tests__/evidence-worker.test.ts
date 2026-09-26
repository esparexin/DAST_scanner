import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runEvidenceWorker } from '../index.js';
import { FindingModel, EvidenceModel } from '@securityscan/database';
import { FindingStatus } from '@securityscan/contracts';
import type { StorageProvider, StoragePutResult } from '@securityscan/storage';

vi.mock('@securityscan/database', () => ({
  FindingModel: {
    find: vi.fn(),
  },
  EvidenceModel: {
    find: vi.fn(),
  },
}));

describe('Evidence Worker Object Storage Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uploads evidence documents to object storage and sets storageKey & storageUrl', async () => {
    const mockFinding = {
      _id: 'finding-101',
      ruleId: 'SEC-SQLI-001',
      title: 'SQL Injection',
      cwe: ['CWE-89'],
      owasp: ['A03:2021'],
      endpoint: '/login',
      method: 'POST',
      parameter: 'username',
      description: 'SQL syntax error detected',
      impact: '',
      remediation: 'Use parameterized queries',
      save: vi.fn().mockResolvedValue(true),
    };

    const mockEvidence = {
      _id: 'evidence-501',
      findingId: 'finding-101',
      scanId: 'scan-abc',
      request: {
        method: 'POST',
        url: 'https://example.com/login',
        headers: { 'content-type': 'application/json' },
        body: '{"username": "\' OR 1=1--"}',
      },
      response: {
        statusCode: 500,
        headers: { 'content-type': 'text/plain' },
        body: 'syntax error in SQL query',
        responseTime: 45,
      },
      endpoint: '/login',
      parameter: 'username',
      authContext: 'anonymous',
      comparisonResults: [],
      relevantHeaders: {},
      relevantResponseData: 'syntax error in SQL query',
      timestamp: new Date(),
      storageKey: undefined,
      storageUrl: undefined,
      save: vi.fn().mockResolvedValue(true),
    };

    (FindingModel.find as any).mockResolvedValue([mockFinding]);
    (EvidenceModel.find as any).mockResolvedValue([mockEvidence]);

    const mockPutObject = vi.fn().mockResolvedValue({
      key: 'evidence/scan-abc/evidence-501.json',
      size: 400,
      contentType: 'application/json',
      uploadedAt: new Date(),
    } as StoragePutResult);

    const mockGetPresignedUrl = vi.fn().mockResolvedValue(
      'https://minio.local/bucket/evidence/scan-abc/evidence-501.json?token=xyz',
    );

    const mockStorage: StorageProvider = {
      putObject: mockPutObject,
      getObject: vi.fn(),
      deleteObject: vi.fn(),
      exists: vi.fn(),
      getPresignedUrl: mockGetPresignedUrl,
    };

    const enrichedCount = await runEvidenceWorker('scan-abc', {
      storageProvider: mockStorage,
    });

    expect(enrichedCount).toBe(1);
    expect(mockFinding.save).toHaveBeenCalled();
    expect(mockFinding.impact).toBeDefined();

    expect(mockPutObject).toHaveBeenCalledWith(
      'evidence/scan-abc/evidence-501.json',
      expect.stringContaining('syntax error in SQL query'),
      'application/json',
      expect.objectContaining({ scanId: 'scan-abc', findingId: 'finding-101' }),
    );

    expect(mockGetPresignedUrl).toHaveBeenCalledWith(
      'evidence/scan-abc/evidence-501.json',
      86400,
    );

    expect(mockEvidence.storageKey).toBe('evidence/scan-abc/evidence-501.json');
    expect(mockEvidence.storageUrl).toBe(
      'https://minio.local/bucket/evidence/scan-abc/evidence-501.json?token=xyz',
    );
    expect(mockEvidence.save).toHaveBeenCalled();
  });

  it('skips uploading evidence if storageKey is already present', async () => {
    (FindingModel.find as any).mockResolvedValue([]);
    const mockEvidence = {
      _id: 'ev-already-stored',
      findingId: 'f-1',
      scanId: 'scan-1',
      storageKey: 'evidence/scan-1/ev-already-stored.json',
      save: vi.fn(),
    };
    (EvidenceModel.find as any).mockResolvedValue([mockEvidence]);

    const mockPutObject = vi.fn();
    const mockStorage: StorageProvider = {
      putObject: mockPutObject,
      getObject: vi.fn(),
      deleteObject: vi.fn(),
      exists: vi.fn(),
      getPresignedUrl: vi.fn(),
    };

    await runEvidenceWorker('scan-1', { storageProvider: mockStorage });

    expect(mockPutObject).not.toHaveBeenCalled();
    expect(mockEvidence.save).not.toHaveBeenCalled();
  });
});
