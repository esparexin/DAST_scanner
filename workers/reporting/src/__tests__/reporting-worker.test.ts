import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runReportingWorker } from '../index.js';
import { ScanModel, TargetModel, FindingModel, ReportModel } from '@securityscan/database';
import { ReportFormat, ScanStatus } from '@securityscan/contracts';
import type { StorageProvider, StoragePutResult } from '@securityscan/storage';

vi.mock('@securityscan/database', () => ({
  ScanModel: {
    findById: vi.fn(),
    findByIdAndUpdate: vi.fn(),
  },
  TargetModel: {
    findById: vi.fn(),
  },
  FindingModel: {
    find: vi.fn(),
  },
  ReportModel: {
    create: vi.fn(),
  },
}));

describe('Reporting Worker Object Storage Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('generates a report and uploads it to storage provider with presigned URL', async () => {
    const mockScan = {
      _id: 'scan-123',
      projectId: 'project-456',
      targetId: 'target-789',
      profile: 'WEB_STANDARD',
      startedAt: new Date('2026-09-01T00:00:00Z'),
    };
    const mockTarget = {
      _id: 'target-789',
      name: 'Test App',
      baseUrl: 'https://app.example.com',
      scope: {
        allowedHosts: ['app.example.com'],
        excludedHosts: [],
      },
    };
    const mockFindings = [
      {
        toObject: () => ({
          _id: 'finding-1',
          ruleId: 'SEC-XSS-001',
          title: 'Reflected Cross-Site Scripting',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          status: 'VERIFIED',
          category: 'INJECTION',
          endpoint: '/search',
          method: 'GET',
        }),
      },
    ];

    const mockReport = {
      _id: 'report-999',
      scanId: 'scan-123',
      projectId: 'project-456',
      targetId: 'target-789',
      format: ReportFormat.JSON,
      storageKey: '',
      storageUrl: '',
      filePath: '',
      save: vi.fn().mockResolvedValue(true),
    };

    (ScanModel.findById as any).mockResolvedValue(mockScan);
    (TargetModel.findById as any).mockResolvedValue(mockTarget);
    (FindingModel.find as any).mockResolvedValue(mockFindings);
    (ReportModel.create as any).mockResolvedValue(mockReport);
    (ScanModel.findByIdAndUpdate as any).mockResolvedValue({});

    const mockPutObject = vi.fn().mockResolvedValue({
      key: 'reports/project-456/scan-123/report-report-999.json',
      size: 1024,
      url: 'https://s3.amazonaws.com/bucket/report-999.json',
      contentType: 'application/json',
      uploadedAt: new Date(),
    } as StoragePutResult);

    const mockGetPresignedUrl = vi.fn().mockResolvedValue(
      'https://s3.amazonaws.com/bucket/report-999.json?X-Amz-Signature=abc',
    );

    const mockStorage: StorageProvider = {
      putObject: mockPutObject,
      getObject: vi.fn(),
      deleteObject: vi.fn(),
      exists: vi.fn(),
      getPresignedUrl: mockGetPresignedUrl,
    };

    const reportId = await runReportingWorker('scan-123', {
      format: ReportFormat.JSON,
      storageProvider: mockStorage,
    });

    expect(reportId).toBe('report-999');
    expect(mockPutObject).toHaveBeenCalledWith(
      'reports/project-456/scan-123/report-report-999.json',
      expect.any(String),
      'application/json',
      expect.objectContaining({ scanId: 'scan-123', format: ReportFormat.JSON }),
    );
    expect(mockGetPresignedUrl).toHaveBeenCalledWith(
      'reports/project-456/scan-123/report-report-999.json',
      86400,
    );
    expect(mockReport.storageKey).toBe('reports/project-456/scan-123/report-report-999.json');
    expect(mockReport.storageUrl).toBe(
      'https://s3.amazonaws.com/bucket/report-999.json?X-Amz-Signature=abc',
    );
    expect(mockReport.save).toHaveBeenCalled();
    expect(ScanModel.findByIdAndUpdate).toHaveBeenCalledWith('scan-123', {
      status: ScanStatus.COMPLETED,
      completedAt: expect.any(Date),
      'progress.phase': ScanStatus.COMPLETED,
    });
  });

  it('generates SARIF report and uploads to storage provider', async () => {
    const mockScan = {
      _id: 'scan-sarif',
      projectId: 'proj-1',
      targetId: 't-1',
      profile: 'API_STANDARD',
    };
    const mockTarget = {
      _id: 't-1',
      name: 'API Service',
      baseUrl: 'https://api.example.com',
      scope: { allowedHosts: ['api.example.com'], excludedHosts: [] },
    };
    const mockReport = {
      _id: 'report-sarif',
      save: vi.fn().mockResolvedValue(true),
    };

    (ScanModel.findById as any).mockResolvedValue(mockScan);
    (TargetModel.findById as any).mockResolvedValue(mockTarget);
    (FindingModel.find as any).mockResolvedValue([]);
    (ReportModel.create as any).mockResolvedValue(mockReport);
    (ScanModel.findByIdAndUpdate as any).mockResolvedValue({});

    const mockPutObject = vi.fn().mockResolvedValue({
      key: 'key',
      size: 500,
      contentType: 'application/sarif+json',
      uploadedAt: new Date(),
    } as StoragePutResult);
    const mockStorage: StorageProvider = {
      putObject: mockPutObject,
      getObject: vi.fn(),
      deleteObject: vi.fn(),
      exists: vi.fn(),
      getPresignedUrl: vi.fn().mockResolvedValue('https://download-url'),
    };

    const reportId = await runReportingWorker('scan-sarif', {
      format: ReportFormat.SARIF,
      storageProvider: mockStorage,
    });

    expect(reportId).toBe('report-sarif');
    expect(mockPutObject).toHaveBeenCalledWith(
      'reports/proj-1/scan-sarif/report-report-sarif.sarif',
      expect.any(String),
      'application/sarif+json',
      expect.objectContaining({ format: ReportFormat.SARIF }),
    );
  });
});
