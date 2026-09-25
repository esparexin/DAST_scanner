import { describe, it, expect, vi } from 'vitest';
import { processScan } from '../scan-processor.js';
import { ScanModel, TargetModel } from '@securityscan/database';
import { ScanStatus } from '@securityscan/contracts';

vi.mock('@securityscan/database', () => ({
  ScanModel: {
    findById: vi.fn(),
    findByIdAndUpdate: vi.fn(),
  },
  TargetModel: {
    findById: vi.fn(),
  },
  EndpointModel: {
    insertMany: vi.fn(),
    find: vi.fn().mockResolvedValue([]),
  },
  FindingModel: {
    create: vi.fn(),
    find: vi.fn().mockResolvedValue([]),
    updateMany: vi.fn(),
    countDocuments: vi.fn().mockResolvedValue(0),
  },
  ReportModel: {
    create: vi.fn(),
  },
  AuthProfileModel: {
    find: vi.fn().mockResolvedValue([]),
  },
}));

describe('Scan Processor Orchestration', () => {
  it('aborts immediately if target is not AUTHORIZED', async () => {
    (ScanModel.findById as any).mockResolvedValue({
      _id: 'scan-1',
      targetId: 'target-1',
      projectId: 'proj-1',
      status: ScanStatus.CREATED,
    });
    (TargetModel.findById as any).mockResolvedValue({
      _id: 'target-1',
      authorization: 'PENDING', // NOT AUTHORIZED
    });

    await processScan('scan-1');

    expect(ScanModel.findByIdAndUpdate).toHaveBeenCalledWith(
      'scan-1',
      expect.objectContaining({
        status: ScanStatus.FAILED,
        failureReason: expect.stringContaining('not AUTHORIZED'),
      }),
    );
  });
});
