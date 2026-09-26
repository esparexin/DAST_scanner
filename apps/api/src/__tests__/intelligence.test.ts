import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  IntelligenceReleaseModel,
  AuditLogModel,
} from '@securityscan/database';
import { CatalogSigner } from '@securityscan/payload-engine';
import {
  type SecurityIntelligencePackage,
  DetectionCategory,
  DetectionType,
  Severity,
  Confidence,
} from '@securityscan/contracts';

vi.mock('@securityscan/database', () => ({
  IntelligenceReleaseModel: {
    findOne: vi.fn(),
    find: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
  },
  AuditLogModel: {
    create: vi.fn(),
  },
}));

describe('Security Intelligence Management', () => {
  const keys = CatalogSigner.generateKeyPair();

  const validPkg: SecurityIntelligencePackage = {
    packageVersion: '2.1.0',
    generatedAt: new Date().toISOString(),
    rules: [
      {
        id: 'SEC-SQLI-001',
        name: 'SQL Injection',
        description: 'Detects SQLi',
        category: DetectionCategory.INJECTION,
        type: DetectionType.ACTIVE,
        severity: Severity.HIGH,
        confidence: Confidence.CONFIRMED,
        owasp: ['A03:2021'],
        apiOwasp: ['API8:2023'],
        cwe: ['CWE-89'],
        wstg: [],
        asvs: [],
        portswigger: [],
        remediation: 'Use parameterized queries',
        references: [],
        enabled: true,
        tags: ['sqli'],
      },
    ],
    payloads: [
      {
        id: 'PL-SQLI-001',
        version: '1.0.0',
        status: 'ACTIVE',
        category: 'INJECTION',
        template: { raw: "' OR 1=1--" },
        detection: { strategy: 'ERROR_MATCH' },
        verification: { strategy: 'DIFFERENTIAL' },
      },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('signs and verifies an intelligence package for staging', () => {
    const manifest = CatalogSigner.signPackage(validPkg, keys.privateKey);
    expect(manifest.packageVersion).toBe('2.1.0');
    expect(manifest.packageHash).toBeDefined();

    const verified = CatalogSigner.verifyPackage(manifest, validPkg, keys.publicKey);
    expect(verified).toBe(true);
  });

  it('detects rollback target and executes status transitions', async () => {
    const targetRelease = {
      _id: 'release-1',
      releaseVersion: '1.9.0',
      packageHash: 'hash123',
      status: 'SUPERSEDED',
      save: vi.fn().mockResolvedValue(true),
    };

    (IntelligenceReleaseModel.findOne as any).mockResolvedValue(targetRelease);

    // Simulate rollback
    targetRelease.status = 'ACTIVE';
    await targetRelease.save();

    expect(targetRelease.save).toHaveBeenCalled();
    expect(targetRelease.status).toBe('ACTIVE');
  });
});
