import { describe, it, expect } from 'vitest';
import {
  type SecurityIntelligencePackage,
  DetectionCategory,
  DetectionType,
  Severity,
  Confidence,
} from '@securityscan/contracts';
import { CatalogSigner } from '@securityscan/payload-engine';
import { StagedIntelligencePipeline } from '../intelligence/staged-pipeline.js';
import { IntelligenceChangeDetector } from '../intelligence/change-detector.js';

describe('StagedIntelligencePipeline', () => {
  const keys = CatalogSigner.generateKeyPair();

  const validPkg: SecurityIntelligencePackage = {
    packageVersion: '1.2.0',
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
        wstg: ['WSTG-INPV-05'],
        asvs: ['V5.3.4'],
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

  it('successfully passes all stages for a valid signed package', async () => {
    const manifest = CatalogSigner.signPackage(validPkg, keys.privateKey);
    const pipeline = new StagedIntelligencePipeline({
      publicKey: keys.publicKey,
    });

    const result = await pipeline.execute(validPkg, manifest);
    expect(result.success).toBe(true);
    expect(result.promotedVersion).toBe('1.2.0');
    expect(result.diff).toBeDefined();
    expect(result.diff?.rules.added).toContain('SEC-SQLI-001');
  });

  it('aborts at SIGNATURE_VERIFICATION when signature is forged', async () => {
    const wrongKeys = CatalogSigner.generateKeyPair();
    const manifest = CatalogSigner.signPackage(validPkg, wrongKeys.privateKey);

    const pipeline = new StagedIntelligencePipeline({
      publicKey: keys.publicKey, // mismatched key
    });

    const result = await pipeline.execute(validPkg, manifest);
    expect(result.success).toBe(false);
    expect(result.failedStage).toBe('SIGNATURE_VERIFICATION');
    expect(result.error).toContain('signature');
  });

  it('aborts at SCHEMA_VALIDATION if a rule is missing mandatory fields', async () => {
    const invalidPkg: SecurityIntelligencePackage = {
      packageVersion: '1.2.1',
      generatedAt: new Date().toISOString(),
      rules: [
        {
          id: 'SEC-BAD-001',
          name: '', // Empty name violates schema
        } as any,
      ],
      payloads: validPkg.payloads,
    };

    const manifest = CatalogSigner.signPackage(invalidPkg, keys.privateKey);
    const pipeline = new StagedIntelligencePipeline({
      publicKey: keys.publicKey,
    });

    const result = await pipeline.execute(invalidPkg, manifest);
    expect(result.success).toBe(false);
    expect(result.failedStage).toBe('SCHEMA_VALIDATION');
  });

  it('aborts at REGRESSION_TESTING if automated regression tests fail', async () => {
    const manifest = CatalogSigner.signPackage(validPkg, keys.privateKey);
    const pipeline = new StagedIntelligencePipeline({
      publicKey: keys.publicKey,
      regressionTestRunner: async () => ({
        passed: false,
        failures: ['SQL Injection check generated false positive on safe endpoint'],
      }),
    });

    const result = await pipeline.execute(validPkg, manifest);
    expect(result.success).toBe(false);
    expect(result.failedStage).toBe('REGRESSION_TESTING');
    expect(result.error).toContain('false positive');
  });

  it('detects added, modified, and deprecated rules accurately', () => {
    const currentRules = [validPkg.rules[0]!];
    const incomingRules = [
      { ...validPkg.rules[0]!, status: 'DEPRECATED' as const },
      {
        id: 'SEC-XSS-001',
        name: 'Cross-Site Scripting',
        description: 'Detects XSS',
        category: DetectionCategory.XSS,
        type: DetectionType.ACTIVE,
        severity: Severity.HIGH,
        confidence: Confidence.CONFIRMED,
        owasp: ['A03:2021'],
        apiOwasp: ['API8:2023'],
        cwe: ['CWE-79'],
        wstg: [],
        asvs: [],
        portswigger: [],
        remediation: 'Encode output',
        references: [],
        enabled: true,
        tags: ['xss'],
      },
    ];

    const diff = IntelligenceChangeDetector.diff(currentRules, incomingRules, [], []);
    expect(diff.rules.added).toContain('SEC-XSS-001');
    expect(diff.rules.deprecated).toContain('SEC-SQLI-001');
    expect(diff.hasBreakingChanges).toBe(false);
  });
});
