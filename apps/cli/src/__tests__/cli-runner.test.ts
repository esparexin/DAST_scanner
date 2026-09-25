import { describe, it, expect } from 'vitest';
import { runCliScan } from '../runner.js';

describe('CLI Runner Integration', () => {
  it('supports dry-run mode and produces compliant SARIF with exit code 0', async () => {
    const result = await runCliScan({
      target: 'https://api.example.com',
      dryRun: true,
      failOn: 'HIGH',
    });

    expect(result.exitCode).toBe(0);
    expect(result.policyFailed).toBe(false);
    expect(result.totalFindings).toBe(0);
    const parsed = JSON.parse(result.sarifOutput);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
  });
});
