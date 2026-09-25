import type { IFinding } from '@securityscan/contracts';

export class SarifGenerator {
  generate(findings: IFinding[], targetUrl: string): string {
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'SecurityScan',
              version: '0.1.0',
              informationUri: 'https://github.com/securityscan',
              rules: this.buildRules(findings),
            },
          },
          results: this.buildResults(findings),
          invocations: [
            {
              executionSuccessful: true,
              properties: { targetUrl },
            },
          ],
        },
      ],
    };
    return JSON.stringify(sarif, null, 2);
  }

  private buildRules(findings: IFinding[]) {
    const seen = new Set<string>();
    return findings
      .filter((f) => {
        if (seen.has(f.ruleId)) return false;
        seen.add(f.ruleId);
        return true;
      })
      .map((f) => ({
        id: f.ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        help: { text: f.remediation },
        properties: {
          tags: f.owasp,
          cwe: f.cwe,
        },
        defaultConfiguration: {
          level: this.severityToLevel(f.severity),
        },
      }));
  }

  private buildResults(findings: IFinding[]) {
    return findings.map((f) => ({
      ruleId: f.ruleId,
      level: this.severityToLevel(f.severity),
      message: { text: f.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.endpoint,
            },
          },
          properties: {
            method: f.method,
            parameter: f.parameter,
          },
        },
      ],
    }));
  }

  private severityToLevel(severity: string): string {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
      case 'INFO':
        return 'note';
      default:
        return 'none';
    }
  }
}
