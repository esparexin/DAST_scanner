import { Severity } from '@securityscan/contracts';
import type { IFinding, IReportScope, IReportSummary } from '@securityscan/contracts';

export interface ReportData {
  title: string;
  scope: IReportScope;
  findings: IFinding[];
  generatedAt: Date;
}

export class ReportGenerator {
  generateSummary(findings: IFinding[]): IReportSummary {
    return {
      totalFindings: findings.length,
      criticalCount: findings.filter((f) => f.severity === Severity.CRITICAL).length,
      highCount: findings.filter((f) => f.severity === Severity.HIGH).length,
      mediumCount: findings.filter((f) => f.severity === Severity.MEDIUM).length,
      lowCount: findings.filter((f) => f.severity === Severity.LOW).length,
      infoCount: findings.filter((f) => f.severity === Severity.INFO).length,
      confirmedCount: findings.filter((f) => f.status === 'VERIFIED').length,
      endpointsScanned: new Set(findings.map((f) => f.endpoint)).size,
      requestsMade: 0,
    };
  }

  generateJSON(data: ReportData): string {
    const summary = this.generateSummary(data.findings);
    return JSON.stringify(
      {
        title: data.title,
        generatedAt: data.generatedAt.toISOString(),
        scope: data.scope,
        summary,
        findings: data.findings.map((f) => ({
          title: f.title,
          description: f.description,
          severity: f.severity,
          confidence: f.confidence,
          status: f.status,
          category: f.category,
          endpoint: f.endpoint,
          method: f.method,
          parameter: f.parameter,
          remediation: f.remediation,
          cwe: f.cwe,
          owasp: f.owasp,
          references: f.references,
        })),
      },
      null,
      2,
    );
  }

  generateHTML(data: ReportData): string {
    const summary = this.generateSummary(data.findings);
    const findingsHTML = data.findings
      .map(
        (f) => `
      <div class="finding finding-${f.severity.toLowerCase()}">
        <h3>${this.escapeHtml(f.title)}</h3>
        <span class="badge severity-${f.severity.toLowerCase()}">${f.severity}</span>
        <span class="badge">${f.confidence}</span>
        <p>${this.escapeHtml(f.description)}</p>
        <p><strong>Endpoint:</strong> ${f.method} ${this.escapeHtml(f.endpoint)}</p>
        ${f.parameter ? `<p><strong>Parameter:</strong> ${this.escapeHtml(f.parameter)}</p>` : ''}
        <p><strong>CWE:</strong> ${f.cwe.join(', ')}</p>
        <p><strong>OWASP:</strong> ${f.owasp.join(', ')}</p>
        <h4>Remediation</h4>
        <p>${this.escapeHtml(f.remediation)}</p>
      </div>`,
      )
      .join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${this.escapeHtml(data.title)}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
    h1 { color: #fff; } h2 { color: #ccc; border-bottom: 1px solid #333; padding-bottom: 8px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
    .stat { background: #1a1a1a; padding: 16px; border-radius: 8px; text-align: center; }
    .stat .value { font-size: 2em; font-weight: bold; }
    .stat.critical .value { color: #ff4444; } .stat.high .value { color: #ff8800; }
    .stat.medium .value { color: #ffcc00; } .stat.low .value { color: #44aaff; }
    .finding { background: #1a1a1a; padding: 16px; margin: 12px 0; border-radius: 8px; border-left: 4px solid #333; }
    .finding-critical { border-left-color: #ff4444; } .finding-high { border-left-color: #ff8800; }
    .finding-medium { border-left-color: #ffcc00; } .finding-low { border-left-color: #44aaff; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; background: #333; margin-right: 4px; }
    .severity-critical { background: #ff4444; color: white; } .severity-high { background: #ff8800; color: white; }
    .severity-medium { background: #ffcc00; color: black; } .severity-low { background: #44aaff; color: white; }
  </style>
</head>
<body>
  <h1>${this.escapeHtml(data.title)}</h1>
  <p>Generated: ${data.generatedAt.toISOString()}</p>
  <p>Target: ${this.escapeHtml(data.scope.targetUrl)}</p>
  <h2>Summary</h2>
  <div class="summary">
    <div class="stat critical"><div class="value">${summary.criticalCount}</div>Critical</div>
    <div class="stat high"><div class="value">${summary.highCount}</div>High</div>
    <div class="stat medium"><div class="value">${summary.mediumCount}</div>Medium</div>
    <div class="stat low"><div class="value">${summary.lowCount}</div>Low</div>
    <div class="stat"><div class="value">${summary.infoCount}</div>Info</div>
    <div class="stat"><div class="value">${summary.totalFindings}</div>Total</div>
  </div>
  <h2>Findings</h2>
  ${findingsHTML || '<p>No findings.</p>'}
</body>
</html>`;
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}
