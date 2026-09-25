import type { SecurityCheck, CheckContext, CheckResult } from '@securityscan/detection-engine';
import { DetectionCategory, DetectionType, Severity, Confidence, HttpMethod } from '@securityscan/contracts';

export class FileUploadChecks {
  static getChecks(): SecurityCheck[] {
    return [
      {
        rule: {
          id: 'SEC-UPL-001',
          name: 'Unrestricted File Upload / Executable Extension Bypass',
          description: 'The endpoint accepts file uploads with executable extensions or MIME-type spoofing.',
          category: DetectionCategory.FILE_UPLOAD,
          type: DetectionType.ACTIVE,
          severity: Severity.CRITICAL,
          confidence: Confidence.CONFIRMED,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
          cvssScore: 8.8,
          owasp: ['A04:2021'],
          apiOwasp: [],
          cwe: ['CWE-434'],
          wstg: ['WSTG-BUSL-09'],
          asvs: ['V12.1.1'],
          portswigger: ['https://portswigger.net/web-security/file-upload'],
          remediation: 'Validate file extensions against an allowlist of non-executable types. Store files outside web root.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
          enabled: true,
          tags: ['file-upload'],
        },
        async run(ctx: CheckContext): Promise<CheckResult[]> {
          // Only test upload candidate endpoints
          if (!/(upload|file|attachment|avatar|import|document)/i.test(ctx.endpoint.url)) {
            return [];
          }

          // Benign canary test file: harmless text content disguised with executable extension
          const boundary = '----WebKitFormBoundarySecurityScanCanary';
          const multipartBody =
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="file"; filename="canary.php.png"\r\n` +
            `Content-Type: image/png\r\n\r\n` +
            `SECURITYSCAN_BENIGN_TEST_PAYLOAD\r\n` +
            `--${boundary}--\r\n`;

          try {
            const res = await ctx.httpClient.request({
              method: HttpMethod.POST,
              url: ctx.endpoint.url,
              headers: {
                'Content-Type': `multipart/form-data; boundary=${boundary}`,
              },
              body: multipartBody,
            });

            if (res.statusCode >= 200 && res.statusCode < 300) {
              return [{
                ruleId: 'SEC-UPL-001',
                title: 'Unrestricted File Upload: Double/Executable Extension Accepted',
                description: `Upload endpoint accepted a file with double extension 'canary.php.png' without rejection.`,
                impact: 'May allow remote code execution if server executes scripts in the public upload directory.',
                severity: Severity.HIGH,
                confidence: Confidence.MEDIUM,
                category: DetectionCategory.FILE_UPLOAD,
                endpoint: ctx.endpoint.url,
                method: 'POST',
                remediation: 'Validate file content bytes, sanitize filename to a random hash, and serve files from a separate domain.',
                cwe: ['CWE-434'],
                owasp: ['A04:2021'],
                apiOwasp: [],
                references: [],
                evidence: {
                  request: { method: 'POST', url: ctx.endpoint.url, headers: {} },
                  response: { statusCode: res.statusCode, headers: res.headers, responseTime: res.responseTime },
                },
              }];
            }
          } catch {
            // Safe ignore
          }
          return [];
        },
      },
    ];
  }
}
