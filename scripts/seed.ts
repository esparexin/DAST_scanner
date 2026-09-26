import {
  connectDatabase,
  disconnectDatabase,
  UserModel,
  ProjectModel,
  TargetModel,
  AuthProfileModel,
  ScanModel,
  FindingModel,
  AuditLogModel,
} from '@securityscan/database';
import {
  Severity,
  Confidence,
  DetectionCategory,
  ScanStatus,
  ScanProfile,
  AuthorizationState,
  AuditAction,
  FindingStatus,
} from '@securityscan/contracts';

const MONGODB_URI = process.env['MONGODB_URI'] || 'mongodb://localhost:27017/securityscan';

export async function seedDatabase() {
  console.log(`Connecting to MongoDB at ${MONGODB_URI}...`);
  try {
    await connectDatabase(MONGODB_URI);
  } catch (err) {
    console.warn('Could not connect to MongoDB. Skipping database seeding.');
    return;
  }

  console.log('Seeding initial workspace data...');

  // 1. Create Default Admin User
  const adminUser = await UserModel.findOneAndUpdate(
    { email: 'admin@securityscan.dev' },
    {
      email: 'admin@securityscan.dev',
      name: 'Security Admin',
      passwordHash: '$2a$10$abcdefghijklmnopqrstuv.mockhash',
      role: 'admin',
    },
    { upsert: true, new: true },
  );
  console.log(`✓ Admin user created: ${adminUser.email} (${adminUser._id})`);

  // 2. Create Demo Project
  const project = await ProjectModel.findOneAndUpdate(
    { name: 'E-Commerce Platform' },
    {
      name: 'E-Commerce Platform',
      description: 'Production web application and microservices API assessment',
      ownerId: adminUser._id,
    },
    { upsert: true, new: true },
  );
  console.log(`✓ Project created: ${project.name} (${project._id})`);

  // 3. Create Target
  const target = await TargetModel.findOneAndUpdate(
    { baseUrl: 'https://api.shop.example.com', projectId: project._id },
    {
      name: 'Shop Core API',
      baseUrl: 'https://api.shop.example.com',
      projectId: project._id,
      authorization: AuthorizationState.AUTHORIZED,
      authorizedAt: new Date(),
      authorizedBy: adminUser._id,
      scope: {
        allowedHosts: ['api.shop.example.com'],
        excludedHosts: [],
        allowedPaths: ['/*'],
        excludedPaths: ['/internal/*'],
        maxRequestsPerSecond: 10,
        maxConcurrency: 2,
        maxRequests: 100,
        maxCrawlDepth: 3,
        maxScanDuration: 300,
        timeoutPerRequest: 5000,
      },
    },
    { upsert: true, new: true },
  );
  console.log(`✓ Target created: ${target.name} (${target.baseUrl})`);

  // 4. Create Auth Profile
  const authProfile = await AuthProfileModel.findOneAndUpdate(
    { name: 'Customer JWT Profile', projectId: project._id },
    {
      name: 'Customer JWT Profile',
      type: 'BEARER',
      projectId: project._id,
      config: {
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.mock_token',
      },
      isValid: true,
    },
    { upsert: true, new: true },
  );
  console.log(`✓ Auth Profile created: ${authProfile.name}`);

  // 5. Create Historical Scan
  const scan = await ScanModel.findOneAndUpdate(
    { targetId: target._id, profile: ScanProfile.WEB_STANDARD },
    {
      targetId: target._id,
      projectId: project._id,
      profile: ScanProfile.WEB_STANDARD,
      status: ScanStatus.COMPLETED,
      startedAt: new Date(Date.now() - 3600000),
      completedAt: new Date(),
      configuration: {
        profile: ScanProfile.WEB_STANDARD,
        authProfileIds: [authProfile._id],
        enabledCategories: [],
        excludedChecks: [],
        maxRequestsPerSecond: 10,
        maxConcurrency: 2,
        maxRequests: 100,
        maxCrawlDepth: 3,
        maxResponseSize: 1048576,
        maxScanDuration: 300,
        timeoutPerRequest: 5000,
        followRedirects: true,
        maxRedirects: 5,
      },
      progress: {
        phase: ScanStatus.COMPLETED,
        totalRequests: 85,
        completedRequests: 85,
        endpointsDiscovered: 12,
        assetsDiscovered: 4,
        checksExecuted: 42,
        checksTotal: 42,
        findingsTotal: 4,
        findingsConfirmed: 4,
        errors: 0,
      },
    },
    { upsert: true, new: true },
  );
  console.log(`✓ Scan created: ${scan.profile} (${scan.status})`);

  // 6. Create Realistic Findings
  const demoFindings = [
    {
      scanId: scan._id,
      ruleId: 'SEC-SQLI-001',
      title: 'SQL Injection in Search Query Parameter',
      description: "Parameter 'q' leaked database error signatures when injected with quote disruption payloads.",
      severity: Severity.CRITICAL,
      confidence: Confidence.CONFIRMED,
      category: DetectionCategory.INJECTION,
      endpoint: `${target.baseUrl}/v1/products/search?q=test`,
      method: 'GET',
      parameter: 'q',
      cwe: ['CWE-89'],
      owasp: ['A03:2021'],
      cvssScore: 9.8,
      remediation: 'Implement parameterized queries and prepared statements.',
      status: FindingStatus.VERIFIED,
    },
    {
      scanId: scan._id,
      ruleId: 'SEC-XSS-001',
      title: 'Reflected Cross-Site Scripting (XSS) in Category Filter',
      description: "Parameter 'category' reflects unescaped canary token into HTML response body markup.",
      severity: Severity.HIGH,
      confidence: Confidence.CONFIRMED,
      category: DetectionCategory.XSS,
      endpoint: `${target.baseUrl}/products?category=test`,
      method: 'GET',
      parameter: 'category',
      cwe: ['CWE-79'],
      owasp: ['A03:2021'],
      cvssScore: 6.1,
      remediation: 'Implement context-aware HTML entity encoding on all user output.',
      status: FindingStatus.VERIFIED,
    },
    {
      scanId: scan._id,
      ruleId: 'SEC-PT-001',
      title: 'Path Traversal / Local File Exposure via Template Parameter',
      description: "Parameter 'template' accepts relative traversal sequences (../) allowing system file access.",
      severity: Severity.HIGH,
      confidence: Confidence.CONFIRMED,
      category: DetectionCategory.PATH_TRAVERSAL,
      endpoint: `${target.baseUrl}/templates?template=../../../../etc/passwd`,
      method: 'GET',
      parameter: 'template',
      cwe: ['CWE-22'],
      owasp: ['A01:2021'],
      cvssScore: 7.5,
      remediation: 'Canonicalize paths and match requested files against a strict allowlist.',
      status: FindingStatus.VERIFIED,
    },
    {
      scanId: scan._id,
      ruleId: 'SEC-CONF-001',
      title: 'Missing Content-Security-Policy and HSTS Headers',
      description: 'The endpoint does not return Content-Security-Policy or Strict-Transport-Security headers.',
      severity: Severity.MEDIUM,
      confidence: Confidence.CONFIRMED,
      category: DetectionCategory.MISCONFIGURATION,
      endpoint: target.baseUrl,
      method: 'GET',
      cwe: ['CWE-693'],
      owasp: ['A05:2021'],
      cvssScore: 5.3,
      remediation: 'Add strict Content-Security-Policy and Strict-Transport-Security headers.',
      status: FindingStatus.VERIFIED,
    },
  ];

  for (const f of demoFindings) {
    await FindingModel.findOneAndUpdate(
      { scanId: f.scanId, ruleId: f.ruleId },
      f,
      { upsert: true },
    );
  }
  console.log(`✓ Seeded ${demoFindings.length} demo findings`);

  // 7. Create Audit Logs
  const demoLogs = [
    {
      actorId: adminUser._id,
      actorEmail: adminUser.email,
      action: AuditAction.SCAN_STARTED,
      resourceType: 'Scan',
      resourceId: scan._id.toString(),
      ipAddress: '192.168.1.100',
      details: { profile: scan.profile, targetUrl: target.baseUrl },
      timestamp: new Date(Date.now() - 3600000),
    },
    {
      actorId: adminUser._id,
      actorEmail: adminUser.email,
      action: AuditAction.TARGET_AUTHORIZED,
      resourceType: 'Target',
      resourceId: target._id.toString(),
      ipAddress: '192.168.1.100',
      details: { validated: true, method: 'HTTP_CHALLENGE' },
      timestamp: new Date(Date.now() - 3590000),
    },
    {
      actorId: adminUser._id,
      actorEmail: adminUser.email,
      action: AuditAction.SCAN_COMPLETED,
      resourceType: 'Scan',
      resourceId: scan._id.toString(),
      ipAddress: '127.0.0.1',
      details: { totalFindings: demoFindings.length, status: 'COMPLETED' },
      timestamp: new Date(),
    },
  ];

  for (const log of demoLogs) {
    await AuditLogModel.create(log);
  }
  console.log(`✓ Seeded ${demoLogs.length} audit log entries`);

  await disconnectDatabase();
  console.log('\nDatabase seeding complete!');
}

if (process.argv[1]?.endsWith('seed.ts') || process.argv[1]?.endsWith('seed.js')) {
  seedDatabase().catch(console.error);
}
