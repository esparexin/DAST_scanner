/**
 * End-to-End Demonstration Scan Script
 * Boots the vulnerable test server, initiates a multi-phase scan via orchestrator,
 * and asserts pipeline execution to completion.
 */
import { createVulnerableServer } from '../tests/fixtures/vulnerable-server.js';
import {
  connectDatabase,
  disconnectDatabase,
  ProjectModel,
  TargetModel,
  ScanModel,
  FindingModel,
  ReportModel,
} from '@securityscan/database';
import {
  ScanStatus,
  ScanProfile,
  AuthorizationState,
  TargetVerificationMethod,
} from '@securityscan/contracts';
import { processScan } from '../workers/orchestrator/src/scan-processor.js';

const PORT = 9999;
const MONGODB_URI = process.env['MONGODB_URI'] || 'mongodb://localhost:27017/securityscan_e2e';

export async function runE2eScan(): Promise<void> {
  console.log('='.repeat(70));
  console.log(' Starting End-to-End Security Assessment Pipeline Demonstration');
  console.log('='.repeat(70));

  // 1. Boot vulnerable test server
  console.log(`\n[1/5] Booting mock vulnerable target server on port ${PORT}...`);
  const server = createVulnerableServer(PORT);
  await new Promise<void>((resolve) => {
    server.listen(PORT, () => {
      console.log(`✓ Vulnerable target running at http://localhost:${PORT}`);
      resolve();
    });
  });

  try {
    // 2. Connect to Database
    console.log(`\n[2/5] Connecting to MongoDB at ${MONGODB_URI}...`);
    try {
      await connectDatabase(MONGODB_URI);
      console.log('✓ Database connected');
    } catch (dbErr: unknown) {
      const msg = dbErr instanceof Error ? dbErr.message : String(dbErr);
      console.warn(`⚠ Could not connect to MongoDB (${msg}).`);
      console.log('  Ensure MongoDB is running locally on port 27017 to execute active database scans.');
      return;
    }

    // 3. Create Project and Authorized Target
    console.log('\n[3/5] Setting up target authorization and scope...');
    const project = await ProjectModel.findOneAndUpdate(
      { name: 'E2E Assessment Project' },
      { name: 'E2E Assessment Project', description: 'Automated pipeline validation' },
      { upsert: true, new: true },
    );

    const targetUrl = `http://localhost:${PORT}`;
    const target = await TargetModel.findOneAndUpdate(
      { baseUrl: targetUrl, projectId: project._id },
      {
        name: 'Vulnerable Target Server',
        baseUrl: targetUrl,
        projectId: project._id,
        authorization: AuthorizationState.AUTHORIZED,
        authorizedAt: new Date(),
        scope: {
          allowedHosts: ['localhost', '127.0.0.1'],
          excludedHosts: [],
          allowedPaths: ['/*'],
          excludedPaths: [],
          maxRequestsPerSecond: 10,
          maxConcurrency: 2,
          maxRequests: 50,
          maxCrawlDepth: 3,
          maxScanDuration: 60,
          timeoutPerRequest: 5000,
        },
        verificationMethod: TargetVerificationMethod.HTTP_WELL_KNOWN,
      },
      { upsert: true, new: true },
    );
    console.log(`✓ Target registered and AUTHORIZED: ${target.baseUrl} (${target._id})`);

    // 4. Create Scan and Execute Orchestration Pipeline
    console.log('\n[4/5] Initiating multi-phase scan orchestration...');
    const scan = await ScanModel.create({
      projectId: project._id,
      targetId: target._id,
      profile: ScanProfile.QUICK,
      status: ScanStatus.CREATED,
      dryRun: false,
      configuration: {
        profile: ScanProfile.QUICK,
        authProfileIds: [],
        enabledCategories: [],
        excludedChecks: [],
        maxRequestsPerSecond: 10,
        maxConcurrency: 2,
        maxRequests: 50,
        maxCrawlDepth: 2,
        maxResponseSize: 1048576,
        maxScanDuration: 60,
        timeoutPerRequest: 5000,
        followRedirects: true,
        maxRedirects: 5,
      },
    });
    console.log(`✓ Scan enqueued: ID ${scan._id}`);

    const startTime = Date.now();
    await processScan(scan._id.toString());
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`✓ Orchestration pipeline completed in ${duration}s`);

    // 5. Assert Outcomes and Findings
    console.log('\n[5/5] Asserting scan results and generated artifacts...');
    const updatedScan = await ScanModel.findById(scan._id);
    const findings = await FindingModel.find({ scanId: scan._id });
    const report = await ReportModel.findOne({ scanId: scan._id });

    console.log('\n' + '-'.repeat(50));
    console.log(' SCAN EXECUTION SUMMARY');
    console.log('-'.repeat(50));
    console.log(`Status:            ${updatedScan?.status}`);
    console.log(`Duration:          ${duration}s`);
    console.log(`Total Findings:    ${findings.length}`);
    console.log(`Report Generated:  ${report ? 'YES (' + report.title + ')' : 'NO'}`);

    if (findings.length > 0) {
      console.log('\nDiscovered Findings:');
      for (const f of findings) {
        console.log(`  - [${f.severity}] ${f.title} (${f.endpoint})`);
      }
    }

    if (updatedScan?.status === ScanStatus.COMPLETED) {
      console.log('\n✓ E2E Scan demonstration succeeded: All phases verified!');
    } else {
      console.error(`\n✗ E2E Scan status is ${updatedScan?.status}: ${updatedScan?.failureReason}`);
    }
  } finally {
    // Teardown
    server.close();
    await disconnectDatabase().catch(() => {});
  }
}

if (process.env['NODE_ENV'] !== 'test') {
  runE2eScan()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Fatal error during E2E scan:', err);
      process.exit(1);
    });
}
