#!/usr/bin/env node

import { Command } from 'commander';
import { writeFileSync } from 'node:fs';
import { runCliScan } from './runner.js';

const program = new Command();

program
  .name('securityscan')
  .description('Authorized Web Application & API Security Testing Platform CLI')
  .version('0.1.0');

program
  .command('run')
  .description('Execute an authorized security test scan against a target')
  .requiredOption('-t, --target <url>', 'Authorized target base URL')
  .option('-p, --profile <profile>', 'Scan Profile', 'CICD')
  .option('--fail-on <severity>', 'Fail pipeline on findings at or above severity (CRITICAL, HIGH, MEDIUM, LOW)', 'HIGH')
  .option('-o, --output <file>', 'Path to write SARIF v2.1.0 report')
  .option('--dry-run', 'Run scope evaluation and test planning only without active scanning')
  .option('--rate-limit <rps>', 'Max requests per second', '10')
  .action(async (opts) => {
    try {
      console.log(`[SecurityScan CLI] Initiating scan for: ${opts.target}`);
      console.log(`[SecurityScan CLI] Profile: ${opts.profile} | Fail Policy Threshold: ${opts.failOn}`);

      const result = await runCliScan({
        target: opts.target,
        profile: opts.profile,
        failOn: opts.failOn,
        dryRun: opts.dryRun,
        rateLimit: parseInt(opts.rateLimit, 10),
      });

      if (opts.output) {
        writeFileSync(opts.output, result.sarifOutput, 'utf8');
        console.log(`[SecurityScan CLI] SARIF report written to: ${opts.output}`);
      }

      console.log('\nScan Summary:');
      console.log(`Total Findings: ${result.totalFindings}`);
      console.log(`Critical: ${result.criticalFindings} | High: ${result.highFindings} | Medium: ${result.mediumFindings}`);

      if (result.policyFailed) {
        console.error(`\n[FAIL] Pipeline policy violated: Findings at or above ${opts.failOn} detected.`);
        process.exit(result.exitCode);
      } else {
        console.log('\n[PASS] No policy-violating findings detected.');
        process.exit(0);
      }
    } catch (err) {
      console.error('[SecurityScan CLI] Fatal error:', (err as Error).message);
      process.exit(1);
    }
  });

program.parse(process.argv);
