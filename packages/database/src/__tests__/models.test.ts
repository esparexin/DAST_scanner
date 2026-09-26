import { describe, it, expect } from 'vitest';
import mongoose from 'mongoose';
import { UserModel } from '../models/user.model.js';
import { OrganizationModel } from '../models/organization.model.js';
import { MembershipModel } from '../models/membership.model.js';
import { ProjectModel } from '../models/project.model.js';
import { TargetModel } from '../models/target.model.js';
import { FindingModel } from '../models/finding.model.js';
import { WebhookSubscriptionModel } from '../models/webhook-subscription.model.js';
import { ScanScheduleModel } from '../models/scan-schedule.model.js';
import {
  AuthorizationState,
  TargetEnvironment,
  Severity,
  Confidence,
  FindingStatus,
  DetectionCategory,
  WebhookEvent,
  WebhookFormat,
  ScheduleFrequency,
} from '@securityscan/contracts';

describe('Database Models Schema Validation', () => {
  it('validates User model schema requirements', async () => {
    const invalidUser = new UserModel({});
    const error = invalidUser.validateSync();
    expect(error?.errors['email']).toBeDefined();
    expect(error?.errors['passwordHash']).toBeDefined();
  });

  it('validates Project model schema requirements', async () => {
    const invalidProject = new ProjectModel({});
    const error = invalidProject.validateSync();
    expect(error?.errors['name']).toBeDefined();
    expect(error?.errors['ownerId']).toBeDefined();
  });

  it('validates Target model schema requirements', async () => {
    const validTarget = new TargetModel({
      projectId: new mongoose.Types.ObjectId(),
      name: 'Production API',
      baseUrl: 'https://api.example.com',
      environment: TargetEnvironment.PRODUCTION,
      authorization: AuthorizationState.AUTHORIZED,
      scope: {
        allowedHosts: ['api.example.com'],
        excludedHosts: [],
        allowedPaths: [],
        excludedPaths: [],
      },
    });
    const error = validTarget.validateSync();
    expect(error).toBeUndefined();
  });

  it('validates Finding model schema requirements', async () => {
    const validFinding = new FindingModel({
      scanId: new mongoose.Types.ObjectId(),
      projectId: new mongoose.Types.ObjectId(),
      targetId: new mongoose.Types.ObjectId(),
      ruleId: 'SEC-HDR-001',
      title: 'Missing HSTS',
      description: 'Strict-Transport-Security header is missing',
      severity: Severity.MEDIUM,
      confidence: Confidence.CONFIRMED,
      status: FindingStatus.VERIFIED,
      category: DetectionCategory.MISCONFIGURATION,
      endpoint: 'https://api.example.com',
      method: 'GET',
      deduplicationKey: 'abc123hash',
    });
    const error = validFinding.validateSync();
    expect(error).toBeUndefined();
  });

  it('validates Organization model schema requirements', async () => {
    const org = new OrganizationModel({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: new mongoose.Types.ObjectId(),
    });
    const error = org.validateSync();
    expect(error).toBeUndefined();
    expect(org.tier).toBe('FREE');
  });

  it('validates Membership model schema requirements', async () => {
    const membership = new MembershipModel({
      organizationId: new mongoose.Types.ObjectId(),
      userId: new mongoose.Types.ObjectId(),
    });
    const error = membership.validateSync();
    expect(error).toBeUndefined();
    expect(membership.role).toBe('VIEWER');
  });

  it('validates WebhookSubscription model schema requirements', async () => {
    const webhook = new WebhookSubscriptionModel({
      organizationId: new mongoose.Types.ObjectId(),
      name: 'Slack Alerts',
      url: 'https://hooks.slack.com/services/T00/B00/X00',
      secret: 'whsec_test123456789',
      events: [WebhookEvent.SCAN_COMPLETED, WebhookEvent.FINDING_CRITICAL],
      format: WebhookFormat.SLACK,
    });
    const error = webhook.validateSync();
    expect(error).toBeUndefined();
    expect(webhook.enabled).toBe(true);
    expect(webhook.format).toBe('SLACK');
  });

  it('validates ScanSchedule model schema requirements', async () => {
    const schedule = new ScanScheduleModel({
      organizationId: new mongoose.Types.ObjectId(),
      projectId: new mongoose.Types.ObjectId(),
      targetId: new mongoose.Types.ObjectId(),
      name: 'Daily Production Audit',
      cron: '0 2 * * *',
      frequency: ScheduleFrequency.DAILY,
    });
    const error = schedule.validateSync();
    expect(error).toBeUndefined();
    expect(schedule.enabled).toBe(true);
    expect(schedule.profile).toBe('WEB_STANDARD');
  });
});
