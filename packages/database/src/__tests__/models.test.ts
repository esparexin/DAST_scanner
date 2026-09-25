import { describe, it, expect } from 'vitest';
import mongoose from 'mongoose';
import { UserModel } from '../models/user.model.js';
import { ProjectModel } from '../models/project.model.js';
import { TargetModel } from '../models/target.model.js';
import { FindingModel } from '../models/finding.model.js';
import { AuthorizationState, TargetEnvironment, Severity, Confidence, FindingStatus, DetectionCategory } from '@securityscan/contracts';

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
});
