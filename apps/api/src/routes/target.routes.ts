import { Router } from 'express';
import { TargetModel, ProjectModel } from '@securityscan/database';
import { CreateTargetSchema, UpdateTargetSchema, AuthorizationState } from '@securityscan/contracts';
import { authenticate, type AuthRequest } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';

export const targetRouter = Router();
targetRouter.use(authenticate);

targetRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.query;
    if (!projectId) {
      res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'projectId is required' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }
    const targets = await TargetModel.find({ projectId }).sort({ createdAt: -1 });
    res.json({ data: targets });
  } catch (err) {
    next(err);
  }
});

targetRouter.get('/:id', async (req: AuthRequest, res, next) => {
  try {
    const target = await TargetModel.findById(req.params['id']);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: target.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    res.json({ data: target });
  } catch (err) {
    next(err);
  }
});

targetRouter.post('/', validate(CreateTargetSchema), async (req: AuthRequest, res, next) => {
  try {
    const project = await ProjectModel.findOne({ _id: req.body.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }
    const target = await TargetModel.create({
      ...req.body,
      authorization: AuthorizationState.PENDING,
    });
    res.status(201).json({ data: target });
  } catch (err) {
    next(err);
  }
});

targetRouter.patch('/:id', validate(UpdateTargetSchema), async (req: AuthRequest, res, next) => {
  try {
    const target = await TargetModel.findById(req.params['id']);
    if (!target) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }
    const project = await ProjectModel.findOne({ _id: target.projectId, ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Target not found' } });
      return;
    }

    // Track authorization changes
    if (req.body.authorization === AuthorizationState.AUTHORIZED && target.authorization !== AuthorizationState.AUTHORIZED) {
      req.body.authorizedAt = new Date();
      req.body.authorizedBy = req.userId;
    }

    // Handle nested scope update
    const updateData: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(req.body)) {
      if (key === 'scope' && typeof value === 'object' && value !== null) {
        for (const [sk, sv] of Object.entries(value as Record<string, unknown>)) {
          updateData[`scope.${sk}`] = sv;
        }
      } else {
        updateData[key] = value;
      }
    }

    const updated = await TargetModel.findByIdAndUpdate(
      req.params['id'],
      { $set: updateData },
      { new: true },
    );
    res.json({ data: updated });
  } catch (err) {
    next(err);
  }
});
