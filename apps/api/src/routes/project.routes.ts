import { Router } from 'express';
import { ProjectModel } from '@securityscan/database';
import { CreateProjectSchema, UpdateProjectSchema } from '@securityscan/contracts';
import { authenticate, type AuthRequest } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';

export const projectRouter = Router();
projectRouter.use(authenticate);

projectRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const projects = await ProjectModel.find({ ownerId: req.userId }).sort({ createdAt: -1 });
    res.json({ data: projects });
  } catch (err) {
    next(err);
  }
});

projectRouter.get('/:id', async (req: AuthRequest, res, next) => {
  try {
    const project = await ProjectModel.findOne({ _id: req.params['id'], ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }
    res.json({ data: project });
  } catch (err) {
    next(err);
  }
});

projectRouter.post('/', validate(CreateProjectSchema), async (req: AuthRequest, res, next) => {
  try {
    const project = await ProjectModel.create({ ...req.body, ownerId: req.userId });
    res.status(201).json({ data: project });
  } catch (err) {
    next(err);
  }
});

projectRouter.patch('/:id', validate(UpdateProjectSchema), async (req: AuthRequest, res, next) => {
  try {
    const project = await ProjectModel.findOneAndUpdate(
      { _id: req.params['id'], ownerId: req.userId },
      { $set: req.body },
      { new: true },
    );
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }
    res.json({ data: project });
  } catch (err) {
    next(err);
  }
});

projectRouter.delete('/:id', async (req: AuthRequest, res, next) => {
  try {
    const project = await ProjectModel.findOneAndDelete({ _id: req.params['id'], ownerId: req.userId });
    if (!project) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Project not found' } });
      return;
    }
    res.status(204).send();
  } catch (err) {
    next(err);
  }
});
