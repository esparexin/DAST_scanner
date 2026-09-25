import { Router } from 'express';
import { FindingModel, EvidenceModel } from '@securityscan/database';
import { FindingFilterSchema, UpdateFindingStatusSchema } from '@securityscan/contracts';
import { authenticate, type AuthRequest } from '../middleware/auth.js';

export const findingRouter = Router();
findingRouter.use(authenticate);

findingRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const filters = FindingFilterSchema.parse(req.query);
    const query: Record<string, unknown> = {};
    if (filters.scanId) query['scanId'] = filters.scanId;
    if (filters.projectId) query['projectId'] = filters.projectId;
    if (filters.severity) query['severity'] = filters.severity;
    if (filters.confidence) query['confidence'] = filters.confidence;
    if (filters.status) query['status'] = filters.status;
    if (filters.category) query['category'] = filters.category;

    const skip = (filters.page - 1) * filters.limit;
    const [data, total] = await Promise.all([
      FindingModel.find(query).sort({ severity: 1, createdAt: -1 }).skip(skip).limit(filters.limit),
      FindingModel.countDocuments(query),
    ]);

    res.json({ data, pagination: { page: filters.page, limit: filters.limit, total } });
  } catch (err) {
    next(err);
  }
});

findingRouter.get('/:id', async (req: AuthRequest, res, next) => {
  try {
    const finding = await FindingModel.findById(req.params['id']);
    if (!finding) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Finding not found' } });
      return;
    }
    res.json({ data: finding });
  } catch (err) {
    next(err);
  }
});

findingRouter.get('/:id/evidence', async (req: AuthRequest, res, next) => {
  try {
    const evidence = await EvidenceModel.find({ findingId: req.params['id'] });
    res.json({ data: evidence });
  } catch (err) {
    next(err);
  }
});

findingRouter.patch('/:id/status', async (req: AuthRequest, res, next) => {
  try {
    const { status } = UpdateFindingStatusSchema.parse(req.body);
    const finding = await FindingModel.findByIdAndUpdate(
      req.params['id'],
      { $set: { status } },
      { new: true },
    );
    if (!finding) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Finding not found' } });
      return;
    }
    res.json({ data: finding });
  } catch (err) {
    next(err);
  }
});
