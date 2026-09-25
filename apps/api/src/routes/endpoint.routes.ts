import { Router } from 'express';
import { EndpointModel } from '@securityscan/database';
import { authenticate, type AuthRequest } from '../middleware/auth.js';

export const endpointRouter = Router();
endpointRouter.use(authenticate);

endpointRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { scanId, targetId } = req.query;
    const filter: Record<string, unknown> = {};
    if (scanId) filter['scanId'] = scanId;
    if (targetId) filter['targetId'] = targetId;
    const endpoints = await EndpointModel.find(filter).sort({ path: 1 });
    res.json({ data: endpoints });
  } catch (err) { next(err); }
});
