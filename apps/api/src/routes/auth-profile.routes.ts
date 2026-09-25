import { Router } from 'express';
import { AuthProfileModel, ProjectModel } from '@securityscan/database';
import { CreateAuthProfileSchema } from '@securityscan/contracts';
import { authenticate, type AuthRequest } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { CredentialEncryption } from '@securityscan/authentication';

const encryption = new CredentialEncryption();

export const authProfileRouter = Router();
authProfileRouter.use(authenticate);

authProfileRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.query;
    if (!projectId) { res.status(400).json({ error: { message: 'projectId required' } }); return; }
    const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
    if (!project) { res.status(404).json({ error: { message: 'Project not found' } }); return; }
    const profiles = await AuthProfileModel.find({ projectId });
    // Never return credentials
    res.json({
      data: profiles.map((p) => ({
        id: p._id, projectId: p.projectId, name: p.name, role: p.role,
        type: p.type, isActive: p.isActive, hasCredentials: true,
        createdAt: p.createdAt, updatedAt: p.updatedAt,
      })),
    });
  } catch (err) { next(err); }
});

authProfileRouter.post('/', validate(CreateAuthProfileSchema), async (req: AuthRequest, res, next) => {
  try {
    const { projectId, name, role, type, configuration } = req.body;
    const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
    if (!project) { res.status(404).json({ error: { message: 'Project not found' } }); return; }

    const encryptedConfiguration = encryption.encrypt(JSON.stringify(configuration));
    const profile = await AuthProfileModel.create({
      projectId, name, role, type, encryptedConfiguration,
    });

    res.status(201).json({
      data: {
        id: profile._id, projectId: profile.projectId, name: profile.name,
        role: profile.role, type: profile.type, isActive: profile.isActive,
        hasCredentials: true, createdAt: profile.createdAt, updatedAt: profile.updatedAt,
      },
    });
  } catch (err) { next(err); }
});

authProfileRouter.delete('/:id', async (req: AuthRequest, res, next) => {
  try {
    const profile = await AuthProfileModel.findByIdAndDelete(req.params['id']);
    if (!profile) { res.status(404).json({ error: { message: 'Profile not found' } }); return; }
    res.status(204).send();
  } catch (err) { next(err); }
});
