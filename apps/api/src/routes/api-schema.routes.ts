import { Router } from 'express';
import { ApiModel, ApiSchemaModel, EndpointModel, ProjectModel } from '@securityscan/database';
import { ApiType, ApiSchemaFormat, HttpMethod } from '@securityscan/contracts';
import { OpenApiParser } from '@securityscan/openapi';
import { authenticate, type AuthRequest } from '../middleware/auth.js';

export const apiSchemaRouter = Router();
apiSchemaRouter.use(authenticate);

apiSchemaRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { projectId } = req.query;
    const apis = await ApiModel.find(projectId ? { projectId } : {});
    res.json({ data: apis });
  } catch (err) { next(err); }
});

apiSchemaRouter.post('/import', async (req: AuthRequest, res, next) => {
  try {
    const { projectId, targetId, name, content, format } = req.body;
    const project = await ProjectModel.findOne({ _id: projectId, ownerId: req.userId });
    if (!project) { res.status(404).json({ error: { message: 'Project not found' } }); return; }

    const parser = new OpenApiParser();
    const parsed = parser.parse(content, format as ApiSchemaFormat);

    const api = await ApiModel.create({
      projectId, targetId, name: name ?? parsed.title ?? 'Imported API',
      type: ApiType.REST, baseUrl: parsed.baseUrl, version: parsed.version,
    });

    const schema = await ApiSchemaModel.create({
      apiId: api._id, projectId, format, content,
      parsed: true, valid: parsed.valid,
      validationErrors: parsed.errors, endpointCount: parsed.endpoints.length,
    });

    api.schemaId = schema._id;
    await api.save();

    res.status(201).json({
      data: { api, schema: { id: schema._id, endpoints: parsed.endpoints.length, valid: parsed.valid } },
    });
  } catch (err) { next(err); }
});
