import { Router } from 'express';
import { ReportModel, ScanModel, FindingModel, TargetModel } from '@securityscan/database';
import { GenerateReportSchema, ReportFormat } from '@securityscan/contracts';
import { ReportGenerator } from '@securityscan/reporting';
import { SarifGenerator } from '@securityscan/reporting';
import { authenticate, type AuthRequest } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';

export const reportRouter = Router();
reportRouter.use(authenticate);

reportRouter.get('/', async (req: AuthRequest, res, next) => {
  try {
    const { scanId, projectId } = req.query;
    const filter: Record<string, unknown> = {};
    if (scanId) filter['scanId'] = scanId;
    if (projectId) filter['projectId'] = projectId;
    const reports = await ReportModel.find(filter).sort({ createdAt: -1 });
    res.json({ data: reports });
  } catch (err) { next(err); }
});

reportRouter.get('/:id', async (req: AuthRequest, res, next) => {
  try {
    const report = await ReportModel.findById(req.params['id']);
    if (!report) { res.status(404).json({ error: { message: 'Report not found' } }); return; }
    res.json({ data: report });
  } catch (err) { next(err); }
});

reportRouter.post('/generate', validate(GenerateReportSchema), async (req: AuthRequest, res, next) => {
  try {
    const { scanId, format, title } = req.body;
    const scan = await ScanModel.findById(scanId);
    if (!scan) { res.status(404).json({ error: { message: 'Scan not found' } }); return; }
    const target = await TargetModel.findById(scan.targetId);
    if (!target) { res.status(404).json({ error: { message: 'Target not found' } }); return; }
    const findings = await FindingModel.find({ scanId: scan._id });
    const findingsObj = findings.map((f) => f.toObject() as any);

    const reportGen = new ReportGenerator();
    const sarifGen = new SarifGenerator();
    const summary = reportGen.generateSummary(findingsObj);

    const reportTitle = title ?? `Security Report - ${target.name}`;
    const scope = {
      targetUrl: target.baseUrl,
      allowedHosts: target.scope.allowedHosts,
      excludedHosts: target.scope.excludedHosts,
      scanProfile: scan.profile,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
    };

    let content: string;
    if (format === ReportFormat.SARIF) {
      content = sarifGen.generate(findingsObj, target.baseUrl);
    } else if (format === ReportFormat.HTML) {
      content = reportGen.generateHTML({ title: reportTitle, scope, findings: findingsObj, generatedAt: new Date() });
    } else {
      content = reportGen.generateJSON({ title: reportTitle, scope, findings: findingsObj, generatedAt: new Date() });
    }

    const report = await ReportModel.create({
      scanId: scan._id, projectId: scan.projectId, targetId: scan.targetId,
      format, title: reportTitle, generatedAt: new Date(), scope, summary, content,
    });

    res.status(201).json({ data: report });
  } catch (err) { next(err); }
});
