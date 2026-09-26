import { Router } from 'express';
import { ReportModel, ScanModel, FindingModel, TargetModel } from '@securityscan/database';
import { GenerateReportSchema, ReportFormat } from '@securityscan/contracts';
import { ReportGenerator } from '@securityscan/reporting';
import { SarifGenerator } from '@securityscan/reporting';
import { createStorageProvider } from '@securityscan/storage';
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

reportRouter.get('/:id/download', async (req: AuthRequest, res, next) => {
  try {
    const report = await ReportModel.findById(req.params['id']);
    if (!report) { res.status(404).json({ error: { message: 'Report not found' } }); return; }

    const ext = report.format === ReportFormat.SARIF ? 'sarif' : report.format === ReportFormat.HTML ? 'html' : 'json';
    const filename = `report-${report._id}.${ext}`;
    const contentType =
      report.format === ReportFormat.SARIF
        ? 'application/sarif+json'
        : report.format === ReportFormat.HTML
          ? 'text/html'
          : 'application/json';

    if (report.storageKey) {
      try {
        const storage = createStorageProvider();
        const presignedUrl = await storage.getPresignedUrl(report.storageKey, 3600);
        if (presignedUrl.startsWith('http://') || presignedUrl.startsWith('https://')) {
          res.redirect(presignedUrl);
          return;
        }
        const buffer = await storage.getObject(report.storageKey);
        if (buffer) {
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.send(buffer);
          return;
        }
      } catch {
        // Fall back to content field
      }
    }

    if (report.content) {
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(report.content);
      return;
    }

    res.status(404).json({ error: { message: 'Report content not found' } });
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
    let contentType: string;
    let ext: string;
    if (format === ReportFormat.SARIF) {
      content = sarifGen.generate(findingsObj, target.baseUrl);
      contentType = 'application/sarif+json';
      ext = 'sarif';
    } else if (format === ReportFormat.HTML) {
      content = reportGen.generateHTML({ title: reportTitle, scope, findings: findingsObj, generatedAt: new Date() });
      contentType = 'text/html';
      ext = 'html';
    } else {
      content = reportGen.generateJSON({ title: reportTitle, scope, findings: findingsObj, generatedAt: new Date() });
      contentType = 'application/json';
      ext = 'json';
    }

    let storageKey: string | undefined;
    let storageUrl: string | undefined;
    try {
      const storage = createStorageProvider();
      storageKey = `reports/${scan.projectId}/${scan._id}/report-${Date.now()}.${ext}`;
      await storage.putObject(storageKey, content, contentType, {
        scanId: scan._id.toString(),
        projectId: scan.projectId.toString(),
        format,
      });
      storageUrl = await storage.getPresignedUrl(storageKey, 86400);
    } catch {
      // Storage upload optional fallback
    }

    const report = await ReportModel.create({
      scanId: scan._id,
      projectId: scan.projectId,
      targetId: scan.targetId,
      format,
      title: reportTitle,
      generatedAt: new Date(),
      scope,
      summary,
      content,
      storageKey,
      storageUrl,
    });

    res.status(201).json({ data: report });
  } catch (err) { next(err); }
});
