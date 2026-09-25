import type { ReportFormat } from '../enums.js';

export interface IReport {
  id: string;
  scanId: string;
  projectId: string;
  targetId: string;
  format: ReportFormat;
  title: string;
  generatedAt: Date;
  scope: IReportScope;
  summary: IReportSummary;
  content?: string;
  filePath?: string;
  createdAt: Date;
}

export interface IReportScope {
  targetUrl: string;
  allowedHosts: string[];
  excludedHosts: string[];
  scanProfile: string;
  startedAt?: Date;
  completedAt?: Date;
}

export interface IReportSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  confirmedCount: number;
  endpointsScanned: number;
  requestsMade: number;
}

export interface IGenerateReport {
  scanId: string;
  format: ReportFormat;
  title?: string;
}
