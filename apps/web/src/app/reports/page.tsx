'use client';

import { useEffect, useState } from 'react';
import { GenerateReportModal } from '@/components/generate-report-modal';
import { reportsApi, scansApi, authApi, type ApiReport, type ApiScan } from '@/lib/api';

export default function ReportsPage() {
  const [reports, setReports] = useState<ApiReport[]>([]);
  const [scans, setScans] = useState<ApiScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterFormat, setFilterFormat] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);

  async function loadData() {
    try {
      setLoading(true);
      await authApi.ensureSession();
      const [reportsData, scansData] = await Promise.all([
        reportsApi.list().catch(() => []),
        scansApi.list().catch(() => []),
      ]);
      setReports(reportsData);
      setScans(scansData);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  const filteredReports = reports.filter((r) => {
    const matchesFormat = filterFormat === 'ALL' || r.format === filterFormat;
    const matchesSearch =
      searchQuery === '' ||
      r.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.scanId?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.scope?.targetUrl?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFormat && matchesSearch;
  });

  const formatCounts = {
    JSON: reports.filter((r) => r.format === 'JSON').length,
    SARIF: reports.filter((r) => r.format === 'SARIF').length,
    HTML: reports.filter((r) => r.format === 'HTML').length,
    PDF: reports.filter((r) => r.format === 'PDF').length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-black tracking-tight">Security Reports</h1>
          <p className="mt-1 text-sm text-gray-700">
            Generated executive, technical, and CI/CD compliance audit reports stored in object storage.
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="inline-flex items-center px-4 py-2 border border-black text-sm font-bold rounded-lg shadow-sm text-white bg-black hover:bg-gray-800 transition"
        >
          + Generate Report
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
          {(['ALL', 'JSON', 'SARIF', 'HTML', 'PDF'] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => setFilterFormat(fmt)}
              className={`px-3 py-1.5 rounded-full text-xs font-bold transition ${
                filterFormat === fmt
                  ? 'bg-black text-white shadow-sm'
                  : 'bg-white text-black border border-gray-300 hover:bg-gray-100'
              }`}
            >
              {fmt}
              {fmt !== 'ALL' && ` (${formatCounts[fmt]})`}
              {fmt === 'ALL' && ` (${reports.length})`}
            </button>
          ))}
        </div>
        <div className="w-full md:w-72">
          <input
            type="text"
            placeholder="Search reports or scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-white border border-gray-300 rounded-md px-3 py-1.5 text-sm text-black placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-black"
          />
        </div>
      </div>

      {/* Reports Content */}
      {loading ? (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="animate-pulse bg-white border border-gray-200 rounded-lg p-6 h-32" />
          ))}
        </div>
      ) : filteredReports.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-12 text-center shadow-sm">
          <svg
            className="mx-auto h-12 w-12 text-gray-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <h3 className="mt-4 text-sm font-bold text-black">No reports found</h3>
          <p className="mt-1 text-sm text-gray-600">
            {reports.length === 0
              ? 'Generate your first security report from a completed scan.'
              : 'No reports match your current filter criteria.'}
          </p>
          {reports.length === 0 && (
            <button
              onClick={() => setIsModalOpen(true)}
              className="mt-4 inline-flex items-center px-3.5 py-1.5 border border-black text-xs font-bold rounded-lg text-white bg-black hover:bg-gray-800 transition"
            >
              Generate Report
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {filteredReports.map((report) => {
            const formatColors: Record<string, string> = {
              JSON: 'bg-purple-50 text-purple-800 border-purple-300',
              SARIF: 'bg-blue-50 text-blue-800 border-blue-300',
              HTML: 'bg-emerald-50 text-emerald-800 border-emerald-300',
              PDF: 'bg-rose-50 text-rose-800 border-rose-300',
            };

            const downloadUrl = reportsApi.getDownloadUrl(report._id);

            return (
              <div
                key={report._id}
                className="bg-white rounded-lg border border-gray-200 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 shadow-sm hover:border-gray-400 transition"
              >
                <div className="space-y-2 flex-1">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                        formatColors[report.format] ?? 'bg-gray-100 text-black border-gray-300'
                      }`}
                    >
                      {report.format}
                    </span>
                    <h3 className="text-base font-bold text-black">
                      {report.title || `Scan Report: ${report.scanId}`}
                    </h3>
                    {report.storageKey && (
                      <span className="inline-flex items-center text-xs font-semibold text-gray-700 bg-gray-100 border border-gray-300 px-2 py-0.5 rounded">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 mr-1.5" />
                        Stored
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-4 text-xs text-gray-700 flex-wrap">
                    {report.scope?.targetUrl && (
                      <span>
                        Target: <strong className="text-black">{report.scope.targetUrl}</strong>
                      </span>
                    )}
                    <span>
                      Scan ID: <code className="text-black font-mono font-semibold">{report.scanId}</code>
                    </span>
                    <span>
                      Generated:{' '}
                      {new Date(report.generatedAt ?? report.createdAt).toLocaleDateString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>

                  {/* Summary Findings Chips */}
                  {report.summary && (
                    <div className="flex items-center gap-2 pt-1 flex-wrap">
                      <span className="text-xs font-bold text-black">Findings:</span>
                      <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-100 text-red-800 border border-red-300">
                        {report.summary.criticalCount} Critical
                      </span>
                      <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-100 text-orange-800 border border-orange-300">
                        {report.summary.highCount} High
                      </span>
                      <span className="px-2 py-0.5 rounded text-xs font-bold bg-yellow-100 text-yellow-800 border border-yellow-300">
                        {report.summary.mediumCount} Medium
                      </span>
                      <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-100 text-blue-800 border border-blue-300">
                        {report.summary.lowCount} Low
                      </span>
                      <span className="text-xs font-medium text-gray-700 ml-1">
                        ({report.summary.totalFindings} total)
                      </span>
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-3">
                  <a
                    href={downloadUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center px-3.5 py-2 border border-gray-300 text-sm font-bold rounded-md text-black bg-white hover:bg-gray-100 transition shadow-xs"
                  >
                    <svg
                      className="w-4 h-4 mr-2 text-black"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                      />
                    </svg>
                    Download
                  </a>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Generate Report Modal */}
      <GenerateReportModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        scans={scans}
        onSuccess={loadData}
      />
    </div>
  );
}
