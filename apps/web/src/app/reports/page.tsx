'use client';

import { useEffect, useState } from 'react';
import { Nav } from '@/components/nav';
import { GenerateReportModal } from '@/components/generate-report-modal';
import { reportsApi, scansApi, type ApiReport, type ApiScan } from '@/lib/api';

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
    <>
      <Nav />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-100">Security Reports</h1>
            <p className="mt-1 text-sm text-gray-400">
              Generated executive, technical, and CI/CD compliance audit reports stored in object storage.
            </p>
          </div>
          <button
            onClick={() => setIsModalOpen(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 transition"
          >
            + Generate Report
          </button>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-6">
          <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
            {(['ALL', 'JSON', 'SARIF', 'HTML', 'PDF'] as const).map((fmt) => (
              <button
                key={fmt}
                onClick={() => setFilterFormat(fmt)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition ${
                  filterFormat === fmt
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
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
              className="w-full bg-gray-900 border border-gray-800 rounded-md px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
        </div>

        {/* Reports Content */}
        {loading ? (
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="animate-pulse bg-gray-900 border border-gray-800 rounded-lg p-6 h-32" />
            ))}
          </div>
        ) : filteredReports.length === 0 ? (
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-12 text-center">
            <svg
              className="mx-auto h-12 w-12 text-gray-600"
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
            <h3 className="mt-4 text-sm font-medium text-gray-300">No reports found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {reports.length === 0
                ? 'Generate your first security report from a completed scan.'
                : 'No reports match your current filter criteria.'}
            </p>
            {reports.length === 0 && (
              <button
                onClick={() => setIsModalOpen(true)}
                className="mt-4 inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded text-indigo-400 bg-indigo-950 hover:bg-indigo-900 transition"
              >
                Generate Report
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            {filteredReports.map((report) => {
              const formatColors: Record<string, string> = {
                JSON: 'bg-purple-900/60 text-purple-300 border-purple-800',
                SARIF: 'bg-blue-900/60 text-blue-300 border-blue-800',
                HTML: 'bg-emerald-900/60 text-emerald-300 border-emerald-800',
                PDF: 'bg-rose-900/60 text-rose-300 border-rose-800',
              };

              const downloadUrl = reportsApi.getDownloadUrl(report._id);

              return (
                <div
                  key={report._id}
                  className="bg-gray-900 rounded-lg border border-gray-800 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 hover:border-gray-700 transition"
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                          formatColors[report.format] ?? 'bg-gray-800 text-gray-300 border-gray-700'
                        }`}
                      >
                        {report.format}
                      </span>
                      <h3 className="text-base font-semibold text-gray-200">
                        {report.title || `Scan Report: ${report.scanId}`}
                      </h3>
                      {report.storageKey && (
                        <span className="inline-flex items-center text-xs text-gray-500 bg-gray-950 border border-gray-800 px-2 py-0.5 rounded">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5" />
                          S3 Stored
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-4 text-xs text-gray-400 flex-wrap">
                      {report.scope?.targetUrl && (
                        <span>
                          Target: <strong className="text-gray-300">{report.scope.targetUrl}</strong>
                        </span>
                      )}
                      <span>
                        Scan ID: <code className="text-indigo-400">{report.scanId}</code>
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
                        <span className="text-xs text-gray-500">Findings:</span>
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-950/80 text-red-400 border border-red-900/60">
                          {report.summary.criticalCount} Critical
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-orange-950/80 text-orange-400 border border-orange-900/60">
                          {report.summary.highCount} High
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-950/80 text-yellow-400 border border-yellow-900/60">
                          {report.summary.mediumCount} Medium
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-950/80 text-blue-400 border border-blue-900/60">
                          {report.summary.lowCount} Low
                        </span>
                        <span className="text-xs text-gray-400 ml-1">
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
                      className="inline-flex items-center px-3.5 py-2 border border-gray-700 text-sm font-medium rounded-md text-gray-200 bg-gray-800 hover:bg-gray-700 hover:text-white transition"
                    >
                      <svg
                        className="w-4 h-4 mr-2 text-indigo-400"
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
      </main>
    </>
  );
}
