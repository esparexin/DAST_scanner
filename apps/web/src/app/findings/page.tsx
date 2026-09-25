'use client';

import { useEffect, useState } from 'react';
import { SeverityBadge } from '../../components/severity-badge';
import { findingsApi, type ApiFinding } from '../../lib/api';

export default function FindingsPage() {
  const [findings, setFindings] = useState<ApiFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('ALL');

  useEffect(() => {
    async function load() {
      try {
        const data = await findingsApi.list();
        setFindings(data);
      } catch {
        setFindings([]);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const filtered =
    filter === 'ALL'
      ? findings
      : findings.filter((f) => f.severity === filter);

  const severityCounts = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length,
    INFO: findings.filter((f) => f.severity === 'INFO').length,
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Findings</h1>
        <p className="mt-1 text-gray-600">Security vulnerabilities detected</p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              filter === sev
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {sev}
            {sev !== 'ALL' && ` (${severityCounts[sev]})`}
            {sev === 'ALL' && ` (${findings.length})`}
          </button>
        ))}
      </div>

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Finding
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Severity
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Category
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Endpoint
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-500">
                  Loading findings...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-500">
                  {findings.length === 0
                    ? 'No findings detected. Run a scan to discover vulnerabilities.'
                    : 'No findings match the selected filter.'}
                </td>
              </tr>
            ) : (
              filtered.map((finding) => (
                <tr key={finding._id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 max-w-xs">
                    <div className="truncate">{finding.title}</div>
                    {finding.cwe && finding.cwe.length > 0 && (
                      <span className="text-xs text-gray-400 font-mono">
                        {finding.cwe.join(', ')}
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {finding.category}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono max-w-xs truncate">
                    {finding.endpoint}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        finding.status === 'OPEN'
                          ? 'bg-red-100 text-red-700'
                          : finding.status === 'FIXED'
                            ? 'bg-green-100 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                      }`}
                    >
                      {finding.status}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
