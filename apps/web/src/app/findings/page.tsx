'use client';

import { useEffect, useState } from 'react';
import { SeverityBadge } from '../../components/severity-badge';
import { findingsApi, authApi, type ApiFinding } from '../../lib/api';

export default function FindingsPage() {
  const [findings, setFindings] = useState<ApiFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('ALL');

  useEffect(() => {
    async function load() {
      try {
        await authApi.ensureSession();
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
        <h1 className="text-3xl font-bold text-black">Findings</h1>
        <p className="mt-1 text-sm text-gray-700">Security vulnerabilities detected across scanned targets</p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-3 py-1.5 rounded-full text-xs font-bold transition-colors ${
              filter === sev
                ? 'bg-black text-white shadow-xs'
                : 'bg-white text-black border border-gray-300 hover:bg-gray-100'
            }`}
          >
            {sev}
            {sev !== 'ALL' && ` (${severityCounts[sev]})`}
            {sev === 'ALL' && ` (${findings.length})`}
          </button>
        ))}
      </div>

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Finding
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Category
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Endpoint
              </th>
              <th className="px-6 py-3.5 text-left text-xs font-bold text-black uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-600 font-medium">
                  Loading findings...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-sm text-gray-600 font-medium">
                  {findings.length === 0
                    ? 'No findings detected. Run a scan to discover vulnerabilities.'
                    : 'No findings match the selected filter.'}
                </td>
              </tr>
            ) : (
              filtered.map((finding) => (
                <tr key={finding._id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4 text-sm font-bold text-black max-w-xs">
                    <div className="truncate">{finding.title}</div>
                    {finding.cwe && finding.cwe.length > 0 && (
                      <span className="text-xs text-gray-600 font-mono font-normal">
                        {finding.cwe.join(', ')}
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-800">
                    {finding.category}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-800 font-mono max-w-xs truncate font-medium">
                    {finding.endpoint}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <span
                      className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                        finding.status === 'OPEN'
                          ? 'bg-red-50 text-red-800 border border-red-300'
                          : finding.status === 'FIXED'
                            ? 'bg-emerald-50 text-emerald-800 border border-emerald-300'
                            : 'bg-gray-100 text-gray-800 border border-gray-300'
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
