'use client';

import { useEffect, useState, useCallback } from 'react';
import { StatusBadge } from '../../components/status-badge';
import { scansApi, type ApiScan, type CreateScanRequest } from '../../lib/api';

const SCAN_PROFILES = [
  'PASSIVE',
  'QUICK',
  'WEB_STANDARD',
  'API_STANDARD',
  'AUTHENTICATED',
  'AUTHORIZATION',
  'FULL_ASSESSMENT',
  'CICD',
  'PRODUCTION_SAFE',
  'SECURITY_LAB',
];

export default function ScansPage() {
  const [scans, setScans] = useState<ApiScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [newTarget, setNewTarget] = useState('');
  const [newProfile, setNewProfile] = useState('WEB_STANDARD');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const loadScans = useCallback(async () => {
    try {
      const data = await scansApi.list();
      setScans(data);
    } catch {
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [loadScans]);

  const handleCreate = async () => {
    if (!newTarget.trim()) return;
    setSubmitting(true);
    setError('');
    try {
      const payload: CreateScanRequest = {
        targetUrl: newTarget.trim(),
        scopePatterns: [`${new URL(newTarget.trim()).origin}/*`],
        profile: newProfile,
      };
      await scansApi.create(payload);
      setShowNew(false);
      setNewTarget('');
      await loadScans();
    } catch (err: any) {
      setError(err.message || 'Failed to create scan');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Scans</h1>
          <p className="mt-1 text-gray-600">
            Manage and monitor security scans
          </p>
        </div>
        <button
          onClick={() => setShowNew(true)}
          className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 transition-colors"
        >
          New Scan
        </button>
      </div>

      {showNew && (
        <div className="bg-white rounded-lg shadow p-6 border-l-4 border-indigo-600">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Scan</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Target URL
              </label>
              <input
                type="url"
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                placeholder="https://api.example.com"
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:ring-indigo-500 focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Scan Profile
              </label>
              <select
                value={newProfile}
                onChange={(e) => setNewProfile(e.target.value)}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:ring-indigo-500 focus:border-indigo-500"
              >
                {SCAN_PROFILES.map((p) => (
                  <option key={p} value={p}>
                    {p.replace(/_/g, ' ')}
                  </option>
                ))}
              </select>
            </div>
          </div>
          {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
          <div className="mt-4 flex gap-3">
            <button
              onClick={handleCreate}
              disabled={submitting}
              className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700 disabled:opacity-50 text-sm"
            >
              {submitting ? 'Creating...' : 'Start Scan'}
            </button>
            <button
              onClick={() => setShowNew(false)}
              className="bg-gray-100 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-200 text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Target
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Profile
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Findings
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Created
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-500">
                  Loading scans...
                </td>
              </tr>
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-500">
                  No scans yet. Click "New Scan" to get started.
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan._id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {scan.targetUrl}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {scan.profile}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {scan.findingsCount ?? 0}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(scan.createdAt).toLocaleString()}
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
