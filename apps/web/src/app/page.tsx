'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { scansApi, findingsApi, type ApiScan, type ApiFinding } from '../lib/api';
import { SeverityBadge } from '../components/severity-badge';
import { StatusBadge } from '../components/status-badge';

export default function DashboardPage() {
  const [recentScans, setRecentScans] = useState<ApiScan[]>([]);
  const [criticalFindings, setCriticalFindings] = useState<ApiFinding[]>([]);
  const [stats, setStats] = useState({ scans: 0, projects: 0, findings: 0, reports: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [scans, findings] = await Promise.allSettled([
          scansApi.list(),
          findingsApi.list(),
        ]);

        const scanList = scans.status === 'fulfilled' ? scans.value : [];
        const findingList = findings.status === 'fulfilled' ? findings.value : [];

        setRecentScans(scanList.slice(0, 5));
        setCriticalFindings(
          findingList
            .filter((f) => f.severity === 'CRITICAL' && f.status === 'OPEN')
            .slice(0, 5),
        );
        setStats({
          scans: scanList.filter((s) => s.status === 'RUNNING' || s.status === 'TESTING').length,
          projects: 0,
          findings: findingList.filter((f) => f.status === 'OPEN').length,
          reports: 0,
        });
      } catch {
        // API not available, show empty state
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-2 text-gray-600">
          Web Application & API Security Testing Platform
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <DashboardCard
          title="Active Scans"
          value={loading ? '...' : String(stats.scans)}
          description="Currently running"
          href="/scans"
        />
        <DashboardCard
          title="Projects"
          value={loading ? '...' : String(stats.projects)}
          description="Configured"
          href="/projects"
        />
        <DashboardCard
          title="Findings"
          value={loading ? '...' : String(stats.findings)}
          description="Open vulnerabilities"
          href="/findings"
        />
        <DashboardCard
          title="Reports"
          value={loading ? '...' : String(stats.reports)}
          description="Generated"
          href="/reports"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Recent Scans
          </h2>
          {recentScans.length === 0 ? (
            <p className="text-gray-500 text-sm">
              No recent scans. Start a new scan to begin testing.
            </p>
          ) : (
            <div className="space-y-3">
              {recentScans.map((scan) => (
                <div
                  key={scan._id}
                  className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0"
                >
                  <div>
                    <p className="text-sm font-medium text-gray-900 truncate max-w-xs">
                      {scan.targetUrl}
                    </p>
                    <p className="text-xs text-gray-500">{scan.profile}</p>
                  </div>
                  <StatusBadge status={scan.status} />
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Critical Findings
          </h2>
          {criticalFindings.length === 0 ? (
            <p className="text-gray-500 text-sm">
              No critical findings detected.
            </p>
          ) : (
            <div className="space-y-3">
              {criticalFindings.map((f) => (
                <div
                  key={f._id}
                  className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0"
                >
                  <div>
                    <p className="text-sm font-medium text-gray-900 truncate max-w-xs">
                      {f.title}
                    </p>
                    <p className="text-xs text-gray-500 font-mono">{f.endpoint}</p>
                  </div>
                  <SeverityBadge severity={f.severity} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DashboardCard({
  title,
  value,
  description,
  href,
}: {
  title: string;
  value: string;
  description: string;
  href: string;
}) {
  return (
    <Link href={href}>
      <div className="bg-white rounded-lg shadow p-6 hover:shadow-md transition-shadow cursor-pointer">
        <p className="text-sm font-medium text-gray-600">{title}</p>
        <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
        <p className="mt-1 text-sm text-gray-500">{description}</p>
      </div>
    </Link>
  );
}
