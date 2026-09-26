'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  scansApi,
  findingsApi,
  targetsApi,
  reportsApi,
  authApi,
  type ApiScan,
  type ApiFinding,
} from '../lib/api';
import { SeverityBadge } from '../components/severity-badge';
import { StatusBadge } from '../components/status-badge';

export default function DashboardPage() {
  const [recentScans, setRecentScans] = useState<ApiScan[]>([]);
  const [criticalFindings, setCriticalFindings] = useState<ApiFinding[]>([]);
  const [stats, setStats] = useState({ scans: 0, targets: 0, findings: 0, reports: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        await authApi.ensureSession();
        const [scans, findings, targets, reports] = await Promise.allSettled([
          scansApi.list(),
          findingsApi.list(),
          targetsApi.list(),
          reportsApi.list(),
        ]);

        const scanList = scans.status === 'fulfilled' ? scans.value : [];
        const findingList = findings.status === 'fulfilled' ? findings.value : [];
        const targetList = targets.status === 'fulfilled' ? targets.value : [];
        const reportList = reports.status === 'fulfilled' ? reports.value : [];

        setRecentScans(scanList.slice(0, 5));
        setCriticalFindings(
          findingList
            .filter((f) => f.severity === 'CRITICAL' && f.status === 'OPEN')
            .slice(0, 5),
        );
        setStats({
          scans: scanList.filter((s) => s.status === 'RUNNING' || s.status === 'TESTING').length,
          targets: targetList.length,
          findings: findingList.filter((f) => f.status === 'OPEN').length,
          reports: reportList.length,
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
        <h1 className="text-3xl font-bold text-black">Security Dashboard</h1>
        <p className="mt-2 text-gray-700">
          Enterprise Dynamic Application Security Testing (DAST) Platform
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <DashboardCard
          title="Targets"
          value={loading ? '...' : String(stats.targets)}
          description="Monitored domains & endpoints"
          href="/targets"
        />
        <DashboardCard
          title="Active Scans"
          value={loading ? '...' : String(stats.scans)}
          description="Currently executing"
          href="/scans"
        />
        <DashboardCard
          title="Open Findings"
          value={loading ? '...' : String(stats.findings)}
          description="Vulnerabilities detected"
          href="/findings"
        />
        <DashboardCard
          title="Reports"
          value={loading ? '...' : String(stats.reports)}
          description="Generated compliance reports"
          href="/reports"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-bold text-black">
              Recent Scans
            </h2>
            <Link href="/scans" className="text-xs font-bold text-black underline">
              View all
            </Link>
          </div>
          {recentScans.length === 0 ? (
            <p className="text-gray-600 text-sm font-medium">
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
                    <p className="text-sm font-semibold text-black truncate max-w-xs">
                      {scan.targetUrl}
                    </p>
                    <p className="text-xs text-gray-700 font-medium">{scan.profile}</p>
                  </div>
                  <StatusBadge status={scan.status} />
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-bold text-black">
              Critical Findings
            </h2>
            <Link href="/findings" className="text-xs font-bold text-black underline">
              View all
            </Link>
          </div>
          {criticalFindings.length === 0 ? (
            <p className="text-gray-600 text-sm font-medium">
              No critical findings detected. All verified targets look healthy.
            </p>
          ) : (
            <div className="space-y-3">
              {criticalFindings.map((f) => (
                <div
                  key={f._id}
                  className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0"
                >
                  <div>
                    <p className="text-sm font-semibold text-black truncate max-w-xs">
                      {f.title}
                    </p>
                    <p className="text-xs text-gray-700 font-mono font-medium">{f.endpoint}</p>
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
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 hover:shadow-md hover:border-gray-400 transition cursor-pointer">
        <p className="text-sm font-bold text-black uppercase tracking-wider">{title}</p>
        <p className="mt-2 text-3xl font-bold text-black">{value}</p>
        <p className="mt-1 text-xs text-gray-700 font-medium">{description}</p>
      </div>
    </Link>
  );
}
