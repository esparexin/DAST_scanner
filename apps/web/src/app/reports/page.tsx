import { Nav } from '@/components/nav';

export default function ReportsPage() {
  return (
    <>
      <Nav />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1 className="text-3xl font-bold mb-8">Reports</h1>
        <div className="bg-gray-900 rounded-lg border border-gray-800">
          <div className="p-6 text-center text-gray-500">
            No reports generated yet. Complete a scan to generate a report.
          </div>
        </div>
      </main>
    </>
  );
}
