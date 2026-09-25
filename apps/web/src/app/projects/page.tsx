import { Nav } from '@/components/nav';

export default function ProjectsPage() {
  return (
    <>
      <Nav />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Projects</h1>
          <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            New Project
          </button>
        </div>
        <div className="bg-gray-900 rounded-lg border border-gray-800">
          <div className="p-6 text-center text-gray-500">
            No projects yet. Create one to start security testing.
          </div>
        </div>
      </main>
    </>
  );
}
