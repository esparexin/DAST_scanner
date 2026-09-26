export default function ProjectsPage() {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-black">Projects</h1>
          <p className="mt-1 text-sm text-gray-700">Organize targets, scope configurations, and scan policies</p>
        </div>
        <button className="bg-black hover:bg-gray-800 text-white px-4 py-2 rounded-lg text-sm font-bold transition-colors shadow-sm">
          + New Project
        </button>
      </div>
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-12 text-center">
        <p className="text-gray-700 font-medium text-sm">
          Default project configured. Create dedicated workspace projects to segment production vs staging assets.
        </p>
      </div>
    </div>
  );
}
