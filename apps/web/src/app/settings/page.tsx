import { Nav } from '@/components/nav';

export default function SettingsPage() {
  return (
    <>
      <Nav />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <h1 className="text-3xl font-bold mb-8">Settings</h1>
        <div className="space-y-6">
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
            <h2 className="text-lg font-semibold mb-4">Scanner Defaults</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <SettingField label="Max Requests/Second" value="10" />
              <SettingField label="Max Concurrency" value="5" />
              <SettingField label="Max Total Requests" value="10,000" />
              <SettingField label="Max Crawl Depth" value="5" />
              <SettingField label="Max Scan Duration" value="3600s" />
              <SettingField label="Request Timeout" value="30s" />
            </div>
          </div>
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
            <h2 className="text-lg font-semibold mb-4">Account</h2>
            <p className="text-gray-500">Account settings will be available here.</p>
          </div>
        </div>
      </main>
    </>
  );
}

function SettingField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <label className="block text-sm text-gray-400 mb-1">{label}</label>
      <input
        type="text"
        defaultValue={value}
        className="w-full bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-gray-200"
        readOnly
      />
    </div>
  );
}
