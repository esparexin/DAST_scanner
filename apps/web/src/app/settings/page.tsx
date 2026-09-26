export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-black">Settings</h1>
        <p className="mt-1 text-sm text-gray-700">Scanner operational parameters, rate limiting, and crawl policy</p>
      </div>
      <div className="space-y-6">
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-lg font-bold text-black mb-4">Scanner Defaults</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <SettingField label="Max Requests/Second" value="10" />
            <SettingField label="Max Concurrency" value="5" />
            <SettingField label="Max Total Requests" value="10,000" />
            <SettingField label="Max Crawl Depth" value="5" />
            <SettingField label="Max Scan Duration" value="3600s" />
            <SettingField label="Request Timeout" value="30s" />
          </div>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-lg font-bold text-black mb-4">Account & Role</h2>
          <p className="text-gray-700 text-sm font-medium">Logged in as Security Administrator (Full Permissions). Multi-tenant tenant ID assigned.</p>
        </div>
      </div>
    </div>
  );
}

function SettingField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <label className="block text-xs font-bold text-black mb-1">{label}</label>
      <input
        type="text"
        defaultValue={value}
        className="w-full bg-gray-50 border border-gray-300 rounded-lg px-3 py-2 text-sm text-black font-mono font-semibold"
        readOnly
      />
    </div>
  );
}
