const statusColors: Record<string, string> = {
  CREATED: 'bg-gray-600',
  VALIDATING: 'bg-blue-600',
  QUEUED: 'bg-blue-500',
  DISCOVERING: 'bg-indigo-500',
  CRAWLING: 'bg-indigo-600',
  PASSIVE_ANALYSIS: 'bg-purple-500',
  ACTIVE_TESTING: 'bg-purple-600',
  API_TESTING: 'bg-violet-500',
  VERIFYING: 'bg-amber-500',
  EVIDENCE_COLLECTION: 'bg-amber-600',
  REPORTING: 'bg-teal-500',
  COMPLETED: 'bg-green-600',
  FAILED: 'bg-red-600',
  CANCELLED: 'bg-gray-500',
  TIMEOUT: 'bg-orange-600',
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium text-white ${statusColors[status] ?? 'bg-gray-600'}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}
