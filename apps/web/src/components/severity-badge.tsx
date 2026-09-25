const colors: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${colors[severity] ?? 'bg-gray-600'}`}
    >
      {severity}
    </span>
  );
}
