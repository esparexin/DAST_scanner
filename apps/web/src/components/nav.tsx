'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const navItems = [
  { href: '/', label: 'Dashboard' },
  { href: '/targets', label: 'Targets' },
  { href: '/scans', label: 'Scans' },
  { href: '/findings', label: 'Findings' },
  { href: '/reports', label: 'Reports' },
  { href: '/projects', label: 'Projects' },
  { href: '/audit', label: 'Audit' },
  { href: '/settings', label: 'Settings' },
];

export function Nav() {
  const pathname = usePathname();

  return (
    <nav className="bg-white border-b border-gray-200 sticky top-0 z-40 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-8">
            <Link href="/" className="font-bold text-xl text-black flex items-center gap-2.5">
              <span className="inline-block w-3.5 h-3.5 bg-black rounded-sm" />
              <span>Security Scanner</span>
            </Link>
            <div className="hidden md:flex space-x-1">
              {navItems.map((item) => {
                const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`px-3 py-2 rounded-md text-sm font-semibold transition-colors ${
                      isActive
                        ? 'bg-gray-100 text-black border-b-2 border-black'
                        : 'text-gray-800 hover:text-black hover:bg-gray-50'
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <span className="text-xs font-bold uppercase tracking-wider text-black bg-gray-100 border border-gray-300 px-2.5 py-1 rounded">
              Console
            </span>
          </div>
        </div>
      </div>
    </nav>
  );
}
