import { networkInterfaces } from 'node:os';

/**
 * Check if an IP address falls within a private/internal range.
 * These are blocked by default to prevent SSRF.
 */
export function isPrivateIp(ip: string): boolean {
  // IPv4 private ranges
  if (isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts as [number, number, number, number];

    // 10.0.0.0/8
    if (a === 10) return true;

    // 172.16.0.0/12
    if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;

    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;

    // 127.0.0.0/8 (loopback)
    if (a === 127) return true;

    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) return true;

    // 0.0.0.0/8
    if (a === 0) return true;

    return false;
  }

  // IPv6 private ranges
  if (isIPv6(ip)) {
    const normalized = normalizeIPv6(ip);

    // ::1 (loopback)
    if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') {
      return true;
    }

    // fc00::/7 (unique local)
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
      return true;
    }

    // fe80::/10 (link-local)
    if (normalized.startsWith('fe80')) {
      return true;
    }

    // :: (unspecified)
    if (normalized === '::' || normalized === '0000:0000:0000:0000:0000:0000:0000:0000') {
      return true;
    }

    return false;
  }

  // Unknown format, block by default (safe)
  return true;
}

function isIPv4(ip: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
}

function isIPv6(ip: string): boolean {
  return ip.includes(':');
}

function normalizeIPv6(ip: string): string {
  return ip.toLowerCase();
}
