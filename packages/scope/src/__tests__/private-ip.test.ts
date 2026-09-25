import { describe, it, expect } from 'vitest';
import { isPrivateIp } from '../private-ip.js';

describe('isPrivateIp', () => {
  describe('IPv4 private ranges', () => {
    it('blocks 10.x.x.x', () => {
      expect(isPrivateIp('10.0.0.1')).toBe(true);
      expect(isPrivateIp('10.255.255.255')).toBe(true);
    });

    it('blocks 172.16-31.x.x', () => {
      expect(isPrivateIp('172.16.0.1')).toBe(true);
      expect(isPrivateIp('172.31.255.255')).toBe(true);
    });

    it('allows 172.32.x.x', () => {
      expect(isPrivateIp('172.32.0.1')).toBe(false);
    });

    it('blocks 192.168.x.x', () => {
      expect(isPrivateIp('192.168.0.1')).toBe(true);
      expect(isPrivateIp('192.168.1.1')).toBe(true);
    });

    it('blocks 127.x.x.x (loopback)', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true);
      expect(isPrivateIp('127.255.255.255')).toBe(true);
    });

    it('blocks 169.254.x.x (link-local)', () => {
      expect(isPrivateIp('169.254.0.1')).toBe(true);
    });

    it('blocks 0.0.0.0', () => {
      expect(isPrivateIp('0.0.0.0')).toBe(true);
    });

    it('allows public IPs', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false);
      expect(isPrivateIp('93.184.216.34')).toBe(false);
      expect(isPrivateIp('1.1.1.1')).toBe(false);
    });
  });

  describe('IPv6 private ranges', () => {
    it('blocks ::1 (loopback)', () => {
      expect(isPrivateIp('::1')).toBe(true);
    });

    it('blocks fc00::/7 (unique local)', () => {
      expect(isPrivateIp('fc00::1')).toBe(true);
      expect(isPrivateIp('fd00::1')).toBe(true);
    });

    it('blocks fe80::/10 (link-local)', () => {
      expect(isPrivateIp('fe80::1')).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('blocks unknown formats (fail-safe)', () => {
      expect(isPrivateIp('not-an-ip')).toBe(true);
    });
  });
});
