import { describe, it, expect } from 'vitest';
import { CredentialEncryption } from '../credential-encryption.js';

describe('CredentialEncryption', () => {
  const enc = new CredentialEncryption('this-is-a-32-byte-test-key-here!');

  it('encrypts and decrypts correctly', () => {
    const plaintext = JSON.stringify({ token: 'secret123', password: 'hunter2' });
    const encrypted = enc.encrypt(plaintext);
    expect(encrypted).not.toBe(plaintext);
    expect(encrypted).toContain(':');
    const decrypted = enc.decrypt(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it('produces different ciphertext each time (random IV)', () => {
    const plaintext = 'same-value';
    const e1 = enc.encrypt(plaintext);
    const e2 = enc.encrypt(plaintext);
    expect(e1).not.toBe(e2);
    expect(enc.decrypt(e1)).toBe(plaintext);
    expect(enc.decrypt(e2)).toBe(plaintext);
  });

  it('throws on invalid ciphertext', () => {
    expect(() => enc.decrypt('invalid')).toThrow();
  });

  it('throws on tampered ciphertext', () => {
    const encrypted = enc.encrypt('test');
    const parts = encrypted.split(':');
    parts[2] = 'tampered';
    expect(() => enc.decrypt(parts.join(':'))).toThrow();
  });
});
