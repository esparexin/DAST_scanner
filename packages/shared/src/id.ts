import { randomBytes } from 'node:crypto';

/**
 * Generate a random hex ID for non-MongoDB contexts.
 */
export function generateId(length: number = 16): string {
  return randomBytes(length).toString('hex');
}
