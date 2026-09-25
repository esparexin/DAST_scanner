import { describe, it, expect } from 'vitest';
import { createApp } from '../app.js';

describe('API App Initialization', () => {
  it('creates express application successfully', () => {
    const app = createApp();
    expect(app).toBeDefined();
    expect(typeof app.listen).toBe('function');
  });
});
