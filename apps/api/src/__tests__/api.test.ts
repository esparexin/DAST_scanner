import { describe, it, expect } from 'vitest';
import { createApp } from '../app.js';

describe('API App Initialization', () => {
  it('creates express application successfully', () => {
    const app = createApp();
    expect(app).toBeDefined();
    expect(typeof app.listen).toBe('function');
  });

  it('registers organization and target verification routes', () => {
    const app = createApp();
    const routes = (app as any)._router?.stack
      ?.filter((r: any) => r.route || r.name === 'router')
      ?.map((r: any) => r.regexp?.toString());

    expect(routes).toBeDefined();
    expect(routes.length).toBeGreaterThan(5);
  });
});
