import { describe, it, expect } from 'vitest';
import {
  AppError,
  ValidationError,
  NotFoundError,
  AuthorizationError,
  ScopeError,
} from '../errors.js';

describe('AppError', () => {
  it('creates with defaults', () => {
    const err = new AppError('test error');
    expect(err.message).toBe('test error');
    expect(err.statusCode).toBe(500);
    expect(err.code).toBe('INTERNAL_ERROR');
    expect(err.isOperational).toBe(true);
  });

  it('creates with custom values', () => {
    const err = new AppError('custom', 418, 'TEAPOT', false);
    expect(err.statusCode).toBe(418);
    expect(err.code).toBe('TEAPOT');
    expect(err.isOperational).toBe(false);
  });
});

describe('ValidationError', () => {
  it('has 400 status code', () => {
    const err = new ValidationError('bad input');
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe('VALIDATION_ERROR');
  });
});

describe('NotFoundError', () => {
  it('has 404 status code', () => {
    const err = new NotFoundError('Project', '123');
    expect(err.statusCode).toBe(404);
    expect(err.message).toContain('Project');
    expect(err.message).toContain('123');
  });

  it('works without id', () => {
    const err = new NotFoundError('Resource');
    expect(err.message).toBe('Resource not found');
  });
});

describe('AuthorizationError', () => {
  it('has 403 status code', () => {
    const err = new AuthorizationError();
    expect(err.statusCode).toBe(403);
    expect(err.code).toBe('AUTHORIZATION_ERROR');
  });
});

describe('ScopeError', () => {
  it('has 403 status code', () => {
    const err = new ScopeError('out of scope');
    expect(err.statusCode).toBe(403);
    expect(err.code).toBe('SCOPE_VIOLATION');
  });
});
