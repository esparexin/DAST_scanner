import { describe, it, expect } from 'vitest';
import { WorkflowEngine, type Workflow } from '../workflow-engine.js';

describe('WorkflowEngine', () => {
  const engine = new WorkflowEngine();

  const validWorkflow: Workflow = {
    id: 'wf-auth-flow',
    name: 'Authentication and Resource Lifecycle',
    steps: [
      { id: 's1', name: 'Login', type: 'request', config: { endpoint: '/login' } },
      { id: 's2', name: 'Create Project', type: 'request', config: { endpoint: '/projects' }, dependsOn: ['s1'] },
      { id: 's3', name: 'Delete Project', type: 'request', config: { endpoint: '/projects/:id' }, dependsOn: ['s2'] },
    ],
  };

  it('registers and retrieves workflows', () => {
    engine.register(validWorkflow);
    expect(engine.get('wf-auth-flow')).toBeDefined();
    expect(engine.getAll()).toHaveLength(1);
  });

  it('validates dependency order for valid workflows', () => {
    const errors = engine.validateOrder(validWorkflow);
    expect(errors).toHaveLength(0);
  });

  it('flags missing dependencies in workflow steps', () => {
    const invalidWorkflow: Workflow = {
      id: 'wf-broken',
      name: 'Broken dependencies',
      steps: [
        { id: 's1', name: 'Step 1', type: 'request', config: {}, dependsOn: ['non_existent'] },
      ],
    };
    const errors = engine.validateOrder(invalidWorkflow);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain('non_existent');
  });
});
