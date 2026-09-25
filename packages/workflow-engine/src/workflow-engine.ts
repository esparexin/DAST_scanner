import { createLogger } from '@securityscan/shared';

const logger = createLogger('workflow-engine');

export interface WorkflowStep {
  id: string;
  name: string;
  type: 'request' | 'extract' | 'assert' | 'wait';
  config: Record<string, unknown>;
  dependsOn?: string[];
}

export interface Workflow {
  id: string;
  name: string;
  steps: WorkflowStep[];
}

/**
 * Business-logic workflow engine for multi-step testing.
 * Example: Login -> Create -> Modify -> Delete
 * To be expanded after core engines are stable.
 */
export class WorkflowEngine {
  private workflows: Map<string, Workflow> = new Map();

  register(workflow: Workflow): void {
    this.workflows.set(workflow.id, workflow);
    logger.debug({ id: workflow.id, steps: workflow.steps.length }, 'Workflow registered');
  }

  get(id: string): Workflow | undefined {
    return this.workflows.get(id);
  }

  getAll(): Workflow[] {
    return Array.from(this.workflows.values());
  }

  validateOrder(workflow: Workflow): string[] {
    const errors: string[] = [];
    const defined = new Set(workflow.steps.map((s) => s.id));
    for (const step of workflow.steps) {
      if (step.dependsOn) {
        for (const dep of step.dependsOn) {
          if (!defined.has(dep)) {
            errors.push(`Step '${step.id}' depends on undefined step '${dep}'`);
          }
        }
      }
    }
    return errors;
  }
}
