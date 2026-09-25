import { ScanStateMachine } from './state-machine.js';
import { ScanStatus } from '@securityscan/contracts';
import type { IScopeConfig } from '@securityscan/contracts';
import { ScopeGuard, ScopeValidator } from '@securityscan/scope';
import { createLogger } from '@securityscan/shared';

const logger = createLogger('scan-orchestrator');

export interface ScanContext {
  scanId: string;
  targetId: string;
  projectId: string;
  scopeConfig: IScopeConfig;
  dryRun: boolean;
}

export class ScanOrchestrator {
  private readonly stateMachine: ScanStateMachine;
  private readonly context: ScanContext;
  private readonly scopeValidator: ScopeValidator;
  private onStateChange?: (scanId: string, status: ScanStatus) => Promise<void>;

  constructor(context: ScanContext, onStateChange?: (scanId: string, status: ScanStatus) => Promise<void>) {
    this.context = context;
    this.stateMachine = new ScanStateMachine(ScanStatus.CREATED);
    this.scopeValidator = ScopeGuard.createValidator(context.scopeConfig);
    this.onStateChange = onStateChange;
  }

  get status(): ScanStatus {
    return this.stateMachine.status;
  }

  get validator(): ScopeValidator {
    return this.scopeValidator;
  }

  async transitionTo(status: ScanStatus): Promise<void> {
    this.stateMachine.transition(status);
    logger.info({ scanId: this.context.scanId, status }, 'Scan state changed');
    if (this.onStateChange) {
      await this.onStateChange(this.context.scanId, status);
    }
  }

  cancel(): void {
    if (!this.stateMachine.isTerminal()) {
      this.scopeValidator.cancel();
      this.stateMachine.transition(ScanStatus.CANCELLED);
      logger.info({ scanId: this.context.scanId }, 'Scan cancelled');
    }
  }

  isTerminal(): boolean {
    return this.stateMachine.isTerminal();
  }
}
