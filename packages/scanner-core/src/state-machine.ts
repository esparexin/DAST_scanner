import { ScanStatus, SCAN_STATE_TRANSITIONS } from '@securityscan/contracts';
import { AppError } from '@securityscan/shared';

export class ScanStateMachine {
  private _status: ScanStatus;

  constructor(initialStatus: ScanStatus = ScanStatus.CREATED) {
    this._status = initialStatus;
  }

  get status(): ScanStatus {
    return this._status;
  }

  canTransition(to: ScanStatus): boolean {
    const allowed = SCAN_STATE_TRANSITIONS[this._status];
    return allowed?.includes(to) ?? false;
  }

  transition(to: ScanStatus): void {
    if (!this.canTransition(to)) {
      throw new AppError(
        `Invalid state transition: ${this._status} -> ${to}`,
        400,
        'INVALID_STATE_TRANSITION',
      );
    }
    this._status = to;
  }

  isTerminal(): boolean {
    return [
      ScanStatus.COMPLETED,
      ScanStatus.FAILED,
      ScanStatus.CANCELLED,
      ScanStatus.TIMEOUT,
    ].includes(this._status);
  }

  isActive(): boolean {
    return !this.isTerminal() && this._status !== ScanStatus.CREATED;
  }
}
