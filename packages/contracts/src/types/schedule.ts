import { ScanProfile, ScheduleFrequency } from '../enums.js';

export interface IScanSchedule {
  id: string;
  organizationId: string;
  projectId: string;
  targetId: string;
  name: string;
  cron: string;
  frequency: ScheduleFrequency;
  profile: ScanProfile;
  enabled: boolean;
  lastRunAt?: Date;
  nextRunAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICreateScheduleInput {
  name: string;
  projectId: string;
  targetId: string;
  cron?: string;
  frequency?: ScheduleFrequency;
  profile?: ScanProfile;
  enabled?: boolean;
}

export interface IUpdateScheduleInput {
  name?: string;
  cron?: string;
  frequency?: ScheduleFrequency;
  profile?: ScanProfile;
  enabled?: boolean;
}
