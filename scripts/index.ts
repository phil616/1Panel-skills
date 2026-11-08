import { openrestyModule } from './modules/openresty.js';
import { filesModule } from './modules/files.js';
import { mtlsModule } from './modules/mtls.js';
import type { ModuleDefinition } from './types.js';
import { appsModule } from './modules/apps.js';
import { containersModule } from './modules/containers.js';
import { cronjobsModule } from './modules/cronjobs.js';
import { logsModule } from './modules/logs.js';
import { monitoringModule } from './modules/monitoring.js';
import { nodesModule } from './modules/nodes.js';
import { taskCenterModule } from './modules/task-center.js';
import { websitesModule } from './modules/websites.js';

export const modules: Record<string, ModuleDefinition> = {
  openresty: openrestyModule,
  files: filesModule,
  mtls: mtlsModule,
  monitoring: monitoringModule,
  websites: websitesModule,
  apps: appsModule,
  containers: containersModule,
  logs: logsModule,
  cronjobs: cronjobsModule,
  'task-center': taskCenterModule,
  nodes: nodesModule,
};

export function listModules(): ModuleDefinition[] {
  return Object.values(modules);
}

export function getModule(moduleId: string): ModuleDefinition | undefined {
  return modules[moduleId];
}
