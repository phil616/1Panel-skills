import { listModules } from '../index.js';
// POST is not inherently read-only. Use implemented read action metadata, never suffix guessing.
export function isReadRequest(method: string, path: string) {
  if (method === 'GET') return /^\/api\/v2\//.test(path);
  return listModules().some((module) =>
    Object.values(module.actions).some(
      (action) =>
        !action.mutation &&
        action.method === method &&
        action.path === path &&
        !action.path.includes(':'),
    ),
  );
}
