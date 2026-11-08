import path from 'node:path';
import type { OnePanelClientLike } from '../types.js';
import { unwrap } from './discovery.js';
import { PanelError, requireInput } from './errors.js';
export function controlledPath(root: string, candidate: string, directory = false) {
  requireInput(
    typeof candidate === 'string' &&
      candidate.startsWith('/') &&
      !/[\\\0\r\n%]/.test(candidate) &&
      !candidate.split('/').some((x) => x === '.' || x === '..') &&
      path.posix.normalize(candidate) === candidate,
    'Path must be a normalized absolute POSIX path',
  );
  requireInput(
    root.endsWith('/mtls') && (directory ? candidate === root : candidate.startsWith(root + '/')),
    'Path escapes the selected site policy directory',
  );
  requireInput(
    directory ||
      /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(conf|pem|crt|lua|json)$/.test(
        path.posix.basename(candidate),
      ),
    'Only flat .conf/.pem/.crt/.lua/.json policy files supported',
  );
  requireInput(
    directory || path.posix.dirname(candidate) === root,
    'Nested policy paths are not supported',
  );
  return candidate;
}
// Inspect every ancestor from its parent: lstat of only the final path misses symlinked parents.
export async function remoteStat(
  client: OnePanelClientLike,
  candidate: string,
  node: string,
): Promise<any | null> {
  const parts = candidate.split('/').filter(Boolean);
  let parent = '/';
  let found: any;
  for (let i = 0; i < parts.length; i++) {
    const data = unwrap(
      await client.request({
        method: 'POST',
        path: '/api/v2/files/search',
        operateNode: node,
        readOnly: true,
        body: {
          path: parent,
          search: parts[i],
          expand: true,
          showHidden: true,
          page: 1,
          pageSize: 1000,
        },
      }),
    );
    requireInput(
      data?.path === parent &&
        data.isDir === true &&
        data.isSymlink === false &&
        (Array.isArray(data.items) || (data.items === null && data.itemTotal === 0)),
      'File metadata API unavailable',
    );
    if ((data.itemTotal ?? 0) > 1000)
      throw new PanelError('API_UNSUPPORTED', 'Cannot inspect an ambiguous or paginated parent');
    const matches = (data.items ?? []).filter(
      (x: any) => x.name === parts[i] && x.path === path.posix.join(parent, parts[i]),
    );
    if (!matches.length) return null;
    requireInput(
      matches.length === 1 && typeof matches[0].isSymlink === 'boolean',
      'Cannot prove path metadata',
    );
    found = matches[0];
    if (found.isSymlink || found.linkPath)
      throw new PanelError('FORBIDDEN', 'Symbolic link in managed path');
    if (i < parts.length - 1) requireInput(found.isDir === true, 'Parent is not a directory');
    parent = path.posix.join(parent, parts[i]);
  }
  return found;
}
