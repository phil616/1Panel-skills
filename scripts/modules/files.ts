import { readFile } from 'node:fs/promises';
import type { ModuleDefinition, OnePanelClientLike } from '../types.js';
import { safeWrite, type WriteIntent } from '../security/change-plan.js';
import { type Target, discoverSite, result, checkContent, unwrap } from '../security/discovery.js';
import { controlledPath, remoteStat } from '../security/path-policy.js';
import { fileResource } from '../security/resources.js';
import { requireInput } from '../security/errors.js';
import { validateManagedLua } from '../security/mtls-policy.js';
import { parseCABundle } from '../security/certificates.js';
export interface FileInput extends WriteIntent {
  target: Target;
  path: string;
  content: string;
  isDir?: boolean;
  confirmLua?: boolean;
}
export interface UploadInput extends WriteIntent {
  target: Target;
  path: string;
  localFile: string;
}
async function writeFile(client: OnePanelClientLike, input: FileInput) {
  requireInput(
    !/\/policy-[a-f0-9]{64}\.json$/.test(input.path),
    'Immutable manifests are managed by mtls policy updates',
  );
  if (input.path.endsWith('.lua')) validateManagedLua(input.content);
  if (/\.(pem|crt)$/.test(input.path)) parseCABundle(input.content);
  if (input.path.endsWith('.lua') && input.apply)
    requireInput(
      input.confirmLua === true,
      'Lua upload requires confirmLua:true and reviewed isolated tests',
    );
  const resource = await fileResource(client, input.target, input.path);
  return result({
    ...(await safeWrite(resource, input.content, input)),
    loading: 'FILE_SAVED_ONLY; active configurations require a verified reload',
  });
}
async function createFile(client: OnePanelClientLike, input: FileInput) {
  if (!input.isDir) {
    if (input.path.endsWith('.lua')) validateManagedLua(input.content);
    if (/\.(pem|crt)$/.test(input.path)) parseCABundle(input.content);
    const resource = await fileResource(client, input.target, input.path, 'create');
    const existing = await resource.read();
    requireInput(
      existing === null || existing === input.content,
      'createFile refuses overwriting an existing different file',
    );
    if (input.path.endsWith('.lua') && input.apply)
      requireInput(input.confirmLua === true, 'Lua create requires confirmLua:true');
    return result(await safeWrite(resource, input.content, input));
  }
  const site = await discoverSite(client, input.target);
  const root = controlledPath(site.policyRoot, input.path, true);
  return result(
    await safeWrite(
      {
        id: 'files.mkdir',
        target: input.target,
        async read() {
          const info = await remoteStat(client, root, input.target.operateNode);
          if (!info) return null;
          requireInput(info.isDir === true, 'Policy path is not a directory');
          return 'directory';
        },
        async write(content) {
          if (content === null) {
            const listing = unwrap(
              await client.request({
                method: 'POST',
                path: '/api/v2/files/search',
                operateNode: input.target.operateNode,
                readOnly: true,
                body: { path: root, expand: true, showHidden: true, page: 1, pageSize: 1000 },
              }),
            );
            requireInput(
              listing.itemTotal === 0 && (!listing.items || listing.items.length === 0),
              'Directory is not empty; refuse recovery deletion',
            );
            await client.request({
              method: 'POST',
              path: '/api/v2/files/del',
              operateNode: input.target.operateNode,
              body: { path: root, isDir: true, forceDelete: true },
            });
            return;
          }
          await client.request({
            method: 'POST',
            path: '/api/v2/files',
            operateNode: input.target.operateNode,
            body: {
              path: root,
              isDir: true,
              mode: 493,
              isLink: false,
              isSymlink: false,
              sub: false,
            },
          });
        },
      },
      'directory',
      input,
    ),
  );
}
async function uploadFile(client: OnePanelClientLike, input: UploadInput) {
  requireInput(/\.(pem|crt)$/.test(input.path), 'Uploads support public CA bundles only');
  const bytes = await readFile(input.localFile);
  requireInput(bytes.length <= 1024 * 1024, 'CA bundle exceeds 1 MiB');
  const content = bytes.toString('utf8');
  checkContent(content);
  parseCABundle(content);
  return result({
    ...(await safeWrite(
      await fileResource(client, input.target, input.path, 'upload'),
      content,
      input,
    )),
    loading: 'FILE_SAVED_ONLY; reload and test consumers',
  });
}
export const filesModule: ModuleDefinition = {
  id: 'files',
  title: 'Policy files',
  description: 'Bounded site mtls directory, public CA and reviewed Lua files only.',
  actions: {
    readFile: {
      id: 'readFile',
      summary: 'Read a bounded regular policy file after ancestor symlink checks.',
      method: 'POST',
      path: '/api/v2/files/content',
      nodeAware: true,
      execute: async (client, input: { target: Target; path: string }) =>
        result({
          path: input.path,
          content: await (await fileResource(client, input.target, input.path)).read(),
        }),
    },
    writeFile: {
      id: 'writeFile',
      summary: 'Plan/apply controlled policy text; saving does not reload consumers.',
      method: 'POST',
      path: '/api/v2/files/save',
      nodeAware: true,
      mutation: true,
      scope: 'Selected site mtls directory',
      execute: writeFile,
    },
    createFile: {
      id: 'createFile',
      summary: 'Create a policy directory or new policy file; no links.',
      method: 'POST',
      path: '/api/v2/files',
      nodeAware: true,
      mutation: true,
      scope: 'Selected site mtls directory',
      execute: createFile,
    },
    uploadFile: {
      id: 'uploadFile',
      summary: 'Multipart public CA upload from a local file with baseline and read-back.',
      method: 'POST',
      path: '/api/v2/files/upload',
      nodeAware: true,
      mutation: true,
      scope: 'Selected site mtls directory; public CA PEM only',
      execute: uploadFile,
    },
  },
  reservedMutations: [],
};
