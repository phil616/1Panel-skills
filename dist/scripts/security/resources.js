import path from 'node:path';
import { sha256 } from './change-plan.js';
import { parseNginx } from './nginx-config.js';
import { checkContent, discoverSite, unwrap } from './discovery.js';
import { controlledPath, remoteStat } from './path-policy.js';
import { requireInput } from './errors.js';
export async function siteResource(client, target) {
    const discovered = await discoverSite(client, target);
    return {
        id: 'websites.raw',
        target,
        validate(value) {
            checkContent(value);
            requireInput(parseNginx(value).some((node) => node.name === 'server' && node.children), 'Full site config with a server block required');
        },
        async read() {
            await discoverSite(client, target);
            const info = await remoteStat(client, discovered.configPath, target.operateNode);
            requireInput(info && !info.isDir, 'Site config must exist');
            return unwrap(await client.request({
                method: 'GET',
                path: `/api/v2/websites/${target.websiteId}/config/openresty`,
                operateNode: target.operateNode,
            })).content;
        },
        async write(content) {
            checkContent(content);
            await client.request({
                method: 'POST',
                path: '/api/v2/websites/nginx/update',
                operateNode: target.operateNode,
                body: { id: target.websiteId, content },
            });
        },
    };
}
export async function fileResource(client, target, candidate, mode = 'save') {
    const site = await discoverSite(client, target);
    const filePath = controlledPath(site.policyRoot, candidate);
    let createdEmpty = false;
    return {
        id: `files.${mode}:${filePath}`,
        target,
        ownsIntermediate(value) {
            return createdEmpty && value === '';
        },
        validate(content) {
            if (content !== null) {
                checkContent(content, path.posix.extname(filePath) === '.lua' ? 64 * 1024 : 1024 * 1024);
                const versioned = /^(?:ca|acl|policy)-([a-f0-9]{64})\.(pem|lua|conf)$/.exec(path.posix.basename(filePath));
                if (versioned)
                    requireInput(sha256(content) === versioned[1], 'Versioned artifact filename must match its content digest');
            }
        },
        async read() {
            const info = await remoteStat(client, filePath, target.operateNode);
            if (!info)
                return null;
            requireInput(info.isDir === false && info.size <= 1024 * 1024, 'Expected bounded regular file');
            const data = unwrap(await client.request({
                method: 'POST',
                path: '/api/v2/files/content',
                operateNode: target.operateNode,
                readOnly: true,
                body: { path: filePath, isDetail: false },
            }));
            requireInput(data.path === filePath &&
                !data.isSymlink &&
                typeof data.content === 'string' &&
                Buffer.byteLength(data.content) === data.size, 'Full unmodified UTF-8 file content required');
            return data.content;
        },
        async write(content) {
            const info = await remoteStat(client, filePath, target.operateNode);
            if (content === null) {
                if (info)
                    await client.request({
                        method: 'POST',
                        path: '/api/v2/files/del',
                        operateNode: target.operateNode,
                        body: { path: filePath, isDir: false, forceDelete: true },
                    });
                return;
            }
            const parent = await remoteStat(client, site.policyRoot, target.operateNode);
            requireInput(parent?.isDir === true, 'Create the policy directory before writing files');
            if (mode === 'upload') {
                await client.request({
                    method: 'POST',
                    path: '/api/v2/files/upload',
                    operateNode: target.operateNode,
                    multipart: {
                        fields: { path: site.policyRoot, overwrite: 'true' },
                        file: {
                            name: path.posix.basename(filePath),
                            content: Buffer.from(content),
                            contentType: 'application/x-pem-file',
                        },
                    },
                });
            }
            else if (info) {
                await client.request({
                    method: 'POST',
                    path: '/api/v2/files/save',
                    operateNode: target.operateNode,
                    body: { path: filePath, content },
                });
            }
            else {
                await client.request({
                    method: 'POST',
                    path: '/api/v2/files',
                    operateNode: target.operateNode,
                    body: {
                        path: filePath,
                        content: '',
                        isDir: false,
                        mode: 420,
                        isLink: false,
                        isSymlink: false,
                        sub: false,
                    },
                });
                createdEmpty = true;
                // FileCreate.Content is present in the DTO but ignored by the server implementation.
                await client.request({
                    method: 'POST',
                    path: '/api/v2/files/save',
                    operateNode: target.operateNode,
                    body: { path: filePath, content },
                });
            }
        },
    };
}
