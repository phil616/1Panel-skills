import path from 'node:path';
import { safeWrite } from '../security/change-plan.js';
import { checkContent, discoverInstance, result, unwrap, } from '../security/discovery.js';
import { requireInput } from '../security/errors.js';
import { parseNginx } from '../security/nginx-config.js';
import { remoteStat } from '../security/path-policy.js';
export async function updateGlobalConfig(client, input) {
    const app = await discoverInstance(client, input.target);
    checkContent(input.content);
    const roots = parseNginx(input.content);
    requireInput(roots.some((n) => n.name === 'events' && n.children) &&
        roots.some((n) => n.name === 'http' && n.children), 'Full global configuration with events and http required');
    if (input.apply)
        requireInput(input.confirmGlobal === true && input.backup === true, 'Global apply needs confirmGlobal:true and backup:true');
    const filePath = path.posix.join(app.path, 'conf/nginx.conf');
    const change = await safeWrite({
        id: 'openresty.global',
        target: input.target,
        async read() {
            const info = await remoteStat(client, filePath, input.target.operateNode);
            requireInput(info && !info.isDir, 'Global configuration must be a regular file');
            return unwrap(await client.request({
                method: 'GET',
                path: '/api/v2/openresty',
                operateNode: input.target.operateNode,
            })).content;
        },
        async write(content) {
            await client.request({
                method: 'POST',
                path: '/api/v2/openresty/file',
                operateNode: input.target.operateNode,
                body: { content, backup: true },
            });
        },
    }, input.content, input);
    return result({
        ...change,
        loading: 'API check/reload returned successfully only when APPLIED; runtime E2E not implied',
    });
}
export const openrestyModule = {
    id: 'openresty',
    title: 'OpenResty',
    description: 'Global configuration, status, capability discovery, guarded writes.',
    actions: {
        getGlobalConfig: {
            id: 'getGlobalConfig',
            summary: 'Read full nginx.conf on a selected node.',
            method: 'GET',
            path: '/api/v2/openresty',
            nodeAware: true,
            execute: (client, input = {}) => client.request({
                method: 'GET',
                path: '/api/v2/openresty',
                operateNode: input.operateNode,
            }),
        },
        getStatus: {
            id: 'getStatus',
            summary: 'Read stub_status; this does not prove policy enforcement.',
            method: 'GET',
            path: '/api/v2/openresty/status',
            nodeAware: true,
            execute: (client, input = {}) => client.request({
                method: 'GET',
                path: '/api/v2/openresty/status',
                operateNode: input.operateNode,
            }),
        },
        discoverCapabilities: {
            id: 'discoverCapabilities',
            summary: 'Probe installed instance and read endpoints without mutation.',
            method: 'GET',
            path: '/api/v2/openresty',
            nodeAware: true,
            execute: async (client, input) => {
                const instance = await discoverInstance(client, input.target);
                const config = unwrap(await client.request({
                    method: 'GET',
                    path: '/api/v2/openresty',
                    operateNode: input.target.operateNode,
                }));
                return result({
                    instance: {
                        container: instance.container,
                        path: instance.path,
                        status: instance.status,
                        version: instance.version,
                    },
                    globalReadable: typeof config.content === 'string',
                    writeEndpoints: 'SOURCE_VERIFIED_NOT_PROBED',
                    syntaxAndReload: 'Performed inside supported config write APIs; no standalone test/reload endpoint',
                });
            },
        },
        updateGlobalConfig: {
            id: 'updateGlobalConfig',
            summary: 'Plan/apply full nginx.conf with backup, baseline, and global confirmation.',
            method: 'POST',
            path: '/api/v2/openresty/file',
            nodeAware: true,
            mutation: true,
            scope: 'Exact node and OpenResty instance; global nginx.conf',
            execute: updateGlobalConfig,
        },
    },
    reservedMutations: [],
};
