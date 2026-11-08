import path from 'node:path';
import { safeWrite, sha256 } from '../security/change-plan.js';
import { discoverSite, unwrap, result, checkContent } from '../security/discovery.js';
import { siteResource } from '../security/resources.js';
import { assertLuaUnchanged } from '../security/nginx-config.js';
import { remoteStat } from '../security/path-policy.js';
import { PanelError, requireInput } from '../security/errors.js';
const keys = {
    index: ['index'],
    'limit-conn': ['limit_conn', 'limit_rate', 'limit_conn_zone'],
    'http-per': [
        'server_names_hash_bucket_size',
        'client_header_buffer_size',
        'client_max_body_size',
        'keepalive_timeout',
        'gzip',
        'gzip_min_length',
        'gzip_comp_level',
        'gzip_types',
        'gzip_vary',
        'gzip_proxied',
    ],
};
function scopeKeys(scope) {
    requireInput(Object.hasOwn(keys, scope), 'Scope unsupported: use index, limit-conn or http-per; SSL keys/private keys excluded');
    return keys[scope];
}
export async function updateWebsiteRawConfig(client, input) {
    return result({
        ...(await safeWrite(await siteResource(client, input.target), input.content, input)),
        loading: 'API check/reload returned only for APPLIED; HTTP E2E not implied',
    });
}
export async function getProxyConfig(client, input) {
    requireInput(Number.isSafeInteger(input.id) && input.id > 0, 'Positive website id required');
    return client.request({
        method: 'POST',
        path: '/api/v2/websites/proxies',
        operateNode: input.operateNode,
        readOnly: true,
        body: { id: input.id },
    });
}
export async function updateProxyRawConfig(client, input) {
    requireInput(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$/.test(input.name) &&
        !['default', '..', '.'].includes(input.name) &&
        !input.name.endsWith('.conf'), 'Existing proxy name without extension required');
    checkContent(input.content);
    if (/\bssl_(?:client_certificate|verify_client|verify_depth)\b/.test(input.content))
        throw new PanelError('INVALID_INPUT', 'mTLS directives cannot go in a location proxy file');
    const site = await discoverSite(client, input.target);
    const read = async () => {
        const proxies = unwrap(await getProxyConfig(client, {
            id: input.target.websiteId,
            operateNode: input.target.operateNode,
        }));
        const matches = (proxies ?? []).filter((p) => p.name === input.name && p.enable === true);
        if (matches.length !== 1)
            throw new PanelError('NOT_FOUND', 'Existing active proxy file required');
        const filePath = path.posix.join(site.sitePath, 'proxy', input.name + '.conf');
        requireInput(matches[0].filePath === filePath &&
            (await remoteStat(client, filePath, input.target.operateNode))?.isDir === false, 'Unexpected proxy path');
        return matches[0].content;
    };
    assertLuaUnchanged(await read(), input.content);
    return result(await safeWrite({
        id: 'websites.proxy:' + input.name,
        target: input.target,
        read,
        async write(content) {
            await client.request({
                method: 'POST',
                path: '/api/v2/websites/proxies/file',
                operateNode: input.target.operateNode,
                body: { websiteID: input.target.websiteId, name: input.name, content },
            });
        },
    }, input.content, input));
}
export async function getSiteNginxSettings(client, input) {
    scopeKeys(input.scope);
    requireInput(Number.isSafeInteger(input.websiteId) && input.websiteId > 0, 'Positive websiteId required');
    return client.request({
        method: 'POST',
        path: '/api/v2/websites/config',
        operateNode: input.operateNode,
        readOnly: true,
        body: { websiteId: input.websiteId, scope: input.scope },
    });
}
export async function updateSiteNginxSettings(client, input) {
    const allowed = scopeKeys(input.scope);
    requireInput(['add', 'update', 'delete'].includes(input.operate), 'Invalid operate');
    requireInput(input.params &&
        typeof input.params === 'object' &&
        !Array.isArray(input.params) &&
        Object.entries(input.params).every(([k, v]) => allowed.includes(k) &&
            typeof v === 'string' &&
            v.length <= 4096 &&
            !/[;{}\r\n\0]/.test(v)), 'Only supported scope params with simple string values');
    const site = await discoverSite(client, input.target);
    const canonical = (params) => JSON.stringify(allowed.map((name) => ({
        name,
        params: params.filter((p) => p.name === name).flatMap((p) => p.params ?? []),
    })));
    const read = async () => canonical(unwrap(await getSiteNginxSettings(client, {
        websiteId: input.target.websiteId,
        scope: input.scope,
        operateNode: input.target.operateNode,
    })).params);
    const before = await read();
    const old = JSON.parse(before);
    requireInput(allowed.every((k) => old.find((x) => x.name === k).params.length === 0 ||
        !['limit_conn', 'limit_conn_zone'].includes(k)), 'Repeated structured directives require raw config editing');
    const next = canonical(allowed.map((name) => ({
        name,
        params: input.operate === 'delete'
            ? []
            : Object.hasOwn(input.params, name)
                ? input.params[name].trim().split(/\s+/)
                : old.find((p) => p.name === name).params,
    })));
    let committedRaw;
    const raw = async () => unwrap(await client.request({
        method: 'GET',
        path: `/api/v2/websites/${input.target.websiteId}/config/openresty`,
        operateNode: input.target.operateNode,
    })).content;
    return result(await safeWrite({
        id: 'websites.settings:' + input.scope,
        target: input.target,
        read,
        recoverySnapshot: site.content,
        async guardRollback() {
            requireInput(committedRaw !== undefined && sha256(await raw()) === sha256(committedRaw), 'Raw site changed during structured operation; manual recovery required');
        },
        async verify(content) {
            if (content === before && sha256(await raw()) !== sha256(site.content))
                throw new PanelError('VERIFY_FAILED', 'Scope restored but raw site differs; inspect full backup');
        },
        async write(content) {
            if (content === before) {
                await client.request({
                    method: 'POST',
                    path: '/api/v2/websites/nginx/update',
                    operateNode: input.target.operateNode,
                    body: { id: input.target.websiteId, content: site.content },
                });
            }
            else {
                if (sha256(await raw()) !== sha256(site.content))
                    throw new PanelError('CONFLICT', 'Full site changed before structured mutation');
                await client.request({
                    method: 'POST',
                    path: '/api/v2/websites/config/update',
                    operateNode: input.target.operateNode,
                    body: {
                        websiteId: input.target.websiteId,
                        scope: input.scope,
                        operate: input.operate,
                        params: input.params,
                    },
                });
                committedRaw = await raw();
            }
        },
    }, next, input));
}
export const websiteSecurityActions = Object.fromEntries([
    [
        'updateWebsiteRawConfig',
        '/api/v2/websites/nginx/update',
        updateWebsiteRawConfig,
        true,
        'Full site configuration',
    ],
    [
        'getSiteNginxSettings',
        '/api/v2/websites/config',
        getSiteNginxSettings,
        false,
        'Selected structured scope',
    ],
    [
        'updateSiteNginxSettings',
        '/api/v2/websites/config/update',
        updateSiteNginxSettings,
        true,
        'Supported structured scope only',
    ],
    ['getProxyConfig', '/api/v2/websites/proxies', getProxyConfig, false, 'Existing proxy files'],
    [
        'updateProxyRawConfig',
        '/api/v2/websites/proxies/file',
        updateProxyRawConfig,
        true,
        'One existing proxy file',
    ],
].map(([id, path, execute, mutation, scope]) => [
    id,
    { id, summary: scope, method: 'POST', path, execute, mutation, nodeAware: true, scope },
]));
