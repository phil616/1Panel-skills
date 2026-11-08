import path from 'node:path';
import { PanelError, requireInput } from './errors.js';
export function unwrap(response) {
    const value = response.data;
    if (response.status >= 400 ||
        (typeof value?.code === 'number' && value.code !== 200 && value.code !== 0))
        throw new PanelError('API_ERROR', 'Client returned an unsuccessful API response');
    return (value && typeof value === 'object' && 'code' in value && 'data' in value ? value.data : value);
}
export function result(data) {
    return { status: 200, headers: {}, data, rawBody: '' };
}
export function validateTarget(client, target) {
    requireInput(target &&
        typeof target.baseUrl === 'string' &&
        typeof target.operateNode === 'string' &&
        target.operateNode.length > 0 &&
        typeof target.instance === 'string' &&
        /^[a-zA-Z0-9_.-]+$/.test(target.instance), 'Explicit baseUrl, operateNode (local or node name), and instance required');
    if (!client.targetOrigin ||
        new URL(target.baseUrl).origin !== client.targetOrigin ||
        new URL(target.baseUrl).href !== client.targetOrigin + '/')
        throw new PanelError('TARGET_MISMATCH', 'Plan target differs from client origin');
}
export async function discoverInstance(client, target) {
    validateTarget(client, target);
    const apps = unwrap(await client.request({
        method: 'POST',
        path: '/api/v2/apps/installed/search',
        operateNode: target.operateNode,
        readOnly: true,
        body: { page: 1, pageSize: 100, name: '', type: '', unused: false, all: true },
    }));
    const matches = (apps?.items ?? []).filter((a) => a.appKey === 'openresty' && a.container === target.instance);
    if (matches.length !== 1)
        throw new PanelError('TARGET_MISMATCH', 'Expected one exact OpenResty container on the selected node');
    requireInput(typeof matches[0].path === 'string' && path.posix.isAbsolute(matches[0].path), 'OpenResty install path unavailable');
    return matches[0];
}
export async function discoverSite(client, target) {
    validateTarget(client, target);
    requireInput(Number.isSafeInteger(target.websiteId) &&
        target.websiteId > 0 &&
        /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(target.alias) &&
        !['default', '.', '..'].includes(target.alias), 'Positive websiteId and explicit non-default alias required');
    const site = unwrap(await client.request({
        method: 'GET',
        path: `/api/v2/websites/${target.websiteId}`,
        operateNode: target.operateNode,
    }));
    if (site?.id !== target.websiteId || site?.alias !== target.alias || site.type === 'stream')
        throw new PanelError('TARGET_MISMATCH', 'Website ID/alias/type mismatch');
    const sitePath = site.sitePath;
    requireInput(typeof sitePath === 'string' &&
        path.posix.isAbsolute(sitePath) &&
        path.posix.normalize(sitePath) === sitePath &&
        sitePath.endsWith('/sites/' + target.alias), 'Actual site path must be discovered from API');
    const instance = await discoverInstance(client, target);
    const config = unwrap(await client.request({
        method: 'GET',
        path: `/api/v2/websites/${target.websiteId}/config/openresty`,
        operateNode: target.operateNode,
    }));
    const configPath = path.posix.join(path.posix.dirname(path.posix.dirname(sitePath)), 'conf.d', target.alias + '.conf');
    requireInput(config?.path === configPath && typeof config.content === 'string' && config.isSymlink !== true, 'Unexpected website config path, symlink, or unavailable full content');
    return {
        site,
        sitePath,
        instance,
        configPath,
        content: config.content,
        policyRoot: sitePath + '/mtls',
    };
}
export function checkContent(content, maxBytes = 1024 * 1024) {
    requireInput(typeof content === 'string' &&
        !content.includes('\0') &&
        Buffer.byteLength(content) <= maxBytes &&
        !/-----BEGIN [^-]*PRIVATE KEY-----/.test(content), `Expected text <= ${maxBytes} bytes without private keys`);
}
