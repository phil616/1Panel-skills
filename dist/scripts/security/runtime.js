import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { certificateFingerprint } from './certificates.js';
import { parseNginx, flatten } from './nginx-config.js';
import { sha256 } from './change-plan.js';
import { PanelError, requireInput } from './errors.js';
const exec = promisify(execFile);
async function docker(args) {
    try {
        return await exec('docker', args, {
            timeout: 30000,
            maxBuffer: 8 * 1024 * 1024,
            encoding: 'utf8',
        });
    }
    catch {
        throw new PanelError('DEPENDENCY_MISSING', 'Local Docker/OpenResty runtime probe failed; inspect container status, syntax and Lua dependencies');
    }
}
export async function probeRuntime(target, sitePath, globalConfig, candidateLua, siteContent) {
    requireInput(target.operateNode === 'local' &&
        ['127.0.0.1', 'localhost', '[::1]'].includes(new URL(target.baseUrl).hostname), 'Automatic runtime validation supports explicitly local Docker targets only');
    const inspected = JSON.parse((await docker(['inspect', target.instance])).stdout)[0];
    requireInput(inspected.State?.Running === true, 'OpenResty must be running for runtime validation');
    const mount = inspected.Mounts?.filter((m) => m.Destination === '/www' && m.Source === path.posix.dirname(path.posix.dirname(sitePath)));
    requireInput(mount?.length === 1, 'Cannot prove /www host/container mapping for selected site');
    const dump = await docker(['exec', target.instance, 'nginx', '-T']);
    const configDump = dump.stdout;
    const sections = configDump
        .split(/^# configuration file /m)
        .slice(1)
        .map((section) => ({
        path: section.slice(0, section.indexOf('\n')).replace(/:$/, ''),
        body: section.slice(section.indexOf('\n') + 1),
    }));
    for (const section of sections) {
        if (section.path.startsWith(`/www/sites/${target.alias}/mtls/policy-`))
            continue;
        const nodes = flatten(parseNginx(section.body));
        if (nodes.some((n) => /^access_by_lua/.test(n.name)))
            throw new PanelError('CONFLICT', 'Runtime includes an existing Lua/WAF access handler; verified composition required');
        if (nodes.some((n) => ['ssl_client_certificate', 'ssl_verify_client', 'ssl_verify_depth'].includes(n.name)))
            throw new PanelError('CONFLICT', 'Runtime includes administrator mTLS directives');
        if (nodes.some((n) => n.name === 'return' ||
            n.name === 'rewrite' ||
            (n.name === 'satisfy' && n.args.includes('any'))))
            throw new PanelError('CONFLICT', 'Expanded include contains early return/rewrite or satisfy-any; cannot prove access enforcement');
    }
    const hostConfig = path.posix.join(path.posix.dirname(path.posix.dirname(sitePath)), 'conf.d', target.alias + '.conf');
    const loadedSite = sections.find((section) => {
        const mounts = inspected.Mounts.filter((m) => section.path === m.Destination || section.path.startsWith(m.Destination + '/')).sort((a, b) => b.Destination.length - a.Destination.length);
        return (mounts.length &&
            path.posix.join(mounts[0].Source, section.path.slice(mounts[0].Destination.length)) ===
                hostConfig);
    });
    requireInput(loadedSite && (siteContent === undefined || loadedSite.body.trim() === siteContent.trim()), 'Selected website configuration is not in the runtime include graph');
    const main = '/usr/local/openresty/nginx/conf/nginx.conf';
    const section = configDump
        .split(`# configuration file ${main}:\n`)[1]
        ?.split(/^# configuration file /m)[0];
    requireInput(section !== undefined && section.trim() === globalConfig.trim(), 'Runtime nginx.conf differs from the panel; cannot prove inherited configuration');
    const fixture = await readFile(fileURLToPath(new URL(import.meta.url.includes('/dist/')
        ? '../../../assets/fingerprint-vector.pem'
        : '../../assets/fingerprint-vector.pem', import.meta.url)), 'utf8');
    const vector = certificateFingerprint(fixture);
    const code = `local x=require('resty.openssl.x509');local d=require('resty.openssl.digest');local s=require('resty.string');local c=assert(x.new(${JSON.stringify(fixture)}));local h=assert(d.new('sha256'));assert(h:update(assert(c:tostring("DER"))));print(s.to_hex(assert(h:final())):upper())`;
    const answer = (await docker(['exec', target.instance, '/usr/local/openresty/bin/resty', '-e', code])).stdout.trim();
    requireInput(answer === vector, 'Runtime DER SHA-256 test vector failed');
    if (candidateLua) {
        // Compilation only. Runtime dependencies were exercised above. No arbitrary user Lua executes here.
        const compile = `assert(loadstring(${JSON.stringify(candidateLua)})); print('SYNTAX_OK')`;
        requireInput((await docker(['exec', target.instance, '/usr/local/openresty/bin/resty', '-e', compile])).stdout.trim() === 'SYNTAX_OK', 'Lua syntax check failed');
    }
    return {
        status: 'PASS',
        mapping: '/www',
        derSha256Vector: vector,
        configurationSha256: sha256(configDump),
        luaDependencies: ['resty.openssl.x509', 'resty.openssl.digest', 'resty.string'],
        validation: 'nginx -T plus Lua compilation and real DER SHA-256 vector',
    };
}
export async function checkReloaded(target) {
    const result = await docker(['exec', target.instance, 'nginx', '-t']);
    requireInput(/successful/.test(result.stderr + result.stdout), 'Post-apply nginx -t failed');
    return { syntax: 'PASS', reload: 'API_RETURNED_SUCCESS', runtime: 'HTTP_E2E_REQUIRED' };
}
