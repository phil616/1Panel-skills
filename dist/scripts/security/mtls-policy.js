import { normalizeFingerprints } from './certificates.js';
import { requireInput } from './errors.js';
export const LUA_VERSION = 'sha256-acl-v1';
export function buildLuaPolicy(fingerprints) {
    const list = normalizeFingerprints(fingerprints);
    return `-- 1panel-skills ${LUA_VERSION}; immutable reviewed template\nlocal ok, authorized = pcall(function()\n    if ngx.var.ssl_client_verify ~= "SUCCESS" then return false end\n    local x509 = require "resty.openssl.x509"\n    local digest = require "resty.openssl.digest"\n    local str = require "resty.string"\n    local pem = ngx.var.ssl_client_raw_cert\n    if not pem or pem == "" then return false end\n    local cert = assert(x509.new(pem))\n    local der = assert(cert:tostring("DER"))\n    local ctx = assert(digest.new("sha256"))\n    assert(ctx:update(der))\n    local fingerprint = str.to_hex(assert(ctx:final())):upper()\n    local allowed = {\n${list.map((f) => `        ["${f}"] = true,`).join('\n')}\n    }\n    return allowed[fingerprint] == true\nend)\nif not ok or not authorized then\n    return ngx.exit(ngx.HTTP_FORBIDDEN)\nend\n`;
}
export function validateManagedLua(content) {
    const fingerprints = [...content.matchAll(/\["([A-F0-9]{64})"\] = true,/g)].map((m) => m[1]);
    requireInput(content === buildLuaPolicy(fingerprints), 'Only the reviewed versioned Lua template is supported; arbitrary Lua is not accepted');
    return fingerprints;
}
export function policyConfig(caPath, luaPath, verifyClient, verifyDepth) {
    requireInput(['on', 'optional'].includes(verifyClient) &&
        Number.isInteger(verifyDepth) &&
        verifyDepth >= 1 &&
        verifyDepth <= 10, 'Invalid mTLS mode or verifyDepth (1–10)');
    requireInput([caPath, luaPath].every((p) => /^\/www\/sites\/[A-Za-z0-9_.-]+\/mtls\/[A-Za-z0-9_.-]+$/.test(p)), 'Invalid runtime policy path');
    return `# 1panel-skills mtls v1; enforce; fail-closed\nssl_client_certificate ${caPath};\nssl_verify_client ${verifyClient};\nssl_verify_depth ${verifyDepth};\nssl_session_cache off;\nssl_session_tickets off;\naccess_by_lua_file ${luaPath};\n`;
}
