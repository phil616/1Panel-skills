#!/usr/bin/env node
import { signHeaders } from './client.js';
import { redact } from './security/redaction.js';
import { PanelError, requireInput } from './security/errors.js';
import { OnePanelClient } from './client.js';
import { getModule, listModules } from './index.js';
async function main() {
    const args = process.argv.slice(2);
    const [command, ...rest] = args;
    if (!command || command === '--help' || command === '-h' || command === 'help') {
        printHelp();
        return;
    }
    switch (command) {
        case 'modules':
            handleModules();
            return;
        case 'actions':
            handleActions(rest);
            return;
        case 'sign':
            handleSign(rest);
            return;
        case 'request':
            await handleRequest(rest);
            return;
        case 'run':
            await handleRun(rest);
            return;
        default:
            throw new Error(`Unknown command: ${command}`);
    }
}
function printHelp() {
    console.log(`1panel-skills

Usage:
  1panel-skills modules
  1panel-skills actions <module>
  1panel-skills sign [--base-url URL] [--api-key KEY]
  1panel-skills request <METHOD> <PATH> [--body-json JSON] [--query-json JSON] [--node NODE]
  1panel-skills run <module> <action> [--input-json JSON] [--input-file FILE] [--node NODE] [--apply --confirm] [--output-file FILE]

Environment:
  ONEPANEL_BASE_URL
  ONEPANEL_API_KEY
  ONEPANEL_SIGNATURE_VERSION (md5 compatibility default, or hmac-sha256; never auto-downgraded)
  ONEPANEL_KEY_ID (optional independent API key ID)
  ONEPANEL_STATE_DIR (private 0700 backup/audit directory)
  ONEPANEL_TIMEOUT_MS
  ONEPANEL_SKIP_TLS_VERIFY

Managed writes: default dry-run. Apply requires target, expectedSha256 and confirm:true.
mTLS also requires confirmLua:true and acknowledgeNonAtomic:true. Use --input-file for plans.
--output-file writes a private full response for local review; stdout is redacted.
Generic request: GET and known POST reads only. Writes use managed module actions.

Examples:
  1panel-skills modules
  1panel-skills actions monitoring
  1panel-skills request GET /api/v2/dashboard/base/os
  1panel-skills run monitoring getCurrentNode
  1panel-skills run websites searchWebsites --input-json '{"page":1,"pageSize":20}'
`);
}
function handleModules() {
    console.log(JSON.stringify(listModules().map((moduleDef) => ({
        id: moduleDef.id,
        title: moduleDef.title,
        description: moduleDef.description,
    })), null, 2));
}
function handleActions(args) {
    const [moduleId] = args;
    if (!moduleId) {
        throw new Error('Missing module name');
    }
    const moduleDef = getRequiredModule(moduleId);
    console.log(JSON.stringify({
        module: moduleDef.id,
        actions: Object.values(moduleDef.actions).map((action) => ({
            id: action.id,
            summary: action.summary,
            method: action.method,
            path: action.path,
            nodeAware: Boolean(action.nodeAware),
            mutation: Boolean(action.mutation),
            scope: action.scope,
        })),
        reservedMutations: moduleDef.reservedMutations,
    }, null, 2));
}
function handleSign(args) {
    const { flags } = parseArgs(args);
    const config = resolveClientConfig(flags);
    const timestamp = `${Math.floor(Date.now() / 1000)}`;
    const headers = signHeaders(config.apiKey, timestamp, (process.env.ONEPANEL_SIGNATURE_VERSION || 'md5'), process.env.ONEPANEL_KEY_ID);
    console.log(JSON.stringify({
        baseUrl: config.baseUrl,
        headers,
    }, null, 2));
}
async function handleRequest(args) {
    const [method, path, ...rest] = args;
    if (!method || !path) {
        throw new Error('Usage: request <METHOD> <PATH> [--body-json JSON] [--query-json JSON] [--node NODE]');
    }
    const { flags } = parseArgs(rest);
    const client = createClient(flags);
    const body = parseOptionalJson(flags['body-json']);
    const query = parseOptionalJson(flags['query-json']);
    const operateNode = readOptionalString(flags.node);
    const { isReadRequest } = await import('./security/request-policy.js');
    requireInput(isReadRequest(method.toUpperCase(), path), 'Generic request cannot send mutations; use a guarded module action');
    await executeAndPrint(flags, () => client.request({
        readOnly: true,
        method: method.toUpperCase(),
        path,
        body,
        query: isRecord(query)
            ? query
            : undefined,
        operateNode,
    }));
}
async function handleRun(args) {
    const [moduleId, actionId, ...rest] = args;
    if (!moduleId || !actionId) {
        throw new Error('Usage: run <module> <action> [--input-json JSON] [--input-file FILE] [--node NODE]');
    }
    const { flags } = parseArgs(rest);
    const moduleDef = getRequiredModule(moduleId);
    const action = moduleDef.actions[actionId];
    if (!action) {
        throw new Error(`Unknown action "${actionId}" in module "${moduleId}"`);
    }
    const input = await loadInput(flags);
    const operateNode = readOptionalString(flags.node);
    let finalInput = mergeOperateNode(input, operateNode);
    if (isRecord(finalInput)) {
        finalInput = {
            ...finalInput,
            ...(flags.apply === true ? { apply: true } : {}),
            ...(flags.confirm === true ? { confirm: true } : {}),
        };
    }
    const client = createClient(flags);
    await executeAndPrint(flags, () => action.execute(client, finalInput));
}
async function executeAndPrint(flags, operation) {
    const fs = await import('node:fs/promises');
    const outputFile = readOptionalString(flags['output-file']);
    const file = outputFile ? await fs.open(outputFile, 'wx', 0o600) : undefined;
    try {
        const response = await operation();
        if (file) {
            await file.writeFile(JSON.stringify(response.data, null, 2) + '\n');
            await file.sync();
        }
        printResponse(response.status, response.data, response.rawBody);
    }
    finally {
        await file?.close();
    }
}
function parseArgs(args) {
    const positionals = [];
    const flags = {};
    for (let index = 0; index < args.length; index += 1) {
        const current = args[index];
        if (!current.startsWith('--')) {
            positionals.push(current);
            continue;
        }
        const key = current.slice(2);
        const next = args[index + 1];
        if (!next || next.startsWith('--')) {
            flags[key] = true;
            continue;
        }
        flags[key] = next;
        index += 1;
    }
    return { positionals, flags };
}
function resolveClientConfig(flags) {
    const baseUrl = readOptionalString(flags['base-url']) || process.env.ONEPANEL_BASE_URL;
    const apiKey = readOptionalString(flags['api-key']) || process.env.ONEPANEL_API_KEY;
    if (!baseUrl) {
        throw new Error('Missing ONEPANEL_BASE_URL or --base-url');
    }
    if (!apiKey) {
        throw new Error('Missing ONEPANEL_API_KEY or --api-key');
    }
    return { baseUrl, apiKey };
}
function createClient(flags) {
    const config = resolveClientConfig(flags);
    return OnePanelClient.fromEnv({
        ...process.env,
        ONEPANEL_BASE_URL: config.baseUrl,
        ONEPANEL_API_KEY: config.apiKey,
    });
}
async function loadInput(flags) {
    const inputFile = readOptionalString(flags['input-file']);
    const inputJson = readOptionalString(flags['input-json']);
    if (inputFile && inputJson) {
        throw new Error('Use only one of --input-file or --input-json');
    }
    if (inputFile) {
        const fs = await import('node:fs/promises');
        const content = await fs.readFile(inputFile, 'utf8');
        return parseInputJson(content);
    }
    if (inputJson) {
        return parseInputJson(inputJson);
    }
    return {};
}
function mergeOperateNode(input, operateNode) {
    if (!operateNode) {
        return input;
    }
    if (!isRecord(input)) {
        return { operateNode };
    }
    if (isRecord(input.target) &&
        input.target.operateNode &&
        input.target.operateNode !== operateNode)
        throw new PanelError('TARGET_MISMATCH', '--node conflicts with explicit target');
    if (isRecord(input.plan) &&
        isRecord(input.plan.target) &&
        input.plan.target.operateNode !== operateNode)
        throw new PanelError('TARGET_MISMATCH', '--node conflicts with reviewed plan target');
    return {
        ...input,
        operateNode,
        ...(isRecord(input.target) ? { target: { ...input.target, operateNode } } : {}),
    };
}
function parseInputJson(content) {
    try {
        return JSON.parse(content);
    }
    catch {
        throw new PanelError('INVALID_INPUT', 'Input must be valid JSON; inspect the private input file locally');
    }
}
function parseOptionalJson(value) {
    const stringValue = readOptionalString(value);
    if (!stringValue) {
        return undefined;
    }
    return parseInputJson(stringValue);
}
function readOptionalString(value) {
    return typeof value === 'string' ? value : undefined;
}
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function getRequiredModule(moduleId) {
    const moduleDef = getModule(moduleId);
    if (!moduleDef) {
        throw new Error(`Unknown module: ${moduleId}`);
    }
    return moduleDef;
}
function printResponse(status, data, rawBody) {
    const output = {
        status,
        ok: status >= 200 && status < 300 && !(isRecord(data) && data.status === 'FAIL'),
        data: redact(data),
    };
    console.log(JSON.stringify(output, null, 2));
    if (status >= 400 || (isRecord(data) && data.status === 'FAIL')) {
        if (!data && rawBody) {
            console.error(rawBody);
        }
        process.exitCode = 1;
    }
}
main().catch((error) => {
    console.error(JSON.stringify({
        ok: false,
        error: error instanceof Error ? error.message : 'Unexpected failure',
        code: error instanceof PanelError ? error.code : 'INVALID_INPUT',
        details: error instanceof PanelError ? redact(error.details) : undefined,
    }, null, 2));
    process.exit(1);
});
