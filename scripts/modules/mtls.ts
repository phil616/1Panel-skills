import path from 'node:path';
import https from 'node:https';
import { isIP } from 'node:net';
import { readFile } from 'node:fs/promises';
import type { ModuleDefinition, OnePanelClientLike } from '../types.js';
import {
  sha256,
  digest,
  ABSENT_SHA256,
  safeWrite,
  previewDiff,
  type WriteIntent,
  type Resource,
} from '../security/change-plan.js';
import { discoverSite, result, unwrap, type Target } from '../security/discovery.js';
import { fileResource, siteResource } from '../security/resources.js';
import { remoteStat } from '../security/path-policy.js';
import { normalizeFingerprints, parseCABundle } from '../security/certificates.js';
import {
  buildLuaPolicy,
  LUA_VERSION,
  policyConfig,
  validateManagedLua,
} from '../security/mtls-policy.js';
import {
  inspectNginx,
  managedSiteConfig,
  managedPath,
  removeManagedInclude,
} from '../security/nginx-config.js';
import { probeRuntime, checkReloaded } from '../security/runtime.js';
import { filesModule } from './files.js';
import { PanelError, requireInput } from '../security/errors.js';
export interface MtlsPolicy {
  caBundle: string;
  fingerprints: string[];
  verifyClient?: 'on' | 'optional';
  verifyDepth?: number;
  mode?: 'enforce';
  luaVersion?: typeof LUA_VERSION;
}
export interface PlanInput {
  target: Target;
  policy: MtlsPolicy;
  probeRuntime?: boolean;
}
export interface Artifact {
  path: string;
  content: string;
  expectedSha256: string;
  afterSha256: string;
}
export interface MtlsPlan {
  version: 1;
  target: Target;
  policy: MtlsPolicy;
  expectedSha256: string;
  afterSha256: string;
  globalSha256: string;
  siteContent: string;
  artifacts: Artifact[];
  planSha256: string;
  reviewDiff: unknown;
  caFingerprints: string[];
  runtime: unknown;
}
function planDigest(plan: Omit<MtlsPlan, 'planSha256'> | MtlsPlan) {
  return sha256(
    JSON.stringify({
      version: plan.version,
      target: plan.target,
      policy: plan.policy,
      expectedSha256: plan.expectedSha256,
      afterSha256: plan.afterSha256,
      globalSha256: plan.globalSha256,
      siteContent: plan.siteContent,
      artifacts: plan.artifacts,
    }),
  );
}
async function globalContent(client: OnePanelClientLike, target: Target) {
  return unwrap(
    await client.request({
      method: 'GET',
      path: '/api/v2/openresty',
      operateNode: target.operateNode,
    }),
  ).content as string;
}
export async function planMtlsPolicy(client: OnePanelClientLike, input: PlanInput) {
  requireInput(
    input.policy?.mode === undefined || input.policy.mode === 'enforce',
    'Only enforce mode is implemented',
  );
  requireInput(
    input.policy.luaVersion === undefined || input.policy.luaVersion === LUA_VERSION,
    'Unsupported Lua template version',
  );
  const discovered = await discoverSite(client, input.target);
  const ca = parseCABundle(input.policy.caBundle),
    fingerprints = normalizeFingerprints(input.policy.fingerprints);
  const policy: MtlsPolicy = {
    caBundle: ca.bundle,
    fingerprints,
    verifyClient: input.policy.verifyClient ?? 'on',
    verifyDepth: input.policy.verifyDepth ?? 3,
    mode: 'enforce',
    luaVersion: LUA_VERSION,
  };
  const lua = buildLuaPolicy(fingerprints);
  validateManagedLua(lua);
  const runtimeRoot = `/www/sites/${input.target.alias}/mtls`;
  const caName = `ca-${sha256(ca.bundle)}.pem`,
    luaName = `acl-${sha256(lua)}.lua`;
  const config = policyConfig(
    `${runtimeRoot}/${caName}`,
    `${runtimeRoot}/${luaName}`,
    policy.verifyClient!,
    policy.verifyDepth!,
  );
  const configName = `policy-${sha256(config)}.conf`;
  const content = managedSiteConfig(discovered.content, `${runtimeRoot}/${configName}`);
  const previousPath = managedPath(discovered.content);
  if (previousPath)
    requireInput(
      previousPath.startsWith(runtimeRoot + '/'),
      'Managed include belongs to a different site',
    );
  const proposed = [
    { path: discovered.policyRoot + '/' + caName, content: ca.bundle },
    { path: discovered.policyRoot + '/' + luaName, content: lua },
    { path: discovered.policyRoot + '/' + configName, content: config },
    {
      path: discovered.policyRoot + '/' + configName.replace('.conf', '.json'),
      content: JSON.stringify(policy, null, 2) + '\n',
    },
  ];
  const artifacts: Artifact[] = [];
  for (const file of proposed) {
    const current = await (await fileResource(client, input.target, file.path)).read();
    requireInput(
      current === null || current === file.content,
      'Immutable policy file has unexpected bytes; stop and investigate',
    );
    artifacts.push({ ...file, expectedSha256: digest(current), afterSha256: sha256(file.content) });
  }
  const global = await globalContent(client, input.target);
  let runtime: unknown = {
    status: 'NOT_RUN',
    reason:
      'Use probeRuntime:true for local dependency and inherited-handler checks; apply always probes',
  };
  if (input.probeRuntime) {
    try {
      runtime = await probeRuntime(
        input.target,
        discovered.sitePath,
        global,
        lua,
        discovered.content,
      );
    } catch (err) {
      runtime = {
        status: 'BLOCKED',
        code: err instanceof PanelError ? err.code : 'API_ERROR',
        reason: err instanceof Error ? err.message : 'Probe failed',
      };
    }
  }
  const a = discovered.content.split('\n'),
    b = content.split('\n');
  const summary = previewDiff(discovered.content, content);
  const base: Omit<MtlsPlan, 'planSha256'> = {
    version: 1,
    target: input.target,
    policy,
    expectedSha256: sha256(discovered.content),
    afterSha256: sha256(content),
    globalSha256: sha256(global),
    siteContent: content,
    artifacts,
    reviewDiff: {
      ...summary,
      removed: a.slice(summary.startLine - 1, summary.startLine - 1 + summary.removedLines),
      added: b.slice(summary.startLine - 1, summary.startLine - 1 + summary.addedLines),
    },
    caFingerprints: ca.fingerprints,
    runtime,
  };
  return result({ ...base, planSha256: planDigest(base) } as MtlsPlan);
}
export interface RuntimeChecks {
  probe: typeof probeRuntime;
  check: typeof checkReloaded;
}
const runtimeChecks: RuntimeChecks = { probe: probeRuntime, check: checkReloaded };
export interface ApplyInput extends WriteIntent {
  plan: MtlsPlan;
  confirmLua?: boolean;
}
export async function applyMtlsPolicy(
  client: OnePanelClientLike,
  input: ApplyInput,
  checks: RuntimeChecks = runtimeChecks,
) {
  const plan = input.plan;
  requireInput(
    plan?.version === 1 && plan.planSha256 === planDigest(plan),
    'Plan is incomplete or modified',
  );
  if (!input.apply) return result({ status: 'DRY_RUN', plan });
  requireInput(
    input.confirm === true &&
      input.confirmLua === true &&
      input.acknowledgeNonAtomic === true &&
      input.expectedSha256 === plan.expectedSha256,
    'Apply needs expectedSha256, confirm, confirmLua and acknowledgeNonAtomic',
  );
  const discovered = await discoverSite(client, plan.target);
  const currentGlobal = await globalContent(client, plan.target);
  if (sha256(currentGlobal) !== plan.globalSha256)
    throw new PanelError('CONFLICT', 'Global configuration changed since planning');
  const lua = buildLuaPolicy(plan.policy.fingerprints);
  const runtime = await checks.probe(
    plan.target,
    discovered.sitePath,
    currentGlobal,
    lua,
    discovered.content,
  );
  if (sha256(discovered.content) === plan.afterSha256) {
    for (const artifact of plan.artifacts)
      if (
        digest(await (await fileResource(client, plan.target, artifact.path)).read()) !==
        artifact.afterSha256
      )
        throw new PanelError('CONFLICT', 'Already-referenced policy artifact differs');
    return result({ status: 'UNCHANGED', runtime, enforcement: 'HTTP_E2E_REQUIRED' });
  }
  if (sha256(discovered.content) !== plan.expectedSha256)
    throw new PanelError('CONFLICT', 'Site configuration changed since planning');
  const rebuilt = (await planMtlsPolicy(client, { target: plan.target, policy: plan.policy })).data;
  if (rebuilt.planSha256 !== plan.planSha256)
    throw new PanelError('CONFLICT', 'Rebuilt plan differs; review a new plan');
  const completed: { resource: Resource; before: string | null; after: string }[] = [];
  const changes: unknown[] = [];
  let siteApplied = false;
  let createdDir = false;
  try {
    const dir = await remoteStat(client, discovered.policyRoot, plan.target.operateNode);
    if (!dir) {
      await filesModule.actions.createFile.execute(client, {
        target: plan.target,
        path: discovered.policyRoot,
        isDir: true,
        content: '',
        apply: true,
        confirm: true,
        expectedSha256: ABSENT_SHA256,
      });
      createdDir = true;
    }
    for (const artifact of plan.artifacts) {
      const resource = await fileResource(client, plan.target, artifact.path, 'create');
      const before = await resource.read();
      changes.push(
        await safeWrite(resource, artifact.content, {
          apply: true,
          confirm: true,
          expectedSha256: artifact.expectedSha256,
        }),
      );
      if (before !== artifact.content)
        completed.push({ resource, before, after: artifact.content });
    }
    const preSwitch = await checks.probe(
      plan.target,
      discovered.sitePath,
      currentGlobal,
      lua,
      discovered.content,
    );
    requireInput(
      preSwitch.configurationSha256 === runtime.configurationSha256,
      'Loaded include graph changed while staging',
    );
    const resource = await siteResource(client, plan.target);
    changes.push(
      await safeWrite(resource, plan.siteContent, {
        apply: true,
        confirm: true,
        expectedSha256: plan.expectedSha256,
      }),
    );
    siteApplied = true;
    const loaded = await checks.check(plan.target);
    await checks.probe(plan.target, discovered.sitePath, currentGlobal, lua, plan.siteContent);
    return result({
      status: 'APPLIED',
      planSha256: plan.planSha256,
      changes,
      runtime,
      loaded,
      enforcement: 'HTTP_E2E_REQUIRED',
      transaction: 'NON_ATOMIC; immutable files staged before a single include switch',
    });
  } catch (err) {
    const failures: string[] = [];
    if (siteApplied) {
      try {
        await safeWrite(await siteResource(client, plan.target), discovered.content, {
          apply: true,
          confirm: true,
          expectedSha256: plan.afterSha256,
        });
        await checks.check(plan.target);
      } catch {
        failures.push('site include recovery');
      }
    }
    // Do not remove files if a possibly live include still references them.
    const current = await (await siteResource(client, plan.target)).read().catch(() => null);
    if (current === discovered.content) {
      for (const item of completed.reverse())
        try {
          await safeWrite(item.resource, item.before, {
            apply: true,
            confirm: true,
            expectedSha256: sha256(item.after),
          });
        } catch {
          failures.push(item.resource.id);
        }
      if (createdDir && !failures.length)
        try {
          const list = unwrap(
            await client.request({
              method: 'POST',
              path: '/api/v2/files/search',
              operateNode: plan.target.operateNode,
              readOnly: true,
              body: {
                path: discovered.policyRoot,
                showHidden: true,
                expand: true,
                page: 1,
                pageSize: 1000,
              },
            }),
          );
          requireInput(
            list.itemTotal === 0 &&
              (list.items === null || (Array.isArray(list.items) && list.items.length === 0)),
            'Policy directory no longer empty',
          );
          await client.request({
            method: 'POST',
            path: '/api/v2/files/del',
            operateNode: plan.target.operateNode,
            body: { path: discovered.policyRoot, isDir: true, forceDelete: true },
          });
        } catch {
          failures.push('empty policy directory recovery');
        }
    } else failures.push('site state unknown; retained staged files for recovery');
    if (failures.length)
      throw new PanelError(
        'ROLLBACK_FAILED',
        'mTLS deployment partially failed; preserve backups, inspect loaded includes, then restore site before removing files',
        { failures, changes, originalCode: err instanceof PanelError ? err.code : 'API_ERROR' },
      );
    throw new PanelError(
      err instanceof PanelError ? err.code : 'API_ERROR',
      'mTLS deployment failed; original site and staged files restored',
      {
        changes,
        originalCode: err instanceof PanelError ? err.code : 'API_ERROR',
        reason: err instanceof PanelError ? err.message : 'Unexpected verification failure',
      },
    );
  }
}
async function currentPolicy(client: OnePanelClientLike, target: Target) {
  const site = await discoverSite(client, target),
    runtime = managedPath(site.content);
  requireInput(
    runtime?.startsWith(`/www/sites/${target.alias}/mtls/`),
    'No policy owned by this module is enabled',
  );
  const filename = path.posix.basename(runtime!).replace('.conf', '.json');
  const content = await (
    await fileResource(client, target, site.policyRoot + '/' + filename)
  ).read();
  requireInput(content !== null, 'Managed policy manifest missing');
  let policy: MtlsPolicy;
  try {
    policy = JSON.parse(content) as MtlsPolicy;
  } catch {
    throw new PanelError(
      'INVALID_INPUT',
      'Managed policy manifest is invalid JSON; inspect its private local copy',
    );
  }
  parseCABundle(policy.caBundle);
  normalizeFingerprints(policy.fingerprints);
  return { site, policy };
}
export async function inspectSiteMtls(
  client: OnePanelClientLike,
  input: { target: Target; probeRuntime?: boolean },
) {
  const site = await discoverSite(client, input.target);
  const sources: { path: string; analysis: unknown }[] = [
    { path: site.configPath, analysis: inspectNginx(site.content) },
  ];
  const managed = managedPath(site.content);
  if (managed) {
    requireInput(
      managed.startsWith(`/www/sites/${input.target.alias}/mtls/`),
      'Cross-site managed include',
    );
    const content = await (
      await fileResource(client, input.target, site.policyRoot + '/' + path.posix.basename(managed))
    ).read();
    if (content) sources.push({ path: managed, analysis: inspectNginx(content) });
  }
  const global = await globalContent(client, input.target);
  sources.push({ path: 'global nginx.conf', analysis: inspectNginx(global) });
  let runtime: unknown = {
    status: 'NOT_RUN',
    reason:
      'File inspection does not establish runtime behavior; unresolved includes may contain WAF/Lua handlers',
  };
  if (input.probeRuntime)
    try {
      runtime = await probeRuntime(input.target, site.sitePath, global);
    } catch (err) {
      runtime = {
        status: 'BLOCKED',
        code: err instanceof PanelError ? err.code : 'API_ERROR',
        reason: err instanceof Error ? err.message : 'Runtime probe failed',
      };
    }
  return result({
    target: input.target,
    sitePath: site.sitePath,
    configPath: site.configPath,
    sources,
    runtime,
    managed: !!managed,
    risks: [
      'Nginx $ssl_client_fingerprint is SHA-1; this module uses leaf DER SHA-256',
      'Unresolved includes and inherited handlers require runtime probe',
      'Existing keepalive connections and graceful worker drain need separate revocation checks',
    ],
  });
}
export async function disableMtlsPolicy(
  client: OnePanelClientLike,
  input: WriteIntent & { target: Target },
) {
  const site = await discoverSite(client, input.target),
    managed = managedPath(site.content);
  requireInput(
    !managed || managed.startsWith(`/www/sites/${input.target.alias}/mtls/`),
    'Cross-site managed include',
  );
  const content = removeManagedInclude(site.content);
  const change = await safeWrite(await siteResource(client, input.target), content, input);
  return result({
    ...change,
    retained:
      'Immutable policy, CA and Lua files retained for rollback; only the owned include is removed',
    enforcement: 'DISABLED only for APPLIED/UNCHANGED; administrator directives preserved',
  });
}
async function updatePolicy(
  client: OnePanelClientLike,
  input: WriteIntent & { target: Target; confirmLua?: boolean },
  policy: MtlsPolicy,
) {
  const plan = (await planMtlsPolicy(client, { target: input.target, policy })).data;
  if (!input.apply) return result({ status: 'DRY_RUN', plan });
  return applyMtlsPolicy(client, { ...input, plan });
}
export async function updateTrustedCAs(
  client: OnePanelClientLike,
  input: WriteIntent & { target: Target; caBundle: string; confirmLua?: boolean },
) {
  const current = await currentPolicy(client, input.target),
    next = parseCABundle(input.caBundle),
    before = parseCABundle(current.policy.caBundle);
  const update = await updatePolicy(client, input, { ...current.policy, caBundle: next.bundle });
  return result({
    change: update.data,
    beforeFingerprints: before.fingerprints,
    afterFingerprints: next.fingerprints,
  });
}
export async function updateCertificateFingerprintAllowlist(
  client: OnePanelClientLike,
  input: WriteIntent & { target: Target; fingerprints: string[]; confirmLua?: boolean },
) {
  const current = await currentPolicy(client, input.target);
  return updatePolicy(client, input, {
    ...current.policy,
    fingerprints: normalizeFingerprints(input.fingerprints),
  });
}
export async function updateLuaPolicy(
  client: OnePanelClientLike,
  input: WriteIntent & {
    target: Target;
    luaVersion: typeof LUA_VERSION;
    fingerprints?: string[];
    confirmLua?: boolean;
    content?: never;
  },
) {
  requireInput(
    input.luaVersion === LUA_VERSION && input.content === undefined,
    'Only reviewed sha256-acl-v1 template is supported; arbitrary Lua is rejected',
  );
  const current = await currentPolicy(client, input.target);
  return updatePolicy(client, input, {
    ...current.policy,
    luaVersion: input.luaVersion,
    fingerprints: input.fingerprints ?? current.policy.fingerprints,
  });
}
export interface MtlsTestCase {
  name: 'trusted-allowed' | 'no-certificate' | 'untrusted-ca' | 'trusted-denied';
  certFile?: string;
  keyFile?: string;
  expected: 'allow' | 'deny';
}
export interface MtlsTestInput {
  target: Target;
  authorizedTest?: boolean;
  url?: string;
  connectAddress?: string;
  serverCaFile?: string;
  cases?: MtlsTestCase[];
}
export async function testMtlsPolicy(client: OnePanelClientLike, input: MtlsTestInput) {
  if (!input.authorizedTest || !input.url || !input.cases)
    return result({
      status: 'NOT RUN',
      reason: 'No explicitly authorized test endpoint and certificate matrix',
    });
  const site = await discoverSite(client, input.target);
  const url = new URL(input.url);
  requireInput(
    url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.hash &&
      url.hostname === site.site.primaryDomain,
    'Test URL must match the selected website primary domain',
  );
  requireInput(
    input.cases.length >= 4 &&
      ['trusted-allowed', 'no-certificate', 'untrusted-ca', 'trusted-denied'].every((name) =>
        input.cases!.some((c) => c.name === name),
      ),
    'All four required test cases must be present',
  );
  requireInput(
    !input.connectAddress || isIP(input.connectAddress) > 0,
    'connectAddress must be an explicit IP address',
  );
  const serverCa = input.serverCaFile ? await readFile(input.serverCaFile) : undefined;
  const evidence = [];
  for (const item of input.cases) {
    requireInput(
      item.expected === (item.name === 'trusted-allowed' ? 'allow' : 'deny'),
      'Incorrect test expectation',
    );
    requireInput(
      item.name === 'no-certificate'
        ? !item.certFile && !item.keyFile
        : !!item.certFile && !!item.keyFile,
      'Certificate/key files required for certificate cases only',
    );
    const cert = item.certFile ? await readFile(item.certFile) : undefined,
      key = item.keyFile ? await readFile(item.keyFile) : undefined;
    const actual = await new Promise<{
      outcome: string;
      status?: number;
      tls?: string;
      error?: string;
    }>((resolve) => {
      const req = https.request(
        url,
        {
          method: 'GET',
          agent: false,
          cert,
          key,
          ca: serverCa,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
          headers: { Connection: 'close', Host: url.host },
          ...(input.connectAddress
            ? { hostname: input.connectAddress, servername: url.hostname }
            : {}),
        },
        (res) => {
          res.resume();
          resolve({
            outcome:
              res.statusCode && res.statusCode >= 200 && res.statusCode < 300
                ? 'allow'
                : [400, 403, 495, 496].includes(res.statusCode ?? 0)
                  ? 'deny'
                  : 'error',
            status: res.statusCode,
            tls: (res.socket as any).getProtocol?.(),
          });
        },
      );
      req.setTimeout(8000, () => req.destroy(new Error('timeout')));
      req.on('error', (err: any) =>
        resolve({
          outcome: /TLS.*ALERT.*(CERTIFICATE|UNKNOWN_CA)|CERTIFICATE_REQUIRED|BAD_CERTIFICATE/.test(
            err.code ?? '',
          )
            ? 'deny'
            : 'error',
          error: String(err.code ?? 'NETWORK'),
        }),
      );
      req.end();
    });
    evidence.push({
      name: item.name,
      expected: item.expected,
      ...actual,
      passed: actual.outcome === item.expected,
    });
  }
  return result({
    status: evidence.every((e) => e.passed) ? 'PASS' : 'FAIL',
    at: new Date().toISOString(),
    target: input.target,
    url: input.url,
    evidence,
    scope:
      'New TLS connections and HTTP/1.1 requests; HTTP2/QUIC and existing connections require separate tests',
  });
}
export const mtlsModule: ModuleDefinition = {
  id: 'mtls',
  title: 'Composed mTLS policies',
  description: 'Versioned enforce-only CA and leaf DER SHA-256 ACL using existing 1Panel APIs.',
  actions: {
    inspectSiteMtls: {
      id: 'inspectSiteMtls',
      summary: 'Inspect configuration sources, inherited-handler probe and risks.',
      method: 'GET',
      path: 'composed',
      nodeAware: true,
      execute: inspectSiteMtls,
    },
    planMtlsPolicy: {
      id: 'planMtlsPolicy',
      summary: 'Produce a full reviewable no-write plan with immutable artifacts.',
      method: 'GET',
      path: 'composed',
      nodeAware: true,
      execute: planMtlsPolicy,
    },
    applyMtlsPolicy: {
      id: 'applyMtlsPolicy',
      summary: 'Apply reviewed plan with local Docker validation and compensation.',
      method: 'POST',
      path: 'composed',
      nodeAware: true,
      mutation: true,
      scope: 'One explicit site; non-atomic staged files and include switch',
      execute: applyMtlsPolicy,
    },
    disableMtlsPolicy: {
      id: 'disableMtlsPolicy',
      summary: 'Remove only the owned include; retain versioned files for recovery.',
      method: 'POST',
      path: 'composed',
      nodeAware: true,
      mutation: true,
      scope: 'Owned include on selected site',
      execute: disableMtlsPolicy,
    },
    updateTrustedCAs: {
      id: 'updateTrustedCAs',
      summary: 'Validate and rotate multiple CAs, then reload a versioned policy.',
      method: 'POST',
      path: 'composed',
      nodeAware: true,
      mutation: true,
      scope: 'Selected managed site CA set',
      execute: updateTrustedCAs,
    },
    updateCertificateFingerprintAllowlist: {
      id: 'updateCertificateFingerprintAllowlist',
      summary: 'Rotate SHA-256 leaf certificate ACL; empty denies all.',
      method: 'POST',
      path: 'composed',
      nodeAware: true,
      mutation: true,
      scope: 'Selected managed site ACL',
      execute: updateCertificateFingerprintAllowlist,
    },
    updateLuaPolicy: {
      id: 'updateLuaPolicy',
      summary: 'Install reviewed versioned Lua template; arbitrary Lua rejected.',
      method: 'POST',
      path: 'composed',
      nodeAware: true,
      mutation: true,
      scope: 'Selected managed site reviewed Lua template',
      execute: updateLuaPolicy,
    },
    testMtlsPolicy: {
      id: 'testMtlsPolicy',
      summary: 'Run an explicitly authorized four-case TLS and HTTP matrix.',
      method: 'GET',
      path: 'composed',
      nodeAware: true,
      execute: testMtlsPolicy,
    },
  },
  reservedMutations: [],
};
