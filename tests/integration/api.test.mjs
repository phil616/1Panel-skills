import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { panelServer, originalSite } from '../fixtures/panel-server.mjs';
import { makePki } from '../fixtures/make-pki.mjs';
import { getModule, listModules } from '../../dist/scripts/index.js';
import { sha256, ABSENT_SHA256 } from '../../dist/scripts/security/change-plan.js';
import {
  applyMtlsPolicy,
  planMtlsPolicy,
  testMtlsPolicy,
} from '../../dist/scripts/modules/mtls.js';
import { remoteStat } from '../../dist/scripts/security/path-policy.js';
import { isReadRequest } from '../../dist/scripts/security/request-policy.js';
const dir = mkdtempSync(join(tmpdir(), 'onepanel-integration-'));
process.env.ONEPANEL_STATE_DIR = dir;
const pki = makePki();
after(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(pki.dir, { recursive: true, force: true });
});
const run = (s, module, action, input) =>
  getModule(module).actions[action].execute(s.client, input);
const intent = (hash) => ({ apply: true, confirm: true, expectedSha256: hash });
const runtime = {
  probe: async () => ({ status: 'MOCK', configurationSha256: 'fixed' }),
  check: async () => ({ syntax: 'MOCK' }),
};
const policy = { caBundle: pki.read('bundle.pem'), fingerprints: [] };
test('site dry-run → apply → verify → journal uses exact node, DTO and endpoint', async () => {
  const s = await panelServer();
  try {
    const content = originalSite.replace('127.0.0.1:8080', '127.0.0.1:9000');
    const plan = (await run(s, 'websites', 'updateWebsiteRawConfig', { target: s.target, content }))
      .data;
    assert.equal(plan.status, 'DRY_RUN');
    assert.equal(s.records.filter((r) => r.path === '/api/v2/websites/nginx/update').length, 0);
    const applied = (
      await run(s, 'websites', 'updateWebsiteRawConfig', {
        target: s.target,
        content,
        ...intent(plan.expectedSha256),
      })
    ).data;
    assert.equal(applied.status, 'APPLIED');
    assert.equal(s.files.get('/opt/1panel/www/conf.d/test.conf'), content);
    const writes = s.records.filter((r) => r.path === '/api/v2/websites/nginx/update');
    assert.equal(writes.length, 1);
    assert.deepEqual(writes[0].body, { id: 7, content });
    assert.equal(writes[0].node, 'local');
    assert.equal(s.records.at(-1).path, '/api/v2/websites/7/config/openresty');
    assert.equal(JSON.parse(readFileSync(applied.backupPath + '.audit.json')).result, 'APPLIED');
  } finally {
    await s.close();
  }
});
for (const [status, code] of [
  [401, 'AUTH_FAILED'],
  [403, 'FORBIDDEN'],
  [404, 'NOT_FOUND'],
  [405, 'API_UNSUPPORTED'],
])
  test('site discovery handles HTTP ' + status + ' before writing', async () => {
    const s = await panelServer();
    s.state.handler = (r, { send }) => {
      if (r.path === '/api/v2/websites/7') {
        send({}, status, status);
        return true;
      }
    };
    try {
      await assert.rejects(
        run(s, 'websites', 'updateWebsiteRawConfig', {
          target: s.target,
          content: originalSite,
          ...intent(sha256('old')),
        }),
        { code },
      );
      assert.equal(s.reloads, 0);
    } finally {
      await s.close();
    }
  });
test('HTTP-200 business error does not report a successful mutation', async () => {
  const s = await panelServer();
  s.state.handler = (r, { res }) => {
    if (r.path === '/api/v2/websites/nginx/update') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ code: 500, message: 'nginx reload failed' }));
      return true;
    }
  };
  try {
    await assert.rejects(
      run(s, 'websites', 'updateWebsiteRawConfig', {
        target: s.target,
        content: originalSite + '\n',
        ...intent(sha256(originalSite)),
      }),
      (e) => e.code === 'RELOAD_FAILED' && e.details.audit.result === 'ROLLED_BACK',
    );
    assert.equal(s.files.get('/opt/1panel/www/conf.d/test.conf'), originalSite);
  } finally {
    await s.close();
  }
});
test('network disconnect after commit is reconciled without a duplicate write', async () => {
  const s = await panelServer();
  s.state.handler = (r, { req }) => {
    if (r.path === '/api/v2/websites/nginx/update') {
      s.files.set('/opt/1panel/www/conf.d/test.conf', r.body.content);
      req.socket.destroy();
      return true;
    }
  };
  try {
    assert.equal(
      (
        await run(s, 'websites', 'updateWebsiteRawConfig', {
          target: s.target,
          content: originalSite + '\n',
          ...intent(sha256(originalSite)),
        })
      ).data.status,
      'APPLIED',
    );
    assert.equal(s.records.filter((r) => r.path === '/api/v2/websites/nginx/update').length, 1);
  } finally {
    await s.close();
  }
});
test('concurrent edit detected between discovery and actual mutation', async () => {
  const s = await panelServer();
  try {
    const next = originalSite + '\n';
    const plan = (
      await run(s, 'websites', 'updateWebsiteRawConfig', { target: s.target, content: next })
    ).data;
    s.files.set('/opt/1panel/www/conf.d/test.conf', originalSite + '# someone else\n');
    await assert.rejects(
      run(s, 'websites', 'updateWebsiteRawConfig', {
        target: s.target,
        content: next,
        ...intent(plan.expectedSha256),
      }),
      { code: 'CONFLICT' },
    );
    assert.equal(s.records.filter((r) => r.path.endsWith('nginx/update')).length, 0);
  } finally {
    await s.close();
  }
});
for (const changed of [
  { alias: 'other' },
  { websiteId: 8 },
  { operateNode: 'missing' },
  { instance: 'wrong' },
  { baseUrl: 'http://127.0.0.1:999' },
])
  test('wrong explicit target refuses mutation ' + JSON.stringify(changed), async () => {
    const s = await panelServer();
    if (changed.operateNode)
      s.state.handler = (r, { send }) => {
        if (r.node === 'missing') {
          send({}, 403, 403);
          return true;
        }
      };
    try {
      await assert.rejects(
        run(s, 'websites', 'updateWebsiteRawConfig', {
          target: { ...s.target, ...changed },
          content: originalSite + '\n',
          ...intent(sha256(originalSite)),
        }),
      );
      assert.equal(s.records.filter((r) => r.path.endsWith('nginx/update')).length, 0);
    } finally {
      await s.close();
    }
  });
test('symlink in any ancestor blocks managed file read/write', async () => {
  const s = await panelServer();
  s.dirs.add('/opt/1panel/www/sites/test/mtls');
  s.state.symlinks.add('/opt/1panel/www/sites/test');
  try {
    await assert.rejects(
      run(s, 'files', 'writeFile', {
        target: s.target,
        path: '/opt/1panel/www/sites/test/mtls/ca.pem',
        content: pki.read('root.pem'),
      }),
      { code: 'FORBIDDEN' },
    );
  } finally {
    await s.close();
  }
});
test('global config requires extra confirmation and serializes backup:true', async () => {
  const s = await panelServer();
  try {
    const content = 'events {}\nhttp {}\n';
    const plan = (await run(s, 'openresty', 'updateGlobalConfig', { target: s.target, content }))
      .data;
    await assert.rejects(
      run(s, 'openresty', 'updateGlobalConfig', {
        target: s.target,
        content,
        ...intent(plan.expectedSha256),
      }),
      { code: 'INVALID_INPUT' },
    );
    assert.equal(
      (
        await run(s, 'openresty', 'updateGlobalConfig', {
          target: s.target,
          content,
          backup: true,
          confirmGlobal: true,
          ...intent(plan.expectedSha256),
        })
      ).data.status,
      'APPLIED',
    );
    assert.deepEqual(s.records.find((r) => r.path === '/api/v2/openresty/file').body, {
      content,
      backup: true,
    });
  } finally {
    await s.close();
  }
});
test('existing proxy DTO uses id for read and websiteID for write', async () => {
  const s = await panelServer();
  try {
    const content = 'location /proxy { proxy_pass http://127.0.0.1:9999; }\n';
    const plan = (
      await run(s, 'websites', 'updateProxyRawConfig', {
        target: s.target,
        name: 'upstream',
        content,
      })
    ).data;
    await run(s, 'websites', 'updateProxyRawConfig', {
      target: s.target,
      name: 'upstream',
      content,
      ...intent(plan.expectedSha256),
    });
    assert.deepEqual(s.records.find((r) => r.path === '/api/v2/websites/proxies').body, { id: 7 });
    assert.deepEqual(s.records.find((r) => r.path === '/api/v2/websites/proxies/file').body, {
      websiteID: 7,
      name: 'upstream',
      content,
    });
    await assert.rejects(
      run(s, 'websites', 'updateProxyRawConfig', { target: s.target, name: '../../x', content }),
      { code: 'INVALID_INPUT' },
    );
    await assert.rejects(
      run(s, 'websites', 'updateProxyRawConfig', { target: s.target, name: 'missing', content }),
      { code: 'NOT_FOUND' },
    );
  } finally {
    await s.close();
  }
});
test('structured scope uses only server-supported keys and canonical scope digest', async () => {
  const s = await panelServer();
  try {
    const input = {
      target: s.target,
      scope: 'index',
      operate: 'update',
      params: { index: 'index.html index.htm' },
    };
    const plan = (await run(s, 'websites', 'updateSiteNginxSettings', input)).data;
    assert.equal(
      (
        await run(s, 'websites', 'updateSiteNginxSettings', {
          ...input,
          ...intent(plan.expectedSha256),
        })
      ).data.status,
      'APPLIED',
    );
    assert.deepEqual(s.records.find((r) => r.path === '/api/v2/websites/config/update').body, {
      websiteId: 7,
      scope: 'index',
      operate: 'update',
      params: { index: 'index.html index.htm' },
    });
    await assert.rejects(run(s, 'websites', 'updateSiteNginxSettings', { ...input, scope: 'ssl' }));
    await assert.rejects(
      run(s, 'websites', 'updateSiteNginxSettings', {
        ...input,
        params: { access_by_lua_file: '/evil.lua' },
      }),
    );
  } finally {
    await s.close();
  }
});
test('create directory and multipart CA upload read back exact UTF-8', async () => {
  const s = await panelServer();
  try {
    const root = '/opt/1panel/www/sites/test/mtls';
    const plan = (
      await run(s, 'files', 'createFile', {
        target: s.target,
        path: root,
        isDir: true,
        content: '',
      })
    ).data;
    assert.equal(plan.expectedSha256, ABSENT_SHA256);
    await run(s, 'files', 'createFile', {
      target: s.target,
      path: root,
      isDir: true,
      content: '',
      ...intent(ABSENT_SHA256),
    });
    const localFile = join(dir, 'ca.pem');
    writeFileSync(localFile, pki.read('bundle.pem'));
    const upload = { target: s.target, path: root + '/ca.pem', localFile };
    assert.equal((await run(s, 'files', 'uploadFile', upload)).data.status, 'DRY_RUN');
    assert.equal(s.records.filter((r) => r.path === '/api/v2/files/upload').length, 0);
    await run(s, 'files', 'uploadFile', { ...upload, ...intent(ABSENT_SHA256) });
    assert.equal(s.files.get(root + '/ca.pem'), pki.read('bundle.pem'));
    assert.equal(s.records.filter((r) => r.path === '/api/v2/files/upload').length, 1);
  } finally {
    await s.close();
  }
});
test('mTLS complete mock composition stages files, switches once, verifies and disables only own include', async () => {
  const s = await panelServer();
  try {
    const plan = (await planMtlsPolicy(s.client, { target: s.target, policy })).data;
    assert.equal(plan.artifacts.length, 4);
    assert.equal(
      s.records.filter((r) =>
        ['/api/v2/files', '/api/v2/files/save', '/api/v2/websites/nginx/update'].includes(r.path),
      ).length,
      0,
    );
    assert.equal((await applyMtlsPolicy(s.client, { plan })).data.status, 'DRY_RUN');
    const input = {
      plan,
      ...intent(plan.expectedSha256),
      confirmLua: true,
      acknowledgeNonAtomic: true,
    };
    const out = await applyMtlsPolicy(s.client, input, runtime);
    assert.equal(out.data.status, 'APPLIED');
    assert.equal(s.files.get('/opt/1panel/www/conf.d/test.conf'), plan.siteContent);
    assert.equal(s.records.filter((r) => r.path === '/api/v2/websites/nginx/update').length, 1);
    assert.equal((await applyMtlsPolicy(s.client, input, runtime)).data.status, 'UNCHANGED');
    const disable = (await run(s, 'mtls', 'disableMtlsPolicy', { target: s.target })).data;
    await run(s, 'mtls', 'disableMtlsPolicy', {
      target: s.target,
      ...intent(disable.expectedSha256),
    });
    assert.equal(s.files.get('/opt/1panel/www/conf.d/test.conf'), originalSite);
    assert.ok(s.files.has(plan.artifacts[0].path));
  } finally {
    await s.close();
  }
});
test('mTLS refused without runtime dependencies; no staging side effects', async () => {
  const s = await panelServer();
  try {
    const plan = (await planMtlsPolicy(s.client, { target: s.target, policy })).data;
    const failing = {
      ...runtime,
      probe: async () => {
        const e = new Error('missing Lua');
        e.code = 'DEPENDENCY_MISSING';
        throw e;
      },
    };
    await assert.rejects(
      applyMtlsPolicy(
        s.client,
        { plan, ...intent(plan.expectedSha256), confirmLua: true, acknowledgeNonAtomic: true },
        failing,
      ),
    );
    assert.equal(s.records.filter((r) => r.path === '/api/v2/files').length, 0);
  } finally {
    await s.close();
  }
});
test('mTLS include reload failure compensates all staged files and empty directory', async () => {
  const s = await panelServer();
  s.state.handler = (r, { send }) => {
    if (r.path === '/api/v2/websites/nginx/update') {
      send({}, 200, 500);
      return true;
    }
  };
  try {
    const plan = (await planMtlsPolicy(s.client, { target: s.target, policy })).data;
    await assert.rejects(
      applyMtlsPolicy(
        s.client,
        { plan, ...intent(plan.expectedSha256), confirmLua: true, acknowledgeNonAtomic: true },
        runtime,
      ),
    );
    assert.equal(s.files.get('/opt/1panel/www/conf.d/test.conf'), originalSite);
    assert.equal(s.dirs.has('/opt/1panel/www/sites/test/mtls'), false);
    for (const artifact of plan.artifacts) assert.equal(s.files.has(artifact.path), false);
  } finally {
    await s.close();
  }
});
test('mTLS reload verification and rollback failure propagate partial status', async () => {
  const s = await panelServer();
  let n = 0;
  s.state.handler = (r, { send }) => {
    if (r.path === '/api/v2/websites/nginx/update' && ++n > 1) {
      send({}, 200, 500);
      return true;
    }
  };
  try {
    const plan = (await planMtlsPolicy(s.client, { target: s.target, policy })).data;
    await assert.rejects(
      applyMtlsPolicy(
        s.client,
        { plan, ...intent(plan.expectedSha256), confirmLua: true, acknowledgeNonAtomic: true },
        {
          ...runtime,
          check: async () => {
            throw new Error('reload health failure');
          },
        },
      ),
      { code: 'ROLLBACK_FAILED' },
    );
    assert.ok(s.files.has(plan.artifacts[0].path));
  } finally {
    await s.close();
  }
});
test('tampered plans and missing second Lua confirmation are rejected before staging', async () => {
  const s = await panelServer();
  try {
    const plan = (await planMtlsPolicy(s.client, { target: s.target, policy })).data;
    await assert.rejects(
      applyMtlsPolicy(
        s.client,
        {
          plan: { ...plan, siteContent: 'evil' },
          ...intent(plan.expectedSha256),
          confirmLua: true,
          acknowledgeNonAtomic: true,
        },
        runtime,
      ),
      { code: 'INVALID_INPUT' },
    );
    await assert.rejects(
      applyMtlsPolicy(s.client, { plan, ...intent(plan.expectedSha256) }, runtime),
      { code: 'INVALID_INPUT' },
    );
  } finally {
    await s.close();
  }
});
test('unconfigured E2E reports NOT RUN', async () => {
  const s = await panelServer();
  try {
    assert.equal((await testMtlsPolicy(s.client, { target: s.target })).data.status, 'NOT RUN');
  } finally {
    await s.close();
  }
});
test('upstream module IDs, action entrypoints and reserved definitions remain discoverable', () => {
  for (const id of [
    'monitoring',
    'websites',
    'apps',
    'containers',
    'logs',
    'cronjobs',
    'task-center',
    'nodes',
  ]) {
    assert.ok(getModule(id));
    const mod = getModule(id);
    assert.ok(Object.keys(mod.actions).length);
    for (const r of mod.reservedMutations) assert.equal(mod.actions[r.id], undefined);
  }
  const command = spawnSync(process.execPath, ['dist/scripts/cli.js', 'actions', 'websites'], {
    encoding: 'utf8',
  });
  assert.equal(command.status, 0);
  assert.ok(JSON.parse(command.stdout).actions.some((a) => a.id === 'getWebsiteConfig'));
});
test('generic request retains GET/known POST reads and refuses unguarded mutations', () => {
  assert.equal(isReadRequest('GET', '/api/v2/dashboard/base/os'), true);
  assert.equal(isReadRequest('POST', '/api/v2/websites/search'), true);
  assert.equal(isReadRequest('POST', '/api/v2/websites/nginx/update'), false);
  assert.equal(isReadRequest('POST', '/api/v2/files/save'), false);
  const run = spawnSync(
    process.execPath,
    ['dist/scripts/cli.js', 'request', 'POST', '/api/v2/files/save'],
    {
      env: { ...process.env, ONEPANEL_BASE_URL: 'http://127.0.0.1:9', ONEPANEL_API_KEY: 'fake' },
      encoding: 'utf8',
    },
  );
  assert.equal(run.status, 1);
  assert.equal(JSON.parse(run.stderr).code, 'INVALID_INPUT');
});

test('known empty-file intermediate is removed when FileCreate succeeds but save fails', async () => {
  const s = await panelServer();
  s.dirs.add('/opt/1panel/www/sites/test/mtls');
  s.state.handler = (r, { send }) => {
    if (r.path === '/api/v2/files/save') {
      send({}, 200, 500);
      return true;
    }
  };
  try {
    await assert.rejects(
      run(s, 'files', 'createFile', {
        target: s.target,
        path: '/opt/1panel/www/sites/test/mtls/test.conf',
        content: 'set $test value;',
        ...intent(ABSENT_SHA256),
      }),
      (e) => e.details.audit.result === 'ROLLED_BACK',
    );
    assert.equal(s.files.has('/opt/1panel/www/sites/test/mtls/test.conf'), false);
  } finally {
    await s.close();
  }
});
test('policy limits and immutable hash filenames reject oversized or inconsistent writes', async () => {
  const s = await panelServer();
  s.dirs.add('/opt/1panel/www/sites/test/mtls');
  try {
    await assert.rejects(
      run(s, 'files', 'writeFile', {
        target: s.target,
        path: '/opt/1panel/www/sites/test/mtls/large.conf',
        content: 'x'.repeat(1024 * 1024 + 1),
      }),
      { code: 'INVALID_INPUT' },
    );
    await assert.rejects(
      run(s, 'files', 'writeFile', {
        target: s.target,
        path: '/opt/1panel/www/sites/test/mtls/ca-' + sha256('wrong') + '.pem',
        content: pki.read('root.pem'),
      }),
      { code: 'INVALID_INPUT' },
    );
    await assert.rejects(
      run(s, 'websites', 'updateWebsiteRawConfig', {
        target: { ...s.target, alias: 'default' },
        content: originalSite,
      }),
      { code: 'INVALID_INPUT' },
    );
  } finally {
    await s.close();
  }
});
test('all upstream module reads retain pinned representative HTTP contracts', async () => {
  const s = await panelServer();
  s.state.handler = (r, { send }) => {
    if (!['/api/v2/apps/installed/search'].includes(r.path)) {
      send({ items: [{ id: 123 }], total: 1 });
      return true;
    }
  };
  const cases = [
    ['monitoring', 'getCurrentNode', {}, 'GET', '/api/v2/dashboard/current/node', {}],
    ['websites', 'listWebsites', {}, 'GET', '/api/v2/websites/list', {}],
    [
      'apps',
      'searchInstalledApps',
      {},
      'POST',
      '/api/v2/apps/installed/search',
      { page: 1, pageSize: 20, name: '', type: '', unused: false, all: false },
    ],
    [
      'containers',
      'searchContainers',
      {},
      'POST',
      '/api/v2/containers/search',
      {
        page: 1,
        pageSize: 20,
        name: '',
        state: '',
        filters: '',
        orderBy: 'created_at',
        order: 'descending',
      },
    ],
    [
      'logs',
      'getOperationLogs',
      {},
      'POST',
      '/api/v2/core/logs/operation',
      { page: 1, pageSize: 20, source: '', status: '', operation: '' },
    ],
    [
      'cronjobs',
      'searchCronjobs',
      {},
      'POST',
      '/api/v2/cronjobs/search',
      { page: 1, pageSize: 20, info: '', groupIDs: [], orderBy: 'created_at', order: 'descending' },
    ],
    [
      'task-center',
      'searchTasks',
      {},
      'POST',
      '/api/v2/logs/tasks/search',
      { page: 1, pageSize: 20, type: '', status: '' },
    ],
    ['nodes', 'listAllNodes', {}, 'GET', '/api/v2/core/nodes/all', {}],
  ];
  try {
    for (const [module, action, input, method, path, body] of cases) {
      const out = await run(s, module, action, input);
      assert.equal(out.status, 200);
      const sent = s.records.at(-1);
      assert.equal(sent.method, method);
      assert.equal(sent.path, path);
      assert.deepEqual(sent.body, body);
    }
  } finally {
    await s.close();
  }
});
test('private full CLI output keeps stdout redacted and reserves output before any API call', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const exec = promisify(execFile);
  const { statSync } = await import('node:fs');
  const s = await panelServer();
  s.state.handler = (r, { send }) => {
    send({
      appKey: 'openresty',
      password: 'test-password',
      privateKey: 'test-private',
      content: 'confidential config',
    });
    return true;
  };
  const output = join(dir, 'private-cli-response.json');
  const env = {
    ...process.env,
    ONEPANEL_BASE_URL: s.target.baseUrl,
    ONEPANEL_API_KEY: 'mock-test-key',
  };
  try {
    const result = await exec(
      process.execPath,
      [
        'dist/scripts/cli.js',
        'request',
        'GET',
        '/api/v2/dashboard/base/os',
        '--output-file',
        output,
      ],
      { env },
    );
    assert.doesNotMatch(result.stdout, /test-password|test-private|confidential config/);
    assert.match(result.stdout, /openresty/);
    assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(output)).data.content, 'confidential config');
    const count = s.records.length;
    await assert.rejects(
      exec(
        process.execPath,
        [
          'dist/scripts/cli.js',
          'request',
          'GET',
          '/api/v2/dashboard/base/os',
          '--output-file',
          output,
        ],
        { env },
      ),
    );
    assert.equal(s.records.length, count);
  } finally {
    await s.close();
  }
});

test('raw site, proxy and global actions cannot introduce unchecked Lua even with confirmation', async () => {
  const s = await panelServer();
  try {
    await assert.rejects(
      run(s, 'websites', 'updateWebsiteRawConfig', {
        target: s.target,
        content: originalSite.replace(
          'location /',
          'access_by_lua_file /tmp/unreviewed.lua; location /',
        ),
        confirmLua: true,
      }),
      { code: 'FORBIDDEN' },
    );
    await assert.rejects(
      run(s, 'websites', 'updateProxyRawConfig', {
        target: s.target,
        name: 'upstream',
        content: 'location /proxy { access_by_lua_block { ngx.say("unreviewed"); } }',
        confirmLua: true,
      }),
      { code: 'FORBIDDEN' },
    );
    await assert.rejects(
      run(s, 'openresty', 'updateGlobalConfig', {
        target: s.target,
        content: 'events {} http { init_by_lua_file /tmp/unreviewed.lua; }',
        confirmLua: true,
        confirmGlobal: true,
        backup: true,
      }),
      { code: 'FORBIDDEN' },
    );
    assert.equal(
      s.records.filter((r) =>
        [
          '/api/v2/websites/nginx/update',
          '/api/v2/websites/proxies/file',
          '/api/v2/openresty/file',
        ].includes(r.path),
      ).length,
      0,
    );
  } finally {
    await s.close();
  }
});
test('controlled conf and JSON files cannot disguise an arbitrary Lua payload', async () => {
  const s = await panelServer();
  s.dirs.add('/opt/1panel/www/sites/test/mtls');
  try {
    await assert.rejects(
      run(s, 'files', 'writeFile', {
        target: s.target,
        path: '/opt/1panel/www/sites/test/mtls/payload.conf',
        content: 'access_by_lua_block { ngx.say("unreviewed"); }',
      }),
      { code: 'INVALID_INPUT' },
    );
    await assert.rejects(
      run(s, 'files', 'writeFile', {
        target: s.target,
        path: '/opt/1panel/www/sites/test/mtls/payload.json',
        content: 'init_by_lua_file /tmp/exec.lua;',
      }),
      { code: 'INVALID_INPUT' },
    );
  } finally {
    await s.close();
  }
});
