import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import https from 'node:https';
import http from 'node:http';
import http2 from 'node:http2';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { OnePanelClient } from '../../dist/scripts/client.js';
import { getModule } from '../../dist/scripts/index.js';
import { sha256, ABSENT_SHA256 } from '../../dist/scripts/security/change-plan.js';
import { certificateFingerprint } from '../../dist/scripts/security/certificates.js';
import { managedPath } from '../../dist/scripts/security/nginx-config.js';
const exec = promisify(execFile);
export async function runMatrix(config) {
  assert.equal(config.isolated, true, 'Explicit isolated test config required');
  assert.equal(config.target.operateNode, 'local');
  assert.match(config.target.instance, /^onepanel-skill/);
  const credentials = JSON.parse(await readFile(config.clientFile, 'utf8'));
  const client = new OnePanelClient({ ...credentials, baseUrl: config.target.baseUrl });
  const target = config.target;
  process.env.ONEPANEL_STATE_DIR = config.journalDir;
  await mkdir(config.journalDir, { recursive: true, mode: 0o700 });
  const run = (module, action, input) =>
    getModule(module)
      .actions[action].execute(client, input)
      .then((r) => r.data);
  const site = () =>
    client
      .request({
        method: 'GET',
        path: `/api/v2/websites/${target.websiteId}/config/openresty`,
        operateNode: target.operateNode,
      })
      .then((r) => r.data.data.content);
  const global = () =>
    client
      .request({ method: 'GET', path: '/api/v2/openresty', operateNode: target.operateNode })
      .then((r) => r.data.data.content);
  const originalSite = await site(),
    originalGlobal = await global();
  assert.equal(managedPath(originalSite), undefined, 'Start from a clean disposable site');
  const before = { siteSha256: sha256(originalSite), globalSha256: sha256(originalGlobal) };
  const evidence = [];
  const cert = await readFile(config.pkiDir + '/allowed-chain.pem'),
    key = await readFile(config.pkiDir + '/allowed.key'),
    ca = await readFile(config.pkiDir + '/root.pem');
  const allowed = certificateFingerprint(await readFile(config.pkiDir + '/allowed.pem', 'utf8')),
    denied = certificateFingerprint(await readFile(config.pkiDir + '/denied.pem', 'utf8'));
  const policy = {
    caBundle: await readFile(config.pkiDir + '/bundle.pem', 'utf8'),
    fingerprints: [allowed],
  };
  const intent = (expectedSha256) => ({
    apply: true,
    confirm: true,
    confirmLua: true,
    acknowledgeNonAtomic: true,
    expectedSha256,
  });
  async function request({ withCert = true, httpVersion = '1.1', maxVersion, path = '/' } = {}) {
    const url = new URL(config.url);
    url.pathname = path;
    const options = {
      ca,
      rejectUnauthorized: true,
      servername: url.hostname,
      ...(withCert ? { cert, key } : {}),
      minVersion: 'TLSv1.2',
      ...(maxVersion ? { maxVersion } : {}),
    };
    if (httpVersion === '2')
      return new Promise((resolve, reject) => {
        const session = http2.connect(`https://${config.connectAddress}:${url.port}`, options);
        let finished = false;
        const timeout = setTimeout(() => {
          session.destroy();
          reject(new Error('HTTP2 timeout'));
        }, 8000);
        session.on('error', reject);
        session.on('close', () => clearTimeout(timeout));
        session.on('connect', () => {
          const req = session.request({ ':path': path, ':authority': url.host });
          req.on('response', (headers) => {
            finished = true;
            resolve({ status: headers[':status'], alpn: session.alpnProtocol });
            req.resume();
            session.close();
          });
          req.on('error', reject);
          req.end();
        });
      });
    return new Promise((resolve, reject) => {
      const req = https.request(
        url,
        {
          ...options,
          hostname: config.connectAddress,
          agent: false,
          headers: { Host: url.host, Connection: 'close' },
        },
        (res) => {
          res.resume();
          resolve({ status: res.statusCode, tls: res.socket.getProtocol() });
        },
      );
      req.setTimeout(8000, () => req.destroy(new Error('HTTPS timeout')));
      req.on('error', reject);
      req.end();
    });
  }
  async function waitStatus(status, options = {}) {
    let last;
    for (let n = 0; n < 30; n++) {
      last = await request(options);
      if (last.status === status) return last;
      await new Promise((r) => setTimeout(r, 100));
    }
    return last;
  }
  async function check(name, fn) {
    const detail = await fn();
    evidence.push({ name, status: 'PASS', detail });
    console.log('E2E PASS:', name);
  }
  async function restoreSite(content = originalSite) {
    return run('websites', 'updateWebsiteRawConfig', {
      target,
      content,
      ...intent(sha256(await site())),
    });
  }
  async function restoreGlobal(content = originalGlobal) {
    return run('openresty', 'updateGlobalConfig', {
      target,
      content,
      backup: true,
      confirmGlobal: true,
      ...intent(sha256(await global())),
    });
  }
  let primaryError;
  try {
    await check('MD5 and HMAC authenticate against real 1Panel', async () => {
      for (const signatureVersion of ['md5', 'hmac-sha256'])
        await new OnePanelClient({
          ...credentials,
          baseUrl: target.baseUrl,
          signatureVersion,
        }).request({ method: 'GET', path: '/api/v2/dashboard/base/os' });
      return ['md5', 'hmac-sha256'];
    });
    await check('baseline HTTPS, reverse proxy and HTTP2', async () => {
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      assert.equal((await waitStatus(200, { withCert: false, path: '/proxy' })).status, 200);
      const h2 = await request({ withCert: false, httpVersion: '2' });
      assert.equal(h2.status, 200);
      assert.equal(h2.alpn, 'h2');
      return h2;
    });
    await check('dry-run leaves bytes and service unchanged', async () => {
      const plan = await run('mtls', 'planMtlsPolicy', { target, policy, probeRuntime: true });
      assert.equal(plan.runtime.status, 'PASS');
      assert.equal(await site(), originalSite);
      assert.equal(await global(), originalGlobal);
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      return { siteSha256: sha256(await site()), artifacts: plan.artifacts.length };
    });
    await check('raw site apply, read-back, idempotence and restore', async () => {
      const content = originalSite + '# harmless isolated test\n';
      const first = await run('websites', 'updateWebsiteRawConfig', {
        target,
        content,
        ...intent(before.siteSha256),
      });
      assert.equal(first.status, 'APPLIED');
      assert.equal(
        (
          await run('websites', 'updateWebsiteRawConfig', {
            target,
            content,
            ...intent(before.siteSha256),
          })
        ).status,
        'UNCHANGED',
      );
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      await restoreSite();
      return { status: first.status, restored: (await site()) === originalSite };
    });
    await check('structured index settings round-trip', async () => {
      const input = {
        target,
        scope: 'index',
        operate: 'update',
        params: { index: 'index.html index.htm' },
      };
      const plan = await run('websites', 'updateSiteNginxSettings', input);
      assert.equal(
        (
          await run('websites', 'updateSiteNginxSettings', {
            ...input,
            ...intent(plan.expectedSha256),
          })
        ).status,
        'APPLIED',
      );
      await restoreSite();
      return 'canonical scope digest verified';
    });
    await check('existing proxy read/write uses real DTO and restores', async () => {
      const proxies = (
        await client.request({
          method: 'POST',
          path: '/api/v2/websites/proxies',
          operateNode: 'local',
          body: { id: target.websiteId },
        })
      ).data.data;
      const proxy = proxies.find((p) => p.name === 'extra');
      assert.ok(proxy);
      const plan = await run('websites', 'updateProxyRawConfig', {
        target,
        name: 'extra',
        content: proxy.content + '# proxy round-trip\n',
      });
      await run('websites', 'updateProxyRawConfig', {
        target,
        name: 'extra',
        content: proxy.content + '# proxy round-trip\n',
        ...intent(plan.expectedSha256),
      });
      await run('websites', 'updateProxyRawConfig', {
        target,
        name: 'extra',
        content: proxy.content,
        ...intent(sha256(proxy.content + '# proxy round-trip\n')),
      });
      await restoreSite();
      assert.equal((await waitStatus(200, { withCert: false, path: '/proxy' })).status, 200);
      return 'proxy and site restored';
    });
    await check('illegal Nginx is rejected and original service survives', async () => {
      await assert.rejects(
        run('websites', 'updateWebsiteRawConfig', {
          target,
          content: originalSite + 'invalid_test_directive on;\n',
          ...intent(sha256(await site())),
        }),
        { code: 'SYNTAX_FAILED' },
      );
      assert.equal(await site(), originalSite);
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      return 'API rejection and read-back restoration';
    });
    await check('concurrent baseline mismatch refuses overwrite', async () => {
      const stale = sha256(await site());
      await restoreSite(originalSite + '# another editor\n');
      await assert.rejects(
        run('websites', 'updateWebsiteRawConfig', {
          target,
          content: originalSite + '# stale plan\n',
          ...intent(stale),
        }),
        { code: 'CONFLICT' },
      );
      assert.match(await site(), /another editor/);
      await restoreSite();
      return 'CONFLICT';
    });
    await check('global guarded write, server backup, and restoration', async () => {
      const next = originalGlobal + '# isolated global round-trip\n';
      await restoreGlobal(next);
      assert.equal(await global(), next);
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      await restoreGlobal();
      return { backup: true, restored: (await global()) === originalGlobal };
    });
    const siteInfo = (
      await client.request({
        method: 'GET',
        path: `/api/v2/websites/${target.websiteId}`,
        operateNode: 'local',
      })
    ).data.data;
    const policyRoot = siteInfo.sitePath + '/mtls';
    await check('controlled directory and multipart CA upload', async () => {
      await run('files', 'createFile', {
        target,
        path: policyRoot,
        isDir: true,
        content: '',
        ...intent(ABSENT_SHA256),
      });
      const upload = {
        target,
        path: policyRoot + '/test-trust.pem',
        localFile: config.pkiDir + '/bundle.pem',
      };
      const plan = await run('files', 'uploadFile', upload);
      assert.equal(plan.status, 'DRY_RUN');
      await run('files', 'uploadFile', { ...upload, ...intent(plan.expectedSha256) });
      const read = await run('files', 'readFile', { target, path: upload.path });
      assert.equal(read.content, policy.caBundle);
      return 'multipart bytes read back';
    });
    await check('inherited WAF handler blocks mTLS composition', async () => {
      await writeFile(policyRoot + '/test-waf.lua', 'return ngx.exit(403)\n');
      const waf = originalGlobal.replace(
        'http {',
        'http { access_by_lua_file /www/sites/' + target.alias + '/mtls/test-waf.lua;',
      );
      // Trusted fault fixture only: deliberately install an existing handler through the real
      // server API. Ordinary CLI/SDK raw configuration actions must refuse introducing Lua.
      const fixtureWrite = (content) =>
        client.request({
          method: 'POST',
          path: '/api/v2/openresty/file',
          operateNode: 'local',
          body: { content, backup: true },
        });
      await assert.rejects(restoreGlobal(waf), { code: 'FORBIDDEN' });
      try {
        await fixtureWrite(waf);
        const plan = await run('mtls', 'planMtlsPolicy', { target, policy, probeRuntime: true });
        assert.equal(plan.runtime.code, 'CONFLICT');
        await assert.rejects(
          run('mtls', 'applyMtlsPolicy', { plan, ...intent(plan.expectedSha256) }),
          { code: 'CONFLICT' },
        );
      } finally {
        await fixtureWrite(originalGlobal);
      }
      return 'CONFLICT without include switch';
    });
    await check('invalid CA, Lua, cross-site path rejected without changes', async () => {
      await assert.rejects(
        run('mtls', 'planMtlsPolicy', {
          target,
          policy: { ...policy, caBundle: await readFile(config.pkiDir + '/allowed.pem', 'utf8') },
        }),
        { code: 'INVALID_INPUT' },
      );
      await assert.rejects(
        run('files', 'writeFile', {
          target,
          path: policyRoot + '/bad.lua',
          content: 'os.execute("id")',
        }),
        { code: 'INVALID_INPUT' },
      );
      await assert.rejects(
        run('files', 'writeFile', {
          target,
          path: policyRoot + '/../escape.pem',
          content: policy.caBundle,
        }),
        { code: 'INVALID_INPUT' },
      );
      assert.equal(await site(), originalSite);
      return 'rejected before writes';
    });
    await check(
      'unknown committed write is reconciled after dropped network response',
      async () => {
        let writes = 0;
        const proxy = http.createServer((req, res) => {
          const upstream = http.request(
            new URL(req.url, target.baseUrl),
            { method: req.method, headers: req.headers },
            (out) => {
              if (req.url.startsWith('/api/v2/websites/nginx/update')) {
                writes++;
                out.resume();
                out.on('end', () => req.socket.destroy());
              } else {
                res.writeHead(out.statusCode, out.headers);
                out.pipe(res);
              }
            },
          );
          req.pipe(upstream);
          upstream.on('error', () => res.destroy());
        });
        await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
        try {
          const origin = 'http://127.0.0.1:' + proxy.address().port;
          const shim = new OnePanelClient({ ...credentials, baseUrl: origin });
          const changed = originalSite + '# disconnect after commit\n';
          const out = await getModule('websites').actions.updateWebsiteRawConfig.execute(shim, {
            target: { ...target, baseUrl: origin },
            content: changed,
            ...intent(sha256(await site())),
          });
          assert.equal(out.data.status, 'APPLIED');
          assert.equal(writes, 1);
          await restoreSite();
          return { writes };
        } finally {
          await new Promise((r) => proxy.close(r));
        }
      },
    );
    await check('mTLS on: four-case TLS1.3 and HTTP request matrix', async () => {
      const plan = await run('mtls', 'planMtlsPolicy', { target, policy, probeRuntime: true });
      assert.equal(plan.runtime.status, 'PASS');
      assert.equal(
        (await run('mtls', 'applyMtlsPolicy', { plan, ...intent(plan.expectedSha256) })).status,
        'APPLIED',
      );
      const cases = [
        {
          name: 'trusted-allowed',
          expected: 'allow',
          certFile: config.pkiDir + '/allowed-chain.pem',
          keyFile: config.pkiDir + '/allowed.key',
        },
        { name: 'no-certificate', expected: 'deny' },
        {
          name: 'untrusted-ca',
          expected: 'deny',
          certFile: config.pkiDir + '/untrusted.pem',
          keyFile: config.pkiDir + '/untrusted.key',
        },
        {
          name: 'trusted-denied',
          expected: 'deny',
          certFile: config.pkiDir + '/denied-chain.pem',
          keyFile: config.pkiDir + '/denied.key',
        },
      ];
      const matrix = await run('mtls', 'testMtlsPolicy', {
        target,
        authorizedTest: true,
        url: config.url,
        connectAddress: config.connectAddress,
        serverCaFile: config.pkiDir + '/root.pem',
        cases,
      });
      assert.equal(matrix.status, 'PASS');
      return matrix.evidence;
    });
    await check('mTLS TLS1.2, HTTP2 and existing reverse-proxy route', async () => {
      const tls12 = await request({ maxVersion: 'TLSv1.2' });
      assert.equal(tls12.status, 200);
      assert.equal(tls12.tls, 'TLSv1.2');
      const h2 = await request({ httpVersion: '2' });
      assert.equal(h2.status, 200);
      assert.equal(h2.alpn, 'h2');
      assert.equal((await waitStatus(200, { path: '/proxy' })).status, 200);
      return { tls12, h2 };
    });
    await check('optional mode still rejects missing certificate in Lua', async () => {
      const plan = await run('mtls', 'planMtlsPolicy', {
        target,
        policy: { ...policy, verifyClient: 'optional' },
      });
      await run('mtls', 'applyMtlsPolicy', { plan, ...intent(plan.expectedSha256) });
      assert.equal((await waitStatus(403, { withCert: false })).status, 403);
      assert.equal((await waitStatus(200)).status, 200);
      return { noCertificate: 403, allowed: 200 };
    });
    await check('empty ACL denies otherwise trusted client', async () => {
      await run('mtls', 'updateCertificateFingerprintAllowlist', {
        target,
        fingerprints: [],
        ...intent(sha256(await site())),
      });
      assert.equal((await waitStatus(403)).status, 403);
      await run('mtls', 'updateCertificateFingerprintAllowlist', {
        target,
        fingerprints: [allowed],
        ...intent(sha256(await site())),
      });
      assert.equal((await waitStatus(200)).status, 200);
      return { empty: 403, restored: 200 };
    });
    await check('fingerprint rotation revokes the old leaf', async () => {
      await run('mtls', 'updateCertificateFingerprintAllowlist', {
        target,
        fingerprints: [denied],
        ...intent(sha256(await site())),
      });
      assert.equal((await waitStatus(403)).status, 403);
      await run('mtls', 'updateCertificateFingerprintAllowlist', {
        target,
        fingerprints: [allowed],
        ...intent(sha256(await site())),
      });
      assert.equal((await waitStatus(200)).status, 200);
      return { oldLeaf: 403, restored: 200 };
    });
    await check('multi-CA rotation reports fingerprints and reloads', async () => {
      const out = await run('mtls', 'updateTrustedCAs', {
        target,
        caBundle: policy.caBundle + (await readFile(config.pkiDir + '/rogue.pem', 'utf8')),
        ...intent(sha256(await site())),
      });
      assert.equal(out.afterFingerprints.length, 3);
      assert.equal((await waitStatus(200)).status, 200);
      return { before: out.beforeFingerprints.length, after: out.afterFingerprints.length };
    });
    await check('reviewed Lua template update is idempotent', async () => {
      const out = await run('mtls', 'updateLuaPolicy', {
        target,
        luaVersion: 'sha256-acl-v1',
        ...intent(sha256(await site())),
      });
      assert.equal(out.status, 'UNCHANGED');
      return out.status;
    });
    await check('Lua runtime exception fails closed and recovers after reload', async () => {
      const active = managedPath(await site());
      const activeHost = policyRoot + '/' + active.split('/').at(-1);
      const conf = await readFile(activeHost, 'utf8');
      const luaPath = /access_by_lua_file ([^;]+);/.exec(conf)[1];
      const luaHost = policyRoot + '/' + luaPath.split('/').at(-1);
      const originalLua = await readFile(luaHost, 'utf8');
      try {
        await writeFile(luaHost, 'error("isolated E2E fault injection")\n');
        await restoreSite((await site()) + '# force new workers\n');
        assert.equal((await waitStatus(500)).status, 500);
      } finally {
        await writeFile(luaHost, originalLua);
        await restoreSite((await site()) + '# recover new workers\n');
      }
      assert.equal((await waitStatus(200)).status, 200);
      return { fault: 500, recovered: 200 };
    });
    await check('disable removes owned include and restores ordinary HTTPS', async () => {
      const preview = await run('mtls', 'disableMtlsPolicy', { target });
      assert.equal(preview.status, 'DRY_RUN');
      await run('mtls', 'disableMtlsPolicy', { target, ...intent(preview.expectedSha256) });
      assert.equal(managedPath(await site()), undefined);
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      return { noCertificateAfterDisable: 200 };
    });
  } catch (err) {
    primaryError = err;
  } finally {
    try {
      await restoreSite();
      await restoreGlobal();
      assert.equal(await site(), originalSite);
      assert.equal(await global(), originalGlobal);
      assert.equal((await waitStatus(200, { withCert: false })).status, 200);
      evidence.push({
        name: 'final restoration and service verification',
        status: 'PASS',
        detail: before,
      });
    } catch (err) {
      throw new AggregateError(
        [primaryError, err].filter(Boolean),
        'E2E recovery failed; keep isolated environment for inspection',
      );
    }
  }
  const report = {
    status: primaryError ? 'FAIL' : 'PASS',
    at: new Date().toISOString(),
    environment: {
      panelVersion: (
        await exec('docker', ['exec', config.names.panel, '/usr/local/bin/1panel-core', 'version'])
      ).stdout.trim(),
      openrestyImage: config.image,
      luaCommit: config.luaCommit,
    },
    passed: evidence.length,
    failed: primaryError ? 1 : 0,
    evidence,
  };
  if (process.env.ONEPANEL_E2E_REPORT)
    await writeFile(process.env.ONEPANEL_E2E_REPORT, JSON.stringify(report, null, 2) + '\n', {
      mode: 0o600,
    });
  if (primaryError) throw primaryError;
  return report;
}
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const input = process.env.ONEPANEL_E2E_CONFIG;
  if (!input || process.env.ONEPANEL_E2E_APPLY !== 'true') {
    console.log(
      'E2E: NOT RUN (no explicitly authorized isolated config; set ONEPANEL_E2E_CONFIG and ONEPANEL_E2E_APPLY=true, or run npm run test:e2e:local)',
    );
  } else {
    try {
      const report = await runMatrix(JSON.parse(await readFile(input, 'utf8')));
      console.log(
        JSON.stringify({ status: report.status, passed: report.passed, failed: report.failed }),
      );
    } catch (err) {
      console.error(err.code || err.name, err.message, err.details || '');
      process.exitCode = 1;
    }
  }
}
