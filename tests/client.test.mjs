import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { readFileSync, rmSync } from 'node:fs';
import { OnePanelClient, signHeaders } from '../dist/scripts/client.js';
import { makePki } from './fixtures/make-pki.mjs';
async function serve(handler, options) {
  const server = options ? https.createServer(options, handler) : http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    baseUrl: `${options ? 'https' : 'http'}://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => server.close(r)),
  };
}
const reply = (res, code = 200, data = { code: 200, data: { ok: true } }) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
};
test('MD5 and HMAC match fixed independent Python/OpenSSL vectors', () => {
  assert.equal(signHeaders('test-key', '1700000000').hasOwnProperty('1Panel-Key-ID'), false);
  assert.equal(
    signHeaders('test-key', '1700000000')['1Panel-Token'],
    'f360f407f5ac39bdb7706111e1cc304f',
  );
  assert.equal(
    signHeaders('test-key', '1700000000', 'hmac-sha256')['1Panel-Token'],
    'cf0e65a8c596da92779958554b82306817e2dc5dbc208966fbc70da9d3dbbbba',
  );
  assert.throws(() => signHeaders('key', '1', 'invalid'));
});
test('UTF-8 JSON, CRLF content, node, HMAC and Key-ID serialize exactly', async () => {
  const seen = [];
  const server = await serve(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    seen.push({ url: req.url, headers: req.headers, body });
    reply(res);
  });
  try {
    const client = new OnePanelClient({
      baseUrl: server.baseUrl,
      apiKey: 'test-key',
      signatureVersion: 'hmac-sha256',
      keyId: 'test-key-id',
      now: () => 1700000000000,
    });
    await client.request({
      method: 'POST',
      path: '/api/v2/files/save',
      operateNode: 'node 中文',
      body: { path: '/www/test.pem', content: '中文\r\n"\\' },
    });
    assert.equal(seen[0].headers['1panel-timestamp'], '1700000000');
    assert.equal(seen[0].headers['1panel-signature-version'], 'hmac-sha256');
    assert.equal(seen[0].headers['1panel-key-id'], 'test-key-id');
    assert.equal(JSON.parse(seen[0].body).content, '中文\r\n"\\');
    assert.equal(Number(seen[0].headers['content-length']), Buffer.byteLength(seen[0].body));
    assert.equal(new URL(seen[0].url, server.baseUrl).searchParams.get('operateNode'), 'node 中文');
  } finally {
    await server.close();
  }
});
for (const [status, expected] of [
  [401, 'AUTH_FAILED'],
  [403, 'FORBIDDEN'],
  [404, 'NOT_FOUND'],
  [405, 'API_UNSUPPORTED'],
  [409, 'CONFLICT'],
  [500, 'API_ERROR'],
])
  test(`HTTP and HTTP-200 business ${status} classify as ${expected}`, async () => {
    for (const httpStatus of [status, 200]) {
      const server = await serve((req, res) =>
        reply(res, httpStatus, { code: status, message: 'API key=test-secret' }),
      );
      try {
        await assert.rejects(
          new OnePanelClient({ baseUrl: server.baseUrl, apiKey: 'test-secret' }).request({
            method: 'GET',
            path: '/api/v2/test',
          }),
          (e) => e.code === expected && !JSON.stringify(e).includes('test-secret'),
        );
      } finally {
        await server.close();
      }
    }
  });
test('syntax and reload errors are machine classified without leaking response body', async () => {
  for (const [message, code] of [
    ['nginx: [emerg] syntax failed', 'SYNTAX_FAILED'],
    ['nginx reload failed', 'RELOAD_FAILED'],
  ]) {
    const s = await serve((req, res) => reply(res, 200, { code: 500, message }));
    try {
      await assert.rejects(
        new OnePanelClient({ baseUrl: s.baseUrl, apiKey: 'test-key' }).request({
          method: 'POST',
          path: '/api/v2/test',
        }),
        { code },
      );
    } finally {
      await s.close();
    }
  }
});
test('malformed JSON rejects cleanly and successful text stays compatible', async () => {
  const s = await serve((req, res) => {
    res.setHeader('Content-Type', req.url.includes('json') ? 'application/json' : 'text/plain');
    res.end('not JSON');
  });
  try {
    const c = new OnePanelClient({ baseUrl: s.baseUrl, apiKey: 'test-key' });
    await assert.rejects(c.request({ method: 'GET', path: '/api/v2/json' }), { code: 'API_ERROR' });
    assert.equal((await c.request({ method: 'GET', path: '/api/v2/text' })).data, 'not JSON');
  } finally {
    await s.close();
  }
});
test('multipart has correct fields, one binary file and random boundary', async () => {
  const seen = [];
  const s = await serve(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    seen.push({ headers: req.headers, body: Buffer.concat(chunks) });
    reply(res);
  });
  try {
    const c = new OnePanelClient({ baseUrl: s.baseUrl, apiKey: 'test-key' });
    for (let n = 0; n < 2; n++)
      await c.request({
        method: 'POST',
        path: '/api/v2/files/upload',
        multipart: {
          fields: { path: '/www/sites/test/mtls', overwrite: 'true' },
          file: { name: 'ca.pem', content: Buffer.from('公开\r\n') },
        },
      });
    for (const r of seen) {
      const boundary = r.headers['content-type'].split('boundary=')[1];
      assert.match(r.body.toString(), /name="file"; filename="ca.pem"/);
      assert.match(r.body.toString(), /name="overwrite"\r\n\r\ntrue/);
      assert.ok(r.body.toString().endsWith('--' + boundary + '--\r\n'));
      assert.equal(r.body.length, Number(r.headers['content-length']));
    }
    assert.notEqual(seen[0].headers['content-type'], seen[1].headers['content-type']);
    await assert.rejects(
      c.request({
        method: 'POST',
        path: '/api/v2/files/upload',
        multipart: { fields: {}, file: { name: '../key', content: Buffer.alloc(0) } },
      }),
      { code: 'INVALID_INPUT' },
    );
  } finally {
    await s.close();
  }
});
test('read network failure retries once; POST mutation and timeout never retry', async () => {
  let attempts = 0;
  const s = await serve((req, res) => {
    attempts++;
    req.socket.destroy();
  });
  try {
    const c = new OnePanelClient({ baseUrl: s.baseUrl, apiKey: 'test-key' });
    await assert.rejects(c.request({ method: 'GET', path: '/api/v2/test' }), { code: 'NETWORK' });
    assert.equal(attempts, 2);
    attempts = 0;
    await assert.rejects(c.request({ method: 'POST', path: '/api/v2/test' }), { code: 'NETWORK' });
    assert.equal(attempts, 1);
    attempts = 0;
    await assert.rejects(
      c.request({ method: 'POST', path: '/api/v2/files/content', readOnly: true }),
      { code: 'NETWORK' },
    );
    assert.equal(attempts, 2);
  } finally {
    await s.close();
  }
  const hanging = await serve((req, res) => {});
  try {
    await assert.rejects(
      new OnePanelClient({ baseUrl: hanging.baseUrl, apiKey: 'test-key', timeoutMs: 20 }).request({
        method: 'POST',
        path: '/api/v2/test',
      }),
      { code: 'TIMEOUT' },
    );
  } finally {
    await hanging.close();
  }
});
test('TLS verification is enabled by default and explicit opt-out remains compatible', async () => {
  const pki = makePki();
  const s = await serve((req, res) => reply(res), {
    key: pki.read('server.key'),
    cert: pki.read('server.pem'),
  });
  try {
    await assert.rejects(
      new OnePanelClient({ baseUrl: s.baseUrl, apiKey: 'test-key' }).request({
        method: 'GET',
        path: '/api/v2/test',
      }),
      { code: 'NETWORK' },
    );
    assert.equal(
      (
        await new OnePanelClient({
          baseUrl: s.baseUrl,
          apiKey: 'test-key',
          skipTlsVerify: true,
        }).request({ method: 'GET', path: '/api/v2/test' })
      ).status,
      200,
    );
  } finally {
    await s.close();
    rmSync(pki.dir, { recursive: true, force: true });
  }
});
test('rejects malformed targets and request escape before opening sockets', async () => {
  for (const baseUrl of [
    'file:///tmp/test',
    'http://user:pass@example.com',
    'http://example.com/sub',
  ])
    assert.throws(() => new OnePanelClient({ baseUrl, apiKey: 'k' }));
  const c = new OnePanelClient({ baseUrl: 'http://127.0.0.1', apiKey: 'k' });
  for (const path of ['//evil.com/api/v2/test', '/api/v2/../test', '/api/v2/test?x=y'])
    await assert.rejects(c.request({ method: 'GET', path }), { code: 'INVALID_INPUT' });
});
