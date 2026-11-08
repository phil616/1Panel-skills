import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { safeWrite, sha256, ABSENT_SHA256 } from '../dist/scripts/security/change-plan.js';
import { controlledPath } from '../dist/scripts/security/path-policy.js';
import {
  parseCABundle,
  normalizeFingerprints,
  certificateFingerprint,
} from '../dist/scripts/security/certificates.js';
import { buildLuaPolicy, validateManagedLua } from '../dist/scripts/security/mtls-policy.js';
import {
  parseNginx,
  managedSiteConfig,
  removeManagedInclude,
} from '../dist/scripts/security/nginx-config.js';
import { PanelError } from '../dist/scripts/security/errors.js';
import { redact } from '../dist/scripts/security/redaction.js';
import { makePki } from './fixtures/make-pki.mjs';
const state = mkdtempSync(join(tmpdir(), 'onepanel-unit-state-'));
process.env.ONEPANEL_STATE_DIR = state;
const pki = makePki();
after(() => {
  rmSync(state, { recursive: true, force: true });
  rmSync(pki.dir, { recursive: true, force: true });
});
const server =
  'server {\n listen 443 ssl;\n ssl_certificate /test/server.pem;\n ssl_certificate_key /test/server.key;\n location / { proxy_pass http://127.0.0.1:8080; }\n}\n';
function memory(value = 'before') {
  let content = value,
    writes = 0,
    reads = 0;
  return {
    resource: {
      id: 'test',
      target: { websiteId: 1 },
      read: async () => {
        reads++;
        return content;
      },
      write: async (v) => {
        writes++;
        content = v;
      },
    },
    get content() {
      return content;
    },
    get writes() {
      return writes;
    },
    get reads() {
      return reads;
    },
  };
}
test('dry-run does not write or persist a backup', async () => {
  const m = memory();
  const out = await safeWrite(m.resource, 'after');
  assert.equal(out.status, 'DRY_RUN');
  assert.equal(m.writes, 0);
  assert.equal(out.expectedSha256, sha256('before'));
});
test('apply needs boolean intent, confirmation and digest', async () => {
  for (const intent of [
    { apply: 'yes' },
    { apply: true },
    { apply: true, confirm: true },
    { apply: true, confirm: true, expectedSha256: 'x' },
  ])
    await assert.rejects(safeWrite(memory().resource, 'after', intent), { code: 'INVALID_INPUT' });
});
test('applies, stores 0600 backup and content-free audit; replay is idempotent', async () => {
  const m = memory();
  const intent = { apply: true, confirm: true, expectedSha256: sha256('before') };
  const out = await safeWrite(m.resource, 'after', intent);
  assert.equal(out.status, 'APPLIED');
  assert.equal(m.content, 'after');
  assert.equal(statSync(out.backupPath).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(out.backupPath)).content, 'before');
  assert.equal(JSON.parse(readFileSync(out.backupPath + '.audit.json')).result, 'APPLIED');
  assert.equal((await safeWrite(m.resource, 'after', intent)).status, 'UNCHANGED');
  assert.equal(m.writes, 1);
});
test('digest conflict and concurrent second read refuse writes', async () => {
  const m = memory();
  await assert.rejects(
    safeWrite(m.resource, 'after', { apply: true, confirm: true, expectedSha256: sha256('stale') }),
    { code: 'CONFLICT' },
  );
  let n = 0;
  const r = { ...m.resource, read: async () => (++n === 1 ? 'before' : 'edited') };
  await assert.rejects(
    safeWrite(r, 'after', { apply: true, confirm: true, expectedSha256: sha256('before') }),
    { code: 'CONFLICT' },
  );
  assert.equal(m.writes, 0);
});
test('ambiguous committed network write is reread rather than retried', async () => {
  const m = memory();
  const original = m.resource.write;
  m.resource.write = async (v) => {
    await original(v);
    throw new PanelError('NETWORK', 'disconnect');
  };
  assert.equal(
    (
      await safeWrite(m.resource, 'after', {
        apply: true,
        confirm: true,
        expectedSha256: sha256('before'),
      })
    ).status,
    'APPLIED',
  );
  assert.equal(m.writes, 1);
});
test('failed semantic verification compensates to original bytes', async () => {
  const m = memory();
  m.resource.verify = async (v) => {
    if (v === 'after') throw new PanelError('VERIFY_FAILED', 'probe failed');
  };
  await assert.rejects(
    safeWrite(m.resource, 'after', {
      apply: true,
      confirm: true,
      expectedSha256: sha256('before'),
    }),
    (e) => e.code === 'VERIFY_FAILED' && e.details.audit.result === 'ROLLED_BACK',
  );
  assert.equal(m.content, 'before');
  assert.equal(m.writes, 2);
});
test('rollback failure is explicit and preserves backup location', async () => {
  const m = memory();
  const write = m.resource.write;
  m.resource.write = async (v) => {
    if (v === 'before') throw new PanelError('RELOAD_FAILED', 'rollback failure');
    await write(v);
  };
  m.resource.verify = async () => {
    throw new Error('failure');
  };
  await assert.rejects(
    safeWrite(m.resource, 'after', {
      apply: true,
      confirm: true,
      expectedSha256: sha256('before'),
    }),
    (e) => e.code === 'ROLLBACK_FAILED' && !!e.details.backupPath,
  );
});
test('unexpected concurrent content is never overwritten by recovery', async () => {
  let value = 'before',
    writes = 0;
  const r = {
    id: 'conflict',
    target: {},
    read: async () => value,
    write: async () => {
      writes++;
      value = 'third-party';
    },
  };
  await assert.rejects(
    safeWrite(r, 'after', { apply: true, confirm: true, expectedSha256: sha256('before') }),
    { code: 'ROLLBACK_FAILED' },
  );
  assert.equal(value, 'third-party');
  assert.equal(writes, 1);
});
test('absent resource has distinct digest from an empty file', () =>
  assert.notEqual(ABSENT_SHA256, sha256('')));
for (const candidate of [
  '/www/sites/site/mtls/../escape.pem',
  '/www/sites/other/mtls/a.pem',
  '/etc/passwd',
  '/www/sites/site/mtls/a.key',
  '/www/sites/site/mtls/a\\b.pem',
  '/www/sites/site/mtls/%2e%2e.pem',
  '/www/sites/site/mtls/nested/a.pem',
  '/www/sites/site/mtls/.hidden.pem',
])
  test('rejects unsafe path ' + candidate, () =>
    assert.throws(() => controlledPath('/www/sites/site/mtls', candidate), {
      code: 'INVALID_INPUT',
    }),
  );
test('fingerprints normalize strict colon form, uppercase and deduplicate', () => {
  const h = 'ab'.repeat(32);
  assert.deepEqual(normalizeFingerprints([h, h.toUpperCase(), h.match(/../g).join(':')]), [
    h.toUpperCase(),
  ]);
  for (const h of ['a:b', 'ab:'.repeat(32), 'ab'.repeat(20), '', '0g'.repeat(32)])
    assert.throws(() => normalizeFingerprints([h]));
});
test('DER SHA-256 agrees with independent OpenSSL digest', () => {
  const der = execFileSync('openssl', [
    'x509',
    '-in',
    'assets/fingerprint-vector.pem',
    '-outform',
    'DER',
  ]);
  const answer = execFileSync('openssl', ['dgst', '-sha256'], { input: der, encoding: 'utf8' })
    .trim()
    .split('= ')[1]
    .toUpperCase();
  assert.equal(
    certificateFingerprint(readFileSync('assets/fingerprint-vector.pem', 'utf8')),
    answer,
  );
});
test('CA bundle parses, verifies chain signatures, sorts and deduplicates', () => {
  const result = parseCABundle(pki.read('bundle.pem') + pki.read('root.pem'));
  assert.equal(result.fingerprints.length, 2);
  assert.equal(parseCABundle(result.bundle).bundle, result.bundle);
  assert.match(
    pki
      .run('verify', '-CAfile', 'root.pem', '-untrusted', 'intermediate.pem', 'allowed.pem')
      .toString(),
    /OK/,
  );
});
test('rejects invalid, leaf, private, expired and unrooted intermediate CA material', () => {
  for (const pem of [
    'garbage',
    pki.read('allowed.pem'),
    pki.read('root.key'),
    pki.read('expired.pem') + pki.read('root.pem'),
    pki.read('intermediate.pem'),
    pki.read('intermediate.pem') + pki.read('rogue.pem'),
  ])
    assert.throws(() => parseCABundle(pem));
});
test('multiple independent root CAs are supported', () =>
  assert.equal(parseCABundle(pki.read('root.pem') + pki.read('rogue.pem')).fingerprints.length, 2));
test('empty ACL is fail-closed, managed Lua cannot be replaced with arbitrary code', () => {
  const lua = buildLuaPolicy([]);
  assert.deepEqual(validateManagedLua(lua), []);
  assert.match(lua, /ssl_client_verify ~= "SUCCESS"/);
  assert.match(lua, /not ok or not authorized/);
  assert.match(lua, /allowed\[fingerprint\] == true/);
  assert.throws(() => validateManagedLua(lua + '\nos.execute("id")'));
  assert.doesNotMatch(lua, /ssl_client_fingerprint/);
});
test('Nginx tokenizer preserves quotes, comments, escapes, nested blocks and variables', () => {
  const config =
    '# { ignored\nserver { set $test "}quoted{"; location ~ "x{1,2}" { set $v ${host}; proxy_pass http://example.com; } }';
  const tree = parseNginx(config);
  assert.equal(tree[0].children[1].children[0].args[1], '${host}');
  assert.throws(() => parseNginx('server {'));
});
test('owned include round trip preserves TLS and proxy bytes exactly', () => {
  const next = managedSiteConfig(server, '/www/sites/site/mtls/policy-' + sha256('test') + '.conf');
  assert.equal(removeManagedInclude(next), server);
  assert.equal(
    managedSiteConfig(next, '/www/sites/site/mtls/policy-' + sha256('test') + '.conf'),
    next,
  );
});
for (const fragment of [
  'access_by_lua_file /waf.lua;',
  'location /a { access_by_lua_block { ngx.exit(403); } }',
  'ssl_verify_client on;',
  'return 200;',
  'satisfy any;',
  'listen 443 quic;',
  'listen 80;',
])
  test('mTLS refuses conflicting or bypassing directive ' + fragment, () =>
    assert.throws(() =>
      managedSiteConfig(
        server.replace(' location /', ` ${fragment}\n location /`),
        '/www/sites/site/mtls/policy-' + sha256('x') + '.conf',
      ),
    ),
  );
test('managed marker with foreign directives is not deleted', () =>
  assert.throws(() =>
    removeManagedInclude(
      'server { # BEGIN 1panel-skills mtls v1\n deny all;\n# END 1panel-skills mtls v1\n}',
    ),
  ));
test('redacts credentials, raw config and PEM without hiding operation result', () => {
  const value = redact({
    apiKey: 'secret',
    target: { instance: 'test' },
    caBundle: 'cert',
    siteContent: 'Authorization Bearer secret',
    status: 'APPLIED',
    message: 'token=secret',
    pem: pki.read('root.pem'),
  });
  assert.equal(value.status, 'APPLIED');
  assert.doesNotMatch(JSON.stringify(value), /secret|BEGIN CERTIFICATE/);
});

test('raw site snippets and maximum-size violations fail before target write', async () => {
  const { checkContent } = await import('../dist/scripts/security/discovery.js');
  assert.throws(() => checkContent('x'.repeat(1024 * 1024 + 1)), { code: 'INVALID_INPUT' });
  assert.throws(() => normalizeFingerprints(Array.from({ length: 513 }, () => 'AA'.repeat(32))), {
    code: 'INVALID_INPUT',
  });
});

test('CA pathLen=0 forbids an additional intermediate below it', () => {
  assert.throws(() => parseCABundle(pki.read('subca.pem') + pki.read('bundle.pem')), {
    code: 'INVALID_INPUT',
  });
  assert.throws(() =>
    pki.run('verify', '-CAfile', 'root.pem', '-untrusted', 'deep-issuers.pem', 'deep-leaf.pem'),
  );
});
