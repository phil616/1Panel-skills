import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
export function makePki() {
  const dir = mkdtempSync(join(tmpdir(), 'onepanel-test-pki-'));
  const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  const put = (file, text) => writeFileSync(join(dir, file), text, { mode: 0o600 });
  for (const name of ['root', 'rogue'])
    run(
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      `${name}.key`,
      '-out',
      `${name}.pem`,
      '-subj',
      `/CN=1panel-test-${name}`,
      '-days',
      '30',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    );
  put(
    'intermediate.ext',
    'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n',
  );
  put(
    'client.ext',
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n',
  );
  put(
    'server.ext',
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:example.com,DNS:localhost\n',
  );
  for (const [name, issuer, ext, days] of [
    ['intermediate', 'root', 'intermediate', '20'],
    ['subca', 'intermediate', 'intermediate', '5'],
    ['deep-leaf', 'subca', 'client', '3'],
    ['allowed', 'intermediate', 'client', '10'],
    ['denied', 'intermediate', 'client', '10'],
    ['untrusted', 'rogue', 'client', '10'],
    ['server', 'root', 'server', '10'],
    ['expired', 'root', 'intermediate', '0'],
  ]) {
    run(
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      `${name}.key`,
      '-out',
      `${name}.csr`,
      '-subj',
      `/CN=${name === 'server' ? 'example.com' : name}`,
    );
    run(
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      `${issuer}.pem`,
      '-CAkey',
      `${issuer}.key`,
      '-CAcreateserial',
      '-out',
      `${name}.pem`,
      '-days',
      days,
      '-extfile',
      `${ext}.ext`,
    );
  }
  for (const name of ['allowed', 'denied'])
    put(
      `${name}-chain.pem`,
      readFileSync(join(dir, `${name}.pem`), 'utf8') +
        readFileSync(join(dir, 'intermediate.pem'), 'utf8'),
    );
  put(
    'bundle.pem',
    readFileSync(join(dir, 'intermediate.pem'), 'utf8') +
      readFileSync(join(dir, 'root.pem'), 'utf8'),
  );
  put(
    'deep-issuers.pem',
    readFileSync(join(dir, 'subca.pem'), 'utf8') +
      readFileSync(join(dir, 'intermediate.pem'), 'utf8'),
  );
  return { dir, read: (name) => readFileSync(join(dir, name), 'utf8'), run };
}
