import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, mkdir, cp, readFile, rm, access, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OnePanelClient } from '../../dist/scripts/client.js';
import { makePki } from '../fixtures/make-pki.mjs';
const exec = promisify(execFile);
const docker = async (...args) =>
  (await exec('docker', args, { maxBuffer: 4 * 1024 * 1024, timeout: 120000 })).stdout;
const image = process.env.ONEPANEL_E2E_IMAGE || '1panel/openresty:1.27.1.2-5-1-focal';
const luaCommit = '4ebee84ec3d829ef610005db1978ae591ed77a31';
// This creates new containers, network and a new DB. No existing panel DB or config is read/copied.
export async function setupLocal() {
  const root = await mkdtemp(path.join(tmpdir(), 'onepanel-skills-e2e-')),
    id = path.basename(root).slice(-6).toLowerCase();
  const names = {
    panel: `onepanel-skills-e2e-${id}-panel`,
    frontend: `onepanel-skills-e2e-${id}-openresty`,
    backend: `onepanel-skills-e2e-${id}-backend`,
    cli: `onepanel-skills-e2e-${id}-cli`,
    network: `onepanel-skills-e2e-${id}-net`,
  };
  const created = [];
  const pki = makePki();
  let networkCreated = false;
  const cleanup = async () => {
    for (const name of [...created].reverse()) await docker('rm', '-f', name).catch(() => {});
    if (networkCreated) await docker('network', 'rm', names.network).catch(() => {});
    await rm(pki.dir, { recursive: true, force: true });
    // The panel creates root-owned state; helper touches only this unique disposable mount.
    await docker(
      'run',
      '--rm',
      '--entrypoint',
      '/bin/chown',
      '-v',
      root + ':/cleanup',
      image,
      '-R',
      `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
      '/cleanup',
    ).catch(() => {});
    await rm(root, { recursive: true, force: true });
  };
  try {
    for (const binary of ['1panel-core', '1panel-agent'])
      await access(path.join(process.env.ONEPANEL_E2E_BIN_DIR || '/usr/local/bin', binary));
    await docker('image', 'inspect', image);
    await writeFile(
      path.join(root, 'DISPOSABLE_TEST_ONLY'),
      'Created solely for 1Panel skill E2E\n',
      { mode: 0o600 },
    );
    const base = path.join(root, '1panel'),
      www = path.join(base, 'www'),
      install = path.join(base, 'apps/openresty/skill-e2e');
    for (const dir of [
      www + '/conf.d',
      www + '/sites/skill-e2e/ssl',
      www + '/sites/skill-e2e/proxy',
      install + '/conf',
      root + '/backend',
      root + '/journal',
    ])
      await mkdir(dir, { recursive: true, mode: 0o700 });
    for (const dir of [
      www,
      www + '/sites',
      www + '/sites/skill-e2e',
      www + '/sites/skill-e2e/ssl',
      www + '/sites/skill-e2e/proxy',
      www + '/conf.d',
    ])
      await chmod(dir, 0o755);
    await cp(pki.dir, root + '/pki', { recursive: true });
    for (const file of ['server.pem', 'server.key'])
      await cp(pki.dir + '/' + file, www + '/sites/skill-e2e/ssl/' + file);
    const site = `server {\n    listen 18443 ssl;\n    http2 on;\n    server_name example.com;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_certificate /www/sites/skill-e2e/ssl/server.pem;\n    ssl_certificate_key /www/sites/skill-e2e/ssl/server.key;\n    location / { proxy_pass http://${names.backend}:18080; }\n    include /www/sites/skill-e2e/proxy/*.conf;\n}\n`;
    await writeFile(www + '/conf.d/skill-e2e.conf', site);
    await writeFile(
      www + '/sites/skill-e2e/proxy/extra.conf',
      `location /proxy { proxy_pass http://${names.backend}:18080; }\n`,
    );
    await writeFile(
      install + '/conf/nginx.conf',
      'worker_processes 1;\nerror_log /dev/stderr notice;\npid /tmp/nginx.pid;\nevents { worker_connections 128; }\nhttp { access_log /dev/stdout; include /www/conf.d/*.conf; }\n',
    );
    await writeFile(
      root + '/backend/nginx.conf',
      'events {}\nhttp { server { listen 18080; location / { return 200 "test-backend-ok\\n"; } } }\n',
    );
    await writeFile(
      root + '/1pctl',
      `BASE_DIR=${root}\nORIGINAL_PORT=15999\nORIGINAL_VERSION=v2.4.2\nORIGINAL_ENTRANCE=skill-e2e\nORIGINAL_USERNAME=skill-e2e\nORIGINAL_PASSWORD=disposable-test-only\nLANGUAGE=en\nPANEL_EDITION=cn\n`,
    );
    await docker('network', 'create', names.network);
    networkCreated = true;
    async function run(name, args) {
      await docker(
        'run',
        '-d',
        '--name',
        name,
        '--label',
        'onepanel-skills.e2e=disposable',
        '--stop-timeout',
        '2',
        ...args,
      );
      created.push(name);
    }
    await run(names.backend, [
      '--network',
      names.network,
      '-v',
      root + '/backend/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro',
      image,
    ]);
    await run(names.frontend, [
      '--network',
      names.network,
      '-p',
      '127.0.0.1::18443',
      '-v',
      www + ':/www',
      '-v',
      install + '/conf/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf',
      image,
    ]);
    await run(names.panel, [
      '-p',
      '127.0.0.1::15999',
      '-v',
      root + ':' + root,
      '-v',
      root + '/1pctl:/usr/local/bin/1pctl:ro',
      ...['1panel-core', '1panel-agent'].flatMap((bin) => [
        '-v',
        path.join(process.env.ONEPANEL_E2E_BIN_DIR || '/usr/local/bin', bin) +
          ':/usr/local/bin/' +
          bin +
          ':ro',
      ]),
      '-v',
      '/var/run/docker.sock:/var/run/docker.sock',
      '--entrypoint',
      '/bin/sh',
      image,
      '-c',
      '/usr/local/bin/1panel-core > /tmp/core.log 2>&1 & core_pid=$!; while [ ! -f /etc/1panel/.1panel ]; do sleep 0.2; done; /usr/local/bin/1panel-agent > /tmp/agent.log 2>&1 & wait "$core_pid"',
    ]);
    let ready = false;
    for (let n = 0; n < 150; n++) {
      try {
        await docker('exec', names.panel, 'test', '-S', '/etc/1panel/agent.sock');
        ready = true;
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    if (!ready)
      throw new Error('Fresh 1Panel initialization timed out; inspect temporary container logs');
    await docker('stop', names.panel);
    await docker(
      'run',
      '--rm',
      '--entrypoint',
      '/bin/chown',
      '-v',
      root + ':/seed',
      image,
      '-R',
      `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`,
      '/seed',
    );
    await exec('python3', [
      fileURLToPath(new URL('seed.py', import.meta.url)),
      root,
      names.frontend,
      names.backend,
    ]);
    const cliImage = 'docker:28.5.2-cli';
    try {
      await docker('image', 'inspect', cliImage);
    } catch {
      await docker('pull', cliImage);
    }
    await docker('create', '--name', names.cli, '--entrypoint', '/bin/true', cliImage);
    created.push(names.cli);
    await docker('cp', names.cli + ':/usr/local/bin/docker', root + '/docker');
    await docker('cp', root + '/docker', names.panel + ':/usr/local/bin/docker');
    // Pin and validate the dependency commit rather than downloading a moving branch.
    await exec(
      'git',
      [
        'clone',
        '--depth',
        '1',
        '--branch',
        '1.9.0',
        'https://github.com/fffonion/lua-resty-openssl.git',
        root + '/lua-resty-openssl',
      ],
      { timeout: 120000 },
    );
    if (
      (
        await exec('git', ['-C', root + '/lua-resty-openssl', 'rev-parse', 'HEAD'])
      ).stdout.trim() !== luaCommit
    )
      throw new Error('Lua dependency tag changed');
    await docker(
      'cp',
      root + '/lua-resty-openssl/lib/resty/openssl',
      names.frontend + ':/usr/local/openresty/lualib/resty/openssl',
    );
    await docker(
      'cp',
      root + '/lua-resty-openssl/lib/resty/openssl.lua',
      names.frontend + ':/usr/local/openresty/lualib/resty/openssl.lua',
    );
    await docker('start', names.panel);
    const panel = JSON.parse(await docker('inspect', names.panel))[0],
      front = JSON.parse(await docker('inspect', names.frontend))[0];
    const port = panel.NetworkSettings.Ports['15999/tcp'][0].HostPort,
      tlsPort = front.NetworkSettings.Ports['18443/tcp'][0].HostPort;
    const target = {
      baseUrl: 'http://127.0.0.1:' + port,
      websiteId: 1,
      alias: 'skill-e2e',
      operateNode: 'local',
      instance: names.frontend,
    };
    const config = {
      isolated: true,
      target,
      clientFile: root + '/client.json',
      pkiDir: root + '/pki',
      url: 'https://example.com:' + tlsPort + '/',
      connectAddress: '127.0.0.1',
      journalDir: root + '/journal',
      names,
      luaCommit,
      image,
    };
    const auth = JSON.parse(await readFile(root + '/client.json', 'utf8'));
    const readyClient = new OnePanelClient({
      ...auth,
      baseUrl: target.baseUrl,
      timeoutMs: 1000,
      readRetries: 0,
    });
    let apiReady = false;
    for (let n = 0; n < 100; n++) {
      try {
        await readyClient.request({
          method: 'GET',
          path: '/api/v2/websites/1',
          operateNode: 'local',
        });
        apiReady = true;
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    if (!apiReady) throw new Error('Fresh isolated panel API did not become ready');
    await writeFile(root + '/e2e.json', JSON.stringify(config, null, 2), { mode: 0o600 });
    return { config, root, cleanup };
  } catch (err) {
    await cleanup();
    throw err;
  }
}
