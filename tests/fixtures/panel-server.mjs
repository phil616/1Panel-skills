import http from 'node:http';
import path from 'node:path';
import { OnePanelClient } from '../../dist/scripts/client.js';
export const originalSite =
  'server {\n listen 443 ssl;\n ssl_certificate /www/sites/test/ssl/fullchain.pem;\n ssl_certificate_key /www/sites/test/ssl/privkey.pem;\n location / { proxy_pass http://127.0.0.1:8080; }\n}\n';
export async function panelServer() {
  const records = [],
    files = new Map(),
    dirs = new Set([
      '/',
      '/opt',
      '/opt/1panel',
      '/opt/1panel/www',
      '/opt/1panel/www/sites',
      '/opt/1panel/www/sites/test',
      '/opt/1panel/www/sites/test/proxy',
      '/opt/1panel/www/conf.d',
      '/opt/1panel/apps',
      '/opt/1panel/apps/openresty',
      '/opt/1panel/apps/openresty/openresty',
      '/opt/1panel/apps/openresty/openresty/conf',
    ]);
  files.set('/opt/1panel/www/conf.d/test.conf', originalSite);
  files.set(
    '/opt/1panel/apps/openresty/openresty/conf/nginx.conf',
    'events {}\nhttp { include /www/conf.d/*.conf; }\n',
  );
  files.set(
    '/opt/1panel/www/sites/test/proxy/upstream.conf',
    'location /proxy { proxy_pass http://127.0.0.1:8080; }\n',
  );
  const state = {
    records,
    files,
    dirs,
    symlinks: new Set(),
    handler: undefined,
    siteReads: 0,
    sitePath: '/opt/1panel/www/sites/test',
    instance: '1Panel-test-openresty',
    reloads: 0,
    scope: { index: ['index.html'] },
  };
  const metadata = (p) => ({
    path: p,
    name: path.posix.basename(p),
    isDir: dirs.has(p),
    isSymlink: state.symlinks.has(p),
    linkPath: '',
    size: Buffer.byteLength(files.get(p) ?? ''),
    content: files.get(p) ?? '',
  });
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks),
      url = new URL(req.url, 'http://localhost');
    let body;
    try {
      body = raw.length && req.headers['content-type']?.includes('json') ? JSON.parse(raw) : {};
    } catch {
      res.writeHead(400);
      res.end();
      return;
    }
    const record = {
      method: req.method,
      path: url.pathname,
      node: url.searchParams.get('operateNode'),
      body,
      raw,
      headers: req.headers,
    };
    records.push(record);
    const send = (data = {}, status = 200, code = 200) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ code, data, message: code === 200 ? '' : 'test server error' }));
    };
    if (await state.handler?.(record, { req, res, send, state })) return;
    const endpoint = url.pathname;
    if (endpoint === '/api/v2/websites/7')
      return send({
        id: 7,
        alias: 'test',
        type: 'proxy',
        sitePath: state.sitePath,
        primaryDomain: 'example.com',
      });
    if (endpoint === '/api/v2/apps/installed/search')
      return send({
        items: [
          {
            id: 1,
            container: state.instance,
            appKey: 'openresty',
            path: '/opt/1panel/apps/openresty/openresty',
            status: 'Running',
            version: 'test',
          },
        ],
      });
    if (endpoint === '/api/v2/websites/7/config/openresty') {
      state.siteReads++;
      return send(metadata('/opt/1panel/www/conf.d/test.conf'));
    }
    if (endpoint === '/api/v2/files/search') {
      if (!dirs.has(body.path)) return send({}, 200, 404);
      const paths = [...dirs, ...files.keys()].filter(
        (p) =>
          p !== body.path &&
          path.posix.dirname(p) === body.path &&
          (!body.search || path.posix.basename(p).includes(body.search)),
      );
      return send({
        ...metadata(body.path),
        items: body.expand ? paths.map(metadata) : null,
        itemTotal: body.expand ? paths.length : 0,
      });
    }
    if (endpoint === '/api/v2/files/content')
      return files.has(body.path)
        ? send({ ...metadata(body.path), ...(body.isDetail ? { content: '' } : {}) })
        : send({}, 200, 404);
    if (endpoint === '/api/v2/files/save') {
      if (!files.has(body.path)) return send({}, 200, 404);
      files.set(body.path, body.content);
      return send();
    }
    if (endpoint === '/api/v2/files') {
      if (body.isDir) dirs.add(body.path);
      else files.set(body.path, '');
      return send();
    }
    if (endpoint === '/api/v2/files/del') {
      if (body.isDir) dirs.delete(body.path);
      else files.delete(body.path);
      return send();
    }
    if (endpoint === '/api/v2/files/upload') {
      const boundary = req.headers['content-type'].split('boundary=')[1];
      const parts = raw.toString().split('--' + boundary);
      const field = parts.find((p) => p.includes('name="path"'));
      const directory = field.split('\r\n\r\n')[1].replace(/\r\n$/, '');
      const file = parts.find((p) => p.includes('name="file"'));
      const filename = /filename="([^"]+)"/.exec(file)[1];
      const content = file.split('\r\n\r\n').slice(1).join('\r\n\r\n').replace(/\r\n$/, '');
      files.set(directory + '/' + filename, content);
      return send();
    }
    if (endpoint === '/api/v2/websites/nginx/update') {
      files.set('/opt/1panel/www/conf.d/test.conf', body.content);
      state.reloads++;
      return send();
    }
    if (endpoint === '/api/v2/openresty' && req.method === 'GET')
      return send({ content: files.get('/opt/1panel/apps/openresty/openresty/conf/nginx.conf') });
    if (endpoint === '/api/v2/openresty/file') {
      files.set('/opt/1panel/apps/openresty/openresty/conf/nginx.conf', body.content);
      state.reloads++;
      return send();
    }
    if (endpoint === '/api/v2/websites/proxies')
      return send([
        {
          name: 'upstream',
          enable: true,
          filePath: '/opt/1panel/www/sites/test/proxy/upstream.conf',
          content: files.get('/opt/1panel/www/sites/test/proxy/upstream.conf'),
        },
      ]);
    if (endpoint === '/api/v2/websites/proxies/file') {
      files.set('/opt/1panel/www/sites/test/proxy/' + body.name + '.conf', body.content);
      state.reloads++;
      return send();
    }
    if (endpoint === '/api/v2/websites/config')
      return send({
        params: Object.entries(state.scope).map(([name, params]) => ({ name, params })),
        enable: true,
      });
    if (endpoint === '/api/v2/websites/config/update') {
      if (body.operate === 'delete') state.scope = { index: [] };
      else
        for (const [key, value] of Object.entries(body.params))
          state.scope[key] = value.split(/\s+/);
      return send();
    }
    if (
      [
        '/api/v2/dashboard/current/node',
        '/api/v2/containers/search',
        '/api/v2/core/logs/operation/search',
        '/api/v2/cronjobs/search',
        '/api/v2/tasks/search',
        '/api/v2/core/nodes/all',
        '/api/v2/websites/list',
      ].includes(endpoint)
    )
      return send({ items: [], total: 0 });
    send({}, 404, 404);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const client = new OnePanelClient({ baseUrl, apiKey: 'mock-test-key', readRetries: 0 });
  return {
    ...state,
    state,
    client,
    target: {
      baseUrl,
      websiteId: 7,
      alias: 'test',
      operateNode: 'local',
      instance: state.instance,
    },
    close: () => new Promise((r) => server.close(r)),
  };
}
