# Verified upstream contract

Skill baseline: [`1Panel-dev/1Panel-skills@33d74c9502e7ae509d8c1d7f3f1c78fd13ac23c6`](https://github.com/1Panel-dev/1Panel-skills/tree/33d74c9502e7ae509d8c1d7f3f1c78fd13ac23c6), official `main`, fetched 2026-11-08. GPL-3.0 retained. `dist/scripts/**` is tracked upstream and regenerated here.

API source baseline: [`1Panel-dev/1Panel@fa125e4386789a31e0521a85cd09e82cd3152e5d`](https://github.com/1Panel-dev/1Panel/tree/fa125e4386789a31e0521a85cd09e82cd3152e5d), official `dev-v2`, fetched 2026-11-08. Real isolated tests used installed 1Panel `v2.4.2 stable`, so source and deployed versions are recorded separately.

Paths below are relative to that main-project commit. Consult these files when upgrading; route names alone are not a DTO contract.

| Endpoint | Request and behavior | Source |
| --- | --- | --- |
| `GET /websites/:id/config/openresty` | Full `FileInfo`, including path/content/size. | `agent/router/ro_website.go`, `agent/app/service/website.go:GetWebsiteNginxConfig` |
| `POST /websites/nginx/update` | `{id,content}` full file; check/reload and single-file restore on error. | `agent/app/dto/request/website.go:WebsiteNginxUpdate`, `service/website.go:UpdateNginxConfigFile` |
| `POST /websites/config` | `{websiteId,scope}`. | `request/nginx.go:NginxScopeReq`, `service/website.go:GetNginxConfigByScope` |
| `POST /websites/config/update` | `{websiteId,scope,operate,params}`; supported key map, string map params. This SDK supports `index`, `limit-conn`, `http-per`; SSL/private-key settings excluded. Digest here covers canonical scope values, not raw file bytes. | `request/nginx.go:NginxConfigUpdate`, `dto/nginx.go:ScopeKeyMap`, `service/website_utils.go:getNginxParams` |
| `POST /websites/proxies` | **`{id}`**, not `websiteID`; returns existing proxy name/filePath/content. | `request/website.go:WebsiteProxyReq`, `service/website_proxy.go:GetProxies` |
| `POST /websites/proxies/file` | `{websiteID,name,content}`; existing active `.conf`, name excludes extension. Service may also reformat the parent site config while reloading. | `request/nginx.go:NginxProxyUpdate`, `service/website_proxy.go:UpdateProxyFile` |
| `GET /openresty` | `{content}` global nginx.conf. | `agent/router/ro_nginx.go`, `service/nginx.go:GetNginxConfig` |
| `POST /openresty/file` | `{content,backup}`; backup + check/reload, may restart a stopped install. SDK requires backup and global confirmation. | `request/nginx.go:NginxConfigFileUpdate`, `service/nginx.go:UpdateConfigFile` |
| `GET /openresty/status` | Stub-status counters, not authentication evidence. | `service/nginx.go:GetStatus` |
| `POST /files/search` | Directory metadata and children require **`expand:true`**; parent-by-parent checks detect symlinks. Empty `items` may be null. | `utils/files/fileinfo.go:handleExpansion/listChildren`, `service/file.go:GetFileList` |
| `POST /files/content` | `{path,isDetail:false}` for bytes. `isDetail:true` returns metadata with empty content. SDK checks size to reject partial/transcoded reads. | `request/file.go:FileContentReq`, `service/file.go:GetContent`, `utils/files/fileinfo.go:handleExpansion` |
| `POST /files/save` | `{path,content}`; saves an existing file and records history. Does not reload consumers. | `request/file.go:FileEdit`, `service/file.go:SaveContent` |
| `POST /files` | `{path,isDir,mode,isLink:false,isSymlink:false,sub:false,content:""}`. **Content field is ignored**; save after file creation. | `request/file.go:FileCreate`, `service/file.go:Create` |
| `POST /files/upload` | multipart fields `path` (destination directory), `overwrite` (boolean string), `file` (filename + bytes). Default server overwrite is true; SDK sets it explicitly. | `agent/app/api/v2/file.go:UploadFiles` |
| `POST /files/del` | `{path,isDir,forceDelete}`. Used only to compensate files created by a failed managed operation, or to remove a verified empty directory. | `request/file.go:FileDelete`, `service/file.go:Delete` |

All routes above use `/api/v2`. `operateNode` is a query parameter; explicit `local` routes to the local agent. See `core/init/router/proxy.go`, `core/app/auth/api_auth.go` and `core/app/auth/api_key.go` for API-key enablement, IP/time windows, independent key selection and grants. Source timestamps accept configured validity plus a 60-second future-skew tolerance; the client generates fresh timestamps, does not compensate by weakening checks, and reports observable server clock skew on API rejection.

Signing: MD5 = `hex(md5('1panel' + key + timestamp))`; HMAC = `hex(HMAC-SHA256(key, '1panel:' + timestamp))`. Use `1Panel-Timestamp`, `1Panel-Token`, explicit `1Panel-Signature-Version`, and optional `1Panel-Key-ID`. No silent downgrade. See the [official API manual](https://1panel-dev.github.io/docs/v2/dev_manual/api_manual/) and `core/app/auth/api_auth.go`.

The API can return HTTP 200 with `{code:500,message:...}`. The shared client checks both transport and business status. Source `agent/app/service/nginx_utils.go:nginxCheckAndReload` runs the check and reload, restoring a single file on failure. There is no standalone `/openresty/test` or `/openresty/reload` route and no multi-file atomic transaction.

Lua dependency tested: [`fffonion/lua-resty-openssl@4ebee84ec3d829ef610005db1978ae591ed77a31`](https://github.com/fffonion/lua-resty-openssl/tree/4ebee84ec3d829ef610005db1978ae591ed77a31) (tag `1.9.0`). DER export is **`x509:tostring("DER")`**. The standard tested 1Panel OpenResty image did not contain this package. It was installed only into disposable test containers; the skill does not silently modify existing installations.

## Keeping the fork maintainable

```bash
git remote -v
git fetch upstream main
git switch main
git merge --ff-only upstream/main
git switch feat/openresty-security-management
git rebase main
npm ci
npm run typecheck
npm run build
npm test
npm run test:e2e:local
```

Resolve any changed DTO, mount, signing or reload behavior using the new upstream source, then update this provenance and the acceptance report. Review generated `dist/` together with TypeScript. Never push a feature PR to the official repository without the user's instruction; this change targets the personal fork's `main`.
