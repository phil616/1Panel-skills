# OpenResty and mTLS operations

This fork extends the existing TypeScript/ESM modules and CLI. It does not change 1Panel itself. Node.js 18+ remains the runtime target. Read [upstream-api.md](upstream-api.md) for the source-pinned DTOs and [SECURITY.md](SECURITY.md) for boundaries and recovery.

## Environment and availability

Use a 1Panel API key authorized for the selected node/site. Configure `ONEPANEL_BASE_URL`, `ONEPANEL_API_KEY`; optional `ONEPANEL_SIGNATURE_VERSION=hmac-sha256`, `ONEPANEL_KEY_ID`, `ONEPANEL_TIMEOUT_MS`, `ONEPANEL_STATE_DIR`. The compatibility default is MD5. TLS verification remains enabled unless explicitly overridden.

P0 actions work through the selected node's API. High-level mTLS apply additionally requires a running local Docker container and a loopback panel origin. The probe proves `/www` maps to the API's actual website root, expands `nginx -T`, checks the chosen site is included, checks inherited handlers/bypasses, compiles Lua and verifies the leaf DER SHA-256 vector in `assets/fingerprint-vector.pem`.

The tested stock image `1panel/openresty:1.27.1.2-5-1-focal` lacks `lua-resty-openssl`. Prepare a reviewed persistent image/module installation before high-level use; do not assume installing into a running container survives replacement. The disposable E2E harness installs pinned `lua-resty-openssl` 1.9.0 commit `4ebee84ec3d829ef610005db1978ae591ed77a31` only in its test container. Missing modules block apply before staging files.

Supported sites: one existing HTTPS-only `server`, no HTTP listener, no QUIC/HTTP3, no existing mTLS/session-cache directives in that server, no other access phase Lua/WAF handler or early return/rewrite/satisfy-any bypass in expanded configuration. The runtime probe is conservative across all included sites. Existing 1Panel WAF commonly defines a global `access_by_lua_file`; it is a conflict. Do not disable WAF silently to make deployment pass. Arbitrary Lua and audit-only mode are not implemented.

## New actions

| Action | Input additions beyond target | Result |
| --- | --- | --- |
| `websites.updateWebsiteRawConfig` | `content`, write intent | Full site config; requires a server block, preserves supplied complete bytes. |
| `websites.getSiteNginxSettings` | `websiteId,scope,operateNode?` | Supported structured scope read. |
| `websites.updateSiteNginxSettings` | `scope,operate,params`, write intent | `index`, `limit-conn`, `http-per` only. Scope-value digest; repeated connection directives require raw config. |
| `websites.getProxyConfig` | `id,operateNode?` | Existing proxy files and content. |
| `websites.updateProxyRawConfig` | `name,content`, write intent | Existing active proxy name without `.conf`; no arbitrary file path or mTLS location directives. |
| `openresty.getGlobalConfig/getStatus` | `operateNode?` | Global bytes or stub-status counters. |
| `openresty.discoverCapabilities` | global target | Installed instance and readable config; write endpoints are source-verified, not probed. |
| `openresty.updateGlobalConfig` | `content,backup:true,confirmGlobal:true`, write intent | Full `events` + `http` configuration, protected backup and check/reload. |
| `files.readFile` | `path` | Complete bounded UTF-8 text in the selected site's policy directory. Stdout redacts content; use a private output file to inspect it. |
| `files.createFile` | `path,isDir?,content`, write intent | Directory or regular text file; no links. |
| `files.writeFile` | `path,content`, write intent | Policy file save/read-back; does not independently reload consumers. |
| `files.uploadFile` | `path,localFile`, write intent | Multipart public CA PEM upload; never private keys. |
| `mtls.inspectSiteMtls` | `probeRuntime?` | Config sources, directives, runtime/conflict status and risks. |
| `mtls.planMtlsPolicy` | `policy,probeRuntime?` | Complete review plan; no mutations. |
| `mtls.applyMtlsPolicy` | `plan`, write intent, Lua/non-atomic acknowledgments | Staged immutable artifacts, include switch, reload result and read-back. |
| `mtls.disableMtlsPolicy` | write intent | Removes exactly the owned comment/include range; keeps all versioned files. |
| `mtls.updateTrustedCAs` | `caBundle`, write intent and acknowledgments | Validated CA set rotation; before/after SHA-256 CA fingerprints. |
| `mtls.updateCertificateFingerprintAllowlist` | `fingerprints`, write intent and acknowledgments | Leaf DER SHA-256 ACL rotation; empty set denies all. |
| `mtls.updateLuaPolicy` | `luaVersion:"sha256-acl-v1",fingerprints?`, intent/acknowledgments | Only the reviewed template; arbitrary `content` rejected. |
| `mtls.testMtlsPolicy` | authorized test target/URL/matrix | Real TLS/HTTP evidence or `NOT RUN`; new connections, HTTP/1.1. |

Write intent is `{apply:true,confirm:true,expectedSha256:"<preview hash>"}`. Without `apply:true` mutations only read/plan. For absent files/directories use the preview's sentinel digest (distinct from an empty file). Multi-file policy apply and rotations additionally require `confirmLua:true,acknowledgeNonAtomic:true`. An apply can return `UNCHANGED` for the same desired bytes.

## Complete CLI example

All identifiers below are examples. Discover real site paths/instance/node using list/detail and capability reads; use only an authorized test site. The PEM and key paths below refer to generated **test** certificates. Configure API credentials privately before running.

```bash
node dist/scripts/cli.js modules
node dist/scripts/cli.js actions mtls
node dist/scripts/cli.js run websites getWebsiteConfig \
  --input-json '{"id":42,"type":"openresty","operateNode":"local"}' \
  --output-file /private/onepanel-example/site-original.json
```

Prepare `/private/onepanel-example/plan-input.json` with a public test CA bundle and a leaf fingerprint, using local Node rather than pasting PEM into shell arguments:

```js
// save as a local .mjs file; run with node
import { readFile, writeFile } from 'node:fs/promises';
import { X509Certificate, createHash } from 'node:crypto';
const leaf = new X509Certificate(await readFile('/private/test-pki/allowed.pem'));
const fingerprint = createHash('sha256').update(leaf.raw).digest('hex');
await writeFile('/private/onepanel-example/plan-input.json', JSON.stringify({
  target: {
    baseUrl: process.env.ONEPANEL_BASE_URL,
    websiteId: 42, alias: 'example.com', operateNode: 'local',
    instance: '1Panel-openresty-example'
  },
  policy: {
    caBundle: await readFile('/private/test-pki/bundle.pem', 'utf8'),
    fingerprints: [fingerprint], verifyClient: 'on', verifyDepth: 3, mode: 'enforce'
  },
  probeRuntime: true
}, null, 2), { mode: 0o600 });
```

Generate a complete plan. No file, upload, configuration or reload API is called by the preview:

```bash
node dist/scripts/cli.js run mtls inspectSiteMtls \
  --input-file /private/onepanel-example/inspect-input.json
node dist/scripts/cli.js run mtls planMtlsPolicy \
  --input-file /private/onepanel-example/plan-input.json \
  --output-file /private/onepanel-example/plan.json
```

`inspect-input.json` contains the same `target` plus `probeRuntime:true`. Review `plan.json` privately: `reviewDiff`, complete `siteContent`, all `artifacts[].content`, CA fingerprints, runtime status and baseline hashes. Stdout only shows a redacted summary. A plan file contains public certificate material and potentially confidential original config fragments; do not commit it.

Create the exact apply input after reviewing the plan:

```js
import { readFile, writeFile } from 'node:fs/promises';
const plan = JSON.parse(await readFile('/private/onepanel-example/plan.json', 'utf8'));
await writeFile('/private/onepanel-example/apply.json', JSON.stringify({
  plan, expectedSha256: plan.expectedSha256,
  apply: true, confirm: true, confirmLua: true, acknowledgeNonAtomic: true
}), { mode: 0o600 });
```

```bash
node dist/scripts/cli.js run mtls applyMtlsPolicy \
  --input-file /private/onepanel-example/apply.json
```

Apply revalidates/rebuilds the plan, checks live runtime dependencies and global baseline, stages content-addressed CA/Lua/config/manifest files, then updates the full site config with one owned include. If any stage fails it attempts compensation. The returned status proves only the reported API/disk/runtime checks. Verify actual requests separately after graceful workers settle.

The test input `/private/onepanel-example/test.json`:

```json
{
  "target": {"baseUrl":"http://127.0.0.1:9999","websiteId":42,"alias":"example.com","operateNode":"local","instance":"1Panel-openresty-example"},
  "authorizedTest": true,
  "url": "https://example.com:18443/",
  "connectAddress": "127.0.0.1",
  "serverCaFile": "/private/test-pki/root.pem",
  "cases": [
    {"name":"trusted-allowed","expected":"allow","certFile":"/private/test-pki/allowed-chain.pem","keyFile":"/private/test-pki/allowed.key"},
    {"name":"no-certificate","expected":"deny"},
    {"name":"untrusted-ca","expected":"deny","certFile":"/private/test-pki/untrusted.pem","keyFile":"/private/test-pki/untrusted.key"},
    {"name":"trusted-denied","expected":"deny","certFile":"/private/test-pki/denied-chain.pem","keyFile":"/private/test-pki/denied.key"}
  ]
}
```

Use the **same actual loopback panel origin** in all target objects, including the test input; the panel port is a placeholder, and high-level apply requires loopback. The TLS test URL must match the selected site's primary domain; connecting to an explicit IP preserves SNI, hostname verification and Host. No server TLS verification bypass is offered. Keys are read only from local test paths and never printed or uploaded.

```bash
node dist/scripts/cli.js run mtls testMtlsPolicy \
  --input-file /private/onepanel-example/test.json
node dist/scripts/cli.js run mtls disableMtlsPolicy \
  --input-file /private/onepanel-example/disable-preview.json \
  --output-file /private/onepanel-example/disable-plan.json
```

`disable-preview.json` contains only the exact target. Use its returned `expectedSha256` to prepare `{target,apply:true,confirm:true,expectedSha256}` in `disable.json`, then:

```bash
node dist/scripts/cli.js run mtls disableMtlsPolicy \
  --input-file /private/onepanel-example/disable.json
```

Test ordinary HTTPS and proxy routes again. Versions remain available for re-enabling or recovery. For an error or interrupted multi-file deployment follow [SECURITY.md#manual-recovery](SECURITY.md#manual-recovery).

## Reproduce tests

```bash
npm ci
npm run typecheck
npm run build
npm test
npm run test:e2e                 # explicitly reports NOT RUN without authorized config
npm run test:e2e:local           # creates and cleans a completely disposable local panel
```

The local suite requires Docker access, installed `/usr/local/bin/1panel-core` and `1panel-agent` (`ONEPANEL_E2E_BIN_DIR` overrides), Python 3, Git, OpenSSL, and image `1panel/openresty:1.27.1.2-5-1-focal` (`ONEPANEL_E2E_IMAGE` overrides). It may fetch the pinned Lua dependency and Docker CLI image. It creates a new database, loopback-only ports, unique network, frontend/backend/panel containers, and short-lived test certificates. It never reads or copies an existing panel database. It mounts the Docker socket solely into the disposable panel so the actual panel services can perform their normal syntax/reload commands.

Optional `ONEPANEL_E2E_REPORT=/private/report.json` writes a redacted evidence report outside the repo. For a separately prepared isolated environment, set `ONEPANEL_E2E_CONFIG=/private/e2e.json` and `ONEPANEL_E2E_APPLY=true`; see `tests/e2e/setup-local.mjs` for the config shape. This mode restores initial site/global configuration but retains policy versions for inspection. The disposable `:local` mode deletes all temporary state afterward.

GitHub CI runs Node 18/24 unit and Mock checks on PRs with read-only permissions. The ClawHub workflow stays manual; select your own publisher namespace before invoking it. No ClawHub publication is part of this delivery.
