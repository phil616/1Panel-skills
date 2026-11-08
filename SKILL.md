---
name: 1panel-skills
description: Manage 1Panel Community Edition through its authenticated API. Use for monitoring, website and proxy configuration, certificates, app/container inspection, logs, cronjobs, nodes, and guarded OpenResty/mTLS policy changes. Includes dry-run plans, backups, conflict checks and versioned CA/Lua SHA-256 ACLs; detects incompatible WAF access handlers.
---

# 1Panel personal operations skill

Use the existing module actions through `node dist/scripts/cli.js`. The fork retains upstream read actions and adds guarded configuration mutations; mTLS is composed from existing APIs, not a native 1Panel endpoint.

## Connect and discover

- Configure `ONEPANEL_BASE_URL` (HTTP(S) origin) and `ONEPANEL_API_KEY` using the host's secret mechanism. Do not put credentials in chat, arguments, examples or tracked files.
- `ONEPANEL_SIGNATURE_VERSION=hmac-sha256` selects the verified new signing algorithm. The default remains `md5` for upstream compatibility. Never silently downgrade. Optional `ONEPANEL_KEY_ID` selects an independent key on versions that support it.
- TLS verification is on. Prefer a trusted server certificate; `ONEPANEL_SKIP_TLS_VERIFY=true` is an explicit compatibility override for an authorized test environment.
- Start with `modules`, `actions <module>`, then list/search and detail reads. Probe `openresty.discoverCapabilities` before changes. API permissions, node grants and API-key IP/time restrictions still apply.
- For every managed write, identify `target: {baseUrl, websiteId, alias, operateNode, instance}`. Use `operateNode:"local"` explicitly for the local node. Global configuration uses the same target without website fields. Never infer a site from a fuzzy match.

## Configuration changes

1. Read the full original configuration, discover its API-reported host path and exact installed OpenResty container.
2. Run the managed action without `apply`. Review the returned digest, scope and diff. For complete proposed files use `--output-file /private/new-plan.json`; stdout masks configuration, PEM and credentials. The output path must not already exist.
3. Apply only within the user's authorized scope, with `apply:true`, `confirm:true` and the preview's `expectedSha256`. CLI also accepts `--apply --confirm`. Existing authorization persists; these machine gates do not require repeatedly asking the user for the same approval.
4. A global write additionally requires `backup:true` and `confirmGlobal:true`. Lua installation requires `confirmLua:true`; multi-file mTLS deployment requires `acknowledgeNonAtomic:true`.
5. Check the result, backup path, audit, and read-back. Distinguish file bytes verified, API check/reload returned, and policy requests verified. Only an actual successful TLS/HTTP matrix establishes the tested enforcement behavior.
6. On conflict, read and review a new plan. Do not replace the expected hash to force a stale plan through. Do not blindly retry an uncertain write. Use returned error codes and protected backups for recovery.

All new mutations default to dry-run and never invoke a write endpoint in preview mode. Writes keep private local backups/audits under `ONEPANEL_STATE_DIR` (default `~/.local/state/1panel-skills`, mode 0700). Keep this directory outside the repository. Audit diffs contain line counts and digests, not config contents. Backups contain the original bytes and must remain private.

1Panel has no atomic compare-and-swap for these APIs. Rechecking hashes reduces races but cannot eliminate a change between the last read and the server write. Coordinate other editors. Multi-file changes use compensating recovery and are not atomic. A recovery failure is `ROLLBACK_FAILED`; stop and inspect the current disk/worker state before using a backup.

Raw site/proxy/global updates preserve existing Lua handlers and dependencies but refuse adding, moving or altering them directly. Use the reviewed mTLS workflow for Lua changes. Policy `.conf` files may reference only this site’s versioned reviewed Lua; `.json` files must be JSON data.

Do not use generic `request`, ad hoc signed HTTP, or unrelated file paths to bypass managed write gates. `request` now permits GET and known implemented POST reads only. Reserved actions remain unimplemented until intentionally extended.

## Select the relevant module

| Module | Use |
| --- | --- |
| `monitoring`, `apps`, `containers`, `logs`, `cronjobs`, `task-center`, `nodes` | Existing upstream inspection actions; node/Pro availability varies. |
| `websites` | Existing site/HTTPS/certificate reads; full site, existing proxy and supported structured settings changes. |
| `openresty` | Global config/status reads, read-only capability probe, guarded global config update. No invented test/reload routes. |
| `files` | Bounded public CA and policy files only in the selected site's `mtls` directory. Never private keys, links or cross-site paths. Saving a file alone does not reload consumers. |
| `mtls` | Inspect, plan, apply, disable, rotate CAs/leaf fingerprints/reviewed Lua, and explicitly authorized TLS tests. |

For mutations, environment setup, complete CLI examples and recovery, read [references/openresty-mtls.md](references/openresty-mtls.md). For path boundaries, failure semantics and limitations read [references/SECURITY.md](references/SECURITY.md). For API source/DTO details and upstream updating read [references/upstream-api.md](references/upstream-api.md). Existing module entrypoints are in [references/module-groups.md](references/module-groups.md).

## mTLS boundaries

- Deploy only the reviewed `sha256-acl-v1` template. Arbitrary Lua is rejected. It validates `ssl_client_verify == SUCCESS`, hashes the actual leaf certificate DER with SHA-256 and denies exceptions/missing certificates/empty ACLs. `$ssl_client_fingerprint` is SHA-1 and is never substituted.
- Require a single HTTPS-only `server`, existing server TLS configuration, no QUIC/HTTP3, no early `return`/rewrite/satisfy-any bypass, and no other access phase Lua/WAF handler in the expanded runtime configuration. Refuse incompatible composition instead of overwriting it.
- High-level apply currently requires a running **local Docker** OpenResty on a loopback panel origin, a proven `/www` mount, and runtime `resty.openssl.x509`, `resty.openssl.digest`, `resty.string` checks. Remote/multi-node high-level deployment is blocked until equivalent runtime verification exists. P0 managed APIs still support explicit remote nodes.
- Policies and public CA bundles are immutable versioned files; switch one owned include after staging them, then reload. Disable removes only that include and retains files for recovery.
- `on` delegates certificate verification rejection to Nginx. `optional` permits missing certificates through TLS but Lua denies them at access time. This skill implements `enforce` only.
- A graceful reload does not instantly revoke existing keepalive, HTTP/2 streams or old workers. Test fresh connections after workers settle; do not claim a live-session revocation guarantee.
- Run `testMtlsPolicy` only against an explicitly authorized isolated site and test certificate matrix. Without one, return `NOT RUN`. Never invent successful E2E results.

## Maintenance

Keep GPL-3.0 and upstream functionality. After source edits run `npm ci`, `npm run typecheck`, `npm run build`, `npm test`; commit the regenerated tracked `dist/`. For the disposable real integration suite run `npm run test:e2e:local` (Docker, installed 1Panel binaries, Python, OpenSSL and Git required). It creates a fresh panel database and removes its containers, network and test certificates afterward. Read [TEST_REPORT.md](TEST_REPORT.md) for the measured acceptance results.
