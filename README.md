# 1Panel Skills — personal fork

[English](./README.md) | [简体中文](./README.zh-CN.md)

A TypeScript/Node.js 18+ 1Panel operations skill, forked from [1Panel-dev/1Panel-skills](https://github.com/1Panel-dev/1Panel-skills). It preserves the upstream monitoring, website, app, container, log, cronjob, task-center and node reads and adds guarded OpenResty/mTLS management.

- Full website, existing reverse-proxy and global OpenResty configuration changes; supported structured site settings.
- Controlled policy directory creation, public CA PEM upload and bounded text files.
- Versioned multi-CA mTLS policies with actual **leaf DER SHA-256** fingerprint ACLs, fail-closed reviewed Lua and WAF/access-handler conflict detection.
- Default dry-run, explicit target/confirmation/baseline gates, private backups, read-back, compensating rollback and redacted audit.
- MD5 compatibility and configurable HMAC-SHA256/independent Key-ID; no automatic downgrade.

## Start

Configure `ONEPANEL_BASE_URL` and `ONEPANEL_API_KEY` privately. Optional: `ONEPANEL_SIGNATURE_VERSION=hmac-sha256`, `ONEPANEL_KEY_ID`, `ONEPANEL_TIMEOUT_MS`, `ONEPANEL_STATE_DIR`. TLS verification is enabled by default. API setup is under panel settings on older versions and the user-information drawer on newer versions; use your panel's documented API-key controls and scope/IP restrictions.

```bash
node dist/scripts/cli.js modules
node dist/scripts/cli.js actions websites
node dist/scripts/cli.js run monitoring getCurrentNode
node dist/scripts/cli.js run websites searchWebsites --input-json '{"page":1,"pageSize":20}'
node dist/scripts/cli.js request GET /api/v2/dashboard/base/os
```

The prebuilt `dist/` is tracked and ready to run. For local skill discovery, link this checkout into the runtime's skill folder (for Codex, `~/.codex/skills/1panel-skills`; for OpenClaw, `~/.openclaw/skills/1panel-skills`). Do not overwrite an existing personal skill without reviewing it.

## Write workflow

Call a managed action without `apply` to preview. Review its digest, diff and exact target. Use `--input-file` for complex plans; `--output-file` exclusively creates a mode-0600 full response for local review while stdout stays redacted. Apply needs `apply:true,confirm:true,expectedSha256`; global writes additionally need `backup:true,confirmGlobal:true`; Lua/mTLS need their specific acknowledgments.

Follow the complete [read → plan → apply → TLS test → disable example](references/openresty-mtls.md). Generic `request` retains GET/known POST reads and refuses mutations. The original `sign`, `modules`, `actions` and read-only `run` commands remain available; `sign` intentionally prints short-lived signature headers, so keep that output private.

P0 APIs support explicit nodes. High-level mTLS apply currently requires a running **local Docker** OpenResty, loopback panel origin, proven mounts and verified Lua crypto dependencies. It rejects QUIC/HTTP3, incompatible WAF/access handlers, early access bypasses, and unsupported site layouts. It supports `enforce` and the reviewed `sha256-acl-v1` template only. The stock tested image needs an additional `lua-resty-openssl` installation; the skill blocks missing dependencies instead of silently installing them.

Server APIs provide no atomic CAS or multi-file transaction. Hash checks reduce races; coordinate concurrent editors. Saving a file alone does not prove reload, and reload alone does not prove security enforcement. Graceful reload does not instantly revoke existing connections. See [security/recovery boundaries](references/SECURITY.md).

## Modules and maintenance

| Module | Scope |
| --- | --- |
| `monitoring` | Metrics, live/top processes, history/GPU |
| `websites` | Existing reads plus full site/proxy and supported structured changes |
| `apps`, `containers` | Catalog/install status, services, containers, stats/logs |
| `logs`, `cronjobs`, `task-center`, `nodes` | Original inspection actions; Pro/node availability varies |
| `openresty` | Global config, status, capability probe, guarded global change |
| `files` | Selected site's `mtls` policy directory, public CA uploads |
| `mtls` | Inspect, plan, apply, disable, rotate CA/ACL/Lua, authorized TLS tests |

Sources live in `scripts/`, shared safety in `scripts/security/`, tests in `tests/`; `assets/fingerprint-vector.pem` is a public test vector. [SKILL.md](SKILL.md) is the Agent entrypoint; [module groups](references/module-groups.md), [verified upstream contracts](references/upstream-api.md) and [TEST_REPORT.md](TEST_REPORT.md) document usage, upgrades and acceptance.

```bash
npm ci
npm run typecheck
npm run build
npm test
npm run test:e2e           # NOT RUN unless an isolated config is explicitly authorized
npm run test:e2e:local     # actual disposable 1Panel + OpenResty; prerequisites in the guide
```

PR CI runs Node 18/24 typechecks and unit/Mock tests with read-only permissions. The manual ClawHub upload includes the public runtime test vector; choose your own publisher namespace before using it.

Commit regenerated `dist/` with source changes. Never commit panel keys, private keys, local plans or production config. Other upstream mutation definitions remain reserved; no changes are made to the 1Panel main project.

## License

GPL-3.0, as provided in the upstream [LICENSE](LICENSE). The upstream README's previous MIT label was inconsistent with that file and is corrected here.
