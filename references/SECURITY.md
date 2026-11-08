# Security model and recovery

## Scope and authorization

The SDK is an administrative client, not a server-side sandbox. A stolen panel key or malicious caller can use the underlying HTTP API outside this SDK. Server API-key permissions, node grants, network restrictions and trusted operators remain necessary. The CLI removes generic mutation bypasses; Agent instructions prohibit replacing managed flows with ad hoc signed requests.

Managed writes bind a panel origin, explicit node, installed container and, for sites, exact ID/alias/API-reported paths. Global writes are separately confirmed and ask 1Panel to make its server-side backup. Read-only capability probes do not send experimental writes. HTTP 404 cannot always distinguish an absent resource from an unavailable route; HTTP 405/501 classify as `API_UNSUPPORTED`.

`files` is restricted to flat files below `<actual-site-path>/mtls`; only `.conf`, `.lua`, `.pem`, `.crt`, `.json` are allowed. All ancestors are listed from their parent with `expand:true`, symlinks and unknown metadata are rejected. This is a client-side check, not `openat(O_NOFOLLOW)` on the server. Symlink replacement between check and use is another unavoidable API race; do not run against an adversarial filesystem administrator.

Limits: text 1 MiB; reviewed Lua 64 KiB; request 2 MiB; response 8 MiB; 32 CA certificates; 512 leaf SHA-256 fingerprints; verification depth 1–10. Private-key PEM, malformed fingerprint separators, non-CA certificates, expired/not-yet-valid CAs, missing issuer links, ambiguous issuers, CA path-length violations and cycles are rejected. Public CA data is accepted only as PEM. Native signature/issuer verification does not replace the OpenResty/OpenSSL runtime's complete path and name-constraint validation, revocation/CRL policy, or certificate-purpose review. Revocation checking is not implemented.

## Write and recovery semantics

- Read full bytes; calculate SHA-256; validate; preview a structural diff without calling any write endpoint.
- Apply requires boolean intent, confirmation and baseline digest. Re-read before sending one mutation; re-read after it. A matching desired state permits idempotent replay.
- Store an exclusive, fsynced mode-0600 backup before mutation. Journal root is owner-private mode 0700. Do not use a journal path with untrusted parent directories. Audit output masks credentials/PEM/config and identifies time, scope, before/after digests and outcome.
- Only GET and explicitly marked read-only POSTs may retry connection/timeout failures. Mutations never blindly retry. An ambiguous write is reconciled by reading the target.
- On failure, recover only if current bytes still equal this attempt's desired state (or its known empty-file creation intermediate). Unknown third-party state is preserved and reported for manual recovery. Recovery is checked too. A rollback failure includes its backup location and machine-readable code.
- There is no server CAS, lock or multi-file transaction. A process crash can leave staged files or an uncertain include switch. Shared editing must be coordinated.
- `FileCreate.content` is ignored by the verified server. Text creation explicitly creates an empty regular file, then saves bytes; this intermediate state is tracked for compensation. `/files/content` must use `isDetail:false` to actually read bytes.
- General policy file saves return `FILE_SAVED_ONLY`. They do not claim reload or enforcement. For active managed Lua/CA changes use mTLS rotations, which generate new filenames and switch the include. Content-addressed `.pem/.lua/.conf` files reject mismatched bytes; managed manifests cannot be edited with `files.writeFile`.
- 1Panel's website/global/proxy APIs check and reload within their service methods. The server may restore one file on error, but does not guarantee restored workers or recovery across multiple files. Client read-back and real service tests are still required.

## mTLS and Lua

Raw site, proxy and global configuration actions refuse directly adding, relocating or altering Lua handlers/dependencies, while preserving existing ones during unrelated edits. Controlled `.conf` files permit only a same-site versioned reviewed Lua reference; `.json` must parse as data. These gates reduce routine bypasses but do not turn an administrative Nginx client into a server sandbox.

The only permitted template is `sha256-acl-v1`. Code review and a real runtime DER hash vector establish the tested implementation; string checks alone do not prove Lua safety. No shell execution or arbitrary Lua endpoint is exposed. Runtime probes invoke fixed Docker/resty arguments with `execFile`, without shell interpolation.

The Lua handler uses `pcall`; any exception or missing dependency denies access. The empty allowlist denies all. Unverified clients are denied before accessing the leaf certificate. Only successful chain validation plus an allowed leaf DER SHA-256 digest authorizes forwarding. Server-level mTLS directives are never placed into ordinary location proxy files.

The local runtime probe runs `nginx -T`, checks the selected site's actual mapped config is included, detects access handlers and rewrite/return/satisfy-any bypasses across expanded includes, verifies the API's global config matches runtime files, loads dependencies, runs a real DER test vector and compiles the generated template. This is conservative and can reject unrelated sites' incompatible handlers. High-level remote/node deployment is deliberately unavailable because this implementation cannot independently validate that runtime. P0 managed API operations are node-aware.

Only `enforce` mode is supported. Session caching/tickets are disabled in the managed policy to reduce resumption issues. Graceful reloads, old workers, TLS sessions and existing HTTP/2 connections still need operational revocation handling. There is no claim of immediate connection termination. HTTP/3/QUIC is blocked. No WAF composition has been proven; an existing handler is a conflict, including global inherited handlers.

## Manual recovery

1. Stop additional changes. Preserve `backupPath` and its `.audit.json`; inspect current config and worker state.
2. Read the backup locally in a private editor. It contains `{resource,target,content}`; never paste it into chat or publish it. Retrieve the current remote digest using the appropriate dry-run action.
3. Build a private JSON input with that exact target, the backup's original content, the **current reviewed** digest, `apply:true`, `confirm:true`. Global restoration also needs `backup:true,confirmGlobal:true`. Use the matching `websites.updateWebsiteRawConfig`, `openresty.updateGlobalConfig` or `files.writeFile` action. Do not force through an unexplained concurrent edit.
4. Restore the previous site include **before** removing any staged file that it might reference. For a normal disable, `mtls.disableMtlsPolicy` removes only the owned include and retains versions.
5. Independently run `docker exec <exact-instance> nginx -t` on the authorized local runtime; check API reload result, read back bytes, and test fresh TLS/HTTP requests. When workers cannot be reloaded, use the panel's normal administrative recovery controls; this skill does not expose an arbitrary shell/restart endpoint.
6. Delete only unreferenced policy versions after review, or retain them for recovery. Backups can contain confidential config; define a local retention policy.

Errors include `AUTH_FAILED`, `FORBIDDEN`, `NOT_FOUND`, `API_UNSUPPORTED`, `INVALID_INPUT`, `TARGET_MISMATCH`, `CONFLICT`, `SYNTAX_FAILED`, `RELOAD_FAILED`, `VERIFY_FAILED`, `ROLLBACK_FAILED`, `NETWORK`, `TIMEOUT`, `DEPENDENCY_MISSING`, `API_ERROR`. CLI failures exit nonzero and never echo a raw server error body that may contain credentials. Panel versions returning only localized free-form messages may classify a service failure as `API_ERROR`; use panel logs for detail.
