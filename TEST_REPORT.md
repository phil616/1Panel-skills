# 验收报告：1P-SKILL-SEC-001

执行日期：2026-11-08。交付位置：[phil616/1Panel-skills](https://github.com/phil616/1Panel-skills)，分支 `feat/openresty-security-management`。以已授权身份实际创建个人 Fork；未向官方仓库提交 PR，未发布 ClawHub 技能。

基础实现提交：[e1f70fde107d11fb33c02dafcd7e563b30fcff09](https://github.com/phil616/1Panel-skills/commit/e1f70fde107d11fb33c02dafcd7e563b30fcff09)。个人 Fork PR：[#1](https://github.com/phil616/1Panel-skills/pull/1)。该基础提交的 [GitHub CI](https://github.com/phil616/1Panel-skills/actions/runs/42495949694) 已实际完成，Node 18 和 Node 24 两个 job 均 SUCCESS；追加的 Lua 旁路限制与最终提交见同一 PR 历史；未自动合并。

## 来源与基线

- 官方 Skill `main`：`33d74c9502e7ae509d8c1d7f3f1c78fd13ac23c6`。
- 官方主项目 `dev-v2`：`fa125e4386789a31e0521a85cd09e82cd3152e5d`。主项目仅克隆用于调查，没有修改。
- 原始 `npm ci`、`npm run typecheck`、`npm run build` 均通过；原始项目没有 test 脚本。
- 上游跟踪 `dist/`，已同步构建。沿用实际 LICENSE 的 GPL-3.0，修正原 README 的 MIT 误标。
- DTO、签名、节点转发、权限和保存行为的逐项依据：[references/upstream-api.md](references/upstream-api.md)。

## 实现范围

| 模块 | 状态 | 单元 / Mock | 真实 E2E | 限制 |
| --- | --- | --- | --- | --- |
| 安全写入基础层 | Implemented | PASS | PASS | 无服务端 CAS；多文件为补偿恢复，不是原子事务 |
| 网站完整配置 / 现有反代 | Implemented | PASS | PASS | 必须完整配置；反代必须已存在；服务端可能重排父站点格式 |
| 结构化站点参数 | Implemented / scoped | PASS | PASS | 只支持 index / limit-conn / http-per 的限定参数；不管理 SSL 私钥；已有连接限制的复杂修改走完整配置 |
| OpenResty 全局配置 | Implemented | PASS | PASS | 额外确认、服务端备份；不编造独立 test/reload 接口 |
| Files / CA multipart | Implemented | PASS | PASS | 仅选定站点的 mtls 目录；不得管理私钥或任意主机文件 |
| mTLS + 多 CA + SHA-256 ACL | Implemented / local Docker | PASS | PASS | 高级远程节点部署 Blocked，缺少等价运行时证明；低层 P0 支持显式节点 |
| Lua 策略 / WAF 检测 | Implemented / reviewed template | PASS | PASS | 仅 sha256-acl-v1，任意 Lua 拒绝；已有 WAF access handler 默认冲突 |
| TLS 策略测试 | Implemented | PASS | PASS | CLI 四类新连接 HTTP/1.1；额外 HTTP/2/TLS1.2 在 E2E 套件验证；QUIC/HTTP3 拒绝 |
| 原查询动作与 CLI | Preserved | PASS | 部分真实查询 + 核心 API | 对八个原模块保留代表性 HTTP 契约回归；并未声称所有版本/Pro 接口均可用 |
| GitHub CI / 技能打包 | Implemented | actionlint PASS | 见 PR checks | Node 18/24 矩阵；无发布凭证的 PR 测试；ClawHub 清单补入公开测试向量 |

新增动作：网站完整配置 / 结构化设置 / 反代文件读写，OpenResty 全局读取、状态、能力探测、受控更新，受控文件读取/保存/创建/CA 上传，以及 mTLS 检查、计划、应用、关闭、CA 更新、指纹更新、Lua 模板更新、实际 TLS/HTTP 测试。现有预留动作未被冒充实现，也无同名重复。

## 实际执行与结果

| 命令 / 检查 | 结果 |
| --- | --- |
| `npm ci` | PASS，安装 3 个开发依赖，无新增运行时框架 |
| `npm run typecheck` | PASS |
| `npm run build` | PASS，重新生成跟踪的 dist |
| `npm test` | **83 passed, 0 failed, 0 skipped** |
| `node --test tests/security.test.mjs` | **37 passed**，路径/变更/CA/DER/配置安全 |
| `node --test tests/client.test.mjs` | **14 passed**，签名/HTTP/TLS/multipart/网络错误 |
| `node --test tests/integration/api.test.mjs` | **32 passed**，真实本地 HTTP Mock server、CLI 与完整流程 |
| `ONEPANEL_E2E_REPORT=/private/report.json npm run test:e2e:local` | **PASS：23 个真实场景，0 failed** |
| Node v18.20.8 Docker 冒烟 | PASS：ESM 的 11 模块注册、固定 HMAC 向量、HTTP 请求、安全写入/备份 |
| `quick_validate.py .` | PASS：Skill is valid |
| `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/ci.yml .github/workflows/push-clawhub.yml` | PASS |
| `git diff --check` | PASS |
| ClawHub 上传目录构造 smoke | PASS，包含公开 fingerprint vector 与报告，未执行登录/发布 |
| GitHub Actions Node 18 / Node 24 | 两个 job 均 SUCCESS，见上方运行链接 |

单元测试并非仅靠 Mock 自证：固定 MD5/HMAC 值独立由 Python 生成；公开证书 DER 的 SHA-256 与 OpenSSL 结果比对；真实 OpenSSL 创建根/中间/叶证书并验证正反链路及 pathLen 约束；HTTPS 测试服务器验证默认 TLS 拒绝无信任证书。Mock 套件校验实际 HTTP 方法、路径、字段大小写、节点 query、请求次数、磁盘状态模型、备份权限和 CLI 输出。

错误路径覆盖：401/403/404/405/409/500、HTTP 200 业务错误、非 JSON、超时、中断、已提交但响应丢失、并发编辑、错误目标/节点、符号链接、超大文件、缺依赖、非法 CA/指纹/Lua、既有 access handler、rollback 失败、空文件创建中间状态恢复、受控 include 仅删除本模块内容、不可变文件摘要不一致、输出文件已存在时不发请求；非法 JSON 报错不回显输入片段；原始站点/反代/全局配置不可直接新增、移动或改写 Lua 处理器/依赖，受控 conf 只可引用本站版本化 Lua，JSON 文件不得伪装代码。

## 真实 E2E 环境与证据

**E2E: PASS。** 使用本机已安装的真实 1Panel 二进制另建独立面板数据库、独立站点、独立 OpenResty/反代后端和独立 Docker 网络。API/TLS 端口仅绑定 127.0.0.1。没有复制原面板数据库或用户密钥，没有启动或修改原面板停止的 OpenResty 容器，也没有修改已有站点。

- 1Panel：`v2.4.2 stable`，Core 与 Agent 均为实际进程。
- OpenResty：`1panel/openresty:1.27.1.2-5-1-focal`，Nginx/OpenResty `1.27.1.2`。
- 实际镜像摘要：`sha256:ee8c5117c291c7384a381c32068e1d9a50adc8bf392f9157c42d14bedbbe018b`。
- Lua：`lua-resty-openssl` 1.9.0，commit `4ebee84ec3d829ef610005db1978ae591ed77a31`；DER 导出使用真实 API `x509:tostring("DER")`。
- 挂载：新建临时目录中的 `1panel/www` → `/www`；全局配置独立挂载到 `/usr/local/openresty/nginx/conf/nginx.conf`。探测核对 API 文件、Docker 映射及 `nginx -T` 的实际包含路径。
- 证书：全部由测试 fixture 临时生成，根 CA + 中间 CA + 允许/拒绝叶证书 + 非信任 CA；测试后删除。公开静态测试向量不含私钥。

| 请求 | 实际结果 | 结论 |
| --- | --- | --- |
| on：信任链 + 白名单客户端 | TLS1.3 / HTTP 200 | 允许 |
| on：无客户端证书 | TLS1.3 / HTTP 400 | Nginx 拒绝 |
| on：非信任 CA | TLS1.3 / HTTP 400 | Nginx 拒绝 |
| on：信任 CA 但指纹不在名单 | TLS1.3 / HTTP 403 | Lua 拒绝 |
| 白名单客户端强制 TLS1.2 | HTTP 200 | TLS1.2 通过 |
| 白名单客户端协商 HTTP/2 | ALPN h2 / HTTP 200 | HTTP/2 通过 |
| 既有 `/proxy` 反代路径 | HTTP 200 | 保持可用 |
| optional：无证书 | HTTP 403 | Lua 默认拒绝 |
| 空 ACL / 撤销原叶证书 | HTTP 403 | 策略更新实际生效 |
| 多 CA 集合从 2 到 3 | 指纹数量核对 + HTTP 200 | 轮换并重新载入 |
| 注入 Lua 运行时异常 | HTTP 500，未放行；恢复并 reload 后 200 | fail-closed 与恢复 |
| 已有全局 WAF access handler | CONFLICT，禁止启用 | 未覆盖既有逻辑 |
| 非法 Nginx 配置 | SYNTAX_FAILED + 原字节及服务核验 | 服务端拒绝/恢复 |
| 写入已提交后代理断开响应 | 仅 1 次写入；回读确认 APPLIED | 没有盲重试 |
| disable | 无证书普通 HTTPS 200 | 仅删除受控 include |
| 最终恢复 | 原站点/全局 SHA-256 相同，普通 HTTPS 200 | 已恢复 |

平滑 reload 返回早于新 worker 完全接管，因此 E2E 对新连接的期望 HTTP 状态做有界只读轮询，不重试写入。不能把这个结果解读为已有连接即时撤销。全部真实场景通过后，套件删除新建容器、网络、数据库、证书、备份和临时目录。无授权配置的普通 `test:e2e` 明确返回 NOT RUN，不能被解读为 PASS。

## 交付文件与已知限制

- 运行时：修改 `scripts/client.ts`、`cli.ts`、`types.ts`、`index.ts`、`modules/websites.ts`；新增 `modules/openresty.ts`、`files.ts`、`website-security.ts`、`mtls.ts` 和 `security/*.ts`；同步 `dist/scripts/**`。
- 测试：`tests/client.test.mjs`、`security.test.mjs`、`integration/api.test.mjs`，真实 HTTP server/PKI fixtures，`tests/e2e/` 的隔离面板创建、真实请求矩阵、初始化与清理脚本；公开 `assets/fingerprint-vector.pem`。
- 文档：SKILL、双语 README、module-groups、安全/操作/上游契约说明、当前报告、Agent UI metadata。工作流仅增加测试与必要打包资源，不执行发布。Node 18 使用保留 `package.json` ESM 声明的完整 Fork checkout；ClawHub 仅验证上传清单，未宣称不含 package.json 的独立归档已通过 Node 18 运行测试。

有意保留的边界：高级远程运行时验证、WAF 合成、任意 Lua、audit-only、HTTP3/QUIC、CRL/OCSP 撤销管理和活跃连接强制终止没有实现。高层需要运行时依赖且只支持明确的 HTTPS server 布局；对其他站点结构或继承 handler 保守拒绝。P0 文件操作仍依赖服务端 API，无法消除 symlink/CAS 竞态。任意未知第三方状态的自动覆盖被禁止，可能需要人工按私密备份恢复。

## 升级、回滚与复现

完整 CLI 示例：[references/openresty-mtls.md](references/openresty-mtls.md)，包括 getWebsiteConfig → plan → 审阅 → apply → test → disable。维护上游的方法：[references/upstream-api.md](references/upstream-api.md)。

配置回滚：停止继续修改 → 保护 `backupPath` / audit → 核对当前状态和摘要 → 用匹配模块对备份原内容生成新计划 → 明确 apply → 回读、语法/reload 和请求验证。先恢复站点 include，再处理未引用的策略版本；正常关闭策略保留文件。失败恢复细节见 [references/SECURITY.md](references/SECURITY.md)。

代码回滚：在个人 Fork 的功能分支上使用 `git revert <implementation-commit>`，然后 `npm ci && npm run typecheck && npm run build && npm test`。撤销代码不会自动撤销远端配置，必须先执行上述配置恢复。没有自动部署或合并 PR。
