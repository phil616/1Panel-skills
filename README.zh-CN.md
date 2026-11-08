# 1Panel Skills — 个人维护版

[English](./README.md) | [简体中文](./README.zh-CN.md)

基于 [1Panel-dev/1Panel-skills](https://github.com/1Panel-dev/1Panel-skills) 官方上游维护的 TypeScript / Node.js 18+ 技能。保留监控、网站、应用、容器、日志、定时任务、任务中心和节点的既有查询，新增 OpenResty 与 mTLS 受控管理，不修改 1Panel 主项目。

- 完整站点配置、已有反代文件、全局配置和服务端支持的结构化参数管理。
- 限定站点策略目录，创建目录/文本文件、multipart 上传公开 CA PEM，禁止私钥。
- 版本化多 CA mTLS、客户端叶证书 **DER SHA-256** 白名单、默认拒绝的受审 Lua 模板，主动检测 WAF/Lua 冲突。
- 所有新增写入默认 dry-run；明确目标、确认、并发摘要后 apply；写前备份、写后回读、补偿恢复、脱敏审计。
- 保留 MD5，支持可配置 HMAC-SHA256 与独立 Key-ID，不自动降级。

## 从 Release ZIP 安装

在 [GitHub Releases](https://github.com/phil616/1Panel-skills/releases) 下载版本化 SKILL ZIP 与 SHA256SUMS。校验后解压，将 `1panel-skills` 目录放入 Agent 的技能目录。Node 18+ 可直接执行 `node dist/scripts/cli.js modules`，无需 npm install。ZIP 保留最小 ESM 运行声明，不含开发依赖和测试凭证；详见 [ZIP 安装与发布流程](references/releasing.md)。开发和测试仍使用完整源码 checkout。

## 使用

通过私密环境变量配置 `ONEPANEL_BASE_URL`、`ONEPANEL_API_KEY`。可选 `ONEPANEL_SIGNATURE_VERSION=hmac-sha256`、`ONEPANEL_KEY_ID`、`ONEPANEL_TIMEOUT_MS`、`ONEPANEL_STATE_DIR`。默认校验 TLS；按面板版本在设置或用户信息抽屉中管理 API Key、授权范围和 IP 限制。

```bash
node dist/scripts/cli.js modules
node dist/scripts/cli.js actions websites
node dist/scripts/cli.js run monitoring getCurrentNode
node dist/scripts/cli.js run websites searchWebsites --input-json '{"page":1,"pageSize":20}'
node dist/scripts/cli.js request GET /api/v2/dashboard/base/os
```

仓库跟踪的 `dist/` 可直接运行。需要本地发现时，将本仓库链接到运行时技能目录，例如 Codex 的 `~/.codex/skills/1panel-skills` 或 OpenClaw 的 `~/.openclaw/skills/1panel-skills`；先检查已有同名技能。

## 写入与 mTLS

先调用受控动作生成预览，审阅目标、摘要及 diff。复杂输入用 `--input-file`，完整结果用 `--output-file` 保存到不存在的私密文件，stdout 默认脱敏。Apply 需要 `apply:true,confirm:true,expectedSha256`；全局修改额外要求 `backup:true,confirmGlobal:true`，Lua 和多文件 mTLS 另有明确确认字段。

完整的 [读取 → 规划 → 审阅 → apply → TLS 测试 → disable 示例](references/openresty-mtls.md) 包含全部动作和恢复说明。通用 `request` 保留 GET/已知 POST 查询，拒绝绕过保护直接写入。`sign` 保留原行为，会主动输出短时签名 Header，应私密使用。

P0 API 支持显式节点；高级 mTLS 发布目前仅支持**本机 Docker、回环面板地址**及已证实的 `/www` 映射。要求单个 HTTPS server、可靠 Lua 加密组件；拒绝 QUIC/HTTP3、现有 WAF/access handler、提前 return/rewrite 等绕过路径和不支持的站点布局。仅实现 enforce 模式及 `sha256-acl-v1` 模板，不接受任意 Lua。测试的默认 OpenResty 镜像缺少 `lua-resty-openssl`，必须准备可持久维护的依赖，技能不会静默安装或覆盖 WAF。

服务端没有原子 CAS 或多文件事务；摘要复查不能彻底消除竞争，需要协调其他编辑器。保存文件不等于 reload，reload 不等于认证策略生效；平滑 reload 也不保证立即撤销已有连接。详见 [安全边界与恢复](references/SECURITY.md)。

## 模块与维护

| 模块 | 能力 |
| --- | --- |
| `monitoring` | 指标、实时/Top 进程、历史/GPU |
| `websites` | 既有读取，新增完整站点/反代及限定结构化写入 |
| `apps`、`containers` | 原应用与容器检查、服务、状态、统计/日志 |
| `logs`、`cronjobs`、`task-center`、`nodes` | 原检查动作；部分节点功能取决于版本/授权 |
| `openresty` | 全局配置、状态、能力探测与受控修改 |
| `files` | 选定站点的 mtls 策略目录与公开 CA 上传 |
| `mtls` | 检查、计划、应用、关闭、CA/指纹/Lua 更新、授权测试 |

源代码位于 `scripts/`，共享保护位于 `scripts/security/`，测试位于 `tests/`；`assets/fingerprint-vector.pem` 为公开测试向量。[SKILL.md](SKILL.md) 为 Agent 入口；另见 [模块说明](references/module-groups.md)、[上游 API 与升级依据](references/upstream-api.md)、[验收报告](TEST_REPORT.md)。

```bash
npm ci
npm run typecheck
npm run build
npm test
npm run test:e2e           # 无明确授权的隔离配置时报告 NOT RUN
npm run test:e2e:local     # 新建并清理独立 1Panel/OpenResty，前提见操作指南
```

PR CI 使用只读权限运行 Node 18/24 类型检查与单元/Mock 测试。手动 ClawHub 打包已包含公开运行时测试向量；使用前应指定自己的发布命名空间，本次未发布。

源码变更应同步提交 `dist/`。不得提交真实 Key、私钥、本地计划或用户配置。其余上游预留写操作继续保留，不宣称已实现。

## 许可证

沿用上游 [LICENSE](LICENSE) 的 GPL-3.0；修正上游 README 原 MIT 标注与许可证文件不一致的问题。
