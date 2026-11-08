# ZIP 安装与 GitHub Release

GitHub Release 的安装包是 `1panel-skills-vX.Y.Z.zip`，唯一顶层目录为 `1panel-skills/`，目录内有 SKILL.md、agents、references、公开 assets、TypeScript 源码和预编译 dist。

安装包只含运行必需的最小 package.json（ESM 声明、版本和 CLI 入口），不含开发依赖、node_modules、Git 历史、测试目录、测试私钥或本地配置。Node.js 18+ 可直接运行，无需 npm install。完整开发、构建与测试请使用仓库 checkout。

## 下载和安装

从 [GitHub Releases](https://github.com/phil616/1Panel-skills/releases) 下载 ZIP 与 SHA256SUMS，放在同一目录：

```bash
sha256sum -c SHA256SUMS
unzip 1panel-skills-v0.1.0.zip
cd 1panel-skills
node dist/scripts/cli.js modules
```

把整个 `1panel-skills` 目录放入 Agent 的 skills 目录即可加载。Codex 可解压到 `~/.codex/skills`，OpenClaw 可解压到 `~/.openclaw/skills`。如已有同名技能，先保留旧版本再替换；API Key 继续通过宿主机的私密环境变量配置，不要写进安装包。

`RELEASE.json` 记录版本、源提交和包内文件 SHA-256；SHA256SUMS 校验完整 ZIP。它们用于完整性核对，不是签名或构建来源证明。原始源码 checkout 仍可用于维护，不必改为从 ZIP 开发。

## 自动发布流程

`.github/workflows/release.yml` 在稳定版本 tag（例如 `v0.1.0`）推送时执行，也可对已存在的 tag 手动 dispatch。默认分支或任意功能分支不能直接 dispatch 发布，tag 必须位于默认分支历史中。

1. Node 18/24 矩阵执行 npm ci、类型检查、83 项既有单元/Mock 测试、运行时构建一致性和打包专项测试。
2. 从干净的已提交源文件构造可复现 ZIP，校验版本、源提交、文件清单/摘要、路径及 ESM 声明；在隔离临时目录运行解压后的 CLI，不依赖开发环境。
3. Node 24 的产物经 Actions artifact 传给发布 job；读取时强制校验 artifact digest。发布 job 仅此时获得 contents:write，测试 job 保持只读。
4. 创建 draft，并上传精确的 ZIP 和 SHA256SUMS。核对远端附件名称、大小、可用的摘要，并重新下载比较最终字节。
5. 全部成功后发布并标为 Latest。不会自动发布到 ClawHub，也不会连接 1Panel。

真实面板 E2E 的历史结果见 TEST_REPORT.md；不在每次 Release 中自动操作面板。工作流使用 GitHub 自带的 GITHUB_TOKEN，不需要新增 PAT 或 ClawHub 密钥。

## 发布后续版本

在个人 Fork 的 main 合并并确认检查通过后：

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.1.1 -m "1Panel Skills v0.1.1"
git push origin refs/tags/v0.1.1
```

推送 tag 后查看 Release skill ZIP 的 run，构建成功不等同于已经发布；应核对整个工作流和最终附件。不要移动已发布 tag 或覆盖已发布 ZIP，修复使用新版本。

本地复现打包（先 npm ci、npm run build，且发布输入文件需要与 HEAD 一致）：

```bash
npm run test:package
npm run package:skill -- --version v0.1.0 --output-dir /tmp/onepanel-release
python3 tools/skill_zip.py verify \
  --archive /tmp/onepanel-release/1panel-skills-v0.1.0.zip --version v0.1.0
```

输出目录须是新的，避免不知情覆盖已有产物。ZIP 使用固定提交时间、顺序和权限；同一版本/提交在相同打包工具环境下产出相同字节。

## 失败恢复

发布脚本在查到同 tag 已有 release/draft 时会停止，不会把认证或网络错误当成“尚不存在”。如果上传或验证失败，保留 draft 供检查，不能盲目 rerun：先核对 tag 源提交、draft 身份、现有附件与本次 run 的哈希，再决定是否补齐这个未发布草稿。不要改动已经发布的版本。

代码/配置回滚仍遵循 references/SECURITY.md。换回旧 ZIP 不会自动回滚远端 1Panel 配置。
