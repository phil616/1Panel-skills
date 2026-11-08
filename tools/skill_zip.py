#!/usr/bin/env python3
"""Build and verify the standalone skill ZIP; Python standard library only."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKILL = '1panel-skills'
VERSION = re.compile(r'^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')
ROOT_FILES = {'SKILL.md', 'README.md', 'README.zh-CN.md', 'LICENSE', 'TEST_REPORT.md'}
REQUIRED = ROOT_FILES | {'agents/openai.yaml', 'assets/fingerprint-vector.pem',
                        'dist/scripts/cli.js', 'dist/scripts/index.js',
                        'dist/scripts/client.js', 'dist/scripts/security/runtime.js'}
GENERATED = {'package.json', 'RELEASE.json'}


def valid_version(version):
    if not VERSION.fullmatch(version):
        raise ValueError('Use a stable SemVer tag such as v0.1.0 (no leading zeroes)')
    return version


def allowed(name):
    path = PurePosixPath(name)
    return (name in ROOT_FILES or name == 'agents/openai.yaml'
            or name == 'assets/fingerprint-vector.pem'
            or name.startswith('references/') and path.suffix == '.md'
            or name.startswith('scripts/') and path.suffix == '.ts'
            or name.startswith('dist/scripts/') and path.suffix == '.js')


def git(*args, root=ROOT):
    return subprocess.check_output(['git', '-C', str(root), *args]).decode().strip()


def collect(root=ROOT):
    selected = {}
    for name in git('ls-files', '-z', root=root).split('\0'):
        if not name or not allowed(name):
            continue
        path = root / name
        if any(part.is_symlink() for part in (path, *path.parents) if part != root.parent):
            raise ValueError('Refusing a symlink in package input: ' + name)
        if not path.is_file():
            raise ValueError('Missing tracked package file: ' + name)
        selected[name] = path.read_bytes()
    missing = REQUIRED - selected.keys()
    if missing:
        raise ValueError('Build runtime before packaging; missing: ' + ', '.join(sorted(missing)))
    return selected


def sha(data):
    return hashlib.sha256(data).hexdigest()


def runtime_manifest(version):
    return {'name': SKILL, 'version': version[1:], 'private': True, 'type': 'module',
            'engines': {'node': '>=18'}, 'bin': {'1panel-skills': './dist/scripts/cli.js'}}


def build(version, output_dir, root=ROOT):
    valid_version(version)
    payload = collect(root)
    state = subprocess.run(['git', '-C', str(root), 'diff', '--quiet', 'HEAD', '--', *sorted(payload)], check=False)
    if state.returncode != 0:
        raise ValueError('Package inputs differ from HEAD; commit changes before a release build')
    commit = git('rev-parse', 'HEAD', root=root)
    epoch = int(git('show', '-s', '--format=%ct', 'HEAD', root=root))
    payload['package.json'] = (json.dumps(runtime_manifest(version), indent=2) + '\n').encode()
    manifest = {'schemaVersion': 1, 'version': version, 'sourceCommit': commit,
                'files': {name: sha(data) for name, data in sorted(payload.items())}}
    payload['RELEASE.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f'{SKILL}-{version}.zip'
    if any((output_dir / name).exists() for name in
           (archive.name, 'SHA256SUMS', 'RELEASE_NOTES.md')):
        raise ValueError('Output files already exist; use a fresh output directory')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, content in sorted(payload.items()):
            info = zipfile.ZipInfo(f'{SKILL}/{name}', time.gmtime(max(epoch, 315532800))[:6])
            info.create_system = 3
            mode = 0o755 if name == 'dist/scripts/cli.js' else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, content, compresslevel=9)
    digest = sha(archive.read_bytes())
    (output_dir / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n', encoding='utf-8')
    notes = f'''# 1Panel Skills {version}

可直接解压使用的个人维护版 SKILL，唯一顶层目录为 `1panel-skills/`。

- 包含 SKILL、双语说明、参考文档、TypeScript 源码、预编译 CLI 和公开 SHA-256 测试向量。
- 保留 Node.js 18+ 所需的 ESM 声明；使用预编译 CLI 无需 npm install。
- 支持受控 OpenResty 配置写入、版本化多 CA mTLS、客户端 DER SHA-256 ACL、备份与审计；写入默认 dry-run。
- 高级 mTLS 需要已验证的本机 Docker/Lua 依赖，WAF 冲突和不支持的站点布局会拒绝覆盖。

## 使用

下载 `{archive.name}` 和 `SHA256SUMS` 到同一目录：

```bash
sha256sum -c SHA256SUMS
unzip {archive.name}
cd 1panel-skills
node dist/scripts/cli.js modules
```

将解压后的 `1panel-skills` 文件夹放入 Agent 的 skills 目录即可加载；API 凭证使用私密环境变量配置。
开发、构建和完整测试请使用 GitHub 源码 checkout，安装 ZIP 不包含开发依赖或测试证书。

## 验证与追溯

发布流水线在 Node 18/24 执行类型检查、构建、单元/Mock 测试、ZIP 校验及解压运行冒烟检查。
真实隔离面板 E2E 的既有结果和已知边界见包内 TEST_REPORT.md；发布流程不会连接你的面板。
`RELEASE.json` 记录版本、源提交及包内文件摘要，SHA256SUMS 校验整个 ZIP；这些校验和不是签名或构建来源证明。

Source commit: `{commit}`
'''
    (output_dir / 'RELEASE_NOTES.md').write_text(notes, encoding='utf-8')
    return archive


def verify(archive, version=None, commit=None, node='node'):
    if version:
        valid_version(version)
    with zipfile.ZipFile(archive) as bundle:
        names = set()
        total = 0
        for item in bundle.infolist():
            path = PurePosixPath(item.filename)
            if (item.filename in names or not path.parts or path.parts[0] != SKILL
                    or len(path.parts) < 2 or item.filename != path.as_posix()
                    or any(p in ('.', '..', '.git', 'node_modules') or p.startswith('.env')
                           for p in path.parts) or '\\' in item.filename
                    or item.is_dir() or stat.S_ISLNK(item.external_attr >> 16)):
                raise ValueError('Unsafe or unexpected ZIP member: ' + item.filename)
            relative = '/'.join(path.parts[1:])
            if not (allowed(relative) or relative in GENERATED):
                raise ValueError('Unexpected package content: ' + relative)
            names.add(item.filename)
            total += item.file_size
            if item.file_size > 5 * 1024 * 1024 or total > 25 * 1024 * 1024:
                raise ValueError('Package exceeds size limits')
        if bundle.testzip():
            raise ValueError('ZIP integrity check failed')
        payload = {name.removeprefix(SKILL + '/'): bundle.read(name) for name in names}
        if not REQUIRED <= payload.keys() or not GENERATED <= payload.keys():
            raise ValueError('Required skill/runtime files are missing')
        metadata = json.loads(payload['RELEASE.json'])
        valid_version(metadata['version'])
        if (metadata.get('schemaVersion') != 1 or
                not re.fullmatch('[a-f0-9]{40}', metadata.get('sourceCommit', '')) or
                version and metadata['version'] != version or
                commit and metadata['sourceCommit'] != commit):
            raise ValueError('Release version/source commit mismatch')
        expected = {name: sha(content) for name, content in payload.items() if name != 'RELEASE.json'}
        if metadata.get('files') != expected:
            raise ValueError('Package inventory or content digest mismatch')
        if json.loads(payload['package.json']) != runtime_manifest(metadata['version']):
            raise ValueError('Standalone ESM runtime metadata differs')
        if not payload['SKILL.md'].startswith(b'---\nname: 1panel-skills\n'):
            raise ValueError('Skill identity/frontmatter differs')
        # Use a clean temporary directory with no parent package.json or development dependencies.
        with tempfile.TemporaryDirectory(prefix='onepanel-skill-zip-') as temporary:
            root = Path(temporary) / SKILL
            for name, content in payload.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            for args in (['modules'], ['actions', 'mtls']):
                response = subprocess.run([node, 'dist/scripts/cli.js', *args], cwd=root,
                                          check=True, capture_output=True, text=True, timeout=30)
                data = json.loads(response.stdout)
                if args == ['modules']:
                    if {d['id'] for d in data} != {'openresty', 'files', 'mtls', 'monitoring',
                            'websites', 'apps', 'containers', 'logs', 'cronjobs', 'task-center', 'nodes'}:
                        raise ValueError('Packaged CLI module registration differs')
                elif not any(a['id'] == 'applyMtlsPolicy' for a in data['actions']):
                    raise ValueError('Packaged mTLS actions unavailable')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='command', required=True)
    pack = modes.add_parser('build')
    pack.add_argument('--version', required=True)
    pack.add_argument('--output-dir', type=Path, required=True)
    check = modes.add_parser('verify')
    check.add_argument('--archive', type=Path, required=True)
    check.add_argument('--version')
    check.add_argument('--commit')
    check.add_argument('--node', default='node')
    args = parser.parse_args()
    if args.command == 'build':
        archive = build(args.version, args.output_dir)
        print(archive)
    else:
        metadata = verify(args.archive, args.version, args.commit, args.node)
        print(f"ZIP verified: {metadata['version']} {metadata['sourceCommit']}; extracted CLI smoke PASS")


if __name__ == '__main__':
    main()
