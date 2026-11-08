import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('skill_zip', ROOT / 'tools/skill_zip.py')
skill_zip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(skill_zip)


class SkillZipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='onepanel-packaging-test-')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def build(self, name='release'):
        return skill_zip.build('v0.1.0', self.output / name)

    def rewrite(self, archive, transform):
        target = self.output / 'altered.zip'
        with zipfile.ZipFile(archive) as source, zipfile.ZipFile(target, 'w') as out:
            files = {name: source.read(name) for name in source.namelist()}
            transform(files)
            for name, content in files.items():
                out.writestr(name, content)
        return target

    def test_standalone_zip_includes_runtime_and_excludes_development_secrets(self):
        archive = self.build()
        metadata = skill_zip.verify(archive, 'v0.1.0', skill_zip.git('rev-parse', 'HEAD'))
        self.assertEqual(metadata['version'], 'v0.1.0')
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
        self.assertIn('1panel-skills/SKILL.md', names)
        self.assertIn('1panel-skills/assets/fingerprint-vector.pem', names)
        self.assertFalse(any('/tests/' in n or '/node_modules/' in n or '/.git/' in n for n in names))
        self.assertEqual((archive.parent / 'SHA256SUMS').read_text(),
                         f'{skill_zip.sha(archive.read_bytes())}  {archive.name}\n')

    def test_same_commit_build_is_byte_reproducible(self):
        self.assertEqual(self.build('one').read_bytes(), self.build('two').read_bytes())

    def test_invalid_versions_and_existing_output_are_rejected(self):
        for version in ('v01.0.0', 'v0.1', 'main', 'v0.1.0;echo secret', '../v1.0.0'):
            with self.assertRaises(ValueError):
                skill_zip.valid_version(version)
        self.build()
        with self.assertRaises(ValueError):
            self.build()

    def test_tampered_runtime_is_rejected_before_execution(self):
        altered = self.rewrite(self.build(), lambda f: f.__setitem__(
            '1panel-skills/dist/scripts/cli.js', b'throw new Error("tampered")'))
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            skill_zip.verify(altered)

    def test_traversal_or_unexpected_top_folder_is_rejected(self):
        for name in ('1panel-skills/../escape', '/tmp/escape', 'other/SKILL.md'):
            altered = self.rewrite(self.build(name.replace('/', '_')), lambda f: f.__setitem__(name, b'bad'))
            with self.assertRaises(ValueError):
                skill_zip.verify(altered)
            altered.unlink()

    def test_wrong_source_or_version_is_rejected(self):
        archive = self.build()
        for version, commit in [('v0.2.0', None), (None, '0' * 40)]:
            with self.assertRaisesRegex(ValueError, 'commit mismatch'):
                skill_zip.verify(archive, version, commit)

    def test_dirty_release_inputs_are_rejected(self):
        repo = self.output / 'dirty-fixture'
        repo.mkdir()
        for name, content in skill_zip.collect().items():
            file = repo / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(content)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Package Test',
                        '-c', 'user.email=test@example.com', 'commit', '-qm', 'fixture'], check=True)
        (repo / 'README.md').write_text('uncommitted runtime docs')
        with self.assertRaisesRegex(ValueError, 'differ from HEAD'):
            skill_zip.build('v0.1.0', self.output / 'dirty-output', repo)

    def test_symlinked_source_is_rejected(self):
        repo = self.output / 'fixture'
        repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / 'README.md').symlink_to(ROOT / 'README.md')
        subprocess.run(['git', '-C', str(repo), 'add', 'README.md'], check=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            skill_zip.collect(repo)


if __name__ == '__main__':
    unittest.main()
