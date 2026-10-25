#!/usr/bin/env python3
"""Real local filesystem precondition regression; not a macOS result."""
import ast, importlib.util, json, os, platform, stat, subprocess, sys, tempfile, unittest
from pathlib import Path

here = Path(__file__).resolve().parent;target = here/'darwin-production-lifecycle.py'
if not target.exists(): target = here.parents[1]/'tests/darwin-production-lifecycle.py'
spec = importlib.util.spec_from_file_location('production_installer_model', target)
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
tree = ast.parse(target.read_text())
remove = next(item.value.value for item in ast.walk(tree) if isinstance(item, ast.Assign) and
    any(isinstance(name, ast.Name) and name.id == 'remove_parent' for name in item.targets) and isinstance(item.value, ast.Constant))


@unittest.skipUnless(platform.system() == 'Linux' and os.getuid() == 0, 'Explicit root-owned local Linux filesystem fixture')
class InstallationParent(unittest.TestCase):
    def invoke(self, code, *arguments):
        result = subprocess.run([sys.executable, '-c', code, *map(str, arguments)], capture_output=True, text=True, timeout=10)
        print(json.dumps({'scope': 'real Linux filesystem, hosted Darwin condition not inferred',
            'argv': [sys.executable, '-c', code, *map(str, arguments)], 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}))
        return result

    def test_same_child_mkdir_before_after_explicit_missing_parent(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)/'PrivilegedHelperTools';child = parent/'KnowledgeVerification-state'
            argv = ['/bin/mkdir', '-m', '0700', str(child)]
            before = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            print(json.dumps({'phase': 'before', 'argv': argv, 'returncode': before.returncode, 'stdout': before.stdout, 'stderr': before.stderr}))
            self.assertEqual(before.returncode, 1);self.assertFalse(parent.exists())
            prepared = self.invoke(module.INSTALL_PARENT_SCRIPT, parent);self.assertEqual(prepared.returncode, 0)
            facts = json.loads(prepared.stdout);self.assertFalse(facts['exists_before']);self.assertTrue(facts['created'])
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
            after = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            print(json.dumps({'phase': 'after', 'argv': argv, 'returncode': after.returncode, 'stdout': after.stdout, 'stderr': after.stderr}))
            self.assertEqual(after.returncode, 0)
            # Final cleanup cannot remove a parent with even one unexpected
            # remaining child; rmdir has no recursive fallback.
            blocked = self.invoke(remove, parent, json.dumps(facts['identity']));self.assertNotEqual(blocked.returncode, 0)
            self.assertTrue(child.is_dir());child.rmdir()
            closed = self.invoke(remove, parent, json.dumps(facts['identity']));self.assertEqual(closed.returncode, 0)
            self.assertFalse(parent.exists())

    def test_existing_safe_parent_is_read_only_and_unsafe_parent_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)/'existing';parent.mkdir(mode=0o755);before = parent.stat()
            result = self.invoke(module.INSTALL_PARENT_SCRIPT, parent);facts = json.loads(result.stdout)
            self.assertEqual(result.returncode, 0);self.assertFalse(facts['created']);self.assertTrue(facts['exists_before'])
            after = parent.stat();self.assertEqual((after.st_dev, after.st_ino, after.st_mode), (before.st_dev, before.st_ino, before.st_mode))
            parent.chmod(0o777);result = self.invoke(module.INSTALL_PARENT_SCRIPT, parent)
            self.assertNotEqual(result.returncode, 0);self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o777)
            self.assertEqual(json.loads(result.stdout)['errno'], 1)
            link = Path(folder)/'link';link.symlink_to(parent, target_is_directory=True)
            result = self.invoke(module.INSTALL_PARENT_SCRIPT, link);self.assertNotEqual(result.returncode, 0)
            self.assertTrue(link.is_symlink());self.assertTrue(json.loads(result.stdout)['symlink_before'])


if __name__ == '__main__': unittest.main()
