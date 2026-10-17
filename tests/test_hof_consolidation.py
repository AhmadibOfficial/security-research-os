"""Safety and repeatability tests for the consolidated, source-only HOF verifier."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "hof_verify", ROOT / "scripts" / "verify_hof_portfolio.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConsolidatedVerificationTests(unittest.TestCase):
    def test_exactly_eleven_staged_projects_plus_android(self):
        self.assertEqual(set(module.SOURCES), set(range(2, 13)))
        self.assertEqual(len({name for name, _, _ in module.SOURCES.values()}), 11)

    def test_all_git_refs_are_pinned_to_commit_sha(self):
        for _, branch, sha in module.SOURCES.values():
            self.assertTrue(branch.startswith("feature/hof-"))
            self.assertEqual(len(sha), 40)
            self.assertTrue(all(c in "0123456789abcdef" for c in sha))

    def repo(self, root: Path):
        def git(*args):
            r = subprocess.run(["git", *args], cwd=root,
                               capture_output=True, text=True, check=True)
            return r.stdout.strip()
        git("init", "-b", "main")
        git("config", "user.email", "synthetic@example.test")
        git("config", "user.name", "Synthetic")
        return git

    def test_local_git_archive_reconstructs_only_approved_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            git = self.repo(root)
            source = root / "projects" / "sample" / "tests"
            source.mkdir(parents=True)
            (source / "test_synthetic.py").write_text("assert True\n")
            git("add", ".")
            git("commit", "-m", "synthetic fixture")
            sha = git("rev-parse", "HEAD")
            output = Path(tmp) / "scratch"
            output.mkdir()
            module.from_ref(root, "HEAD", sha, "projects/sample", output)
            self.assertEqual((output / "projects/sample/tests/test_synthetic.py").read_text(),
                             "assert True\n")

    def test_wrong_commit_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            git = self.repo(root)
            (root / "portfolio.json").write_text("{}")
            git("add", ".")
            git("commit", "-m", "synthetic fixture")
            output = Path(tmp) / "scratch"
            output.mkdir()
            with self.assertRaises(ValueError):
                module.from_ref(root, "HEAD", "0" * 40, "portfolio.json", output)

    def test_git_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            git = self.repo(root)
            source = root / "projects" / "sample"
            source.mkdir(parents=True)
            (source / "unsafe").symlink_to("/etc/passwd")
            git("add", ".")
            git("commit", "-m", "synthetic unsafe link")
            sha = git("rev-parse", "HEAD")
            output = Path(tmp) / "scratch"
            output.mkdir()
            with self.assertRaises(ValueError):
                module.from_ref(root, "HEAD", sha, "projects/sample", output)

    def test_synthetic_python_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = module.execute(["python3", "-c", "print('OK')"], root)
            self.assertEqual(run["status"], "passed")
            self.assertIn("OK", run["stdout"])


if __name__ == "__main__":
    unittest.main()
