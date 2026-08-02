import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("stack_base_guard.py")


class StackBaseGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        remote = Path(self.tmp.name) / "remote.git"
        subprocess.run(["git", "init", "--bare", remote], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "clone", remote, self.repo], check=True, stdout=subprocess.DEVNULL)
        self.gitrun("git", "config", "user.email", "ci@example.invalid")
        self.gitrun("git", "config", "user.name", "CI")
        (self.repo / "file").write_text("main\n")
        self.gitrun("git", "add", "file"); self.gitrun("git", "commit", "-m", "initial")
        self.gitrun("git", "branch", "-M", "main"); self.gitrun("git", "push", "-u", "origin", "main")

    def tearDown(self): self.tmp.cleanup()
    def gitrun(self, *cmd): return subprocess.run(cmd, cwd=self.repo, check=True, stdout=subprocess.PIPE, text=True)
    def branch(self, name, start="main"):
        self.gitrun("git", "checkout", "-B", name, start)
        with (self.repo / "file").open("a") as f: f.write(name + "\n")
        self.gitrun("git", "commit", "-am", name); self.gitrun("git", "push", "-u", "origin", name)
    def pr(self, head, base, state="open", merged=False):
        return {"head": {"ref": head, "repo": "acme/repo"}, "base": {"ref": base},
                "state": state, "merged_at": "2026-01-01T00:00:00Z" if merged else None}
    def guard(self, base, prs):
        data = self.repo / "prs.json"; data.write_text(json.dumps(prs))
        return subprocess.run(["python3", SCRIPT, "--base", base, "--repository", "acme/repo",
                               "--prs-json", data], cwd=self.repo, text=True, capture_output=True)

    def test_normal_main_pr_passes(self): self.assertEqual(self.guard("main", []).returncode, 0)
    def test_live_multi_level_stack_passes(self):
        self.branch("parent"); self.branch("child-base", "parent")
        result = self.guard("child-base", [self.pr("child-base", "parent"), self.pr("parent", "main")])
        self.assertEqual(result.returncode, 0, result.stdout)
    def test_live_empty_parent_branch_passes(self):
        self.gitrun("git", "branch", "empty-parent", "main")
        self.gitrun("git", "push", "origin", "empty-parent")
        result = self.guard("empty-parent", [self.pr("empty-parent", "main")])
        self.assertEqual(result.returncode, 0, result.stdout)
    def test_deleted_base_fails(self):
        result = self.guard("deleted-parent", [])
        self.assertIn("no longer exists", result.stdout); self.assertEqual(result.returncode, 1)
    def test_orphan_branch_fails(self):
        self.branch("orphan")
        self.assertIn("no open parent PR", self.guard("orphan", []).stdout)
    def test_squash_merged_parent_fails_from_pr_metadata(self):
        self.branch("squashed-parent")
        result = self.guard("squashed-parent", [self.pr("squashed-parent", "main", "closed", True)])
        self.assertEqual(result.returncode, 1)
        self.assertIn("has already merged", result.stdout)
    def test_graph_merged_parent_fails_without_pr_history(self):
        self.branch("graph-parent")
        self.gitrun("git", "checkout", "main")
        self.gitrun("git", "merge", "--ff-only", "graph-parent")
        self.gitrun("git", "push", "origin", "main")
        result = self.guard("graph-parent", [])
        self.assertEqual(result.returncode, 1)
        self.assertIn("already contained in 'main'", result.stdout)
    def test_rebased_child_retargeted_to_main_passes(self):
        self.branch("former-parent"); self.gitrun("git", "checkout", "main"); self.gitrun("git", "merge", "--ff-only", "former-parent")
        self.gitrun("git", "push", "origin", "main")
        self.assertEqual(self.guard("main", [self.pr("former-parent", "main", "closed", True)]).returncode, 0)
    def test_1713_1716_parent_merged_children_still_target_parent(self):
        # Regression: #1713 merged, while #1714-#1716 still targeted its branch.
        self.branch("pr-1713"); self.gitrun("git", "checkout", "main"); self.gitrun("git", "merge", "--ff-only", "pr-1713")
        self.gitrun("git", "push", "origin", "main")
        history = [self.pr("pr-1713", "main", "closed", True)]
        for child in ("pr-1714", "pr-1715", "pr-1716"):
            result = self.guard("pr-1713", history)
            self.assertEqual(result.returncode, 1, child)
            self.assertIn("has already merged", result.stdout)


if __name__ == "__main__": unittest.main()
