"""A commit, an annotated tag or a tagger without a GitHub noreply address fails the run.

`scripts/ci_noreply_identity.py` is the CI twin of the local pre-push check
(`hooks.foreign_identities`), and it runs on a runner that has only git and
Python, as a reusable workflow every repository of the organisation calls. What
is held here:

  1. The allow-list: `@users.noreply.github.com` and the address of
     GitHub's web flow, nothing that merely contains them, never an empty one.
  2. The three roles: author, committer, tagger. A real address in any of them
     is a red run, and the run prints it masked, never whole.
  3. The range is what THIS event makes public: a `git merge origin/main` inside
     a branch must not bring main's old commits in (in push mode and in
     pull-request mode), and `refs/remotes/origin/HEAD` (a symbolic ref to main)
     must not hide the commits of a push to main.
  4. A deleted ref is nothing to check; an unknown commit is exit 2, never green.
  5. The workflow files: the gate of ci.yml waits for the job, and the reusable
     workflow reads the judge from main of the core with the whole history.

The repositories are built here with invented addresses; git is isolated from
the host (no system or global config, a HOME of its own) so the identity of the
machine running the tests cannot leak in or change the result.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_noreply_identity.py"
WORKFLOWS = ROOT / ".github" / "workflows"

ZEROS = "0" * 40
NOREPLY = "1+someone@users.noreply.github.com"
# Written in pieces: the local disclosure scan reads any address that is not a
# noreply one or example.* as a leak, and these are look-alikes on purpose.
def addr(local: str, domain: str) -> str:
    return local + "@" + domain


WEB_FLOW = addr("noreply", "github.com")
REAL = "someone@example.org"
REAL_MASKED = "s***@e***.org"
OTHER_REAL = "another@example.org"


def _load_script():
    spec = importlib.util.spec_from_file_location("ci_noreply_identity", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Repo:
    """A throwaway repository whose remote is simulated with `refs/remotes/origin/*`."""

    def __init__(self, tmp_path: Path):
        self.dir = tmp_path / "repo"
        self.dir.mkdir()
        empty = tmp_path / "gitconfig"
        empty.write_text("", encoding="utf-8")
        home = tmp_path / "home"
        home.mkdir()
        # A hook runs the suite with GIT_DIR and friends exported: drop them, or
        # these commits would land in the repository being pushed.
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(empty),
                    "HOME": str(home), "USERPROFILE": str(home),
                    "GIT_AUTHOR_NAME": "A Person", "GIT_COMMITTER_NAME": "A Person",
                    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"})
        self.env = env
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str, author: str = NOREPLY, committer: str | None = None) -> str:
        env = dict(self.env, GIT_AUTHOR_EMAIL=author, GIT_COMMITTER_EMAIL=committer or author)
        proc = subprocess.run(["git", *args], cwd=self.dir, env=env, capture_output=True,
                              text=True, encoding="utf-8")
        assert proc.returncode == 0, f"git {args}: {proc.stderr}"
        return proc.stdout.strip()

    def commit(self, name: str, author: str = NOREPLY, committer: str | None = None) -> str:
        self.git("commit", "-q", "--allow-empty", "-m", name, author=author, committer=committer)
        return self.git("rev-parse", "HEAD")

    def remote(self, name: str, sha: str) -> None:
        self.git("update-ref", f"refs/remotes/origin/{name}", sha)

    def origin_head_is_main(self) -> None:
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")

    def tag(self, name: str, sha: str, tagger: str) -> str:
        self.git("tag", "-a", name, "-m", name, sha, author=tagger)
        return self.git("rev-parse", f"refs/tags/{name}")

    def run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.dir, env=self.env,
                              capture_output=True, text=True, encoding="utf-8")

    def push(self, ref: str, before: str, after: str) -> subprocess.CompletedProcess:
        return self.run("--event", "push", "--ref", ref, "--before", before, "--after", after)

    def pull_request(self, base: str, head: str, base_ref: str = "main") -> subprocess.CompletedProcess:
        return self.run("--event", "pull_request", "--base", base, "--head", head,
                        "--base-ref", base_ref)


def out(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout + proc.stderr


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    r = Repo(tmp_path)
    root = r.commit("root")
    r.remote("main", root)
    r.origin_head_is_main()
    r.root = root
    return r


# ------------------------------------------------------------ the allow-list

@pytest.mark.parametrize("email", [
    addr("x", "noreply.github.com.example.org"),
    addr("noreply", "github.com.example"),
    "users.noreply.github.com",
    addr("x", "users.noreply.github.com.example.org"),
    addr("someone-noreply", "github.com"),
    REAL,
    "",
])
def test_an_address_that_only_looks_like_noreply_is_not_valid(email):
    assert not _load_script().is_valid(email)


@pytest.mark.parametrize("email", [NOREPLY, "someone@users.noreply.github.com", WEB_FLOW])
def test_the_noreply_addresses_are_valid(email):
    assert _load_script().is_valid(email)


@pytest.mark.parametrize("email, masked", [
    (REAL, REAL_MASKED),
    (addr("a.b", "mail.example.co.uk"), "a***@m***.uk"),
    ("nodomain", "n***"),
    ("local@host", "l***@h***"),
    ("", "<empty>"),
])
def test_an_address_is_masked_to_its_first_letters_and_its_tld(email, masked):
    assert _load_script().mask(email) == masked


# ------------------------------------------------------------- the three roles

def test_a_real_author_in_a_new_branch_fails_and_is_not_printed(repo):
    sha = repo.commit("work", author=REAL, committer=NOREPLY)
    repo.remote("feat", sha)
    proc = repo.push("refs/heads/feat", ZEROS, sha)
    assert proc.returncode == 1
    assert f"{sha[:12]} author: {REAL_MASKED}" in proc.stdout
    assert REAL not in out(proc)


def test_a_real_committer_alone_fails_with_its_own_role(repo):
    sha = repo.commit("work", author=NOREPLY, committer=REAL)
    proc = repo.push("refs/heads/feat", ZEROS, sha)
    assert proc.returncode == 1
    assert f"{sha[:12]} committer: {REAL_MASKED}" in proc.stdout
    assert " author:" not in proc.stdout
    assert REAL not in out(proc)


def test_an_empty_address_fails(repo):
    sha = repo.commit("work", author="", committer=NOREPLY)
    proc = repo.push("refs/heads/feat", ZEROS, sha)
    assert proc.returncode == 1
    assert f"{sha[:12]} author: <empty>" in proc.stdout


def test_every_address_noreply_passes_including_the_web_flow_committer(repo):
    first = repo.commit("one", author=NOREPLY, committer=WEB_FLOW)
    second = repo.commit("two", author="x@users.noreply.github.com", committer=NOREPLY)
    proc = repo.push("refs/heads/feat", ZEROS, second)
    assert proc.returncode == 0, out(proc)
    assert "commits=2" in proc.stdout
    assert first != second


def test_a_tag_with_a_real_tagger_on_a_commit_main_already_has_fails(repo):
    tag = repo.tag("v1", repo.root, tagger=REAL)
    proc = repo.push("refs/tags/v1", ZEROS, tag)
    assert proc.returncode == 1
    assert f"{tag[:12]} tagger: {REAL_MASKED}" in proc.stdout
    assert REAL not in out(proc)
    assert "commits=0" in proc.stdout


def test_a_tag_pushed_with_its_commit_as_after_still_has_its_tagger_judged(repo):
    tag = repo.tag("v1", repo.root, tagger=REAL)
    proc = repo.push("refs/tags/v1", ZEROS, repo.root)
    assert proc.returncode == 1, out(proc)
    assert f"{tag[:12]} tagger: {REAL_MASKED}" in proc.stdout


def test_a_tag_with_a_noreply_tagger_passes(repo):
    tag = repo.tag("v1", repo.root, tagger=NOREPLY)
    proc = repo.push("refs/tags/v1", ZEROS, tag)
    assert proc.returncode == 0, out(proc)


def test_a_tag_on_a_new_commit_with_a_real_author_fails_on_the_commit(repo):
    sha = repo.commit("release", author=REAL, committer=NOREPLY)
    tag = repo.tag("v2", sha, tagger=NOREPLY)
    proc = repo.push("refs/tags/v2", ZEROS, tag)
    assert proc.returncode == 1
    assert f"{sha[:12]} author: {REAL_MASKED}" in proc.stdout
    assert "tagger" not in proc.stdout


def test_a_lightweight_tag_is_judged_by_its_commit(repo):
    sha = repo.commit("release", author=NOREPLY, committer=NOREPLY)
    repo.git("tag", "v3", sha)
    proc = repo.push("refs/tags/v3", ZEROS, sha)
    assert proc.returncode == 0, out(proc)


# ------------------------------------------- the range: only what the event adds

def _branch_with_a_merge_of_public_main(repo: Repo):
    """main (public) has an old commit with a real address; the branch merges it in."""
    old = repo.commit("old, on main", author=OTHER_REAL, committer=OTHER_REAL)
    repo.remote("main", old)
    repo.git("checkout", "-q", "-b", "feat", repo.root)
    own = repo.commit("own work")
    repo.git("merge", "-q", "--no-ff", "-m", "merge main", old)
    merge = repo.git("rev-parse", "HEAD")
    repo.remote("feat", merge)
    return old, own, merge


def test_a_merge_of_public_main_into_a_branch_brings_no_old_commit_in_push_mode(repo):
    old, own, merge = _branch_with_a_merge_of_public_main(repo)
    proc = repo.push("refs/heads/feat", own, merge)
    assert proc.returncode == 0, out(proc)
    assert "commits=1" in proc.stdout
    assert old[:12] not in out(proc)


def test_a_merge_of_public_main_into_a_branch_brings_no_old_commit_in_pull_request_mode(repo):
    old, own, merge = _branch_with_a_merge_of_public_main(repo)
    # --base is the OLD tip of main, as a pull request opened before main moved.
    proc = repo.pull_request(repo.root, merge)
    assert proc.returncode == 0, out(proc)
    assert "commits=2" in proc.stdout
    assert old[:12] not in out(proc)


def test_after_such_a_merge_only_the_new_bad_commit_is_listed(repo):
    old, own, merge = _branch_with_a_merge_of_public_main(repo)
    bad = repo.commit("new work", author=REAL, committer=NOREPLY)
    repo.remote("feat", bad)
    push = repo.push("refs/heads/feat", merge, bad)
    assert push.returncode == 1
    assert push.stdout.count(" author:") + push.stdout.count(" committer:") == 1
    assert f"{bad[:12]} author: {REAL_MASKED}" in push.stdout
    assert old[:12] not in out(push)
    pr = repo.pull_request(repo.root, bad)
    assert pr.returncode == 1
    assert f"{bad[:12]} author: {REAL_MASKED}" in pr.stdout
    assert pr.stdout.count(" author:") + pr.stdout.count(" committer:") == 1
    assert old[:12] not in out(pr)


def test_a_push_to_main_is_checked_although_origin_head_points_at_main(repo):
    bad = repo.commit("to main", author=REAL, committer=NOREPLY)
    repo.remote("main", bad)  # what the checkout of the push does
    refs = repo.git("for-each-ref", "--format=%(refname) %(symref)", "refs/remotes/origin/")
    assert "refs/remotes/origin/HEAD refs/remotes/origin/main" in refs
    proc = repo.push("refs/heads/main", repo.root, bad)
    assert proc.returncode == 1
    assert f"{bad[:12]} author: {REAL_MASKED}" in proc.stdout


def test_a_force_pushed_branch_whose_old_tip_is_gone_is_judged_as_new(repo):
    sha = repo.commit("rewritten", author=REAL, committer=NOREPLY)
    gone = "1" * 40
    proc = repo.push("refs/heads/feat", gone, sha)
    assert proc.returncode == 1
    assert f"{sha[:12]} author: {REAL_MASKED}" in proc.stdout


def test_a_manual_run_judges_what_the_default_branch_does_not_have(repo):
    clean = repo.commit("clean")
    ok = repo.run("--event", "other", "--head", clean, "--default-ref", "main")
    assert ok.returncode == 0, out(ok)
    bad = repo.commit("bad", author=REAL, committer=NOREPLY)
    proc = repo.run("--event", "other", "--head", bad, "--default-ref", "main")
    assert proc.returncode == 1
    assert f"{bad[:12]} author: {REAL_MASKED}" in proc.stdout
    on_main = repo.run("--event", "other", "--head", repo.root, "--default-ref", "main")
    assert on_main.returncode == 0, out(on_main)


# ------------------------------------------------ errors are never a green run

def test_a_deleted_ref_has_nothing_to_check(repo):
    proc = repo.push("refs/heads/feat", repo.root, ZEROS)
    assert proc.returncode == 0, out(proc)
    assert "deleted" in proc.stdout


def _refused(proc: subprocess.CompletedProcess) -> bool:
    """Exit 2 AND the script's own message: a missing script is also exit 2."""
    return proc.returncode == 2 and "noreply-identity: ERROR" in proc.stderr


def test_an_unknown_commit_is_exit_two(repo):
    assert _refused(repo.push("refs/heads/feat", ZEROS, "2" * 40))
    assert _refused(repo.pull_request(repo.root, "2" * 40))
    assert _refused(repo.run("--event", "other", "--head", "2" * 40, "--default-ref", "main"))


def test_missing_arguments_are_exit_two(repo):
    assert _refused(repo.run("--event", "push", "--ref", "refs/heads/feat"))
    assert _refused(repo.run("--event", "pull_request", "--head", repo.root))
    assert _refused(repo.run("--event", "other", "--head", repo.root))
    assert _refused(repo.run("--event", "other", "--head", repo.root,
                             "--default-ref", "no-such-branch"))


def test_a_ref_that_is_neither_a_branch_nor_a_tag_is_exit_two(repo):
    assert _refused(repo.push("refs/pull/1/merge", ZEROS, repo.root))


# ------------------------------------------------------------- the workflows

def _spec(name: str) -> dict:
    spec = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    if True in spec and "on" not in spec:  # PyYAML reads the key `on` as True
        spec["on"] = spec.pop(True)
    return spec


def test_the_gate_waits_for_the_noreply_job_and_requires_it_green():
    spec = _spec("ci.yml")
    job = spec["jobs"]["noreply-identity"]
    assert job["uses"] == "./.github/workflows/noreply-identity.yml"
    gate = spec["jobs"]["gate"]
    assert "noreply-identity" in gate["needs"]
    script = "\n".join(s.get("run", "") for s in gate["steps"])
    assert 'echo "noreply-identity: ${{ needs.noreply-identity.result }}"' in script
    assert 'test "${{ needs.noreply-identity.result }}" = "success"' in script


def test_the_reusable_workflow_reads_its_judge_from_main_of_the_core_with_the_history():
    spec = _spec("noreply-identity.yml")
    assert "workflow_call" in spec["on"]
    steps = spec["jobs"]["noreply-identity"]["steps"]
    judged = [s for s in steps if s.get("uses", "").startswith("actions/checkout")
              and "repository" not in s.get("with", {})]
    assert judged and judged[0]["with"]["fetch-depth"] == 0
    judge = [s for s in steps if s.get("with", {}).get("repository") == "idawnlight/invisible_core"]
    assert judge and judge[0]["with"]["ref"] == "main"
    assert "ci_noreply_identity.py" in judge[0]["with"]["sparse-checkout"]
    assert spec["permissions"] == {"contents": "read"}


def test_the_judged_repository_is_fetched_without_trees_or_files():
    """The engine series is about 5 GB with its trees: a full clone did not finish in the
    job's minutes. Commits and tags are all the judge reads."""
    steps = _spec("noreply-identity.yml")["jobs"]["noreply-identity"]["steps"]
    judged = [s for s in steps if s.get("uses", "").startswith("actions/checkout")
              and "repository" not in s.get("with", {})][0]["with"]
    assert judged["filter"] == "tree:0"
    assert judged["sparse-checkout"].split() == ["/.github/"]
    assert judged["sparse-checkout-cone-mode"] is False
