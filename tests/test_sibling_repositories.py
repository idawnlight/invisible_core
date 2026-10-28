"""Cross-repository checks follow both worktrees of one fork branch."""
import subprocess

import pytest

from _sibling_repositories import repository_root, workspace_root

pytestmark = pytest.mark.unit


def _git(directory, *arguments):
    return subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=True, capture_output=True, text=True,
    )


def _repository(directory):
    directory.mkdir()
    _git(directory, "init", "-b", "main")
    _git(directory, "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "--allow-empty", "-m", "initial")
    return directory


def test_siblings_on_the_same_branch_resolve_to_their_worktrees(tmp_path):
    core = _repository(tmp_path / "invisible_core")
    wrapper = _repository(tmp_path / "invisible_playwright")
    _git(core, "worktree", "add", "-b", "reproduce/firefox-159", str(tmp_path / "core-159"))
    _git(wrapper, "worktree", "add", "-b", "reproduce/firefox-159", str(tmp_path / "wrapper-159"))
    anchor = tmp_path / "core-159"
    assert workspace_root(anchor) == tmp_path
    assert repository_root("invisible_core", anchor) == anchor
    assert repository_root("invisible_playwright", anchor) == tmp_path / "wrapper-159"


def test_consumers_without_the_branch_resolve_to_the_primary_checkout(tmp_path):
    core = _repository(tmp_path / "invisible_core")
    consumer = _repository(tmp_path / "invisible_selenium")
    _git(core, "worktree", "add", "-b", "reproduce/firefox-159", str(tmp_path / "core-159"))
    assert repository_root("invisible_selenium", tmp_path / "core-159") == consumer


def test_detached_current_checkout_still_resolves_to_itself(tmp_path):
    core = _repository(tmp_path / "invisible_core")
    detached = tmp_path / "detached"
    _git(core, "worktree", "add", "--detach", str(detached))
    assert repository_root("invisible_core", detached) == detached
