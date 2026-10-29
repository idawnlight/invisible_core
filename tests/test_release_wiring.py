"""GitHub artifact publishing and the real pre-push hook remain connected."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import invisible_core

# From THIS FILE, not from where the module is installed: the latter is the
# repo under an editable install and .../Lib under a regular one, so the same
# expression means two different things depending on how it was installed.
REPO_ROOT = Path(__file__).resolve().parents[1]
GATE = REPO_ROOT / "scripts" / "version_gate.py"
HOOK = REPO_ROOT / ".githooks" / "pre-push"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"
INSTALLER = REPO_ROOT / "scripts" / "install_hooks.py"

pytestmark = pytest.mark.integration

# These files are outside both build targets, so they are absent from an
# installed copy and from the sdist. Skipping is correct there; failing would
# make `pytest` red for a user who merely installed the package.
_in_checkout = GATE.exists()
requires_checkout = pytest.mark.skipif(
    not _in_checkout, reason="not a source checkout - the release wiring does not ship")


@requires_checkout
def test_every_layer_of_the_wiring_exists():
    missing = [str(p) for p in (GATE, HOOK, WORKFLOW, INSTALLER) if not p.exists()]
    assert missing == [], (
        "the publish gate is wired to nothing again:\n  " + "\n  ".join(missing))


@requires_checkout
def test_the_hook_is_tracked_as_executable():
    """The claim and its measurement live in the helper, which every repo that
    pins this package calls - this hook was tracked 100644 in every one of
    them (three repos when this was found, two since invisible_firefox was
    deleted 2026-08-18), so a per-repo copy of the assertion would have been
    another copy of one finding."""
    from invisible_core.testing import assert_hook_is_executable

    assert_hook_is_executable(REPO_ROOT)


# ------------------------------------------------------------------ layer 2

@requires_checkout
def test_the_upload_job_cannot_start_without_the_gate_job():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    upload = jobs["upload"]
    needs = upload.get("needs")
    assert "gate" in ([needs] if isinstance(needs, str) else needs)
    assert upload["permissions"]["contents"] == "write"
    assert jobs["gate"].get("permissions", {}).get("contents") != "write"
    assert any(step.get("uses", "").startswith("actions/download-artifact@")
               for step in upload["steps"])



@requires_checkout
def test_github_releases_do_not_require_a_python_index_publication():
    import yaml

    text = WORKFLOW.read_text(encoding="utf-8")
    jobs = yaml.safe_load(text)["jobs"]
    assert "already-published" not in jobs
    assert "pypi.org" not in text
    assert "pypi-publish" not in text
    assert "id-token" not in text
    assert "twine" not in text



@requires_checkout
def test_no_job_uploads_without_going_through_the_gate():
    import yaml

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    publishers = []
    for name, job in jobs.items():
        commands = "\n".join(step.get("run", "") for step in job.get("steps", []))
        if "gh release create" in commands or "gh release upload" in commands:
            publishers.append(name)
            needs = job.get("needs")
            assert "gate" in ([needs] if isinstance(needs, str) else needs or [])
            assert "sha256sum --check SHA256SUMS" in commands
    assert publishers == ["upload"]



@requires_checkout
def test_the_gate_tests_and_builds_the_tagged_source_before_artifact_upload():
    import yaml

    gate = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["gate"]
    steps = gate["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert "RELEASE_TAG" in checkout["with"]["ref"]
    runs = [step.get("run", "") for step in steps]
    test_index = next(i for i, run in enumerate(runs) if "python -m pytest" in run)
    build_index = next(i for i, run in enumerate(runs) if "python -m invisible_core.github_release" in run)
    artifact_index = next(i for i, step in enumerate(steps)
                          if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert test_index < build_index < artifact_index
    assert '--tag "$RELEASE_TAG"' in runs[build_index]



# ------------------------------------------------------------------ layer 3
#
# The hook is a STUB now. The policy it hands over to is `invisible_core.hooks`,
# driven against its own known-bad inputs in test_hook_policy.py - forty-odd
# cases, none of which spawn a shell. What is left to check here is the handover
# itself, which is real code and has its own ways of failing silently: finding
# an interpreter, reaching the policy at all, and passing stdin through. git
# feeds the refs being pushed on stdin, and a stub that swallowed them would
# leave every range-dependent gate reporting "nothing to scan" - correctly, and
# with no coverage. That happened, in the shell version, for a day.
#
# So these run the REAL stub, through a real shell, against fake repositories.


def _fake_repo(tmp_path, *, block="pytest = false\npin = false") -> Path:
    """A checkout carrying the real stub and a policy declaration."""
    repo = tmp_path / "repo"
    (repo / ".githooks").mkdir(parents=True)
    (repo / ".githooks" / "pre-push").write_text(
        HOOK.read_text(encoding="utf-8"), encoding="utf-8")
    body = '[project]\nname = "pkg"\nversion = "1.0"\n'
    if block is not None:
        body += "\n[tool.invisible.hooks]\n" + block + "\n"
    (repo / "pyproject.toml").write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True,
                   capture_output=True, text=True)
    return repo


def _push(repo: Path, sh: str, stdin: str, **env) -> tuple[int, str]:
    r = subprocess.run(
        [sh, str(repo / ".githooks" / "pre-push"), "origin",
         "https://example.invalid/x.git"],
        cwd=str(repo), input=stdin, capture_output=True, text=True,
        env={**_env(), "INVISIBLE_GATE_PYTHON": sys.executable, **env})
    return r.returncode, (r.stdout or "") + (r.stderr or "")


@requires_checkout
def test_the_stub_reaches_the_shared_policy_and_says_what_ran(tmp_path):
    """End to end: the real stub, a real shell, the real policy module."""
    sh = _find_sh()
    if sh is None:
        pytest.skip("no POSIX shell available to run the hook")
    code, text = _push(_fake_repo(tmp_path), sh,
                       "refs/heads/main a refs/heads/main b\n")
    assert code == 0, text
    assert "push proceeding" in text, text


@requires_checkout
def test_the_stub_passes_the_pushed_refs_through(tmp_path):
    """The failure that hid for a day in the shell version.

    A `while read` in the first gate drained stdin, so the second one found no
    range and reported "no commit messages scanned" on every push - a true
    statement, printed by a gate covering nothing. Nothing downstream can tell
    "there was no range" from "the range never arrived", so it is asserted here,
    at the only place that can: a release tag is visible ONLY through stdin.
    """
    sh = _find_sh()
    if sh is None:
        pytest.skip("no POSIX shell available to run the hook")
    repo = _fake_repo(tmp_path)
    code, text = _push(repo, sh, "refs/tags/v1.0 aaaa refs/tags/v1.0 0000\n")
    assert "release tag" in text, (
        "the refs did not survive the handover, so no range-dependent gate "
        "could have run:\n" + text)
    # And the gate it starts is the publish gate, which refuses here: this
    # throwaway repo is not a publishable project.
    assert code != 0, text


@requires_checkout
def test_an_ordinary_push_never_starts_the_publish_gate(tmp_path):
    """It builds the project twice. A hook that costs a minute on every push is
    a hook people delete, and deleting it takes every other gate with it."""
    sh = _find_sh()
    if sh is None:
        pytest.skip("no POSIX shell available to run the hook")
    code, text = _push(_fake_repo(tmp_path), sh,
                       "refs/heads/main a refs/heads/main b\n")
    assert code == 0, text
    assert "release tag" not in text
    assert "publish gate" not in text


@requires_checkout
def test_the_stub_refuses_when_it_cannot_reach_the_policy(tmp_path):
    """"The gate is not here" is the condition under which skipping is most
    tempting and least defensible: from the outside it is indistinguishable
    from a gate that was deleted on purpose.

    Driven for real, against a checkout whose own `src/` shadows the installed
    core with one that has no policy in it. That is the shape this actually
    takes: the stub puts `src` FIRST on purpose, so a checkout gates itself with
    the tree being pushed, and a half-written tree therefore wins over whatever
    is installed. Emptying PYTHONPATH instead proved nothing here - the core is
    installed, so it stayed importable and the test skipped itself.
    """
    sh = _find_sh()
    if sh is None:
        pytest.skip("no POSIX shell available to run the hook")
    repo = _fake_repo(tmp_path)
    (repo / "src" / "invisible_core").mkdir(parents=True)
    (repo / "src" / "invisible_core" / "__init__.py").write_text("", encoding="utf-8")
    code, text = _push(repo, sh, "refs/heads/main a refs/heads/main b\n")
    assert code != 0, "a push went out past a hook that could not check it"
    assert "REFUSED" in text and "cannot import" in text, text


@requires_checkout
def test_the_stub_refuses_when_there_is_no_interpreter_at_all(tmp_path):
    """No python means no gate can run, in either direction. The shell version
    resolved an interpreter into a variable and then called bare `python`
    anyway, in one of the three copies."""
    sh = _find_sh()
    if sh is None:
        pytest.skip("no POSIX shell available to run the hook")
    repo = _fake_repo(tmp_path)
    empty = str(tmp_path / "empty-bin")
    (tmp_path / "empty-bin").mkdir()
    r = subprocess.run(
        [sh, str(repo / ".githooks" / "pre-push"), "origin", "https://x.invalid/y"],
        cwd=str(repo), input="refs/tags/v1.0 a refs/tags/v1.0 0\n",
        capture_output=True, text=True,
        env={"PATH": empty, "SYSTEMROOT": _env().get("SYSTEMROOT", "")})
    text = (r.stdout or "") + (r.stderr or "")
    assert r.returncode != 0, "a release tag went out with no interpreter to gate it"
    assert "REFUSED" in text and "no python" in text.lower()


@requires_checkout
def test_the_stub_works_from_any_directory(tmp_path):
    """git runs a hook from the top level, but a worktree, a submodule or a
    human running it by hand does not. The stub cd's to its own parent, and the
    policy reads the repo from there."""
    sh = _find_sh()
    if sh is None:
        pytest.skip("no POSIX shell available to run the hook")
    repo = _fake_repo(tmp_path)
    (repo / "deep" / "deeper").mkdir(parents=True)
    r = subprocess.run(
        [sh, str(repo / ".githooks" / "pre-push"), "origin", "https://x.invalid/y"],
        cwd=str(repo / "deep" / "deeper"),
        input="refs/heads/main a refs/heads/main b\n",
        capture_output=True, text=True,
        env={**_env(), "INVISIBLE_GATE_PYTHON": sys.executable})
    text = (r.stdout or "") + (r.stderr or "")
    assert r.returncode == 0, text
    assert "push proceeding" in text


# ---------------------------------------------- the hooks are actually armed

@requires_checkout
def test_the_hooks_are_armed_in_this_clone():
    """The reminder that does not depend on anybody remembering.

    A checked-in hook directory does nothing until core.hooksPath points at it,
    and git will not do that for you. Running the test suite is the one thing a
    developer does constantly, so the suite is where this belongs.

    The claim and its measurement live once, in the helper, because every repo
    that pins this package makes it (three repos until invisible_firefox was
    deleted 2026-08-18, two since) - until 2026-07-27 only this one did, and
    the other two shipped a hook that nothing armed and nothing checked was
    armed.
    """
    from invisible_core.testing import assert_hooks_are_armed

    assert_hooks_are_armed(REPO_ROOT)


def _find_sh():
    for name in ("sh", "bash"):
        from shutil import which
        p = which(name)
        if p:
            return p
    for p in (r"C:\Program Files\Git\bin\sh.exe", r"C:\Program Files\Git\usr\bin\sh.exe"):
        if Path(p).exists():
            return p
    return None


def _env():
    import os
    return {k: v for k, v in os.environ.items() if k != "INVISIBLE_GATE_PYTHON"}


@requires_checkout
def test_the_hook_and_workflow_use_the_github_release_backend():
    import tomllib

    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["invisible"]["hooks"]["release_backend"] == "github"
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "python -m invisible_core.github_release" in workflow
    assert "gh release create" in workflow
    assert "--verify-tag" in workflow
