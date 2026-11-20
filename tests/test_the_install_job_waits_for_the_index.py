"""The wait of the install job for the index (no network, no browser).

Ledger #250 of 63.66.0: the two jobs "install from index and launch" failed in
``test_user_install_e2e.py::test_the_version_the_index_serves_matches_this_checkout``, which saw 62.65.0 from the index
seconds after the upload, on both runners: the step that waited for the index had asked the JSON endpoint of the version,
which answered, while the install that followed was served an older page (the wrapper's ledger #476 of 0.50.1 failed
the same way; its fix is 299fc9f). The wait now asks the tool that installs: uv (the README's way in, the user path of the
job), after uv is installed, and goes on only after it answered yes several times in a row, because one answer proves that
one request saw the version, not that the next is served by the same node of the index. The script of the step is run
here as it stands in the workflow, in a checkout of version 9.9.9, with a ``uv`` that answers as a lagging index does.

Known-bad input: the step as it was (it asked pip; one answer was enough) - the tests below see pip's answer taken for uv's,
a single yes enough, and a call that hangs wait for it.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import textwrap

import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "user-install.yml"


def _release_backend() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["tool"]["invisible"]["hooks"].get("release_backend", "pypi")


pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        _release_backend() == "github",
        reason="fork uses release_backend='github' (Git tag install, not PyPI index wait)",
    ),
]


def _wait_script() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("- name: wait for the index to serve this version")
    m = re.search(r"python - <<'PY'\n(.*?)\n\s*PY\n", text[start:], re.S)
    assert m, "the wait step has no python script"
    return textwrap.dedent(m.group(1)) + "\n"


def _checkout(tmp_path):
    """A checkout named invisible-core whose tree derives 0.99.0 (src/invisible_core/_version.py) while the ledger pull request records 9.9.9
    (INVCORE_E2E_VERSION, what the step before the wait computes): the wait is about the latter."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "invisible-core"\ndynamic = ["version"]\n', encoding="utf-8")
    pkg = tmp_path / "src" / "invisible_core"
    pkg.mkdir(parents=True)
    (pkg / "_version.py").write_text('__version__ = "0.99.0"\n', encoding="utf-8")


def _run_the_wait(tmp_path, plan, *, seconds=3.0, poll=0.05, call_seconds=None, confirmations=None):
    """Run the wait with a uv that answers call number i as plan[i] says (the last letter repeats): y = resolves it, n = no such version,
    h = does not answer (sleeps 30 s). Returns (completed process, the calls uv got, with their stdin)."""
    _checkout(tmp_path)
    log = tmp_path / "uv-calls.jsonl"
    shim = tmp_path / "uv_shim.py"
    shim.write_text(textwrap.dedent("""
        import json, pathlib, sys, time
        log = pathlib.Path(%r)
        n = len(log.read_text().splitlines()) if log.exists() else 0
        with log.open("a") as f:
            f.write(json.dumps({"args": sys.argv[1:], "stdin": sys.stdin.read()}) + chr(10))
        plan = %r
        what = plan[min(n, len(plan) - 1)]
        if what == "h":
            time.sleep(30)
        if what == "y":
            sys.exit(0)
        sys.stderr.write("  x No solution found when resolving dependencies: invisible-core==9.9.9 was not found in the package registry" + chr(10))
        sys.exit(1)
    """) % (str(log), plan), encoding="utf-8")
    env = dict(os.environ, INDEX_WAIT_UV=json.dumps([sys.executable, str(shim)]), INDEX_WAIT_SECONDS=str(seconds), INDEX_WAIT_POLL=str(poll),
               INVCORE_E2E_VERSION="9.9.9")
    if call_seconds is not None:
        env["INDEX_WAIT_CALL_SECONDS"] = str(call_seconds)
    if confirmations is not None:
        env["INDEX_WAIT_CONFIRMATIONS"] = str(confirmations)
    try:
        r = subprocess.run([sys.executable, "-c", _wait_script()], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        pytest.fail("the wait did not end within 60 s with INDEX_WAIT_SECONDS=%s: it does not read its deadline" % seconds)
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return r, calls


def test_the_wait_asks_uv_for_the_exact_version_and_changes_nothing(tmp_path):
    r, calls = _run_the_wait(tmp_path, "y")
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls, "uv was never asked (the step asks something else)"
    assert calls[0]["args"][:3] == ["pip", "compile", "-"] and "--no-cache" in calls[0]["args"] and "--no-deps" in calls[0]["args"]
    assert calls[0]["stdin"].strip() == "invisible-core==9.9.9"


def test_one_yes_is_not_enough_three_in_a_row_are(tmp_path):
    r, calls = _run_the_wait(tmp_path, "y")
    assert r.returncode == 0 and len(calls) == 3, "it went on after %d yes: %s" % (len(calls), r.stdout + r.stderr)
    assert "uv resolves invisible-core 9.9.9 from the index, 3 times in a row" in r.stdout


def test_a_no_between_the_yes_starts_the_count_again(tmp_path):
    r, calls = _run_the_wait(tmp_path, "yynyyy")
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(calls) == 6, "a stale answer between two good ones must restart the count: %d calls" % len(calls)


def test_the_wait_ends_in_an_error_that_names_the_missing_version_when_the_index_never_has_it(tmp_path):
    r, calls = _run_the_wait(tmp_path, "n", seconds=1.0)
    assert r.returncode == 1, "a forgotten publish must fail the job here: " + r.stdout + r.stderr
    assert "::error::the index does not have invisible-core 9.9.9 yet" in r.stdout
    assert "minutes" in r.stdout and "No solution found" in r.stdout and "0 of 3 confirmations" in r.stdout
    assert len(calls) >= 2


def test_a_version_that_arrives_too_late_for_the_deadline_is_an_error_not_a_pass(tmp_path):
    r, calls = _run_the_wait(tmp_path, "yy" + "n", seconds=1.0)
    assert r.returncode == 1, "two yes then no until the deadline is not three in a row: " + r.stdout + r.stderr


def test_a_call_that_does_not_answer_is_a_no_and_does_not_stop_the_wait(tmp_path):
    r, calls = _run_the_wait(tmp_path, "hyyy", seconds=20.0, call_seconds=0.5)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(calls) == 4, "the hung call counts as one no, then three yes: %d calls" % len(calls)


def test_a_call_that_never_answers_ends_in_the_error_with_what_happened(tmp_path):
    r, calls = _run_the_wait(tmp_path, "h", seconds=1.5, call_seconds=0.3)
    assert r.returncode == 1 and "uv did not answer within" in r.stdout, r.stdout + r.stderr


def test_the_wait_comes_after_uv_is_installed_and_before_the_user_path():
    """The names of the steps are read as text, in file order (the workflow has one job): no YAML library is needed."""
    names = [n.strip() for n in re.findall(r"^\s*-\s*name:\s*(.+)$", WORKFLOW.read_text(encoding="utf-8"), re.M)]
    wait = names.index("wait for the index to serve this version")
    assert max(i for i, n in enumerate(names) if n.startswith("uv, from its own installer")) < wait < names.index("The user path, end to end")


def test_the_wait_step_still_passes_the_gate_of_the_install_job():
    from invisible_core import install_job
    assert install_job.problems(WORKFLOW.read_text(encoding="utf-8")) == []


# ---- the version of a ledger pull request is the one it adds to PUBLISHED.json, not the tree's ------------------------------------------------
# A ledger PR of a release is merged after this job is green, and main may already declare the next version (seal or CORE_REVISION ahead), which
# is not published until that ledger is merged: the wait asked the index for the version derived from the tree, which does not exist, and the pull
# request could never turn green.

def _ledger(*versions):
    return json.dumps({"comment": "x", "schema": 1, "released": [{"version": v} for v in versions]})


def _added_versions_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ci_ledger_added_versions_under_test", ROOT / "scripts" / "ci_ledger_added_versions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_version_of_the_pull_request_is_the_one_it_adds_not_the_one_of_the_tree(tmp_path):
    """base [..67.77.0], head [..67.77.0, 67.78.0], tree 67.79.0 -> 67.78.0 (through the command the step runs)."""
    (tmp_path / "base.json").write_text(_ledger("67.76.0", "67.77.0"), encoding="utf-8")
    (tmp_path / "head.json").write_text(_ledger("67.76.0", "67.77.0", "67.78.0"), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "invisible-core"\nversion = "67.79.0"\n', encoding="utf-8")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "ci_ledger_added_versions.py"), "--base", "base.json", "--head", "head.json",
                        "--tree-pyproject", "pyproject.toml"], cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.strip() == "67.78.0", r.stdout + r.stderr


def test_a_ledger_pull_request_that_adds_nothing_is_an_error_that_says_so():
    module = _added_versions_script()
    with pytest.raises(module.Refused, match="adds no version to PUBLISHED.json"):
        module.the_version_of_the_pr(_ledger("0.54.0", "0.55.0"), _ledger("0.54.0", "0.55.0"))


def test_a_ledger_pull_request_that_adds_two_versions_is_an_error_naming_both():
    module = _added_versions_script()
    with pytest.raises(module.Refused, match=r"adds 2 versions .*0\.56\.0, 0\.57\.0"):
        module.the_version_of_the_pr(_ledger("0.55.0"), _ledger("0.55.0", "0.56.0", "0.57.0"))


def test_a_version_the_head_dropped_is_not_an_addition():
    module = _added_versions_script()
    assert module.added_versions(_ledger("0.54.0", "0.55.0"), _ledger("0.55.0", "0.56.0")) == ["0.56.0"]


def test_the_install_job_takes_the_version_of_a_pull_request_from_the_ledger_and_not_from_the_tree():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "_mod.__version__" not in text and "spec_from_file_location" not in text, \
        "a step derives the version of the tree: a ledger pull request is not about it"
    step = text.index("- name: the version this ledger pull request records")
    wait = text.index("- name: wait for the index to serve this version")
    assert step < wait, "the version is computed after the wait that needs it"
    block = text[step:wait]
    assert "if: github.event_name == 'pull_request'" in block
    assert "github.event.pull_request.base.sha" in block and "scripts/ci_ledger_added_versions.py" in block
    assert 'INVCORE_E2E_VERSION=$version" >> "$GITHUB_ENV"' in block
    assert 'os.environ["INVCORE_E2E_VERSION"]' in text[wait:]


def test_the_install_test_adds_exactly_the_version_of_the_pull_request(monkeypatch):
    import test_user_install_e2e as e2e
    lines = ["uv init", "uv add invisible-core"]
    monkeypatch.delenv("INVCORE_E2E_VERSION", raising=False)
    assert e2e._pinned_to_the_ledger(lines) == lines, "a run with no pull request installs what the README's line installs"
    monkeypatch.setenv("INVCORE_E2E_VERSION", "67.78.0")
    assert e2e._pinned_to_the_ledger(lines) == ["uv init", "uv add invisible-core==67.78.0"]
