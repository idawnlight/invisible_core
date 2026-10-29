"""Three implementations read `invisible-core==X.Y.Z`. This keeps them agreeing.

WHERE THEY ARE.

  * `invisible_core.pin.parse_requirement` + `normalise_name` - the real one, run
    at import time in every consumer (both of them when this was written -
    invisible_playwright and invisible_firefox, the latter deleted
    2026-08-18);
  * `scripts/sync_core_pin.py` in the workbench - its own `normalise()` and its
    own regex;
  * `core-on-index.yml` in the wrapper repo - an inline `norm()` and `PIN_RE`,
    written into the workflow body.

WHY THREE. Neither copy can import the first one. `sync_core_pin.py` compares a
core CHECKOUT against the consumers and deliberately reads `_version.py` by path
rather than importing an installed core, because the installed one is exactly what
might be stale. `core-on-index.yml` exists to answer "is the core on the index
yet?" and runs BEFORE anything is installed - importing the package it is probing
for would be circular.

So three copies is the right answer, and the missing part was that nothing
compared them. Recorded as open item 8 in `18-gate-inventory.md`, "two remaining
forks of the requirement parser", and as §F's recurring shape: a duplicated rule
agrees on the day it is written.

WHAT DISAGREEMENT COSTS. All three answer the same question about the same line of
the same `pyproject.toml`. If the workflow's regex stops matching a shape the
consumer's runtime accepts, CI reports "no pin found" and refuses to run on a repo
that is correctly pinned. If it matches a shape the runtime rejects, CI goes green
on a pin that will fail at import on a user's machine.

The two copies are read as TEXT and their functions exec'd in an isolated
namespace - that is the point, since the whole reason they exist is that they
cannot be imported.
"""
from __future__ import annotations

import pathlib
import re
import tomllib

import pytest

from invisible_core import pin

pytestmark = pytest.mark.unit

from _sibling_repositories import repository_root, workspace_root

_RELEASE = workspace_root(__file__)
_WORKBENCH = _RELEASE.parent
_SYNC = _WORKBENCH / "scripts" / "sync_core_pin.py"
_WRAPPER = repository_root("invisible_playwright", __file__)
_WORKFLOW = _WRAPPER / ".github/workflows/core-on-index.yml"
_BOOTSTRAP = _WRAPPER / "scripts/core_requirement.py"

#: The shapes a real `[project].dependencies` entry can take. Every one of these
#: has appeared in one of the three repos or in a PEP the resolver implements.
_NAMES = [
    "invisible-core", "invisible_core", "Invisible.Core", "INVISIBLE-CORE",
    "invisible--core", "invisible.core", "invisible_playwright", "requests",
]

_REQUIREMENTS = [
    "invisible-core==18.8.0",
    "invisible_core==18.8.0",
    "invisible-core == 18.8.0",
    " Invisible.Core [geo, dev] ( == 18.8.0 ) ; python_version >= '3.11'",
    "invisible-core[extra]==18.8.0",
    "invisible-core==18.8.0 ; python_version >= '3.10'",
    "invisible-core>=18.0.0",
    "invisible-core",
    "requests==2.31.0",
    "invisible-core @ git+https://example.invalid/x.git",
]


def _exec_block(text: str, names) -> dict:
    """Compile just the requested top-level defs/assignments out of a source text.

    Not `exec(whole_file)`: both sources do real work at import (one talks to an
    index, the other reads a checkout). Only the statements that DEFINE the names
    asked for are executed, in a namespace holding nothing but `re`.
    """
    import ast

    tree = ast.parse(text)
    wanted, keep = set(names), []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            keep.append(node)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in wanted:
                    keep.append(node)
    ns: dict = {"re": re}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "<extracted>", "exec"), ns)
    missing = sorted(wanted - set(ns))
    assert not missing, (
        f"could not extract {missing} from the source. Either it was renamed - "
        f"in which case this comparison has stopped covering it and must be "
        f"updated, not deleted - or it stopped being a top-level definition")
    return ns


def _inline_python(workflow_text: str) -> str:
    """The `python - <<'PY' ... PY` heredoc body out of the workflow."""
    m = re.search(r"python - <<'PY'\n(.*?)\n\s*PY\n", workflow_text, re.DOTALL)
    assert m, "the workflow no longer contains a `python - <<'PY'` block"
    body = m.group(1)
    # The block is indented to sit inside the YAML `run: |` scalar.
    indent = min((len(l) - len(l.lstrip()) for l in body.splitlines() if l.strip()),
                 default=0)
    return "\n".join(l[indent:] if len(l) >= indent else l for l in body.splitlines())


@pytest.mark.skipif(not _SYNC.is_file(), reason="not the workbench")
def test_the_sync_script_normalises_names_exactly_as_the_package_does():
    ns = _exec_block(_SYNC.read_text(encoding="utf-8"), ["normalise"])
    differing = {n: (pin.normalise_name(n), ns["normalise"](n))
                 for n in _NAMES if pin.normalise_name(n) != ns["normalise"](n)}
    assert not differing, (
        "sync_core_pin.normalise disagrees with invisible_core.pin.normalise_name:"
        "\n  " + "\n  ".join(f"{n}: package={a!r} script={b!r}"
                             for n, (a, b) in differing.items()))


def _workflow_parser():
    config = tomllib.loads((_WRAPPER / "pyproject.toml").read_text(encoding="utf-8"))
    backend = config["tool"]["invisible"]["hooks"].get("release_backend", "pypi")
    if backend == "github":
        assert "scripts/core_requirement.py" in _WORKFLOW.read_text(encoding="utf-8")
        ns = _exec_block(_BOOTSTRAP.read_text(encoding="utf-8"),
                         ["normalise_name", "parse_core_pin", "_REQ_RE", "_PIN_RE"])
        return ns["normalise_name"], lambda req: (parsed["version"] if (parsed := ns["parse_core_pin"](req)) else None)
    ns = _exec_block(_inline_python(_WORKFLOW.read_text(encoding="utf-8")), ["norm", "PIN_RE"])
    return ns["norm"], lambda req: (match.group("version") if (match := ns["PIN_RE"].match(req))
        and ns["norm"](match.group("name")) == "invisible-core" else None)


@pytest.mark.skipif(not _WORKFLOW.is_file(), reason="not the workbench")
def test_the_workflow_bootstrap_parser_agrees_with_the_package():
    normalise, version = _workflow_parser()
    for name in _NAMES:
        assert normalise(name) == pin.normalise_name(name), name
    for requirement in _REQUIREMENTS:
        parsed = pin.parse_requirement(requirement)
        ours = parsed.pinned if parsed and parsed.name == "invisible-core" else None
        assert version(requirement) == ours, requirement


@pytest.mark.skipif(not _WORKFLOW.is_file(), reason="not the workbench")
def test_the_comparison_is_not_vacuous():
    normalise, version = _workflow_parser()
    assert normalise("Invisible_Core") == "invisible-core"
    assert version("invisible-core==18.8.0") == "18.8.0"
    pinned = [requirement for requirement in _REQUIREMENTS if version(requirement)]
    assert len(pinned) >= 4, pinned
