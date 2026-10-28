"""Resolve sibling source checkouts on the branch under test."""
from __future__ import annotations

from pathlib import Path
import subprocess


def _git(directory: Path, *arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), *arguments],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _checkout(anchor: str | Path) -> tuple[Path, Path, str | None]:
    anchor = Path(anchor).resolve()
    directory = anchor if anchor.is_dir() else anchor.parent
    common = _git(directory, "rev-parse", "--git-common-dir")
    top = _git(directory, "rev-parse", "--show-toplevel")
    if common and top:
        common_path = Path(common)
        if not common_path.is_absolute():
            common_path = (directory / common_path).resolve()
        return Path(top), common_path.parent, _git(directory, "symbolic-ref", "--quiet", "HEAD")
    root = directory.parent if directory.name == "tests" else directory
    return root, root, None


def workspace_root(anchor: str | Path) -> Path:
    return _checkout(anchor)[1].parent


def repository_root(name: str, anchor: str | Path) -> Path:
    """Use a sibling's matching worktree, then its primary checkout.

    The current repository always resolves to its own checkout, including a
    detached HEAD. Repositories without the current branch use their primary
    checkout so consumers without a fork remain part of the API comparison.
    """
    current, primary, branch = _checkout(anchor)
    if primary.name == name:
        return current
    sibling = primary.parent / name
    if branch and sibling.is_dir():
        listing = _git(sibling, "worktree", "list", "--porcelain")
        if listing:
            for entry in listing.split("\n\n"):
                fields = dict(line.split(" ", 1) for line in entry.splitlines() if " " in line)
                if fields.get("branch") == branch and "worktree" in fields:
                    return Path(fields["worktree"])
    return sibling
