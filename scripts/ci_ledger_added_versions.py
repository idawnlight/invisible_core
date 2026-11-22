"""The version a ledger pull request is about: the one it ADDS to PUBLISHED.json, not the one the tree declares.

    python scripts/ci_ledger_added_versions.py --base <ledger-at-base.json> --head <ledger-at-head.json> [--tree-pyproject pyproject.toml]

The ledger PR of a release is opened after the upload and merged after `user-install` is green, so by the time it runs main may already declare the
NEXT version (the tree says 0.57.0 while the PR records 0.56.0, and 0.57.0 is not published until this PR is merged). Asking the index for the
version of pyproject.toml waited for something that does not exist yet. The ledger is the record of what was published: the version of the PR is
the entry its head has and its base does not.

Prints the one added version on stdout. Exits 1, with a line on stderr, when the PR adds none (a ledger PR that records nothing has nothing to
install) or more than one (the job installs and launches one version; two entries in one PR is a ledger that skipped a merge, not a run to
guess at). With ``--tree-pyproject`` the version of the tree is only reported on stderr, never used.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


class Refused(Exception):
    pass


def versions_of(ledger_text: str, where: str) -> list[str]:
    try:
        data = json.loads(ledger_text)
        return [str(entry["version"]) for entry in data["released"]]
    except (ValueError, KeyError, TypeError) as exc:
        raise Refused("the ledger %s cannot be read: %s: %s" % (where, type(exc).__name__, exc))


def added_versions(base_text: str, head_text: str) -> list[str]:
    """The versions the head ledger has and the base ledger does not, in the order of the head."""
    have = set(versions_of(base_text, "of the base"))
    return [v for v in versions_of(head_text, "of the head") if v not in have]


def the_version_of_the_pr(base_text: str, head_text: str) -> str:
    added = added_versions(base_text, head_text)
    if not added:
        raise Refused("this pull request adds no version to PUBLISHED.json: there is no release to install and launch")
    if len(added) > 1:
        raise Refused("this pull request adds %d versions to PUBLISHED.json (%s): the job checks one release per ledger pull request"
                      % (len(added), ", ".join(added)))
    return added[0]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True, help="PUBLISHED.json as the base of the pull request has it")
    ap.add_argument("--head", required=True, help="PUBLISHED.json as the head of the pull request has it")
    ap.add_argument("--tree-pyproject", help="reported only: the tree's version is not the one of the pull request")
    args = ap.parse_args(argv)
    try:
        version = the_version_of_the_pr(Path(args.base).read_text(encoding="utf-8"), Path(args.head).read_text(encoding="utf-8"))
    except (Refused, OSError) as exc:
        print("::error::%s" % exc, file=sys.stderr)
        return 1
    if args.tree_pyproject:
        import tomllib
        tree = tomllib.loads(Path(args.tree_pyproject).read_text(encoding="utf-8"))["project"]["version"]
        print("::notice::the pull request records %s; the tree declares %s (not used)" % (version, tree), file=sys.stderr)
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
