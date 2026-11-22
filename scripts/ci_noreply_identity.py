#!/usr/bin/env python3
"""Fail the run when a commit, an annotated tag or its tagger has no GitHub noreply address.

Standard library only, Python >= 3.11: it runs on a runner that did not install
the package, and the same file is read from main of this repository by every
repository that calls the reusable workflow (noreply-identity.yml), so the
judge is never the branch being judged.

It is the CI twin of `invisible_core.hooks.foreign_identities` (the local
pre-push check): the same allow-list, the same three roles (author, committer,
tagger), and the same rule that a commit a remote already has is public, so this
run answers only for what THIS event makes public.

Exit 0: every address is a noreply one. Exit 1: at least one is not (one line
per violation, the address masked). Exit 2: git or the arguments failed. An
error is never a green.

  --event pull_request --base SHA --head SHA --base-ref NAME
  --event push --ref refs/heads/X|refs/tags/X --before SHA --after SHA
  --event other --head SHA --default-ref NAME
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from typing import Iterable

#: A GitHub noreply address, or the committer GitHub writes on a merge or squash
#: made in its web flow. Anchored at the END and the web-flow one also at the
#: start: a noreply name under somebody else's domain, or `github.com` followed by
#: more labels, is that somebody's own address and must not pass.
VALID = re.compile(r"(@users\.noreply\.github\.com|^noreply@github\.com)$")

# ASCII US (0x1F) separates git log fields without colliding with emails.
UNIT_SEP = chr(0x1F)

Found = list[tuple[str, str, str]]  # (sha, role, email)


class GitError(Exception):
    """A git call or an argument failed: the run must end red (exit 2)."""


def is_valid(email: str) -> bool:
    """True for a noreply address; an empty one is not."""
    return bool(VALID.search(email))


def mask(email: str) -> str:
    """The address with most of it hidden, so a failing run is safe to paste.

    `a.b@example.org` -> `a***@e***.org`; no `@` -> first character + `***`;
    empty -> `<empty>`.
    """
    if not email:
        return "<empty>"
    local, at, domain = email.partition("@")
    if not at:
        return email[:1] + "***"
    labels = domain.split(".")
    tld = "." + labels[-1] if len(labels) > 1 else ""
    return f"{local[:1]}***@{labels[0][:1]}***{tld}"


def git(*args: str, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(["git", *args], input=stdin, capture_output=True,
                              text=True, encoding="utf-8", errors="replace")
    except OSError as exc:
        raise GitError(f"cannot run git: {exc}") from exc
    if check and proc.returncode != 0:
        detail = proc.stderr.strip().splitlines()[-1:] or [f"exit {proc.returncode}"]
        raise GitError(f"git {args[0]} failed: {detail[0]}")
    return proc


def commit_exists(rev: str) -> bool:
    return git("cat-file", "-e", f"{rev}^{{commit}}", check=False).returncode == 0


def ref_exists(ref: str) -> bool:
    return git("rev-parse", "--verify", "-q", f"{ref}^{{commit}}", check=False).returncode == 0


def is_zeros(sha: str) -> bool:
    return bool(sha) and set(sha) == {"0"}


def rev_list(include: str, excluded: Iterable[str]) -> list[str]:
    """Commits reachable from `include` and from none of `excluded`.

    Revisions go through stdin: a repository with thousands of tags would not fit
    on a Windows command line.
    """
    lines = [include, *(f"^{rev}" for rev in excluded)]
    return git("rev-list", "--stdin", stdin="\n".join(lines) + "\n").stdout.split()


def refs_already_public(remote: str, pushed_ref: str) -> list[str]:
    """Every remote-tracking ref and tag of the clone, except the one being pushed.

    Not the symbolic ones (`refs/remotes/origin/HEAD` points at main, and on a
    push to main it would exclude the very commits being judged), and not a ref
    that does not end at a commit.
    """
    fmt = "%(refname) %(symref) %(objecttype) %(*objecttype)"
    out = git("for-each-ref", f"--format={fmt}", f"refs/remotes/{remote}/", "refs/tags/").stdout
    refs = []
    for line in out.splitlines():
        name, symref, kind, peeled = (line.split(" ") + ["", "", "", ""])[:4]
        if symref or name == pushed_ref:
            continue
        if (peeled or kind) != "commit":
            continue
        refs.append(name)
    return refs


def identities(commits: list[str]) -> Found:
    """Author and committer of every commit, merges included."""
    if not commits:
        return []
    out = git("log", "--no-walk=unsorted", "--stdin", "--format=%H%x1f%ae%x1f%ce",
              stdin="\n".join(commits) + "\n").stdout
    found: Found = []
    for line in out.splitlines():
        sha, _s, rest = line.partition(UNIT_SEP)
        author, _s, committer = rest.partition(UNIT_SEP)
        found.append((sha, "author", author))
        found.append((sha, "committer", committer))
    return found


def taggers(obj: str) -> Found:
    """The tagger of an annotated tag object and of every tag nested inside it."""
    found: Found = []
    seen: set[str] = set()
    while obj not in seen and git("cat-file", "-t", obj).stdout.strip() == "tag":
        seen.add(obj)
        header = git("cat-file", "-p", obj).stdout.split("\n\n", 1)[0]
        nxt = None
        for line in header.splitlines():
            if line.startswith("tagger "):
                found.append((obj, "tagger", line.rpartition("<")[2].partition(">")[0]))
            elif line.startswith("object "):
                nxt = line.split(" ", 1)[1].strip()
        if not nxt:
            break
        obj = nxt
    return found


def need(a: argparse.Namespace, *names: str) -> None:
    for name in names:
        if not getattr(a, name):
            raise GitError(f"--event {a.event} needs --{name.replace('_', '-')}")


def plan_pull_request(a: argparse.Namespace) -> tuple[str, Found, list[str]]:
    need(a, "base", "head", "base_ref")
    excluded = [a.base]
    tracking = f"refs/remotes/{a.remote}/{a.base_ref}"
    # A `git merge origin/main` inside the branch must not bring main's commits in.
    if ref_exists(tracking):
        excluded.append(tracking)
    return f"{a.base[:12]}..{a.head[:12]} (and not {tracking})", [], rev_list(a.head, excluded)


def plan_push(a: argparse.Namespace) -> tuple[str, Found, list[str]]:
    need(a, "ref", "before", "after")
    is_tag = a.ref.startswith("refs/tags/")
    if not is_tag and not a.ref.startswith("refs/heads/"):
        raise GitError(f"--ref {a.ref!r} is neither refs/heads/ nor refs/tags/")
    if is_zeros(a.after):
        return "", [], []
    if git("cat-file", "-e", a.after, check=False).returncode != 0 and is_tag:
        git("fetch", "--no-tags", a.remote, f"+{a.ref}:{a.ref}")
    tag_found = taggers(a.after) if git("cat-file", "-t", a.after).stdout.strip() == "tag" else []
    # `after` may name the peeled commit rather than the tag object: the tagger is
    # then read from the pushed ref itself, so an annotated tag is never judged
    # as a lightweight one.
    if is_tag and not tag_found and (
            git("cat-file", "-t", a.ref, check=False).stdout.strip() == "tag"):
        tag_found = taggers(git("rev-parse", a.ref).stdout.strip())
    pushed = a.ref if is_tag else f"refs/remotes/{a.remote}/{a.ref[len('refs/heads/'):]}"
    excluded = refs_already_public(a.remote, pushed)
    # After a force-push the old tip may be gone: the ref is then new for us.
    if not is_zeros(a.before) and commit_exists(a.before):
        excluded.insert(0, a.before)
        span = f"{a.before[:12]}..{a.after[:12]}"
    else:
        span = f"new ref, up to {a.after[:12]}"
    return span, tag_found, rev_list(f"{a.after}^{{commit}}", excluded)


def plan_other(a: argparse.Namespace) -> tuple[str, Found, list[str]]:
    need(a, "head", "default_ref")
    default = f"refs/remotes/{a.remote}/{a.default_ref}"
    if not ref_exists(default):
        raise GitError(f"{default} does not exist in this clone")
    return f"{a.head[:12]} not in {default}", [], rev_list(a.head, [default])


def run(a: argparse.Namespace) -> int:
    if a.event == "pull_request":
        span, tags, commits = plan_pull_request(a)
    elif a.event == "push":
        need(a, "ref", "before", "after")
        if is_zeros(a.after):
            print(f"noreply-identity: push of {a.ref}: the ref was deleted, nothing to check")
            return 0
        span, tags, commits = plan_push(a)
    else:
        span, tags, commits = plan_other(a)
    found = tags + identities(commits)
    print(f"noreply-identity: event={a.event} range={span} commits={len(commits)} "
          f"tags={len({t[0] for t in tags})}")
    bad = [(sha, role, mask(email)) for sha, role, email in found if not is_valid(email)]
    for sha, role, masked in bad:
        print(f"{sha[:12]} {role}: {masked}")
    if bad:
        print(f"noreply-identity: {len(bad)} address(es) are not a GitHub noreply one; "
              "rewrite them and set the noreply identity in the clone "
              "(git config user.email)", file=sys.stderr)
        return 1
    print("noreply-identity: every address is a GitHub noreply one")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fail on any commit, tag or tagger without a GitHub noreply address.")
    p.add_argument("--event", required=True, choices=["pull_request", "push", "other"])
    p.add_argument("--remote", default="origin")
    p.add_argument("--base")
    p.add_argument("--head")
    p.add_argument("--base-ref", dest="base_ref")
    p.add_argument("--ref")
    p.add_argument("--before")
    p.add_argument("--after")
    p.add_argument("--default-ref", dest="default_ref")
    a = p.parse_args(argv)
    try:
        return run(a)
    except GitError as exc:
        print(f"noreply-identity: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
