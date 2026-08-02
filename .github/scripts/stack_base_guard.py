#!/usr/bin/env python3
"""Reject pull requests whose target branch has no live path to main."""

import argparse
import json
import subprocess
import sys


class UnsafeStack(Exception):
    pass


def git(*args):
    return subprocess.run(["git", *args], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True).returncode == 0


def ref_exists(remote, branch):
    return git("show-ref", "--verify", "--quiet", f"refs/remotes/{remote}/{branch}")


def is_ancestor(remote, branch, main):
    return git("merge-base", "--is-ancestor", f"{remote}/{branch}", f"{remote}/{main}")


def field(pr, side, name):
    value = pr.get(side, {})
    value = value.get(name) if isinstance(value, dict) else None
    # GitHub returns head.repo as an object; compact test inventories may use a string.
    if name == "repo" and isinstance(value, dict):
        return value.get("full_name")
    return value


def verify(base, main, remote, repository, prs):
    if base == main:
        return [main]

    path, seen = [], set()
    branch = base
    while branch != main:
        if branch in seen:
            raise UnsafeStack(f"stack cycle detected at '{branch}'")
        seen.add(branch)
        path.append(branch)

        if not ref_exists(remote, branch):
            raise UnsafeStack(
                f"target branch '{branch}' no longer exists on the remote (it may have been deleted)")
        candidates = [p for p in prs if field(p, "head", "ref") == branch and
                      (not repository or field(p, "head", "repo",) in (None, repository))]
        open_prs = [p for p in candidates if p.get("state") == "open"]
        if not open_prs:
            merged = [p for p in candidates if p.get("merged_at")]
            if merged:
                raise UnsafeStack(
                    f"stack parent PR for '{branch}' has already merged, but this PR still targets it")
            if is_ancestor(remote, branch, main):
                raise UnsafeStack(
                    f"stack parent '{branch}' is already contained in '{main}' (the parent has merged)")
            raise UnsafeStack(
                f"target branch '{branch}' has no open parent PR carrying it toward '{main}'")
        if len(open_prs) > 1:
            raise UnsafeStack(f"multiple open parent PRs use '{branch}'; the route to '{main}' is ambiguous")

        # An open parent remains a delivery route even when its branch currently
        # equals main: merging this child adds new work for that parent to carry.
        # With no open parent, the checks above use both merged PR metadata and
        # graph ancestry, defending against squash merges and incomplete history.

        branch = field(open_prs[0], "base", "ref")
        if not branch:
            raise UnsafeStack(f"parent PR for '{path[-1]}' has no base branch metadata")

    path.append(main)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--main", default="main")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--repository", default="")
    parser.add_argument("--prs-json", required=True)
    args = parser.parse_args()
    with open(args.prs_json, encoding="utf-8") as source:
        prs = json.load(source)
    try:
        path = verify(args.base, args.main, args.remote, args.repository, prs)
    except UnsafeStack as error:
        print("::error title=Unsafe stacked PR base::" + str(error))
        print(f"This PR cannot safely merge: merging into '{args.base}' would not reliably carry "
              f"the child into '{args.main}'. Retarget the PR to '{args.main}' (and rebase it), "
              "or restore a live chain of open parent PRs.")
        return 1
    print("Safe PR delivery path: " + " -> ".join(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
