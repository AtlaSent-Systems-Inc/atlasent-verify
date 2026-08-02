# Stacked pull request base guard (H10)

## Why this exists

Merging a child PR into its parent's branch does **not** put the child on `main`. If
the parent was already merged (and especially if its branch is then deleted), the
child can show a successful merge while its commits are unreachable from `main`.
That was the loss pattern in #1713–#1716: the parent landed first and the remaining
PRs continued to merge into an intermediate branch that no longer delivered them.

## Guard and algorithm

`Stacked PR base guard` runs on PR metadata changes (including a parent's closure)
and can be dispatched manually. It checks out the trusted copy of the guard from
`main`, fetches every remote branch and queries all PR states. For
a PR targeting `main`, it succeeds immediately. Otherwise it walks the route:

1. the target remote ref must exist;
2. exactly one open PR must have that branch as its head (an open, initially empty
   parent is valid because merging its child gives it work to carry);
3. merged PR metadata and the actual ancestry graph must not show a dead parent; and
4. that parent's base must recursively satisfy the same rules until `main`.

Thus a live `child -> parent -> main` stack passes, while deleted, orphaned,
ambiguous, cyclic, or already-merged routes fail with retarget/rebase instructions.
The graph check catches merge commits and fast-forwards; merged PR metadata also
catches squash/rebase merges, whose old branch tip is not necessarily an ancestor.

After a parent merges, rebase the child onto `main` and change its base to `main`.
That correctly passes; merely rebasing while retaining a dead target does not make
the merge deliverable and is intentionally rejected.

## Operations and limitations

Make the commit status **`stacked-pr-base-guard`** required for `main` and every
branch used as a stack base. The workflow audits every open PR and republishes its
status whenever any PR closes; this is what invalidates a child's old green status
when its parent merges without changing the child. The workflow can write commit
statuses, but has read-only content/PR permissions and never checks out or executes
PR code. It assumes the delivery branch is named
`main` and same-repository branches are used for intermediate stack parents. PRs
from forks may target `main`, but fork-owned intermediate stacks require a future
identity-aware extension. GitHub's API and a complete remote fetch must be available;
an infrastructure failure fails the check rather than silently approving a route.

Run the hermetic regression suite with:

```sh
python3 -m unittest .github/scripts/test_stack_base_guard.py
```
