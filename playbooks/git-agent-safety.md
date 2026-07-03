# Git Agent Safety

## Purpose

Keep coding-agent changes reviewable and prevent accidental repository damage.

## Use When

- An AI coding agent may edit files, create branches, push, open PRs, or run
  project commands.
- The repository may contain user changes or private artifacts.
- Branch protection or manual merge rules are in place.

## Boundary

The agent may prepare work for review, but merge authority stays with the
maintainer unless explicitly delegated.

## Task Brief Wording

```text
Work through issue -> branch -> commit -> push -> pull request. Do not push to
main. Do not merge. Do not overwrite unrelated user changes. Before editing,
check git status and inspect files you will touch.

Keep private artifacts, credentials, local logs, and generated scratch files out
of the commit.
```

## Example Task Brief

```text
Make this change through a branch and pull request. Before editing, run git
status and list unrelated dirty files. Do not push to main, do not merge, and
do not modify files outside the task scope. After editing, run the relevant
checks and summarize the exact files changed.
```

## Check Before Acting

- What branch am I on?
- Are there unrelated dirty files?
- Which files belong to this task?
- Are private or generated files ignored?
- What tests or checks prove the change?

## Expected Safe Behavior

- Use small coherent commits.
- Leave unrelated changes alone.
- Report exact checks run.
- Open a PR and let the maintainer merge.

## When This Is Not Enough

Use branch protection, required reviews, CI checks, secret scanning, and
repository permissions. A prompt cannot stop a tool from pushing to the wrong
branch if credentials and permissions allow it.
