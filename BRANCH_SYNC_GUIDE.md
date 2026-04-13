# Branch Sync Guide

This repository uses long-lived branches: `cicd`, `staging`, and `main`.

## Safe sync flow

1. Fetch latest refs:

```bash
git fetch --all --prune
```

2. Fast-forward local tracking branches only:

```bash
git checkout main && git pull --ff-only
git checkout staging && git pull --ff-only
git checkout cicd && git pull --ff-only
```

3. Rebase feature branch on the target integration branch:

```bash
git checkout feat/<feature-name>
git rebase cicd
```

4. Push feature branch and open PR to `cicd`:

```bash
git push -u origin feat/<feature-name>
gh pr create --base cicd --head feat/<feature-name>
```

## Notes

- Avoid merge commits for local sync unless explicitly required.
- Prefer `--ff-only` to prevent accidental history divergence.
- Keep one feature per branch for atomic review.
