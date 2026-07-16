# Local git hooks

Optional convenience mirror of the CI mechanical constitution checks (`docs/CONSTITUTION.md` §Enforcement, `.github/workflows/constitution.yml`).

Enable once per clone:

```
git config core.hooksPath .githooks
```

This runs `scripts/constitution/run-all.sh` before every commit. It is not required — CI is the enforcement point of record — but it catches violations before they leave your machine.
