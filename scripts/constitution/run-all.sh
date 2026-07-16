#!/usr/bin/env bash
# Runs every mechanical constitution check. Used by
# .github/workflows/constitution.yml and by the local pre-commit hook
# (see .githooks/pre-commit).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

status=0
for check in scripts/constitution/check-*.sh; do
  echo "== $(basename "$check") =="
  bash "$check" || status=1
  echo
done

if [ "$status" -ne 0 ]; then
  echo "One or more mechanical constitution checks failed. See docs/CONSTITUTION.md §Enforcement."
fi
exit $status
