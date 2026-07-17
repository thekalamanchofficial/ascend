#!/usr/bin/env bash
# Art. 5 (explainability), TypeScript-side: every exported function marked
# "// ascend:mutates" must call logAuditEvent( somewhere in its body. This
# is the TS-capability equivalent of check-audit-events.sh (Go). See
# scripts/constitution/README.md.
#
# Scope: capabilities implemented client-side (apps/mobile/src/capabilities/*)
# rather than in services/api, per the precedent set by Cryptography & Keys
# (docs/DECISION_LOG.md, 2026-07-16, "implementation location is
# apps/mobile, not services/api"). Test files are excluded — a marker
# inside a test fixture isn't a real capability obligation.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

while IFS= read -r marker_loc; do
  file="${marker_loc%%:*}"
  marker_line="${marker_loc#*:}"
  func_line=$((marker_line + 1))

  total_lines=$(wc -l < "$file")
  next_func_offset=$(tail -n "+$((func_line + 1))" "$file" | grep -nE '^(export )?(async )?function ' | head -1 | cut -d: -f1 || true)
  if [ -n "${next_func_offset:-}" ]; then
    end_line=$((func_line + next_func_offset - 1))
  else
    end_line=$total_lines
  fi

  func_name=$( (sed -n "${func_line}p" "$file" | grep -oE 'function [A-Za-z0-9_]+' | awk '{print $2}') || true)
  # Strip full-line comments so a mention of "logAuditEvent(" inside
  # documentation prose can't produce a false pass (same discipline as the
  # Go-side fix, see docs/DECISION_LOG.md 2026-07-16 "Fix: mechanical
  # check scripts crashed on marker text inside prose").
  code_body=$(sed -n "${func_line},${end_line}p" "$file" | grep -v '^[[:space:]]*//')

  if ! echo "$code_body" | grep -q 'logAuditEvent('; then
    echo "ART.5 VIOLATION: ${func_name:-function} (${file}:${func_line}) is marked ascend:mutates but never calls logAuditEvent(...)"
    fail=1
  fi
done < <(grep -rnE --include='*.ts' --exclude='*.test.ts' --exclude-dir='__tests__' -l '^[[:space:]]*//[[:space:]]*ascend:mutates[[:space:]]*$' apps/mobile/src/capabilities services/ai/capabilities 2>/dev/null | xargs -r grep -HnE '^[[:space:]]*//[[:space:]]*ascend:mutates[[:space:]]*$' | sed -E 's/^([^:]+):([0-9]+):.*/\1:\2/')

if [ "$fail" -eq 0 ]; then
  echo "Art. 5 (explainability / audit events, TS): OK"
fi
exit $fail
