#!/usr/bin/env bash
# Art. 5 (explainability): every Go function marked "// ascend:mutates"
# must call audit.Emit( somewhere in its body. See scripts/constitution/README.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

while IFS= read -r marker_loc; do
  file="${marker_loc%%:*}"
  marker_line="${marker_loc#*:}"
  func_line=$((marker_line + 1))

  total_lines=$(wc -l < "$file")
  next_func_offset=$(tail -n "+$((func_line + 1))" "$file" | grep -n '^func ' | head -1 | cut -d: -f1 || true)
  if [ -n "${next_func_offset:-}" ]; then
    end_line=$((func_line + next_func_offset - 1))
  else
    end_line=$total_lines
  fi

  func_name=$(sed -n "${func_line}p" "$file" | grep -oE 'func \(?[^)]*\)? ?[A-Za-z0-9_]+' | awk '{print $NF}')
  body=$(sed -n "${func_line},${end_line}p" "$file")

  if ! echo "$body" | grep -q 'audit\.Emit('; then
    echo "ART.5 VIOLATION: ${func_name:-func} (${file}:${func_line}) is marked ascend:mutates but never calls audit.Emit(...)"
    fail=1
  fi
done < <(grep -rn --include='*.go' -l 'ascend:mutates' . 2>/dev/null | xargs -r grep -Hn 'ascend:mutates' | sed -E 's/^([^:]+):([0-9]+):.*/\1:\2/')

if [ "$fail" -eq 0 ]; then
  echo "Art. 5 (explainability / audit events): OK"
fi
exit $fail
