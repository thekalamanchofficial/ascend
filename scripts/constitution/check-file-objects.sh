#!/usr/bin/env bash
# Art. 2 (files first-class): every Go struct marked "// ascend:file-object"
# must declare fields covering identity, owner, and history. See
# scripts/constitution/README.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

while IFS= read -r marker_loc; do
  file="${marker_loc%%:*}"
  marker_line="${marker_loc#*:}"
  decl_line=$((marker_line + 1))
  decl=$(sed -n "${decl_line}p" "$file")
  type_name=$( (echo "$decl" | grep -oE '^type [A-Za-z0-9_]+ struct' | awk '{print $2}') || true)
  [ -z "$type_name" ] && continue

  close_offset=$(tail -n "+${decl_line}" "$file" | grep -n '^}' | head -1 | cut -d: -f1 || true)
  if [ -z "${close_offset:-}" ]; then
    echo "ART.2 VIOLATION: ${type_name} (${file}:${decl_line}) marked ascend:file-object has no closing brace found"
    fail=1
    continue
  fi
  end_line=$((decl_line + close_offset - 1))
  body=$(sed -n "${decl_line},${end_line}p" "$file")

  for required in ID Owner History; do
    if ! echo "$body" | grep -qi "$required"; then
      echo "ART.2 VIOLATION: ${type_name} (${file}:${decl_line}) marked ascend:file-object is missing a field covering '${required}'"
      fail=1
    fi
  done
done < <(grep -rnE --include='*.go' -l '^[[:space:]]*//[[:space:]]*ascend:file-object[[:space:]]*$' . 2>/dev/null | xargs -r grep -HnE '^[[:space:]]*//[[:space:]]*ascend:file-object[[:space:]]*$' | sed -E 's/^([^:]+):([0-9]+):.*/\1:\2/')

if [ "$fail" -eq 0 ]; then
  echo "Art. 2 (files first-class): OK"
fi
exit $fail
