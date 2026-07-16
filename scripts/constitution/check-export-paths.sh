#!/usr/bin/env bash
# Art. 9 (exportability): every Go struct marked "// ascend:persisted" must
# have a matching Export<TypeName> function and a referencing *_export_test.go
# in the same package. See scripts/constitution/README.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

# Locate marker lines, then check the following line for a struct decl.
while IFS= read -r marker_loc; do
  file="${marker_loc%%:*}"
  marker_line="${marker_loc#*:}"
  next_line=$((marker_line + 1))
  decl=$(sed -n "${next_line}p" "$file")
  type_name=$( (echo "$decl" | grep -oE '^type [A-Za-z0-9_]+ struct' | awk '{print $2}') || true)
  [ -z "$type_name" ] && continue
  pkg_dir=$(dirname "$file")

  if ! grep -rq "func Export${type_name}(" "$pkg_dir" 2>/dev/null; then
    echo "ART.9 VIOLATION: ${type_name} (${file}:${next_line}) is marked ascend:persisted but has no Export${type_name} function in ${pkg_dir}"
    fail=1
    continue
  fi
  if ! ls "$pkg_dir"/*_export_test.go >/dev/null 2>&1 || ! grep -rq "Export${type_name}" "$pkg_dir"/*_export_test.go 2>/dev/null; then
    echo "ART.9 VIOLATION: ${type_name} (${file}:${next_line}) has Export${type_name} but no *_export_test.go in ${pkg_dir} references it"
    fail=1
  fi
done < <(grep -rnE --include='*.go' -l '^[[:space:]]*//[[:space:]]*ascend:persisted[[:space:]]*$' . 2>/dev/null | xargs -r grep -HnE '^[[:space:]]*//[[:space:]]*ascend:persisted[[:space:]]*$' | sed -E 's/^([^:]+):([0-9]+):.*/\1:\2/')

if [ "$fail" -eq 0 ]; then
  echo "Art. 9 (exportability): OK"
fi
exit $fail
