#!/usr/bin/env bash
# Art. 8 (privacy): every capability directory must ship a DATA_MANIFEST.md,
# and every field listed under its "## Fields" section must have a
# "Purpose:" line. See scripts/constitution/README.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

capability_dirs=$(find services/api/internal services/ai/capabilities apps/mobile/src/capabilities -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)

for dir in $capability_dirs; do
  manifest="$dir/DATA_MANIFEST.md"
  if [ ! -f "$manifest" ]; then
    echo "ART.8 VIOLATION: ${dir} has no DATA_MANIFEST.md"
    fail=1
    continue
  fi

  if grep -q '^## Fields' "$manifest"; then
    # Every bullet under "## Fields" must have an associated "Purpose:"
    # somewhere in its block (inline or on a following indented line).
    while IFS= read -r missing; do
      echo "ART.8 VIOLATION: ${manifest} field '${missing#MISSING:}' has no documented Purpose"
      fail=1
    done < <(awk '
      /^## Fields/{infields=1; next}
      /^## /{infields=0}
      infields && /^- / {
        if (bullet != "" && !has_purpose) { print "MISSING:" bullet }
        bullet=$0; has_purpose=0
      }
      infields && /Purpose:/ { has_purpose=1 }
      END { if (bullet != "" && !has_purpose) print "MISSING:" bullet }
    ' "$manifest")
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "Art. 8 (privacy / data manifests): OK"
fi
exit $fail
