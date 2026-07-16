#!/usr/bin/env bash
# Art. 10 (modularity): no capability package under services/api/internal/<X>
# may import services/api/internal/<Y> for a different capability Y. Shared
# packages (internal/platform, internal/audit) and packages/contracts are
# exempt. See scripts/constitution/README.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
root="services/api/internal"
[ -d "$root" ] || { echo "Art. 10 (modularity): OK (no internal/ packages yet)"; exit 0; }

shared_exempt="platform audit"
shopt -s nullglob

for cap_dir in "$root"/*/; do
  cap=$(basename "$cap_dir")
  case " $shared_exempt " in *" $cap "*) continue ;; esac

  while IFS= read -r imp_file; do
    imports=$(grep -oE "\"[^\"]*${root}/[A-Za-z0-9_]+" "$imp_file" || true)
    while IFS= read -r imp; do
      [ -z "$imp" ] && continue
      imported_cap=$(echo "$imp" | sed -E "s#.*${root}/([A-Za-z0-9_]+).*#\1#")
      case " $shared_exempt " in *" $imported_cap "*) continue ;; esac
      if [ "$imported_cap" != "$cap" ]; then
        echo "ART.10 VIOLATION: ${imp_file} in capability '${cap}' imports internal package of capability '${imported_cap}' directly — depend on packages/contracts instead"
        fail=1
      fi
    done <<< "$imports"
  done < <(find "$cap_dir" -name '*.go')
done

if [ "$fail" -eq 0 ]; then
  echo "Art. 10 (modularity): OK"
fi
exit $fail
