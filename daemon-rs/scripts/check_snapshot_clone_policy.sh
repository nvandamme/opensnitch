#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

scan_dir="$repo_root/daemon-rs/crates/daemon/src"

# Policy: runtime code must not deep-clone fields directly from snapshot reads.
# Excludes tests by design.
matches="$(
  rg -n --no-heading -U \
    'snapshot\(_arc\)?\([^)]*\)\.[A-Za-z0-9_]+\.clone\(|\b(snapshot|[A-Za-z0-9_]*_snapshot)\.[A-Za-z0-9_]+\.clone\(' \
    "$scan_dir" \
    -g '!**/tests/**' || true
)"

if [[ -z "$matches" ]]; then
  echo "snapshot-clone policy check: pass"
  exit 0
fi

echo "snapshot-clone policy check: found disallowed snapshot field clone usage(s):"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  echo "  $line"
done <<< "$matches"

echo
echo "Policy: use Arc snapshot reads and borrow fields directly; avoid cloning snapshot-owned values in runtime paths."
exit 1
