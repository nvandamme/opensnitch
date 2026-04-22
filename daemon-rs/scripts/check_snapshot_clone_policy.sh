#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

scan_dir="$repo_root/daemon-rs/crates/daemon/src"

# Policy: Arc-read snapshot access in runtime should be pure memread over
# immutable snapshots.
# Runtime paths must not use mutex/lock-based snapshot reads, must not use
# async snapshot getter wrappers, and must not deep-clone snapshot-owned
# fields at call sites.
# Allowed clone surfaces are restricted to one-time startup/bootstrap initial
# snapshot path extraction.
# Excludes tests by design.
async_snapshot_await_matches="$({
  rg -n --no-heading '\\.[A-Za-z0-9_]*snapshot[A-Za-z0-9_]*\\(\\)\\.await' "$scan_dir" -g '!**/tests/**' || true
} | sed '/^$/d' || true)"

if [[ -n "$async_snapshot_await_matches" ]]; then
  echo "snapshot-clone policy check: found async snapshot getter await usage(s):"
  echo "$async_snapshot_await_matches" | sed 's/^/  /'
  echo
  echo "Policy: arc read cloning is evil at runtime."
  echo "Policy detail: snapshot reads in runtime paths must be direct Arc memreads over immutable snapshots with no mutex/lock path and no async getter wrappers."
  exit 1
fi

matches="$(
  rg -n --no-heading -U \
    '(snapshot|snapshot_arc)\([^)]*\)\.[A-Za-z0-9_]+\.clone\(|\b(snapshot|[A-Za-z0-9_]*_snapshot)\.[A-Za-z0-9_]+\.clone\(' \
    "$scan_dir" \
    -g '!**/tests/**' || true
)"

if [[ -z "$matches" ]]; then
  echo "snapshot-clone policy check: pass"
  exit 0
fi

# Allowed snapshot clone patterns:
# - one-time startup/bootstrap path extraction
allowed_regexes=(
  'daemon-rs/crates/daemon/src/services/task/storage\.rs:.*initial_snapshot\.tasks_config_path\.clone\(\)'
  'daemon-rs/crates/daemon/src/services/config/storage\.rs:.*initial_snapshot\.config_path\.clone\(\)'
)

violations=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  allowed=false
  for pattern in "${allowed_regexes[@]}"; do
    if [[ "$line" =~ $pattern ]]; then
      allowed=true
      break
    fi
  done
  if [[ "$allowed" == false ]]; then
    violations+=("$line")
  fi
done <<< "$matches"

if ((${#violations[@]} == 0)); then
  echo "snapshot-clone policy check: pass"
  exit 0
fi

echo "snapshot-clone policy check: found disallowed snapshot field clone usage(s):"
for line in "${violations[@]}"; do
  echo "  $line"
done

echo
echo "Policy: arc read cloning is evil at runtime."
echo "Policy detail: allow only startup initial_snapshot clones; runtime snapshot reads must stay lock-free, async-free, immutable Arc memreads."
exit 1
