#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

scan_dir="$repo_root/daemon-rs/crates/daemon/src"

matches="$(rg -n --no-heading -U 'send\([^)]*\)\s*\.await' "$scan_dir" -g '!**/tests/**' || true)"

if [[ -z "$matches" ]]; then
  echo "async-send policy check: no awaited send sites found"
  exit 0
fi

# Allowed awaited send patterns:
# 1) Explicit backpressure fallback after try_send in runtime channels.
# 2) Known channel-send call sites currently used in runtime orchestration.
# 3) True async network I/O (reqwest send).
allowed_regexes=(
  'daemon-rs/crates/daemon/src/utils/channel_send\.rs:.*tx\.send\(item\)\.await\.is_ok\(\)'
  'daemon-rs/crates/daemon/src/workers/runtime/verdict/dispatch\.rs:.*verdict_tx\.send\(next\)\.await'
  'daemon-rs/crates/daemon/src/flows/verdict/verdict\.rs:.*bus\.verdict_tx\.send\(verdict\)\.await'
  'daemon-rs/crates/daemon/src/services/task/task\.rs:.*task_lifecycle_tx\.send\(event\)\.await'
  'daemon-rs/crates/daemon/src/services/subscription/refresh_execution\.rs:.*request\.send\(\)\.await'
  'daemon-rs/crates/daemon/src/services/subscription/refresh_execution\.rs:.*retry_request\.send\(\)\.await'
  'daemon-rs/crates/daemon/src/services/task/runtime_handlers\.rs:.*client\.get\(source\.remote\.trim\(\)\)\.send\(\)\.await\?'
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

if ((${#violations[@]} > 0)); then
  echo "async-send policy check: found non-whitelisted awaited send usage(s):"
  for v in "${violations[@]}"; do
    echo "  $v"
  done
  echo
  echo "Policy: use try_send fast path and await only on Full fallback in hot/runtime paths."
  exit 1
fi

echo "async-send policy check: pass"
