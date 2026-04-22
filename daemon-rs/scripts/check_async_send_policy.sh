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
# 2) True async network I/O (reqwest send).
allowed_regexes=(
  'daemon-rs/crates/daemon/src/flows/notification_flow\.rs:.*tx\.send\(item\)\.await\.is_ok\(\)'
  'daemon-rs/crates/daemon/src/flows/verdict_flow\.rs:.*self\.bus\.verdict_tx\.send\(verdict\)\.await'
  'daemon-rs/crates/daemon/src/commands/task_runtime\.rs:.*task_reply_tx\.send\(reply\)\.await'
  'daemon-rs/crates/daemon/src/commands/task_runtime\.rs:.*client\.get\(source\.remote\.trim\(\)\)\.send\(\)\.await\?'
  'daemon-rs/crates/daemon/src/daemon\.rs:.*task_lifecycle_tx\.send\(event\)\.await'
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
