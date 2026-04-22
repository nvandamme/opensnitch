#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
scan_dir="$repo_root/daemon-rs/crates/daemon/src"

# Policy: immutable state/cache/snapshot reads must be lock-free sync memreads.
# Excludes tests by design.

# 1) Runtime call sites must not await state/cache/snapshot getters.
async_state_read_await_matches="$({
  rg -n --no-heading \
    '\\.[A-Za-z0-9_]*(snapshot|state|cache)[A-Za-z0-9_]*\\(\\)\\.await' \
    "$scan_dir" \
    -g '!**/tests/**' || true
} | sed '/^$/d' || true)"

if [[ -n "$async_state_read_await_matches" ]]; then
  echo "immutable-state policy check: found async state/cache/snapshot read await usage(s):"
  echo "$async_state_read_await_matches" | sed 's/^/  /'
  echo
  echo "Policy: immutable state reads must be sync Arc memreads (no async getter wrappers)."
  exit 1
fi

# 2) Service methods on &self that look like state/cache getters must not be async.
async_state_getter_defs="$({
  rg -n --no-heading \
    'async fn [A-Za-z0-9_]*(state|cache)[A-Za-z0-9_]*.*&self' \
    "$scan_dir" \
    -g '!**/tests/**' || true
} | sed '/^$/d' || true)"

if [[ -n "$async_state_getter_defs" ]]; then
  echo "immutable-state policy check: found async state/cache getter definition(s) on &self:"
  echo "$async_state_getter_defs" | sed 's/^/  /'
  echo
  echo "Policy: getter-style immutable state/cache reads on &self must stay sync."
  exit 1
fi

# 3) Runtime paths must not lock snapshot/state/cache fields for read access.
lock_based_state_read_matches="$({
  rg -n --no-heading \
    '\\.[A-Za-z0-9_]*(snapshot|state|cache)[A-Za-z0-9_]*\\.lock\\(\\)\\.await' \
    "$scan_dir" \
    -g '!**/tests/**' || true
} | sed '/^$/d' || true)"

if [[ -n "$lock_based_state_read_matches" ]]; then
  echo "immutable-state policy check: found lock-based snapshot/state/cache read usage(s):"
  echo "$lock_based_state_read_matches" | sed 's/^/  /'
  echo
  echo "Policy: immutable state reads must avoid mutex/lock read paths in runtime hot paths."
  exit 1
fi

echo "immutable-state policy check: pass"
