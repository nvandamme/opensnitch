#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
scan_dir="$repo_root/daemon-rs/crates/daemon/src"

# Rule: serde-backed contracts should live under models/*.
# Allowed exception: generic serde utility internals.
contract_matches="$({
  rg -n --no-heading 'derive\((Serialize|Deserialize)' "$scan_dir" \
    -g '!**/models/**' -g '!**/tests/**' || true
  rg -n --no-heading '^\s*#\[serde\(' "$scan_dir" \
    -g '!**/models/**' -g '!**/tests/**' || true
} | sed '/^$/d' || true)"

allowed_contract_regexes=(
  'daemon-rs/crates/daemon/src/utils/serde_helpers\.rs:'
)

contract_violations=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  allowed=false
  for pattern in "${allowed_contract_regexes[@]}"; do
    if [[ "$line" =~ $pattern ]]; then
      allowed=true
      break
    fi
  done
  if [[ "$allowed" == false ]]; then
    contract_violations+=("$line")
  fi
done <<< "$contract_matches"

if ((${#contract_violations[@]} > 0)); then
  echo "design-rule helper/contract check: serde contract ownership violation(s):"
  for v in "${contract_violations[@]}"; do
    echo "  $v"
  done
  echo
  echo "Policy: serde-backed contract definitions must live under models/* unless explicitly allowlisted as generic serde internals."
  exit 1
fi

# Rule: avoid one-line passthrough wrappers in utils/helpers.
helper_one_liner_matches="$(
  rg -n --no-heading \
    '\b(pub\s+)?fn\s+[A-Za-z0-9_]+\([^)]*\)\s*(->\s*[^\{]+)?\{\s*[A-Za-z0-9_:\.]+\([^;]*\)\s*\}\s*$' \
    "$scan_dir/utils" -g '*.rs' || true
)"

if [[ -n "$helper_one_liner_matches" ]]; then
  echo "design-rule helper/contract check: one-line passthrough helper(s) found in utils:"
  echo "$helper_one_liner_matches" | sed 's/^/  /'
  echo
  echo "Policy: avoid one-line passthrough wrappers that only forward a call without adding intent/invariants/context."
  exit 1
fi

# Rule: remove compatibility shim aliases once call sites migrate.
shim_symbol_matches="$(rg -n --no-heading '\bstatus_ok_payload\b' "$scan_dir" || true)"
if [[ -n "$shim_symbol_matches" ]]; then
  echo "design-rule helper/contract check: compatibility shim symbol(s) found:"
  echo "$shim_symbol_matches" | sed 's/^/  /'
  echo
  echo "Policy: remove compatibility shims in the same refactor slice after migration."
  exit 1
fi

echo "design-rule helper/contract check: pass"
