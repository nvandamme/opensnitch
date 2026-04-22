#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
scan_dir="$repo_root/daemon-rs/crates/daemon/src"

# Rule: no RuntimeIntent symbol usage and no intent.rs files in daemon runtime.
intent_symbol_matches="$(rg -n --no-heading "\\bRuntimeIntent\\b" "$scan_dir" || true)"
if [[ -n "$intent_symbol_matches" ]]; then
  echo "design-rule policy check: RuntimeIntent usage is forbidden"
  echo "$intent_symbol_matches" | sed 's/^/  /'
  exit 1
fi

intent_file_matches="$(find "$scan_dir" -type f -name "intent.rs" -print || true)"
if [[ -n "$intent_file_matches" ]]; then
  echo "design-rule policy check: intent.rs files are forbidden"
  echo "$intent_file_matches" | sed 's/^/  /'
  exit 1
fi

# Rule: services folders must not use *_service suffix.
service_suffix_matches="$(find "$scan_dir/services" -type d -name "*_service" -print || true)"
if [[ -n "$service_suffix_matches" ]]; then
  echo "design-rule policy check: services/*_service directory names are forbidden"
  echo "$service_suffix_matches" | sed 's/^/  /'
  exit 1
fi

# Rule: mod.rs must be linker-only in services/flows/commands/workers.
mod_rule_matches="$(
  rg -n --no-heading "^\\s*(pub\\s+)?(struct|enum|trait|impl|fn)\\s" \
    "$scan_dir" \
    -g "services/**/mod.rs" \
    -g "flows/**/mod.rs" \
    -g "commands/**/mod.rs" \
    -g "workers/**/mod.rs" || true
)"
if [[ -n "$mod_rule_matches" ]]; then
  echo "design-rule policy check: mod.rs linker-only rule violated"
  echo "$mod_rule_matches" | sed 's/^/  /'
  exit 1
fi

echo "design-rule policy check: pass"
