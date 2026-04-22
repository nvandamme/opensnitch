#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <ebpf-artifact> [profile]" >&2
    exit 2
fi

artifact=$1
profile=${2:-unknown}

if [[ ! -f "$artifact" ]]; then
    echo "quirks check failed: missing artifact '$artifact'" >&2
    exit 1
fi

if ! command -v llvm-objdump >/dev/null 2>&1; then
    echo "quirks check failed: llvm-objdump not found in PATH" >&2
    exit 1
fi

# Flag .text.unlikely relocations coming from probe sections documented in QUIRKS.md.
suspicious_lines=$(
    llvm-objdump -r "$artifact" | awk '
        /RELOCATION RECORDS FOR \[/ {
            section=$0
            next
        }
        /\.text\.unlikely/ {
            if (section ~ /\[(tracepoint\/|uprobe\/|uretprobe\/|kprobe\/|kretprobe\/)/) {
                print section " -> " $0
            }
        }
    '
)

if [[ -n "$suspicious_lines" ]]; then
    echo "QUIRKS regression detected for profile '$profile' in '$artifact':" >&2
    echo "$suspicious_lines" >&2
    echo "See crates/ebpf/QUIRKS.md (Relocation Quirk: .text.unlikely entries in probe sections)." >&2
    exit 1
fi

echo "quirks check passed for profile '$profile': no .text.unlikely probe-section relocations"
