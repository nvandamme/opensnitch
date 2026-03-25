# eBPF Quirks and Gotchas

This document tracks non-obvious constraints found while implementing Aya-based eBPF probes in this crate.

## Relocation Quirk: .text.unlikely entries in probe sections

### Symptom

Some probe programs fail to load or verify, often with errors that look unrelated to source code intent.
Common signatures include:

- last insn is not an exit or jmp
- processed 0 insns
- verifier rejection that appears to happen before meaningful instruction analysis

In object-level relocation dumps, affected probe sections show relocations to .text.unlikely.

### Root Cause

Rust debug-oriented panic and safety paths can be lowered into .text.unlikely code blocks.
If probe section code references those blocks, the resulting relocations are not valid for expected BPF loader/runtime behavior in these paths.

This typically happens when probe code introduces:

- implicit bounds checks on slices or indexing-heavy code
- alignment-check or panic-generating code paths
- helper usage patterns that trigger compiler-generated fallback/panic blocks

### Resolution Pattern Used

The stabilization work for DNS and process probes applied these patterns:

1. Prefer explicit section wrapper entrypoints for probes.
- Define exported wrapper functions with explicit link_section names matching the intended probe section.
- Keep core logic in internal handler functions.

1. Keep probe hot paths panic-path-safe.
- Avoid constructs that can trigger hidden panic lowering in probe sections.
- Prefer direct pointer-oriented writes and explicit guard checks over indexing-heavy convenience code in hot probe paths.
- Use scratch maps for temporary buffers where it simplifies verifier-safe memory handling.

1. Keep runtime symbol wiring aligned with wrapper symbols.
- If wrapper symbol names change, update userspace program lookup names accordingly.

1. Validate relocations directly from built artifacts.
- Inspect relocation records for probe sections and ensure they only reference expected map/event symbols.

### Verification Commands

Run from daemon-rs:

Release artifact relocation inspection:

llvm-objdump -r target/bpfel-unknown-none/release/libopensnitch_ebpf.so

Debug artifact relocation inspection:

llvm-objdump -r target/bpfel-unknown-none/debug/libopensnitch_ebpf.so

Filter for suspicious targets and probe sections:

llvm-objdump -r target/bpfel-unknown-none/debug/libopensnitch_ebpf.so | rg 'tracepoint/|uprobe/|uretprobe/|\.text\.unlikely'

### Practical Rule

When adding or refactoring probes:

- start with explicit section wrappers,
- keep probe handlers minimal and verifier-oriented,
- verify relocation tables in both debug and release,
- treat .text.unlikely relocations in probe sections as a regression to fix before relying on runtime smoke tests.
