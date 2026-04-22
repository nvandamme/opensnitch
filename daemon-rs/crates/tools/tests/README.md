# Tools Tests

This folder is reserved for orchestration and harness-oriented tests for the `tools` crate.

Scope examples:
- command wiring and CLI guards
- non-destructive orchestration behavior
- perf/parity command surface validation

Out of scope:
- daemon internal unit tests (kept under `daemon/src/tests` until a future lib/bin split)
