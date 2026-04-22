# Firewall Backend Semantics Fixtures

These fixtures model OpenWrt firewall backend semantics for daemon runtime
adapters/services.

## Boundary

- Files in `daemon-rs/data/*.uci` are **UCI syntax fixtures** for
  `storage-format-uci` parser/emitter coverage only.
- Files in `daemon-rs/data/fixtures/firewall/*.json` are
  **runtime-semantics fixtures** for firewall backend loading, normalization,
  and behavior tests.

Do not mix these two fixture classes in the same test intent.

## Current fixtures

- `openwrt-firewall-runtime.example.json`: chain/rule runtime semantics sample.
- `top-rule-system-fw.example.json`: top-level `SystemRules[].Rule` compatibility shape.
- `position-parsing-system-fw.example.json`: position string parsing edge cases.
- `chain-inherit-system-fw.example.json`: nested chain rule inheritance
  (`table`/`chain` inherited from parent chain).
- `nftables-test-sysfw.example.json`: canonical nftables semantics fixture
  copied from Go daemon testdata for cross-implementation parity checks.
- `nftables-supported-expressions.example.json`: canonical expression samples
  used by nftables netlink support tests, derived from Go testdata semantics.
