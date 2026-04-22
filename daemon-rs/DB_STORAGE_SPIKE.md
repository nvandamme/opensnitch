# DB Storage Spike (redb)

Date: 2026-03-30
Scope: daemon-rs cold persistence only (`db-storage` non-default feature)

## Goal

Evaluate a path to add ACID persistence for cold snapshotables without changing hot-path behavior.

Hot path remains unchanged:
- verdict path (`nfqueue -> owner lookup -> rule match -> verdict`) stays in-memory
- existing `ArcSwap<CompiledRuleSet>`, `quick-cache`, `DashMap` stay as-is
- no database calls on per-packet or per-connection hot loops

## Current Readiness Snapshot

Observed from current code:
- `StorageService` is file-operation-centric and currently acts as a global file API + event bus.
- No generic `StorageBackend` trait exists yet in `services/storage`.
- Domain persistence entry points still rely on file I/O wrappers, including:
  - subscriptions (`services/subscription/storage.rs`)
  - rules (`services/rule/storage.rs` and mutation paths)
  - tasks (`services/task/storage.rs` and runtime handlers)
  - config (`services/config/storage.rs`)
  - process hash cache (domain-specific storage model)

Implication:
- A direct redb insertion would create broad, risky edits.
- A preparatory storage-port seam should be introduced first.

## Proposed Incremental Plan

Phase 0: Port extraction (no behavior change)
- Add `StorageBackend` trait with minimal primitives used by current code paths.
- Implement `FileBackend` using current `StorageService` file logic.
- Make `StorageService` hold `Arc<dyn StorageBackend>` and delegate.
- Keep defaults exactly file-based.

Phase 1: redb backend skeleton (feature-gated, off by default)
- Add `db-storage` Cargo feature and optional `redb` dependency.
- Add `RedbBackend` with open/init and transaction scaffold only.
- Keep all runtime paths on `FileBackend` unless explicitly enabled.

Phase 2: Single-domain pilot
- Migrate `subscriptions` first (lowest blast radius compared to rule/verdict paths).
- Add import path from existing file format into redb when DB is empty.
- Add export command/path back to files for rollback.

Phase 3: Cross-domain transaction envelope
- Extend to rules + tasks + config snapshots + hash cache.
- Add one transaction boundary for multi-entity mutation groups.
- Keep in-memory snapshot swap sequence unchanged.

## Acceptance Checks

Functional:
- Startup with no DB file should still work and preserve current defaults.
- Feature disabled path must be behavior-identical to current file storage.
- Crash between multi-entity writes should not leave partial committed state in DB mode.

Performance:
- No regression on hot-path perf tests.
- No extra lock/wait operations added to verdict flow.

Operational:
- Clear downgrade path: export DB contents back to file format.
- Explicit diagnostics/logging when DB backend is selected.

## Risks

- Schema/version evolution strategy for persisted records.
- Dual-write transition complexity during migration periods.
- Interaction with existing file-watch reload semantics while DB mode is active.

## Recommended Next PR (prep-only)

Submit a no-behavior-change PR containing only:
- `StorageBackend` trait
- `FileBackend` implementation
- delegation wiring in `StorageService`
- unchanged runtime behavior and unchanged on-disk format

This isolates risk before introducing `redb` as an optional backend.
