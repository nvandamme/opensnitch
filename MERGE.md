# Merge Plan for Range `f500b7ca..1945c018`

## Objective

Collapse a long daemon-rs history window into wave-level condensed commits while preserving release checkpoints and changelog continuity.

- Source window: `f500b7ca5fe45a5f99b6b3284ae35e7e565d841b..1945c018a7f1749f2eaa18ae69a266f5cba2a261`
- Expected shape: condensed wave commits on `daemon-rs` (not wave PRs)
- Changelog rule: keep the full aggregated changelog content contributed by commits inside each collapsed wave

## Hard Rules

1. **Waves are collapsed commits, not PR units.**
2. **Release checkpoint commits must remain in history** as explicit milestones.
3. **Checkpoint tags must be namespaced** from `vX.Y...` to `daemon-rs:vX.Y...`.
4. **Tag migration scope is limited to tags that exist on `origin` (`nvandamme/opensnitch`)**.
5. Use `--force-with-lease` for rewritten branch/tag push operations.

## Wave Boundaries

1. Wave 1: `f500b7ca..aaf24845`
2. Wave 2: `aaf24845..b9a4cd58`
3. Wave 3: `b9a4cd58..718d77cb`
4. Wave 4: `718d77cb..967eaf60`
5. Wave 5: `967eaf60..e19ef26d`
6. Wave 6: `e19ef26d..58e133cc`
7. Wave 7: `58e133cc..5b508eea`
8. Wave 8: `5b508eea..95ac3a33`
9. Wave 9: `95ac3a33..4d5a0452`
10. Wave 10: `4d5a0452..1945c018`

## Mandatory Milestone Commits to Keep

- `3246981b` (`release: prepare v0.1.0`)
- `b9a4cd58` (`release: v0.1.1`)
- `718d77cb` (`release: v0.2.0`)
- `967eaf60` (`release: v0.3.0`)
- `e19ef26d` (`release: v0.4.0`)
- `ea6b475a` (`release: v0.5.0`)
- `bdd36b4e` (`release: v0.5.0`)
- `a4e05f8d` (`release: v0.6.0`)
- `5b508eea` (`release: v0.7.0`)

## Collapse Method

For each wave:

1. Replay non-milestone commits as one condensed commit (or segmented condensed commits if split by milestone boundaries).
2. Replay milestone release commits as standalone commits with their release messages intact.
3. Create/update a checkpoint tag `merge-wave-N-ok` at the wave tip.

## Tag Migration Plan

Only for tags present on `origin`:

1. Resolve applicable legacy tags (`v0.1.0` ... `v0.7.0`, and any other daemon-rs version tags present on origin).
2. Create `daemon-rs:v*` tags on the corresponding rewritten milestone commits.
3. Delete migrated legacy `v*` tags on origin.
4. Push new namespaced tags to origin.

## Push Policy

After history rewrite on `daemon-rs`:

```bash
git push --force-with-lease origin daemon-rs
git push --force-with-lease origin --tags
```

For tag replacement operations:

```bash
git push origin :refs/tags/<old-v-tag>
git push origin refs/tags/daemon-rs:<version>
```

## Validation Gates

Minimum required before final push:

1. `git log --first-parent` shows condensed wave commits.
2. Milestone release commits remain reachable from `daemon-rs` history.
3. `git show daemon-rs:v*` resolves for all migrated daemon-rs versions.
4. Changelog contains expected release history after collapse.
5. Working tree clean (excluding intentionally untracked local artifacts).
