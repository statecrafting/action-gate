---
id: "003-statecraft-derived-layout"
title: "Move spec-spine's committed derived artifacts to .statecraft/derived"
status: approved
implementation: complete
created: "2026-10-04"
summary: >
  Moves the committed spec registry and codebase index from the legacy
  repository-root `.derived/` to `.statecraft/derived/`, the location the
  adopted Statecraft profile revision 14 and its managed instructions,
  ignores and AI review exclusion already name. Only the layout changes:
  the shard contents, the spec-spine pin, the CI profile and every managed
  file stay as they are.
amends:
  - "002-statecraft-profile-14"
depends_on:
  - "002-statecraft-profile-14"
obligations:
  - id: "R-1"
    kind: requirement
    text: "spec-spine's derived_dir is .statecraft/derived, the committed registry and index live there, and no repository-root .derived/ remains."
    anchor: "3-layout-contract"
---

# 003: Derived artifacts under .statecraft/derived

## 1. Purpose

Profile revision 14 (spec 002) renders every managed surface on the
assumption that spec-spine's compiled artifacts live under
`.statecraft/derived/`:

- the AI review excludes the prefix `.statecraft/derived`
  (`.statecraft/setup/github-actions-rust.json`, `exclude`), so regenerated
  shards are not reviewed as authored change;
- the managed ignore block ignores `.statecraft/derived/**/build-meta.json`,
  the one non-deterministic artifact;
- the managed `.statecraft/AGENTS.md` names `.statecraft/derived/` as the
  committed home of spec-spine's compiled artifacts.

This repository predates that layout and still set `derived_dir =
".derived"`. Every PR that touched a spec or a claimed source therefore sent
its regenerated shards to the AI review, where they counted toward the diff
budget, and the managed instructions described a directory that did not
exist. This spec closes that gap on the repository's side, without editing
any managed file.

## 2. Territory

This spec owns no product code and changes no published crate. It changes
the adopted `spec-spine.toml` layout and index exclusions, moves the
committed shard trees, and updates the repository's own comments and
attributes that named the old path (`.gitignore`, `.gitattributes`,
`Makefile`). The managed workflows, scripts, setup policy and ignore block
are unchanged, so no review exception is needed.

It amends spec 002 in the way 002 amended 001: 002 adopted revision 14's
managed files but left the repository's own layout on the pre-profile
`.derived/` path, and this spec completes that half of the migration.
Spec 002's text is not edited.

## 3. Layout contract

- `[layout] derived_dir` is `.statecraft/derived`.
- `.statecraft/derived/spec-registry/` and `.statecraft/derived/codebase-index/`
  hold the committed shards; nothing remains at `.derived/`.
- `[index] resolver_exclusions` names `.statecraft/derived` in place of
  `.derived`.
- The repository's own `.derived/**/build-meta.json` ignore is removed,
  because the managed block already ignores
  `.statecraft/derived/**/build-meta.json`.
- The opt-in `action-gate-derived-regen` merge-driver glob follows the
  shards to `.statecraft/derived/**/*.json`.
- `.tooling` is left as it is. The managed ignore block still carries it,
  so retiring it is the profile's decision, not this repository's.

The shards are regenerated with the pinned spec-spine 0.28.0. Every shard
that existed before the move is byte-identical to the one it replaces,
except the codebase index's input manifest, which records the new
`spec-spine.toml` content hash. This spec adds its own two shards.

## 4. Acceptance criteria

- `make gate` passes: the registry and index are fresh at the new location,
  lint is clean, coverage is unchanged, and coupling reports no drift.
- `make code` passes.
- Hosted `ci-gate` passes, and the AI review's subject no longer includes
  derived shards on later PRs.

## 5. Approval basis

The owner chose this task on 2026-10-04 from proposed next steps for this
repository. Merging the PR that carries this spec is the owner's
ratification of it.
