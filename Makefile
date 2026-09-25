# Local entry points. CI runs the same commands.
#
#   make tools  install the pinned spec-spine into .tooling/ (git-ignored)
#   make gate   spec-spine governance: freshness, lint, coupling, coverage
#   make code   build, test, clippy and rustfmt over the workspace
#
# The spec-spine version is pinned twice and must agree: SPEC_SPINE_VERSION
# here and [meta] required_version in spec-spine.toml.

SPEC_SPINE_VERSION := 0.26.0
TOOLING            := $(CURDIR)/.tooling
SPEC_SPINE         := $(TOOLING)/bin/spec-spine

# couple compares HEAD against this base; CI passes the PR's base ref.
BASE ?= origin/main

.PHONY: tools gate code derived

tools:
	cargo install spec-spine-cli --version $(SPEC_SPINE_VERSION) --locked --root $(TOOLING)

gate:
	$(SPEC_SPINE) check --fail-on-warn
	$(SPEC_SPINE) lint --fail-on-warn
	$(SPEC_SPINE) couple --base $(BASE) --head HEAD
	$(SPEC_SPINE) index coverage --fail-on-untraced

# --all-features on clippy and test keeps parity with ci.yml: the optional
# checks-common module is linted and tested too.
code:
	cargo build --workspace --locked
	cargo test --workspace --all-features --locked
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	cargo fmt --all --check

# Regenerate the committed .derived/ after changing specs or claimed sources.
derived:
	$(SPEC_SPINE) compile
	$(SPEC_SPINE) index
