# Local entry points. CI runs the same gate.
#
#   make tools  install the pinned spec-spine into .tooling/ (git-ignored)
#   make gate   spec-spine governance and coupling, through the rendered
#               scripts/statecraft/gate.sh that CI runs
#   make code   build, test, clippy and rustfmt over the workspace
#
# The spec-spine version is pinned twice and must agree: SPEC_SPINE_VERSION
# here and [meta] required_version in spec-spine.toml.

SPEC_SPINE_VERSION := 0.26.0
TOOLING            := $(CURDIR)/.tooling
SPEC_SPINE         := $(TOOLING)/bin/spec-spine
GATE               := sh scripts/statecraft/gate.sh

# couple compares HEAD against this base; CI passes the PR's base ref.
BASE ?= origin/main

.PHONY: tools gate code derived

tools:
	cargo install spec-spine-cli --version $(SPEC_SPINE_VERSION) --locked --root $(TOOLING)

# governance: check, lint, index coverage --fail-on-untraced, index check and
# the authored-content rules, as .statecraft/setup/github-actions-rust.json
# configures them.
gate:
	$(GATE) governance
	BASE_SHA=$(BASE) HEAD_SHA=HEAD $(GATE) couple

# Not `gate.sh code`: that runs clippy and test with default features only.
# --all-features keeps parity with ci.yml, so the optional checks-common and
# golden-vectors code is linted and tested too.
code:
	cargo build --workspace --locked
	cargo test --workspace --all-features --locked
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	cargo fmt --all --check

# Regenerate the committed .derived/ after changing specs or claimed sources.
derived:
	$(SPEC_SPINE) compile
	$(SPEC_SPINE) index
