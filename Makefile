# Local entry points. CI runs the same gate.
#
#   make tools  install the pinned spec-spine into .bin/ (git-ignored)
#   make gate   spec-spine governance and coupling, through the rendered
#               scripts/statecraft/gate.sh that CI runs
#   make code   build, test, clippy and rustfmt over the workspace
#
# The spec-spine version is declared once in spec-spine.toml.

SPEC_SPINE_VERSION := $(shell sed -n 's/^required_version = "=\(.*\)"/\1/p' spec-spine.toml)
TOOLING            := $(CURDIR)/.bin
SPEC_SPINE         := $(TOOLING)/spec-spine
GATE               := sh scripts/statecraft/gate.sh

# couple compares HEAD against this base; CI passes the PR's base ref.
BASE ?= origin/main

.PHONY: tools gate code derived

tools:
	sh scripts/statecraft/install-spec-spine.sh

# governance: check, lint, index coverage --fail-on-untraced, index check and
# the authored-content rules, as .statecraft/setup/github-actions-rust.json
# configures them.
gate:
	$(GATE) governance
	BASE_SHA=$(BASE) HEAD_SHA=HEAD $(GATE) couple

# Not `gate.sh code`: that runs clippy and test with default features only.
# --all-features keeps parity with .github/workflows/all-features.yml, so the
# optional checks-common and golden-vectors code is linted and tested too.
code:
	cargo build --workspace --locked
	cargo test --workspace --all-features --locked
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
	cargo fmt --all --check

# Regenerate the committed .statecraft/derived/ after changing specs or
# claimed sources.
derived:
	$(SPEC_SPINE) compile
	$(SPEC_SPINE) index
