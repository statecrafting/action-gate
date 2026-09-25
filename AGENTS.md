@.statecraft/AGENTS.md

# action-gate

## Continuous integration

CI is rendered by Statecraft from the profile `github-actions-rust`
(revision 7). The managed files are `.github/workflows/statecraft-*.yml`,
`scripts/statecraft/*` and `.statecraft/setup/*`. Change them only by
editing `project.setup.parameters` in `.statecraft/environment.json` and
re-rendering (`statecraft-cli init plan .`, then
`statecraft-cli init apply . --plan <identity>`), never by hand. A change to
any of them, or to any file under `.github/workflows/`, needs the owner's
approval on the `statecraft-review-exception` Environment.

`ci.yml` is not managed. It stays until the rendered CI runs clippy and
test with `--all-features`, which the profile's `code` job does not.

Locally, `make tools gate code` runs the same checks.
