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

`.github/workflows/all-features.yml` is not managed. The profile's `code`
job runs clippy and test with default features only, so this reusable
workflow runs them with `--all-features`. It is declared in
`ci.extra_required_jobs`, so `statecraft-ci.yml` calls it as the job
`all-features` and `ci-gate` blocks on it.

Locally, `make tools gate code` runs the same checks.
