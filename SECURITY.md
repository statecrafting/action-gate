# Security policy

## Reporting a vulnerability

Report security issues **privately, through GitHub's private vulnerability
reporting** for this repository: open the repository's **Security** tab and
choose **Report a vulnerability**. That is the only reporting channel; there
is no security email address.

Please do not open a public issue, pull request or discussion for a suspected
vulnerability.

Private vulnerability reporting is a repository setting the repository owner
enables. If the **Report a vulnerability** button is not shown, the setting is
not yet on; do not fall back to a public channel.

## What is in scope

This repository's code and the crates it publishes: `action-gate-core` and
`action-gate-types` under `crates/`. That includes the secret detector
registry, whose findings must never echo a detected secret. Findings in a
consuming project belong to that project's own policy.

## Supported versions

Reports are judged against the latest published `action-gate-core` release
(currently 0.2.x) and the current `main`. Fixes ship as a new release; older
versions are not patched.
