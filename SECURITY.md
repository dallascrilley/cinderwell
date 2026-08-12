# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/dallascrilley/cinderwell/security/advisories/new),
or by email to dallas@dallascrilley.com. Please do not open a public issue for
a security problem.

Include the affected commit, what you believe the impact is, and steps to
reproduce it. I aim to acknowledge within seven days and to say whether the
report is accepted, with a rough timeline for a fix.

## Supported versions

This project is pre-1.0 and single-branch. Only `main` receives security fixes.

## What this repository is

Cinderwell is an architectural extract: disposable cloud dev servers that
destroy themselves on a lease and produce a proof receipt. It is not a hosted
service. The test suite is hermetic (fakes only); live provider use requires
credentials you supply.

## Trust boundary (short)

| Surface | What it does |
| --- | --- |
| Plan hash | Every mutation names one plan by SHA-256; edits invalidate the hash |
| Authority | Terminal confirmation or a written approval; no environment escape hatch |
| Teardown guards | Account, drift, work preservation, then exact-ID delete + fresh re-read |
| Reaper | Runs ordinary teardown only — no private path, no attestation shortcut |
| Secrets | Config holds **commands that fetch secrets**, never secret values |

Configuration loading refuses values that look like credentials. An already
exported `HCLOUD_TOKEN` wins for interactive use so the config file stays
commit-safe. See **Honest boundaries** in [README.md](README.md) for what this
repository deliberately does not claim (multi-cloud, multi-operator, visual
parity of a live host).

## Credentials

Never commit tokens, OAuth secrets, or real provider resource IDs.
`examples/config.example.json` uses synthetic IDs and a placeholder
`your-secret-tool` command shape. Point the commands at your own secret store
(1Password CLI, `pass`, a custom script) — do not paste secrets into the file.
