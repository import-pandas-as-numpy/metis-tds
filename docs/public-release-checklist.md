# Public repository release checklist

Use this checklist before changing repository visibility.

## Repository contents

- [ ] Review the complete Git history for secrets, private keys, tokens, live captures, personal data, and identifying operational details.
- [ ] Confirm the Apache-2.0 license matches the package metadata and is included in distributed container images.
- [ ] Confirm the example configuration is fictional and is not deployed unchanged on any live honeypot.
- [ ] Replace any live personality derived from `config/example.json` before publication; public seed data is intentionally fingerprintable.
- [ ] Run the test, lint, MSRV, dependency-policy, container-build, and zizmor checks on the exact revision to publish.

## GitHub settings

- [ ] Enable private vulnerability reporting and verify the **Report a vulnerability** path referenced by `SECURITY.md`.
- [ ] Enable the dependency graph, Dependabot alerts, and Dependabot security updates.
- [ ] Enable GitHub's default CodeQL setup for Rust and GitHub Actions.
- [ ] Enable secret scanning and push protection.
- [ ] Protect `main` with a ruleset requiring pull requests and the CI and zizmor checks.
- [ ] Disable unused features such as the wiki, or populate and maintain them.
- [ ] Add the repository topics listed in the project metadata handoff.

## Deployment

- [ ] Build the live container from an exact reviewed public commit without placing GitHub or registry credentials on the VPS.
- [ ] Confirm the runtime configuration, TLS key, telemetry, and captured payloads remain untracked and unreadable to other host users.
- [ ] Confirm the service UID cannot initiate outbound connections.
- [ ] Confirm a rollback image is present and the service remains healthy after the source-built image is activated.

GitHub recommends default CodeQL setup as the lowest-maintenance scanning mode for eligible repositories. Private vulnerability reporting is available to public repositories and provides a private disclosure path through repository security advisories.
