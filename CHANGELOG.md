# Changelog

All notable user-visible changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.1.0 - 2026-08-22

### Added

- Initial contained, stateful TDS honeypot implementation.
- TDS 4.2 LOGIN parsing and pre-parse login-message capture.
- Optional per-source authentication bypass after a configured number of SQL-auth attempts.
- Public contribution, security, conduct, and support policies.
- Anonymous source-build deployment guidance for public checkouts.
- Scheduled coverage-guided fuzz smoke tests.
- Container vulnerability scanning and SPDX SBOM artifacts in CI.

### Security

- Login wire material is kept out of generic parser-failure prefixes.
- Container execution uses an unprivileged identity and documents an external outbound-deny boundary.
