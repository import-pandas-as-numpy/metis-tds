# Changelog

All notable user-visible changes are documented here. The project follows [Semantic Versioning](https://semver.org/) once releases are tagged.

## Unreleased

### Added

- TDS 4.2 LOGIN parsing and pre-parse login-message capture.
- Optional per-source authentication bypass after a configured number of SQL-auth attempts.
- Public contribution, security, conduct, and support policies.
- Anonymous source-build deployment guidance for public checkouts.

### Security

- Login wire material is kept out of generic parser-failure prefixes.
- Container execution uses an unprivileged identity and documents an external outbound-deny boundary.

## 0.1.0 - Unreleased

- Initial contained, stateful TDS honeypot implementation.
