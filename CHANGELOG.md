# Changelog

All notable user-visible changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

## 0.1.7 - 2026-08-23

### Fixed

- Emit protocol-correct TDS 4.2 login acknowledgements, errors, informational messages, result metadata, rows, and completion tokens so legacy clients can remain connected and execute SQL batches.
- Negotiate LOGIN7 response versions and pre-TDS-7.2 field widths from the client's requested protocol instead of always emitting TDS 7.4 layouts.

## 0.1.6 - 2026-08-23

### Fixed

- Parse the 86-byte fixed LOGIN7 header used by TDS 7.0 and 7.1 clients without weakening the 94-byte boundary required by TDS 7.2 and later.

### Changed

- Build amd64 and arm64 release images on native GitHub-hosted runners, then publish them as one attested multi-platform manifest.

## 0.1.5 - 2026-08-23

### Fixed

- Capture and parse plaintext LOGIN and LOGIN7 messages sent after PRELOGIN encryption negotiation by noncompliant scanners, while preserving the normal TLS path for conforming clients.

### Added

- Emit explicit `plaintext_login_after_prelogin` telemetry when a client ignores the negotiated encryption mode.

## 0.1.4 - 2026-08-22

### Fixed

- Encode PRELOGIN instance validation as the one-byte match status required by MS-TDS instead of echoing the configured instance name.
- Return the specified encryption values when required TLS receives `ENCRYPT_ON`, `ENCRYPT_REQ`, or `ENCRYPT_NOT_SUP`.

### Changed

- Record the PRELOGIN instance-match decision in telemetry for protocol-fidelity diagnostics.

## 0.1.3 - 2026-08-22

### Added

- Publish public multi-architecture release images to GitHub Container Registry with an SPDX SBOM, SLSA provenance, and a GitHub artifact attestation.

### Changed

- Document anonymous, digest-pinned GHCR deployment as the preferred container deployment path while retaining the public source-build procedure as a fallback.

## 0.1.2 - 2026-08-22

### Changed

- Distinguish one-byte direct-login candidates from fully framed TDS LOGIN/LOGIN7 messages in telemetry and metrics.
- Identify the specific LOGIN7 variable field and descriptor bounds responsible for parsing failures.

### Security

- Retain only the credential-free eight-byte TDS header for direct-login framing failures while continuing to exclude all login payload bytes from generic failure telemetry.

## 0.1.1 - 2026-08-22

### Security

- Remove Tiberius's unused Windows integrated-authentication feature from the test dependency graph, eliminating the vulnerable `rand` 0.7.3 lockfile entry.

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
