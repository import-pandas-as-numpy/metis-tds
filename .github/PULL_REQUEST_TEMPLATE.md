## Summary

<!-- What changed, and why? -->

## Security and protocol impact

<!-- Describe changes to parsing, authentication, telemetry, containment, compatibility, or resource bounds. Write "None" when not applicable. -->

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo test --all-targets --locked`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] Dependency policy checks pass
- [ ] Container builds, when applicable
- [ ] Documentation and changelog are updated, when applicable

## Data hygiene

- [ ] This change contains no deployment credentials, private keys, access tokens, live captures, personal data, or identifying production telemetry.
