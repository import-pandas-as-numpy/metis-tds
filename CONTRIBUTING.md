# Contributing to Metis TDS

Thanks for helping improve Metis. Contributions that strengthen protocol fidelity, containment, observability, tests, and documentation are welcome.

## Before opening an issue

- Search existing issues and pull requests.
- Do not post vulnerabilities, deployment credentials, captured passwords, raw attacker payloads, or identifying production telemetry in a public issue. Follow [SECURITY.md](SECURITY.md) for private reports.
- Keep operational questions about a specific Internet-facing honeypot free of public IPs and evidence unless disclosure is intentional.

## Development setup

The repository pins its contributor toolchain in `rust-toolchain.toml`. Install [Rust through rustup](https://rustup.rs/), then run:

```console
cargo build --locked
cargo test --all-targets --locked
```

Container changes should also build successfully:

```console
docker build --build-arg VCS_REF=local -t metis-tds:dev .
```

## Required checks

Run these before submitting a pull request:

```console
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check
```

CI also checks the declared Rust 1.85 minimum supported version and builds the production container.

## Pull requests

- Keep each pull request focused and explain the security or protocol tradeoffs it introduces.
- Add regression tests for parser, state-machine, or semantic changes.
- Update `README.md`, `docs/`, and `CHANGELOG.md` when behavior or compatibility claims change.
- Preserve bounded reads, timeouts, generated storage names, and the no-execution/no-outbound safety boundary.
- Do not weaken containment defaults merely to make a compatibility test pass.
- Add an entry under `Unreleased` in `CHANGELOG.md` for user-visible changes.

By submitting a contribution, you agree that it is licensed under the repository's Apache License 2.0.

## Fuzzing

Fuzz targets live in the isolated `fuzz/` package and require nightly Rust plus `cargo-fuzz`:

```console
for target in packet prelogin login7 tokens; do
  cargo +nightly fuzz run "$target" -- -runs=100000 -max_len=65536 -timeout=5
done
```

Minimize new corpus inputs before committing them. Never add live captures, credentials, personal data, malware, or proprietary samples to the corpus. Corpus files must be synthetic or otherwise safe to redistribute under Apache-2.0.
