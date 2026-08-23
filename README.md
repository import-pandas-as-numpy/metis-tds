# Metis TDS honeypot

[![CI](https://github.com/import-pandas-as-numpy/metis-tds/actions/workflows/ci.yml/badge.svg)](https://github.com/import-pandas-as-numpy/metis-tds/actions/workflows/ci.yml)
[![zizmor](https://github.com/import-pandas-as-numpy/metis-tds/actions/workflows/zizmor.yml/badge.svg)](https://github.com/import-pandas-as-numpy/metis-tds/actions/workflows/zizmor.yml)
[![fuzzing](https://github.com/import-pandas-as-numpy/metis-tds/actions/workflows/fuzz.yml/badge.svg)](https://github.com/import-pandas-as-numpy/metis-tds/actions/workflows/fuzz.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Metis is a contained Microsoft SQL Server and SAP ASE TDS honeypot. It accepts real TDS connections, records login and request telemetry, classifies attacker intent, and returns synthetic database responses. It never executes submitted SQL, commands, assemblies, paths, or network destinations.

> [!CAUTION]
> Metis receives untrusted network traffic and can deliberately record attacker-supplied credentials. Deploy it only on infrastructure you own or are authorized to operate, inside the containment boundary described below. It is pre-1.0 research software, not a database server or a security boundary by itself.

Protocol behavior is implemented from the current Microsoft MS-TDS/MS-SSTDS specifications and published SAP/Open Client structures. The project supports bounded TDS 4.2, 4.6, 5.0, 7.x, and 8.0 framing; legacy and LOGIN7 authentication; SQL, RPC, bulk, transaction, federated, NTLM, SPNEGO/Kerberos, and ASE token streams; ASE proprietary-v1 ciphertext negotiation and RSA password negotiation versions 2–4; stateful attacker-oriented semantics; synthetic result sets; JSONL telemetry; and bounded payload capture. See [protocol coverage and evidence](docs/protocol-coverage.md) for precise guarantees and the remaining proprietary cryptographic boundaries.

## Safety boundary

Run this as an unprivileged, isolated service with outbound traffic denied. The runtime intentionally contains no subprocess or generic command-execution facility. Submitted binary material is bounded, hashed, and stored under generated names with mode `0600` when payload capture is enabled. Login-password and full-message capture are separately opt-in; captured credentials are attacker-supplied research data, never deployment credentials.

## Quick start

```console
cargo build --release --locked
cp config/example.json config/local.json
./target/release/metis-tds --config config/local.json
```

The example binds to `127.0.0.1:1433` to avoid accidental exposure. Change the address only after applying the deployment controls in `docs/deployment.md`.

The example personality is entirely fictional and intentionally contains weak honey credentials for adversary interaction. Never reuse its domain, usernames, or passwords for a real identity or service.

Do not expose the public example unchanged. Its server identity, users, schema, and seed records are visible in this repository and are therefore fingerprintable. Create a private deployment configuration with a distinct fictional organization, identities, values, and TLS material. Configuration belongs at deploy time and is never baked into the image.

The research example enables `telemetry.capture_login_passwords` and `payloads.capture_login_messages`. Clear attempted passwords are written only to the mode-`0600` JSONL sink; validation forbids enabling that option while stdout telemetry is active. Every fully framed TDS 4.2/5.0 LOGIN, LOGIN7, and stage-identified authentication continuation is stored before parsing as a mode-`0600` generated artifact. Incomplete authentication exchanges are retained under the same policy. Parser failures never include login payload bytes in generic diagnostics; a direct-login framing failure may include at most its credential-free eight-byte TDS header. The older `payloads.capture_login7` key remains a backward-compatible alias.

`personality.accept_source_after_attempts` optionally admits a source after a configurable number of parsed SQL-auth attempts regardless of the submitted username/password. A value of `X` applies normal authentication to attempts 1 through `X`, then accepts attempt `X+1` and later from that IP. `null` disables the behavior. Counters are in-memory, reset on restart, and do not count or bypass integrated authentication.

TLS certificate conversion, systemd hardening, outbound-deny guidance, and Internet-indexing caveats are in `docs/deployment.md`.

## Container

Release images for `linux/amd64` and `linux/arm64` are public and can be pulled anonymously from GHCR. Pin the reviewed release or, preferably, the manifest digest recorded by the registry:

```console
docker pull ghcr.io/import-pandas-as-numpy/metis-tds:0.1.9
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src="$PWD/config/local.json",dst=/etc/metis-tds/config.json,readonly \
  --mount type=volume,src=metis-tds-data,dst=/var/lib/metis-tds \
  --mount type=volume,src=metis-tds-logs,dst=/var/log/metis-tds \
  -p 1433:1433 ghcr.io/import-pandas-as-numpy/metis-tds:0.1.9
```

The image does not contain a deployment configuration. Supply one at runtime at `/etc/metis-tds/config.json`; for container networking its `listener.address` must use `0.0.0.0:1433`. Keep telemetry and captured-payload paths in the mounted data volumes. For an Internet-facing deployment, enable TLS and enforce outbound denial at the container or host network boundary.

Each release image includes registry SBOM/provenance attestations and a GitHub artifact attestation. See [secure deployment](docs/deployment.md#published-container-on-an-isolated-vps) for digest pinning and verification. Anonymous source builds remain available as a fallback without GitHub or registry credentials.

## Verification

```console
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check
```

The test suite includes strict TDS 4.2, 4.6, and 5.0 login/query/result flows, ASE RSA v2/v3/v4 authentication flows, independent Tiberius client flows for plaintext SQL batch/RPC and TDS 7.x TLS, and a strict TDS 8.0 raw-TLS/PRELOGIN/LOGIN7 flow. `sqlcmd`, SSMS, FreeTDS, Impacket, Censys, and Shodan remain unclaimed until they have been exercised against a deployed instance.

Coverage-guided fuzz targets are isolated from the production dependency graph under `fuzz/`. They require nightly Rust and `cargo-fuzz 0.13.2`:

```console
for target in packet prelogin login7 tokens; do
  cargo +nightly fuzz run "$target" -- -runs=100000 -max_len=65536 -timeout=5
done
```

The corpus directories are intentionally retained. On ptrace-restricted hosts where LeakSanitizer cannot perform its final process scan, build with `cargo +nightly fuzz build` and run the generated ASan-instrumented target with `ASAN_OPTIONS=detect_leaks=0`; do not disable AddressSanitizer itself.

## Project policy

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Support](SUPPORT.md)
- [Changelog](CHANGELOG.md)
- [Protocol coverage](docs/protocol-coverage.md)
- [Secure deployment](docs/deployment.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
