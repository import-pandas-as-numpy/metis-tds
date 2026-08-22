# Metis TDS honeypot

Metis is a contained Microsoft SQL Server TDS 7.x/8.0 honeypot. It accepts real TDS connections, records login and request telemetry, classifies attacker intent, and returns synthetic SQL Server responses. It never executes submitted SQL, commands, assemblies, paths, or network destinations.

The detailed requirements are in `mssql-tds-honeypot-spec.md`; verified progress and compatibility evidence are in `IMPLEMENTATION_LOG.md`.

Protocol behavior is implemented from Microsoft's current MS-TDS and MS-SSTDS open specifications. The project supports bounded multi-packet framing, TDS 4.2 LOGIN (`0x02`), PRELOGIN and direct LOGIN7, TDS 7.x-wrapped TLS 1.2/1.3, TDS 8.0 TLS-before-PRELOGIN with `tds/8.0` ALPN, SQL batches, common RPC parameters, stateful attacker-oriented semantics, synthetic result sets, JSONL telemetry, and bounded payload capture.

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

The research example enables `telemetry.capture_login_passwords` and `payloads.capture_login_messages`. Clear attempted passwords are written only to the mode-`0600` JSONL sink; validation forbids enabling that option while stdout telemetry is active. Every fully framed TDS 4.2 LOGIN or LOGIN7 message is stored before parsing as a mode-`0600` generated artifact, while ordinary failure events never include either login format's wire prefix. The older `payloads.capture_login7` key remains a backward-compatible alias.

`personality.accept_source_after_attempts` optionally admits a source after a configurable number of parsed SQL-auth attempts regardless of the submitted username/password. A value of `X` applies normal authentication to attempts 1 through `X`, then accepts attempt `X+1` and later from that IP. `null` disables the behavior. Counters are in-memory, reset on restart, and do not count or bypass integrated authentication.

TLS certificate conversion, systemd hardening, outbound-deny guidance, and Internet-indexing caveats are in `docs/deployment.md`.

## Container

Build and run the production image with:

```console
docker build -t metis-tds .
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src="$PWD/config/local.json",dst=/etc/metis-tds/config.json,readonly \
  --mount type=volume,src=metis-tds-data,dst=/var/lib/metis-tds \
  --mount type=volume,src=metis-tds-logs,dst=/var/log/metis-tds \
  -p 1433:1433 metis-tds
```

The image does not contain a deployment configuration. Supply one at runtime at `/etc/metis-tds/config.json`; for container networking its `listener.address` must use `0.0.0.0:1433`. Keep telemetry and captured-payload paths in the mounted data volumes. For an Internet-facing deployment, enable TLS and enforce outbound denial at the container or host network boundary.

## Verification

```console
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check
```

The test suite includes a standalone protocol client, independent Tiberius client flows for plaintext SQL batch/RPC and required TDS 7.x TLS, and a strict TDS 8.0 raw-TLS/PRELOGIN/LOGIN7 flow. `sqlcmd`, SSMS, FreeTDS, Impacket, Censys, and Shodan remain unclaimed until they have been exercised against a deployed instance; see the compatibility ledger.

Coverage-guided fuzz targets are isolated from the production dependency graph under `fuzz/`. They require nightly Rust and `cargo-fuzz 0.13.2`:

```console
for target in packet prelogin login7 tokens; do
  cargo +nightly fuzz run "$target" -- -runs=100000 -max_len=65536 -timeout=5
done
```

The corpus directories are intentionally retained. On ptrace-restricted hosts where LeakSanitizer cannot perform its final process scan, build with `cargo +nightly fuzz build` and run the generated ASan-instrumented target with `ASAN_OPTIONS=detect_leaks=0`; do not disable AddressSanitizer itself.
