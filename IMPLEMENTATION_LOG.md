# Implementation ledger

This is the restart-safe source of truth for the project. Update it whenever a feature is implemented, verified, deferred, or found incompatible. A checked box means code and an automated check exist; client compatibility is only claimed when the named client has been exercised.

Last updated: 2026-08-20

## Current phase

- [x] Specification read and decomposed.
- [x] Rust project scaffolded from an empty workspace.
- [x] Direct dependency versions reviewed with Socket MCP.
- [x] Wire-level implementation complete for TDS 7.4 and the TDS 8.0 strict-encryption entry path.
- [x] Behavioral implementation complete for the initial attacker workflow corpus.
- [ ] External client/scanner matrix complete.
- [x] Coverage-guided fuzz targets implemented for the required parser/encoder surfaces.

## Dependency review

Socket MCP scores were checked for every direct dependency before inclusion and imports were reconciled against the manifest (`bytes` was removed as an unused direct dependency). Runtime and test dependencies reported vulnerability 100 and quality 93 or better. Tokio 1.53.1 reported supply-chain 57; this is the explicit user-approved exception. Tiberius 0.12.3 (test-only) scored supply-chain 94, `tokio-util` 100, and `tempfile` 98.

The user explicitly approved cargo-fuzz on 2026-08-17. Socket MCP scored `cargo-fuzz` 0.13.2 at supply-chain 79, quality 93, vulnerability 100 and `libfuzzer-sys` 0.4.10 at supply-chain 58, quality 100, vulnerability 100. Both are isolated in the non-production `fuzz/` workspace. The lower `libfuzzer-sys` supply-chain score is the explicit user-approved exception.

## Requirement status

### Protocol

- [x] Bounded TDS packet framing and multi-packet reassembly; PacketID is recorded but ignored as required by MS-TDS
- [x] PRELOGIN parse/response (VERSION, ENCRYPTION, INSTOPT, THREADID, MARS)
- [x] TDS-encapsulated TLS handshake and encrypted session (TLS 1.3 independently verified; rustls TLS 1.2 enabled)
- [x] TDS 8.0 raw TLS-before-PRELOGIN with `tds/8.0` ALPN and encrypted LOGIN7
- [x] LOGIN7 safe field extraction, transient password discard, and SQL-auth decisions
- [x] LOGINACK / ENVCHANGE / INFO / ERROR / DONE encoding
- [x] SQL_BATCH UTF-16 decoding and result sets
- [x] RPC decoding for common procedure names/IDs and scalar string/binary/integer/bit parameters

### Deception and telemetry

- [x] Isolated per-connection session state (second-session `xp_cmdshell` isolation verified)
- [x] Declarative JSON personality loading
- [x] Discovery query responses for version/server/database/principal/role/permission/linked-server/job queries
- [x] Stateful `USE`, transactions, `sp_configure`, `EXECUTE AS`, and `REVERT`
- [x] Synthetic `xp_cmdshell` with no execution backend
- [x] CLR, SQL Agent, linked-server, filesystem, external-script, OLE, and honey-object classification
- [x] Bounded SHA-256 payload capture using generated mode-0600 non-executable files
- [x] Bounded asynchronous JSONL/stdout telemetry with dropped-event count
- [x] Connection/PRELOGIN/TLS/login/request/state/honey/payload/close/metrics events
- [x] Stage-local failure byte counts, safe TDS header metadata, and bounded pre-LOGIN7 wire prefixes

### Hardening

- [x] Global and per-IP connection limits and per-IP request window
- [x] Packet/message/batch/RPC/payload/request/login/idle/session time limits
- [x] Parser malformed-input tests plus 20,000-case deterministic fuzz smoke
- [x] Isolated cargo-fuzz targets for packet headers, PRELOGIN, LOGIN7/batch/RPC parsing, and token encoding
- [x] Static assertions that process-launch and outbound TCP-connect APIs are absent from `src/`
- [x] systemd/container deployment guidance and outbound-deny example
- [x] `cargo deny check`: advisories/licenses/sources/bans pass; one duplicate `syn` warning is test-only via Tiberius

## Compatibility matrix

Blank means untested, not unsupported.

| Client / scanner | PRELOGIN | TLS | LOGIN7 | SQL_BATCH | RPC | Evidence |
|---|---:|---:|---:|---:|---:|---|
| Built-in protocol test client | pass | not exercised | pass | pass | n/a | `tests/protocol_flow.rs` |
| Tiberius 0.12.3 | pass | pass (required/TLS 1.3) | pass | pass | pass (`sp_executesql`) | `tests/tiberius_compat.rs`, `tests/tls_compat.rs` |
| Built-in strict TDS 8.0 client | pass (inside raw TLS) | pass (TLS first, `tds/8.0` ALPN) | pass | not exercised | not exercised | `tests/tls_compat.rs` |
| sqlcmd |  |  |  |  |  | |
| FreeTDS (`tsql`) |  |  |  |  |  | |
| Impacket `mssqlclient.py` |  |  |  |  |  | |
| SSMS |  |  |  |  |  | |
| Shodan InternetDB/classifier |  | n/a | n/a | n/a | n/a | External validation required |
| Censys service classifier |  | n/a | n/a | n/a | n/a | External validation required |

## Verification evidence

- `cargo test --all-targets --locked`: protocol units, containment checks, 20,000 hostile parser inputs, real TCP lifecycle, JSONL timeline, stateful attacker workflow, payload capture, session isolation, independent Tiberius SQL batch/RPC, and required TLS.
- `cargo clippy --all-targets --locked -- -D warnings`: clean.
- `cargo build --release --locked`: clean.
- `cargo deny check`: advisories, licenses, sources, and bans pass; duplicate-version warning is confined to Tiberius's test dependency graph.
- `cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check`: fuzz dependency advisories, licenses, sources, and bans pass; NCSA is explicitly allowed for `libfuzzer-sys`.
- `cargo +nightly fuzz build`: all four targets compile with `cargo-fuzz` 0.13.2 and exactly pinned `libfuzzer-sys` 0.4.10.
- 2026-08-17 bounded ASan/libFuzzer campaign: 100,000 runs each for `packet`, `prelogin`, `login7` (also batch/RPC), and `tokens`; 400,000 clean executions total with no panic, timeout, sanitizer finding, or retained crash artifact. Final feature coverage was 195, 284, 1,316, and 1,198 respectively. Evolved corpora are retained (58/87/555/341 files) for regression and resumed campaigns.
- Microsoft MS-TDS revision 42.0/current Learn pages were used to verify PRELOGIN packet types/TLS wrapping, LOGIN7, LOGINACK, login token sequencing, and RPC `TYPE_INFO` layout.

## Known limits / next evidence needed

- SQL authentication over TDS 7.4 and the TDS 8.0 strict-encryption entry path are compatibility targets. Integrated SSPI/FedAuth, MARS, TVP/encrypted RPC parameters, and arbitrary T-SQL semantics are intentionally unsupported; integrated LOGIN7 attempts are still identified and logged before rejection.
- `sqlcmd`, FreeTDS, Impacket, and SSMS are not installed in this environment and remain unclaimed.
- Shodan/Censys identification requires deploying the service on a public address and observing the external classifier; local PRELOGIN conformance is necessary but not proof of indexing.
- Coverage-guided fuzzing is approved and scaffolded. See verification evidence for the most recent bounded campaign result.
- Host-firewall proof of zero outbound traffic must be collected on the eventual deployment host. Runtime source has no outbound TCP connector, and deployment guidance supplies an external outbound-deny rule.
- This managed container prevents LeakSanitizer's final ptrace-based process scan. The successful campaign invoked the cargo-fuzz-built ASan binaries with only leak detection disabled (`ASAN_OPTIONS=detect_leaks=0`); AddressSanitizer and coverage instrumentation remained enabled. The wrapper's four zero-byte false crash artifacts were verified and removed.

## Resume instructions

1. Read `mssql-tds-honeypot-spec.md` and this ledger.
2. Run `cargo test --all-targets --locked` and `cargo clippy --all-targets --locked -- -D warnings`.
3. Continue with the external compatibility matrix and rerun/extend the bounded fuzz campaigns, updating this file with evidence.
4. Never claim an external client or search-engine result without an actual observation.
