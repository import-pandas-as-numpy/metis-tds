# MSSQL TDS Honeypot Specification

## 1. Overview

### 1.1 Purpose

This document specifies a purpose-built Microsoft SQL Server (MSSQL) honeypot implemented in Rust that emulates enough of the Tabular Data Stream (TDS) protocol and common SQL Server behavior to interact credibly with real MSSQL clients and attacker tooling without running a legitimate SQL Server instance.

The system is intended to provide:

- High-fidelity visibility into MSSQL-oriented reconnaissance and abuse.
- Session-level attribution for every interaction.
- Safe capture of SQL batches, RPC requests, authentication attempts, and attacker-supplied payloads.
- Stateful, believable responses to common MSSQL discovery and post-authentication activity.
- A controlled environment for evaluating EDR detections and SQL-aware telemetry.
- Strong containment guarantees: attacker-controlled input must never be executed by the operating system, CLR, SQL engine, shell, or network stack beyond the honeypot protocol response path.

The project is explicitly **not** intended to implement a full T-SQL engine or provide general-purpose SQL Server compatibility.

---

## 2. Goals

### 2.1 Primary Goals

1. Accept connections from real MSSQL clients over TCP.
2. Implement sufficient TDS protocol behavior for common clients to complete:
   - PRELOGIN
   - encryption negotiation
   - LOGIN7
   - LOGINACK / ENVCHANGE / DONE response flow
   - SQL batch requests
   - RPC requests
3. Extract and record connection and login metadata, including where available:
   - source IP
   - source port
   - claimed client hostname
   - application name
   - username
   - requested database
   - TDS version
   - encryption capabilities
4. Maintain per-session synthetic MSSQL state.
5. Recognize and respond plausibly to common reconnaissance and attacker-oriented queries.
6. Capture exact attacker-supplied commands and payloads without executing them.
7. Produce structured telemetry suitable for EDR/SIEM ingestion.
8. Support multiple configurable server “personalities.”
9. Make dangerous execution paths architecturally impossible by default.

### 2.2 Secondary Goals

- Support adversary-emulation and EDR regression testing.
- Allow configurable fake database schemas, users, roles, linked servers, SQL Agent jobs, credentials, and server settings.
- Support deterministic scripted scenarios for repeatable testing.
- Allow selective storage of submitted payloads such as CLR assemblies or encoded scripts for later analysis.
- Support controlled deception such as honey credentials and honey database objects.

---

## 3. Non-Goals

The initial implementation will not attempt to:

- Implement full T-SQL syntax or semantics.
- Persist arbitrary relational data.
- Provide ACID transaction guarantees.
- Execute stored procedures.
- Execute shell commands.
- Launch processes.
- Load CLR assemblies.
- Execute PowerShell, cmd, WMI, OLE Automation, Python, R, or external scripts.
- Resolve or contact linked servers.
- Perform outbound SMB, HTTP, DNS, LDAP, Kerberos, or other attacker-requested network operations.
- Mount or access attacker-controlled filesystem paths.
- Emulate every TDS version or every SQL Server feature.
- Defeat sophisticated active fingerprinting in the first release.
- Act as a production database proxy.

---

## 4. Threat Model

### 4.1 Expected Adversary Behavior

The honeypot should assume that remote users may:

- Send malformed TDS packets.
- Fuzz packet lengths and token boundaries.
- Attempt authentication brute force or password spraying.
- Send very large SQL batches.
- Submit intentionally pathological SQL.
- Attempt `xp_cmdshell`.
- Attempt OLE Automation.
- Attempt CLR assembly creation.
- Attempt SQL Agent job creation.
- Attempt linked-server execution.
- Attempt file read/write operations through SQL functionality.
- Submit encoded PowerShell or shell commands.
- Upload binary payloads through SQL statements or RPC parameters.
- Attempt protocol downgrade or TLS abuse.
- Attempt denial-of-service through memory, CPU, or connection exhaustion.
- Attempt to fingerprint the honeypot.

### 4.2 Security Boundary

All remote input is untrusted.

The following invariant is mandatory:

> No attacker-controlled SQL text, RPC argument, payload, filename, command, hostname, URL, assembly, or other value may be interpreted as executable code by the honeypot host.

The implementation must not expose a generic subprocess execution API to request-handling code.

---

## 5. High-Level Architecture

```text
                         ┌───────────────────────┐
                         │   Remote MSSQL Client │
                         └───────────┬───────────┘
                                     │ TCP/1433
                                     ▼
                         ┌───────────────────────┐
                         │     TDS Listener      │
                         │   tokio TcpListener   │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │   Connection Handler  │
                         │ framing / limits / TLS│
                         └───────────┬───────────┘
                                     │
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
        ┌─────────────────────┐              ┌─────────────────────┐
        │   TDS Decoder       │              │   Telemetry Sink    │
        │ PRELOGIN / LOGIN7   │              │ JSON / OTLP / file  │
        │ SQL_BATCH / RPC     │              └─────────────────────┘
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │   Session Engine    │
        │ synthetic DB state  │
        └──────────┬──────────┘
                   │
                   ▼
        ┌─────────────────────┐
        │ Semantic Classifier │
        │ recognize intent    │
        └──────────┬──────────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
┌──────────────────┐  ┌──────────────────┐
│ Personality Model │  │ Payload Capture  │
│ fake server state │  │ hash/store only  │
└─────────┬────────┘  └──────────────────┘
          │
          ▼
┌─────────────────────┐
│   TDS Token Encoder │
│ rows/errors/DONE/etc │
└──────────┬──────────┘
           │
           ▼
      Remote Client
```

---

## 6. Implementation Language and Runtime

### 6.1 Language

Rust.

### 6.2 Runtime

Tokio-based asynchronous networking.

### 6.3 Recommended Libraries

Candidate dependencies include:

- `tokio`
- `bytes`
- `rustls`
- `tokio-rustls`
- `serde`
- `serde_json`
- `tracing`
- `tracing-subscriber`
- `uuid`
- `sha2`
- `regex` or a lightweight tokenizer where appropriate
- `thiserror`

Dependency count should remain deliberately small.

---

## 7. TDS Protocol Scope

### 7.1 Phase 1 Required Packet Types

The minimum viable implementation must support:

- PRELOGIN
- LOGIN7
- SQL_BATCH
- RPC
- server response packets sufficient to carry:
  - LOGINACK
  - ENVCHANGE
  - COLMETADATA
  - ROW / NBCROW where required
  - ERROR
  - INFO
  - DONE / DONEPROC / DONEINPROC

### 7.2 TDS Framing

The implementation must:

- Parse the standard TDS packet header.
- Enforce packet-length limits before allocating.
- Support multi-packet messages.
- Reject invalid status flags and impossible lengths safely.
- Bound total reassembled message size.
- Track packet sequence behavior sufficiently for compatibility.
- Never trust length fields without validating them against configured limits.

### 7.3 PRELOGIN

PRELOGIN parsing should support at minimum:

- VERSION
- ENCRYPTION
- INSTOPT
- THREADID
- MARS

The server should return a configurable but internally coherent response.

### 7.4 TLS

TLS support should be implemented early because modern clients commonly negotiate encryption.

Requirements:

- Use Rustls or equivalent memory-safe TLS.
- Load server certificates from configuration.
- Never generate attacker-influenced filesystem paths for certificates.
- Support configurable encryption policy:
  - optional
  - preferred
  - required
- Log TLS negotiation metadata.
- Do not support insecure fallback modes merely to increase attacker compatibility.

Initial compatibility should focus on TDS 7.x-era client behavior. TDS 8.0-specific compatibility can be added later.

### 7.5 LOGIN7

The LOGIN7 parser should extract, where present:

- username
- password field presence
- client hostname
- application name
- server name
- requested database
- client library
- language
- TDS version
- packet size
- option flags

Passwords must never be logged in plaintext by default.

If authentication capture is enabled for research use, credentials must be:

- explicitly opted in,
- written only to a restricted mode-`0600` JSONL sink with stdout disabled,
- excluded from ordinary parser-error and container-runtime logs.

Complete LOGIN7 messages may also be retained as bounded, generated mode-`0600`
artifacts. The corresponding ordinary event contains only the artifact identifier,
size, and SHA-256 digest. Operators must treat both credential telemetry and
LOGIN7 artifacts as sensitive evidence and apply access control and retention.

### 7.6 Authentication Behavior

Authentication behavior should be personality-configurable.

Supported modes:

1. Accept configured decoy credentials.
2. Reject all unknown credentials.
3. Accept a limited class of usernames with synthetic passwords.
4. Simulate disabled or locked-out accounts.
5. Simulate SQL authentication or integrated-authentication limitations.

The system does not need to validate real Active Directory credentials.

---

## 8. Session Model

Each connection must create an isolated `SessionState`.

Suggested state:

```rust
struct SessionState {
    connection_id: Uuid,
    session_id: u32,

    source_addr: SocketAddr,

    login_name: String,
    effective_login: String,
    client_hostname: Option<String>,
    application_name: Option<String>,

    current_database: String,
    language: String,

    xp_cmdshell_enabled: bool,
    clr_enabled: bool,
    ole_automation_enabled: bool,
    ad_hoc_distributed_queries_enabled: bool,

    impersonation_stack: Vec<String>,

    transaction_depth: u32,

    synthetic_objects: SessionObjects,
}
```

Session state must never provide access to host OS state.

---

## 9. Personality Model

The wire-protocol engine should be separated from the emulated SQL Server identity.

Example abstraction:

```rust
trait SqlPersonality {
    fn server_name(&self) -> &str;
    fn sql_version(&self) -> &str;
    fn os_version(&self) -> &str;

    fn databases(&self) -> &[DatabaseDefinition];
    fn logins(&self) -> &[LoginDefinition];
    fn linked_servers(&self) -> &[LinkedServerDefinition];

    fn authenticate(&self, login: &LoginRequest) -> AuthDecision;

    fn initial_session_state(&self, login: &LoginRequest) -> SessionState;

    fn handle_semantic_request(
        &self,
        session: &mut SessionState,
        request: &SemanticRequest,
    ) -> SyntheticResponse;
}
```

Example personality:

```yaml
name: sql-fin-prod

server:
  hostname: SQL-FIN-01
  sql_version: "Microsoft SQL Server 2022"
  os_version: "Windows Server 2022"
  domain: CORP

databases:
  - master
  - tempdb
  - model
  - msdb
  - Finance
  - Payroll
  - Reporting

logins:
  - CORP\sqladmin
  - CORP\svc_reporting
  - CORP\svc_backup

linked_servers:
  - SQL-REPORT-01
```

Personality data should be declarative where practical.

---

## 10. Query Handling

### 10.1 Philosophy

The honeypot should classify SQL rather than execute it.

Processing flow:

```text
raw request
   ↓
safe decode
   ↓
normalization
   ↓
semantic classification
   ↓
state transition
   ↓
synthetic response
```

### 10.2 SQL Normalization

Normalization may include:

- Unicode normalization.
- Comment stripping for classification only.
- Whitespace normalization.
- Case folding for keywords.
- Extraction of quoted strings.
- Identification of semicolon-separated statements.
- Preservation of the original raw query for telemetry.

The classifier must not rely solely on a single normalized string comparison.

### 10.3 Initial Query Classes

The initial implementation should recognize:

#### Environment Discovery

- `SELECT @@VERSION`
- `SELECT @@SERVERNAME`
- `SELECT SERVERPROPERTY(...)`
- `SELECT SYSTEM_USER`
- `SELECT SUSER_SNAME()`
- `SELECT USER_NAME()`
- `SELECT DB_NAME()`
- database enumeration
- login/principal enumeration
- role enumeration
- permission enumeration

#### Configuration

- `sp_configure`
- `RECONFIGURE`
- xp_cmdshell enablement
- CLR enablement
- OLE Automation enablement
- Ad Hoc Distributed Queries

#### Command Execution Attempts

- `xp_cmdshell`
- SQL Agent command jobs
- OLE Automation
- external scripts

#### Privilege Activity

- `EXECUTE AS`
- `REVERT`
- `CREATE LOGIN`
- `ALTER LOGIN`
- role membership changes
- `GRANT`
- `DENY`
- `REVOKE`

#### CLR Activity

- `CREATE ASSEMBLY`
- `ALTER ASSEMBLY`
- `DROP ASSEMBLY`
- CLR stored procedure/function creation

#### Linked Server Activity

- linked-server enumeration
- linked-server creation
- pass-through query attempts
- remote execution attempts

#### Filesystem-Oriented Activity

- backup/restore
- bulk insert
- OPENROWSET
- file existence/probing functionality
- path discovery

#### SQL Agent

- job enumeration
- job creation
- job step creation
- job execution

### 10.4 Unknown Queries

Unknown queries should not crash or terminate the session.

Configurable behaviors:

- return empty result set,
- return plausible generic result,
- return syntax error,
- return permission denied,
- return unsupported feature error.

Response choice should be personality-specific.

---

## 11. RPC Handling

The honeypot must support enough RPC decoding to observe common calls such as:

- `sp_executesql`
- `sp_configure`
- common system stored procedures
- `xp_cmdshell`

The RPC layer must:

- decode procedure identifiers/names,
- decode parameter metadata safely,
- enforce parameter-size limits,
- preserve raw parameter data where configured,
- pass decoded requests to the same semantic classifier used for SQL batches.

RPC parameters must never be handed to shell or SQL execution primitives.

---

## 12. Stateful Deception

The honeypot should simulate state changes when doing so increases realism.

Example:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

The corresponding session state becomes:

```text
xp_cmdshell_enabled = true
```

A later:

```sql
EXEC xp_cmdshell 'whoami';
```

may return:

```text
nt service\mssqlserver
```

No process is created.

Other stateful behavior may include:

- `USE <database>`
- `EXECUTE AS`
- `REVERT`
- synthetic login creation
- synthetic role changes
- synthetic SQL Agent jobs
- synthetic linked servers
- synthetic assembly creation
- transaction depth

State changes may be session-local initially. Optional per-personality ephemeral shared state may be added later.

---

## 13. Synthetic Command Execution

### 13.1 Hard Rule

There must be no generic command execution backend.

Forbidden patterns in request handling include:

```rust
std::process::Command
tokio::process::Command
libc::system
CreateProcess*
ShellExecute*
```

If such APIs exist elsewhere in the project for development tooling, they must not be reachable from the network-facing runtime.

### 13.2 Command Response Strategy

Known commands may receive canned or generated output:

| Input | Example Synthetic Output |
|---|---|
| `whoami` | `nt service\mssqlserver` |
| `hostname` | `SQL-FIN-01` |
| `ipconfig` | personality-derived fake network data |
| `systeminfo` | fake OS/version data |
| `dir` | synthetic filesystem listing |

Unknown commands may:

- return no output,
- return a plausible command-not-found error,
- return a generic success result.

The original command must be captured in telemetry.

---

## 14. Payload Capture

The honeypot may capture attacker-submitted content such as:

- PowerShell commands
- encoded commands
- scripts
- CLR assemblies
- SQL Agent command bodies
- OLE Automation arguments
- hex/base64 blobs

Payload handling requirements:

1. Never execute.
2. Calculate SHA-256.
3. Enforce strict maximum size.
4. Store outside executable search paths.
5. Use generated filenames, never attacker-provided filenames.
6. Remove execute permissions.
7. Store metadata separately.
8. Optionally archive payloads to a remote analysis system.
9. Never automatically deserialize native executable formats.

Example telemetry:

```json
{
  "event_type": "clr_assembly_submission",
  "connection_id": "4fa0...",
  "session_id": 53,
  "login": "sa",
  "source_ip": "192.0.2.14",
  "sha256": "...",
  "size": 122880,
  "storage_id": "payload-..."
}
```

---

## 15. Telemetry Specification

### 15.1 Connection Event

```json
{
  "event_type": "connection_open",
  "timestamp": "...",
  "connection_id": "...",
  "source_ip": "...",
  "source_port": 50041,
  "destination_port": 1433
}
```

### 15.2 PRELOGIN Event

Fields should include:

- connection ID
- TDS version
- encryption request
- MARS request
- malformed fields
- client capability metadata

### 15.3 Login Event

```json
{
  "event_type": "login_attempt",
  "connection_id": "...",
  "session_id": 55,
  "source_ip": "...",
  "username": "sa",
  "client_hostname": "WS-102",
  "application_name": "Microsoft SQL Server Management Studio",
  "requested_database": "master",
  "accepted": true
}
```

### 15.4 SQL Request Event

```json
{
  "event_type": "sql_batch",
  "connection_id": "...",
  "session_id": 55,
  "login": "sa",
  "effective_login": "sa",
  "database": "master",
  "classification": "xp_cmdshell",
  "raw_sql": "EXEC xp_cmdshell 'whoami'",
  "risk_tags": [
    "os_command_execution"
  ]
}
```

### 15.5 State Change Event

```json
{
  "event_type": "synthetic_state_change",
  "session_id": 55,
  "property": "xp_cmdshell_enabled",
  "old_value": false,
  "new_value": true
}
```

### 15.6 Payload Event

Capture:

- SHA-256
- type
- size
- origin query/RPC
- connection/session ID
- storage reference

### 15.7 Malformed TDS Event

```json
{
  "event_type": "malformed_tds_message",
  "connection_id": "...",
  "source_ip": "...",
  "source_port": 50041,
  "protocol_stage": "login_parse",
  "error_kind": "protocol",
  "error": "TDS protocol error: LOGIN7 fixed header is truncated",
  "bytes_read": 31,
  "bytes_written": 47
}
```

Do not include raw LOGIN7 bytes or password material in parser-error telemetry.

Every failed connection also emits `connection_failure` with stage-local byte
counts and the last successfully framed message metadata. Failures before a
LOGIN7 could contain credentials may include at most the first 256 received
wire bytes as hexadecimal for protocol identification. LOGIN7 and later stages
must never include a raw wire prefix.

### 15.8 Connection Close

Capture:

- source IP and port
- last protocol stage
- structured error kind
- session duration
- request count
- bytes read/written
- termination reason
- parser errors
- highest observed risk classification

---

## 16. Telemetry Output

Initial supported sinks:

1. JSON Lines file.
2. stdout via structured logging.
3. Optional syslog.
4. Optional HTTP/OTLP exporter in later versions.

The network-facing honeypot should not block on telemetry delivery.

Use a bounded asynchronous queue.

When the queue fills:

- never block indefinitely,
- record a dropped-event counter,
- prefer dropping low-value diagnostic events over security events where possible.

---

## 17. EDR Integration

The honeypot is intended to provide ground-truth SQL-session telemetry that can be correlated with EDR events.

Useful correlation keys:

- timestamp
- source IP
- session ID
- connection ID
- login
- requested database
- semantic behavior
- payload hash

Example:

```text
Honeypot:
session=58
login=svc_reporting
source=10.20.30.44
activity=xp_cmdshell
command="powershell ..."

EDR:
No process spawned

Expected result:
Honeypot captures malicious intent while preserving containment.
```

For adversary-emulation testing, the system can compare honeypot semantic events against equivalent activity on an instrumented legitimate SQL Server in an isolated lab.

---

## 18. Honey Objects

Personality definitions may include objects that exist solely for detection.

Examples:

```text
LegacyPayrollArchive
dbo.DomainAdminCredentials
dbo.usp_DecryptPasswords
dbo.usp_EnableRemoteBackup
```

Any access should generate a high-confidence telemetry event.

Example:

```json
{
  "event_type": "honey_object_access",
  "object": "LegacyPayrollArchive.dbo.DomainAdminCredentials",
  "action": "SELECT",
  "severity": "high"
}
```

---

## 19. Honey Credentials

The system may expose synthetic accounts such as:

```text
svc_legacybackup
svc_sqlmigration
svc_domain_sync
```

Authentication attempts using specific honey identities should be independently classified.

The credentials must not correspond to any real account or reusable secret.

---

## 20. Resource Limits

Every network-facing allocation must be bounded.

Configurable limits should include:

- maximum concurrent connections
- maximum connections per source IP
- maximum TDS packet size
- maximum reassembled message size
- maximum SQL batch size
- maximum RPC parameter size
- maximum captured payload size
- maximum requests per session
- maximum session lifetime
- login timeout
- idle timeout
- per-IP request rate

Malformed or oversized traffic should fail closed.

---

## 21. Process Isolation

Recommended deployment:

- dedicated unprivileged service account
- no administrative privileges
- no interactive logon
- minimal filesystem permissions
- read-only application/configuration directory
- dedicated writable payload/log directory
- outbound network access denied by host firewall
- no access to domain credentials
- no access to production secrets
- no Docker socket
- no package-manager credentials
- no cloud instance credentials

Where possible, run inside a dedicated VM or similarly strong isolation boundary.

---

## 22. Network Isolation

Inbound:

- expose only required MSSQL listener ports.

Outbound:

- deny by default.

The honeypot must not honor attacker-supplied requests to contact:

- linked servers
- UNC paths
- HTTP endpoints
- DNS names
- LDAP servers
- SMB servers
- SMTP servers
- SQL Server Browser targets

If simulated outbound activity is desired, return synthetic results without making the connection.

---

## 23. Error Fidelity

Errors should resemble SQL Server sufficiently to preserve client behavior.

The response layer should support configurable synthetic:

- login failures
- permission errors
- syntax errors
- invalid object errors
- invalid database errors
- feature-disabled errors
- `xp_cmdshell` disabled messages
- CLR-disabled messages

Exact error-message fidelity should be treated as a compatibility enhancement rather than an MVP blocker.

---

## 24. Anti-Fingerprinting Considerations

Initial releases are expected to be fingerprintable by sufficiently motivated researchers.

Fingerprint resistance may later include:

- realistic response timing jitter
- coherent SQL Server build/version combinations
- coherent default database metadata
- realistic ordering of system databases
- realistic error codes
- realistic `SERVERPROPERTY` results
- application-specific response quirks
- consistent permissions
- persistent synthetic state
- TDS token ordering fidelity

Avoid random inconsistency. Internal coherence is more important than maximal feature coverage.

---

## 25. Testing Strategy

### 25.1 Protocol Unit Tests

Test:

- packet headers
- multi-packet reconstruction
- PRELOGIN parsing
- LOGIN7 parsing
- token encoding
- Unicode behavior
- malformed offsets
- truncated messages
- oversized fields
- RPC parameter parsing

### 25.2 Fuzzing

Use `cargo-fuzz` against:

- packet parser
- PRELOGIN parser
- LOGIN7 parser
- SQL batch decoder
- RPC decoder
- token encoder

Parsers should never panic on arbitrary input.

### 25.3 Client Compatibility Matrix

Initial test clients:

- `sqlcmd`
- SSMS
- FreeTDS clients
- Impacket MSSQL client
- common ODBC clients

Track:

| Client | PRELOGIN | TLS | LOGIN7 | SQL_BATCH | RPC |
|---|---:|---:|---:|---:|---:|
| sqlcmd | | | | | |
| SSMS | | | | | |
| FreeTDS | | | | | |
| Impacket | | | | | |

### 25.4 Behavioral Test Corpus

Build repeatable scenarios for:

1. login enumeration
2. database enumeration
3. role discovery
4. `sp_configure`
5. `xp_cmdshell`
6. `EXECUTE AS`
7. CLR enablement
8. assembly submission
9. linked-server enumeration
10. SQL Agent job creation
11. backup/restore probing
12. honey-object access
13. malformed TDS
14. brute-force authentication

---

## 26. Observability

Internal metrics should include:

- active connections
- total connections
- rejected connections
- login attempts
- accepted logins
- malformed TDS messages
- SQL batches
- RPC requests
- semantic classifications by type
- payloads captured
- bytes captured
- rate-limit events
- telemetry queue depth
- dropped telemetry events
- parser exceptions/errors
- average session duration

Metrics must not expose secrets.

---

## 27. Configuration

Suggested configuration structure:

```yaml
listener:
  address: "0.0.0.0:1433"
  max_connections: 500
  idle_timeout_seconds: 300

tls:
  mode: optional
  certificate: "/etc/tdshoney/server.crt"
  private_key: "/etc/tdshoney/server.key"

personality:
  file: "/etc/tdshoney/personalities/sql-fin-prod.yaml"

limits:
  max_message_bytes: 8388608
  max_sql_batch_bytes: 1048576
  max_payload_bytes: 16777216

telemetry:
  jsonl_path: "/var/log/tdshoney/events.jsonl"
  stdout: false
  capture_login_passwords: true

payloads:
  enabled: true
  directory: "/var/lib/tdshoney/payloads"
  capture_login7: true
```

---

## 28. Proposed Rust Module Layout

```text
src/
├── main.rs
├── config.rs
├── error.rs
│
├── tds/
│   ├── mod.rs
│   ├── packet.rs
│   ├── prelogin.rs
│   ├── login7.rs
│   ├── rpc.rs
│   ├── batch.rs
│   ├── tokens.rs
│   └── codec.rs
│
├── server/
│   ├── mod.rs
│   ├── listener.rs
│   ├── connection.rs
│   ├── tls.rs
│   └── session.rs
│
├── semantic/
│   ├── mod.rs
│   ├── normalize.rs
│   ├── classify.rs
│   ├── request.rs
│   └── state.rs
│
├── personality/
│   ├── mod.rs
│   ├── model.rs
│   ├── loader.rs
│   └── responses.rs
│
├── telemetry/
│   ├── mod.rs
│   ├── event.rs
│   ├── sink.rs
│   └── jsonl.rs
│
└── payload/
    ├── mod.rs
    ├── capture.rs
    └── hashing.rs
```

---

## 29. Milestones

### Milestone 1 — Wire-Level MVP

Deliver:

- TCP listener
- TDS framing
- PRELOGIN
- LOGIN7 parser
- synthetic authentication
- LOGINACK
- basic ENVCHANGE
- DONE
- structured connection/login telemetry

Success criteria:

- `sqlcmd` completes login and remains connected.

### Milestone 2 — Basic Query Compatibility

Deliver:

- SQL_BATCH handling
- simple result sets
- `@@VERSION`
- `@@SERVERNAME`
- identity functions
- `DB_NAME()`
- database enumeration
- generic errors

Success criteria:

- `sqlcmd` and at least one additional client can issue common discovery queries.

### Milestone 3 — Attacker-Oriented Semantics

Deliver:

- `sp_configure`
- `xp_cmdshell`
- `EXECUTE AS`
- role/login manipulation
- CLR operations
- SQL Agent activity
- linked-server activity
- semantic telemetry

Success criteria:

- common MSSQL post-exploitation workflows receive plausible, stateful responses while no host execution occurs.

### Milestone 4 — RPC and Tool Compatibility

Deliver:

- RPC request parsing
- `sp_executesql`
- RPC-based procedure handling
- compatibility testing against SSMS, FreeTDS, and Impacket

### Milestone 5 — Hardened Honeypot

Deliver:

- fuzzing
- TLS
- per-IP rate limiting
- payload storage
- metrics
- hostile-input testing
- deployment hardening documentation

### Milestone 6 — Deception Profiles

Deliver:

- configurable personalities
- honey objects
- honey accounts
- persistent synthetic state
- scenario packs

---

## 30. Acceptance Criteria

The project is considered viable when all of the following are true:

1. At least three common MSSQL clients can complete a connection and login.
2. Clients can execute basic discovery SQL and receive valid TDS responses.
3. The honeypot captures source/client/login/query metadata for every request.
4. `xp_cmdshell` attempts can be captured and convincingly answered without spawning a process.
5. CLR payloads can be captured without being loaded.
6. Linked-server requests do not produce outbound connections.
7. Fuzzing produces no parser panics or memory-safety failures.
8. A host firewall can show zero honeypot-initiated outbound connections during attacker interaction.
9. Session state remains isolated between connections unless explicitly configured otherwise.
10. Telemetry is sufficient to reconstruct a complete attacker interaction timeline.

---

## 31. Future Enhancements

Potential later work:

- TDS 8.0 fidelity.
- MARS support.
- NTLM/Kerberos negotiation emulation without validating real credentials.
- SQL Server Browser / UDP 1434 emulation.
- named-instance behavior.
- richer SQL Agent state.
- database metadata generation.
- fake table contents.
- realistic permission graphs.
- temporal response modeling.
- shared persistent fake server state.
- replay framework.
- PCAP-to-session comparison tooling.
- automated EDR regression harness.
- ATT&CK technique tagging.
- OpenTelemetry export.
- web UI for captured sessions.

---

## 32. Design Principle Summary

The central design principle is:

> Emulate the protocol and the observable behavior, not the database engine.

The honeypot should be believable enough that normal MSSQL tooling and attacker workflows continue interacting with it, while every dangerous operation terminates in a synthetic state transition and response rather than an execution primitive.

This produces a system with:

- high interaction fidelity,
- strong session attribution,
- low operational risk,
- deterministic telemetry,
- and a useful platform for both deception and EDR research.
