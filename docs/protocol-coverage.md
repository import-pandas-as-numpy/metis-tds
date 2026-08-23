# Protocol coverage

Metis treats protocol coverage as two separate guarantees:

1. Published structures are parsed into bounded semantic telemetry and exercised by native fixtures.
2. Unknown, malformed, future, or proprietary material is retained as a bounded artifact with offsets, lengths, packet metadata, and parse warnings. It must not disappear merely because semantic decoding stops.

Neither guarantee means that Metis is a general-purpose database server. Responses are synthetic and attacker-oriented, and submitted operations are never executed.

## Transport and authentication

| Family | Fielded behavior |
| --- | --- |
| TDS 4.2 and 4.6 | Direct legacy LOGIN with versioned fixed-record, host/process/library/charset, bulk/security/HA and reserved-field inventory; version-aware acknowledgement, single-byte SQL, legacy RPC, BCP, packet status, and token framing |
| SAP ASE TDS 5.0 | LOGIN capability/security sections with recovery around corrupt capability framing, direct normal and command-sequence-login authentication streams, pre-negotiation identity/security telemetry, normal token streams, SQL/RPC/dynamic/cursor/bulk structures, parameter and row metadata, published ASE datatypes, challenge/response material, opaque GSS security, and remote-password material |
| ASE password encryption | Published proprietary-v1 challenge/response framing and exact ciphertext capture; RSA/OAEP-SHA1 extended v2; nonce-bound extended-plus v3 password recovery; nonce-bound v4 password and symmetric-key recovery |
| TDS 7.0–7.4 | PRELOGIN, direct and negotiated LOGIN7, login-only and full-session TLS, SQL batch, RPC, bulk load, transactions, SSPI, federated authentication, feature extensions, and all-headers |
| TDS 8.0 | TLS-before-PRELOGIN, `tds/8.0` ALPN, optional client-certificate observation, PRELOGIN nonce handling, LOGIN7 normalization, and semantic recovery of complete or truncated authentication sent out of order before PRELOGIN |

LOGIN7 feature parsing includes session recovery, FEDAUTH variants, column encryption, global transactions, UTF-8, Azure SQL support, data classification, UTF-8 metadata, vector versions 1 and 2, enhanced routing, and user-agent data. Unknown feature IDs and raw feature data remain visible. A cut-off feature retains its absolute offset, feature ID, declared and available sizes, first data byte, reason, and opt-in exact remainder material; a partial FEDAUTH feature remains classified as authentication and never becomes an ordinary password attempt.

Integrated authentication recognizes NTLM negotiate/authenticate structures and independently recovers valid identity fields around malformed optional buffers. SPNEGO, Kerberos, and other GSS tokens receive bounded DER/BER inventory, including OIDs and printable principal hints. Raw authentication material is emitted only when credential capture is explicitly enabled.

SMP/MARS is never silently treated as an ordinary eight-byte TDS header. Even when MARS was not negotiated, complete frame metadata is inventoried and DATA payloads are checked as bounded inner TDS messages. Complete or truncated nested LOGIN, LOGIN7, SSPI, FEDAUTH, and TDS 5 authentication is classified semantically; the enclosing wire frame follows the restricted authentication-artifact policy rather than generic payload capture.

## Request and value parsing

Modern request parsing covers SQL batches, batched RPC, table-valued parameters, bulk rows, transaction-manager requests, enclave packages, Always Encrypted metadata, XML, JSON, `sql_variant`, and published vector layouts. Future length-delimited vector layouts remain binary instead of aborting their enclosing request.

ASE TDS 5 parsing covers the published token inventory and datatype families, narrow and wide row/parameter formats, alternate compute rows, BLOB/LOB values, language, RPC/DBRPC2, dynamic SQL, cursor operations, capabilities, migration/control messages, and authentication message streams. Both published `DYNAMIC2` token assignments (`0x62` in SAP's current driver and `0xA3` in FreeTDS) are accepted. Structures whose body grammar is not published remain self-framed and explicitly opaque.

## Lossless recovery invariant

For every fully framed inbound message, Metis records packet type, packet boundaries, status bytes, packet IDs, message size, transport interpretation, and authentication classification before semantic request handling. When enabled, authentication messages are archived before parsing under generated mode-`0600` names.

Tolerant parsers retain valid semantic prefixes and suffixes around malformed regions, including authentication parameters embedded after a missing or corrupt TDS 5 capability token. Recovery recognizes every published TDS 5 MSG type rather than a selected password-message subset. TDS 5 security intent and parsed identity are emitted before continuation I/O so a disconnect cannot erase the attempted handshake. Telemetry reports raw/unclassified byte counts, offsets, first bytes, recovery mode, and warnings. Sensitive material is excluded from generic connection-failure prefixes; exact passwords, tokens, and parameter bytes appear only in the opt-in credential telemetry or restricted payload store.

The deterministic hostile-input suite exercises every parser without panics. Dedicated inventory tests cover every published legacy packet ID, LOGIN7 feature ID, ASE TDS 5 token and MSG type, ASE parameter datatype, and Microsoft TYPE_INFO family represented by the current specifications. These tests consume parser-owned inventories instead of maintaining independent coverage lists.

## Deliberate cryptographic boundaries

Two inputs are structurally covered but cannot yet be converted to plaintext from public protocol evidence:

- ASE password-encryption v1 uses an SAP-proprietary cipher. Metis emits the published nullable-VARBINARY message-1 challenge, accepts the message-2 response, and records the exact per-session challenge key and ciphertext under opt-in credential telemetry. It does not invent the unpublished cipher or claim plaintext recovery.
- ASE on-demand command encryption uses a negotiated AES-256 session key, but public material does not establish the IV’s wire placement or derivation. Metis retains each encrypted packet and reports its SHA-256 fingerprint, first and last ciphertext blocks, block alignment, and plausible IV-prefix shape without attempting speculative decryption.

These are explicit evidence gaps, not silent parser failures. Implementing either requires an authoritative wire layout or validated interoperability capture. Until then, raw artifacts and structural telemetry are the source of truth.
