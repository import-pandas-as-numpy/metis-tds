use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::{Instant as TokioInstant, timeout, timeout_at},
};
use uuid::Uuid;

use crate::{
    Error, Result,
    config::TlsMode,
    personality::AuthDecision,
    semantic::{Classification, Outcome, handle_rpc, handle_sql},
    session::SessionState,
    tds::{
        self,
        packet::{read_message, write_message},
        prelogin::Encryption,
        tokens,
    },
    telemetry::Event,
};

use super::{Shared, tls};

pub struct Summary {
    pub reason: String,
    pub session_id: Option<u32>,
    pub requests: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub parser_errors: u64,
    pub highest_risk: String,
}

struct Counters {
    bytes_read: u64,
    bytes_written: u64,
    parser_errors: u64,
    highest_risk: Classification,
}
impl Default for Counters {
    fn default() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            parser_errors: 0,
            highest_risk: Classification::Unknown,
        }
    }
}

pub async fn handle(
    shared: Arc<Shared>,
    mut stream: TcpStream,
    peer: SocketAddr,
    connection_id: Uuid,
) -> Result<Summary> {
    stream.set_nodelay(true)?;
    let mut counters = Counters::default();
    let prelogin_message = timeout(
        shared.config.listener.login_timeout(),
        read_message(
            &mut stream,
            shared.config.limits.max_packet_bytes,
            shared.config.limits.max_message_bytes,
        ),
    )
    .await
    .map_err(|_| Error::Protocol("PRELOGIN timeout".into()))??;
    counters.bytes_read += wire_size(&prelogin_message);
    if prelogin_message.packet_type != tds::PRELOGIN {
        return Err(Error::Protocol("first message was not PRELOGIN".into()));
    }
    let prelogin = tds::prelogin::parse(&prelogin_message.payload)?;
    let requested_encryption = prelogin.encryption.unwrap_or(Encryption::Off);
    let (response_encryption, use_tls) = negotiate(shared.config.tls.mode, requested_encryption);
    shared.telemetry.emit(
        Event::new("prelogin", Some(connection_id), None)
            .field("source_ip", peer.ip().to_string())
            .field("tds_version", prelogin.version.map(hex_version))
            .field(
                "encryption_request",
                format!("{requested_encryption:?}").to_lowercase(),
            )
            .field(
                "encryption_response",
                format!("{response_encryption:?}").to_lowercase(),
            )
            .field("mars_requested", prelogin.mars)
            .field("instance", prelogin.instance)
            .field("unknown_tokens", prelogin.unknown_tokens),
    );
    let response = tds::prelogin::encode_response(
        response_encryption,
        &shared.config.personality.instance_name,
    );
    counters.bytes_written +=
        write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;

    if shared.config.tls.mode == TlsMode::Required
        && requested_encryption == Encryption::NotSupported
    {
        return Ok(summary(
            "client_does_not_support_required_tls",
            None,
            0,
            counters,
        ));
    }
    if use_tls {
        let acceptor = shared
            .tls
            .as_ref()
            .ok_or_else(|| Error::Config("TLS negotiated without an acceptor".into()))?;
        let tls = timeout(
            shared.config.listener.login_timeout(),
            tls::handshake(stream, acceptor),
        )
        .await
        .map_err(|_| Error::Tls("handshake timeout".into()))??;
        let (_, connection) = tls.get_ref();
        shared.telemetry.emit(
            Event::new("tls_negotiated", Some(connection_id), None)
                .field(
                    "protocol",
                    connection.protocol_version().map(|v| format!("{v:?}")),
                )
                .field(
                    "cipher_suite",
                    connection
                        .negotiated_cipher_suite()
                        .map(|s| format!("{:?}", s.suite())),
                ),
        );
        login_and_serve(shared, tls, peer, connection_id, counters).await
    } else {
        login_and_serve(shared, stream, peer, connection_id, counters).await
    }
}

fn negotiate(mode: TlsMode, client: Encryption) -> (Encryption, bool) {
    match mode {
        TlsMode::Disabled => (Encryption::NotSupported, false),
        TlsMode::Optional => match client {
            Encryption::On | Encryption::Required => (Encryption::On, true),
            Encryption::NotSupported => (Encryption::NotSupported, false),
            Encryption::Off => (Encryption::Off, false),
        },
        TlsMode::Preferred => match client {
            Encryption::NotSupported => (Encryption::NotSupported, false),
            _ => (Encryption::On, true),
        },
        TlsMode::Required => (Encryption::Required, client != Encryption::NotSupported),
    }
}

async fn login_and_serve<S>(
    shared: Arc<Shared>,
    mut stream: S,
    peer: SocketAddr,
    connection_id: Uuid,
    mut counters: Counters,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let login_message = timeout(
        shared.config.listener.login_timeout(),
        read_message(
            &mut stream,
            shared.config.limits.max_packet_bytes,
            shared.config.limits.max_message_bytes,
        ),
    )
    .await
    .map_err(|_| Error::Protocol("LOGIN7 timeout".into()))??;
    counters.bytes_read += wire_size(&login_message);
    if login_message.packet_type != tds::LOGIN7 {
        return Err(Error::Protocol("expected LOGIN7 message".into()));
    }
    let mut login = tds::login7::parse(&login_message.payload)?;
    let session_id = shared.sessions.fetch_add(1, Ordering::Relaxed);
    shared
        .metrics
        .login_attempts
        .fetch_add(1, Ordering::Relaxed);
    let decision = if login.integrated_security {
        AuthDecision::Reject
    } else {
        shared.config.personality.authenticate(&login)
    };
    let accepted = decision == AuthDecision::Accept;
    login.discard_password();
    shared.telemetry.emit(
        Event::new("login_attempt", Some(connection_id), Some(session_id))
            .field("source_ip", peer.ip().to_string())
            .field("username", &login.username)
            .field("client_hostname", &login.client_hostname)
            .field("application_name", &login.application_name)
            .field("requested_database", &login.database)
            .field("client_library", &login.client_library)
            .field("tds_version", format!("0x{:08x}", login.tds_version))
            .field("packet_size", login.packet_size)
            .field("password_field_present", login.password_present)
            .field("integrated_security", login.integrated_security)
            .field("accepted", accepted)
            .field(
                "honey_identity",
                shared.config.personality.is_honey_login(&login.username),
            ),
    );
    if !accepted {
        let response = tokens::login_failure(
            &shared.config.personality.server_name,
            decision == AuthDecision::Locked,
        )?;
        counters.bytes_written +=
            write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;
        return Ok(summary("login_rejected", Some(session_id), 0, counters));
    }
    shared
        .metrics
        .accepted_logins
        .fetch_add(1, Ordering::Relaxed);
    let packet_size = if login.packet_size < 512 {
        4096
    } else {
        login
            .packet_size
            .min(shared.config.limits.max_packet_bytes as u32)
    } as usize;
    let response = tokens::login_success(
        if login.database.is_empty() {
            &shared.config.personality.default_database
        } else {
            &login.database
        },
        if login.language.is_empty() {
            &shared.config.personality.language
        } else {
            &login.language
        },
        packet_size as u32,
        "Microsoft SQL Server",
    )?;
    counters.bytes_written +=
        write_message(&mut stream, tds::TABULAR_RESULT, &response, packet_size).await?;
    let mut session = SessionState::new(
        connection_id,
        session_id,
        peer,
        &login,
        &shared.config.personality,
    );
    let deadline = TokioInstant::now() + shared.config.listener.session_timeout();

    loop {
        if session.request_count >= shared.config.limits.max_requests_per_session {
            return Ok(summary(
                "request_limit",
                Some(session_id),
                session.request_count,
                counters,
            ));
        }
        let idle_deadline = TokioInstant::now() + shared.config.listener.idle_timeout();
        let message = match timeout_at(
            deadline.min(idle_deadline),
            read_message(
                &mut stream,
                shared.config.limits.max_packet_bytes,
                shared.config.limits.max_message_bytes,
            ),
        )
        .await
        {
            Ok(Ok(message)) => message,
            Ok(Err(Error::Io(error))) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(summary(
                    "client_closed",
                    Some(session_id),
                    session.request_count,
                    counters,
                ));
            }
            Ok(Err(error)) => {
                shared
                    .metrics
                    .malformed_messages
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
            Err(_) if TokioInstant::now() >= deadline => {
                return Ok(summary(
                    "session_timeout",
                    Some(session_id),
                    session.request_count,
                    counters,
                ));
            }
            Err(_) => {
                return Ok(summary(
                    "idle_timeout",
                    Some(session_id),
                    session.request_count,
                    counters,
                ));
            }
        };
        counters.bytes_read += wire_size(&message);
        if !shared.allow_request(peer.ip()) {
            shared.telemetry.emit(
                Event::new("rate_limit", Some(connection_id), Some(session_id))
                    .field("source_ip", peer.ip().to_string()),
            );
            return Ok(summary(
                "rate_limit",
                Some(session_id),
                session.request_count,
                counters,
            ));
        }
        session.request_count += 1;
        let (outcome, done_proc) = match message.packet_type {
            tds::SQL_BATCH => {
                shared.metrics.sql_batches.fetch_add(1, Ordering::Relaxed);
                let sql =
                    tds::batch::decode(&message.payload, shared.config.limits.max_sql_batch_bytes)?;
                let outcome = handle_sql(&mut session, &shared.config.personality, &sql);
                emit_request(
                    &shared,
                    &session,
                    "sql_batch",
                    outcome.classification,
                    Event::new("sql_batch", Some(connection_id), Some(session_id))
                        .field("raw_sql", &sql),
                );
                (outcome, false)
            }
            tds::RPC => {
                shared.metrics.rpc_requests.fetch_add(1, Ordering::Relaxed);
                let rpc = tds::rpc::parse(
                    &message.payload,
                    shared.config.limits.max_rpc_parameter_bytes,
                )?;
                let outcome = handle_rpc(&mut session, &shared.config.personality, &rpc);
                emit_request(
                    &shared,
                    &session,
                    "rpc_request",
                    outcome.classification,
                    Event::new("rpc_request", Some(connection_id), Some(session_id))
                        .field("procedure", &rpc.procedure)
                        .field("options", rpc.options)
                        .field("parameter_count", rpc.parameters.len())
                        .field(
                            "parameter_names",
                            rpc.parameters
                                .iter()
                                .map(|p| p.name.as_str())
                                .collect::<Vec<_>>(),
                        )
                        .field(
                            "parameter_values",
                            rpc.parameters
                                .iter()
                                .map(|p| p.value.telemetry_value())
                                .collect::<Vec<_>>(),
                        )
                        .field(
                            "output_parameter_count",
                            rpc.parameters.iter().filter(|p| p.status & 1 != 0).count(),
                        ),
                );
                (outcome, true)
            }
            tds::ATTENTION => (
                Outcome {
                    classification: Classification::Unknown,
                    risk_tags: vec![],
                    result_sets: vec![],
                    messages: vec![],
                    error: None,
                    state_changes: vec![],
                    payload_candidate: None,
                    honey_object: None,
                },
                false,
            ),
            other => {
                return Err(Error::Protocol(format!(
                    "unsupported post-login TDS packet type 0x{other:02x}"
                )));
            }
        };
        update_risk(&mut counters, outcome.classification);
        shared.record_classification(outcome.classification);
        process_outcome(&shared, &session, &outcome).await;
        let response = tokens::response(
            &outcome.result_sets,
            &outcome.messages,
            outcome.error.as_ref(),
            &shared.config.personality.server_name,
            done_proc,
        )?;
        counters.bytes_written +=
            write_message(&mut stream, tds::TABULAR_RESULT, &response, packet_size).await?;
    }
}

fn emit_request(
    shared: &Shared,
    session: &SessionState,
    request_type: &str,
    classification: Classification,
    event: Event,
) {
    shared.telemetry.emit(
        event
            .field("request_type", request_type)
            .field("login", &session.login_name)
            .field("effective_login", &session.effective_login)
            .field("database", &session.current_database)
            .field("classification", classification)
            .field("risk_tags", classification.risk_tags()),
    );
}

async fn process_outcome(shared: &Shared, session: &SessionState, outcome: &Outcome) {
    for state in &outcome.state_changes {
        shared.telemetry.emit(
            Event::new(
                "synthetic_state_change",
                Some(session.connection_id),
                Some(session.session_id),
            )
            .field("property", &state.property)
            .field("old_value", &state.old_value)
            .field("new_value", &state.new_value),
        );
    }
    if let Some(object) = &outcome.honey_object {
        shared.telemetry.emit(
            Event::new(
                "honey_object_access",
                Some(session.connection_id),
                Some(session.session_id),
            )
            .field("object", object)
            .field("action", "access")
            .field("severity", "high"),
        );
    }
    if let Some(candidate) = &outcome.payload_candidate {
        match shared.payloads.capture(&candidate.bytes).await {
            Ok(Some(captured)) => {
                shared
                    .metrics
                    .payloads_captured
                    .fetch_add(1, Ordering::Relaxed);
                shared
                    .metrics
                    .bytes_captured
                    .fetch_add(captured.size as u64, Ordering::Relaxed);
                shared.telemetry.emit(
                    Event::new(
                        "payload_capture",
                        Some(session.connection_id),
                        Some(session.session_id),
                    )
                    .field("payload_type", &candidate.kind)
                    .field("sha256", captured.sha256)
                    .field("size", captured.size)
                    .field("storage_id", captured.storage_id),
                );
            }
            Ok(None) => shared.telemetry.emit(
                Event::new(
                    "payload_observed",
                    Some(session.connection_id),
                    Some(session.session_id),
                )
                .field("payload_type", &candidate.kind)
                .field("size", candidate.bytes.len())
                .field("storage_enabled", false),
            ),
            Err(error) => shared.telemetry.emit(
                Event::new(
                    "payload_capture_error",
                    Some(session.connection_id),
                    Some(session.session_id),
                )
                .field("payload_type", &candidate.kind)
                .field("error", error.to_string()),
            ),
        }
    }
}

fn update_risk(counters: &mut Counters, classification: Classification) {
    if risk_rank(classification) > risk_rank(counters.highest_risk) {
        counters.highest_risk = classification;
    }
}
fn risk_rank(c: Classification) -> u8 {
    match c {
        Classification::HoneyObjectAccess => 5,
        Classification::XpCmdshell
        | Classification::ClrActivity
        | Classification::ExternalScripts
        | Classification::SqlAgentActivity => 4,
        Classification::OleAutomation
        | Classification::LinkedServerActivity
        | Classification::FilesystemActivity
        | Classification::LoginManipulation
        | Classification::RoleManipulation
        | Classification::ExecuteAs => 3,
        Classification::Configuration
        | Classification::PrincipalEnumeration
        | Classification::PermissionEnumeration => 2,
        Classification::EnvironmentDiscovery | Classification::DatabaseEnumeration => 1,
        _ => 0,
    }
}
fn wire_size(message: &tds::packet::Message) -> u64 {
    message.payload.len() as u64 + u64::from(message.packet_count) * 8
}
fn hex_version(v: [u8; 6]) -> String {
    format!(
        "{:02x}.{:02x}.{:02x}.{:02x}-{:02x}{:02x}",
        v[0], v[1], v[2], v[3], v[4], v[5]
    )
}
fn summary(reason: &str, session_id: Option<u32>, requests: u64, counters: Counters) -> Summary {
    Summary {
        reason: reason.into(),
        session_id,
        requests,
        bytes_read: counters.bytes_read,
        bytes_written: counters.bytes_written,
        parser_errors: counters.parser_errors,
        highest_risk: format!("{:?}", counters.highest_risk).to_lowercase(),
    }
}
