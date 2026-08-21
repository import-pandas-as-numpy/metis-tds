use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
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
    pub stage: &'static str,
    pub session_id: Option<u32>,
    pub requests: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub parser_errors: u64,
    pub highest_risk: String,
}

pub struct Failure {
    pub error: Error,
    pub stage: &'static str,
    pub session_id: Option<u32>,
    pub requests: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub stage_bytes_read: u64,
    pub stage_bytes_written: u64,
    pub read_prefix: Vec<u8>,
    pub last_packet_type: Option<u8>,
    pub last_first_status: Option<u8>,
    pub last_first_packet_id: Option<u8>,
    pub last_packet_count: Option<u32>,
    pub last_message_bytes: Option<usize>,
    pub highest_risk: String,
}

struct WireCounters {
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    read_prefix: Mutex<Vec<u8>>,
}

const DIAGNOSTIC_PREFIX_BYTES: usize = 256;

impl Default for WireCounters {
    fn default() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_prefix: Mutex::new(Vec::with_capacity(DIAGNOSTIC_PREFIX_BYTES)),
        }
    }
}

struct Progress {
    stage: &'static str,
    session_id: Option<u32>,
    requests: u64,
    highest_risk: Classification,
    wire: Arc<WireCounters>,
    stage_read_started: u64,
    stage_write_started: u64,
    last_packet_type: Option<u8>,
    last_first_status: Option<u8>,
    last_first_packet_id: Option<u8>,
    last_packet_count: Option<u32>,
    last_message_bytes: Option<usize>,
}

impl Progress {
    fn new(wire: Arc<WireCounters>) -> Self {
        Self {
            stage: "connection_setup",
            session_id: None,
            requests: 0,
            highest_risk: Classification::Unknown,
            wire,
            stage_read_started: 0,
            stage_write_started: 0,
            last_packet_type: None,
            last_first_status: None,
            last_first_packet_id: None,
            last_packet_count: None,
            last_message_bytes: None,
        }
    }

    fn enter(&mut self, stage: &'static str) {
        self.stage = stage;
        self.stage_read_started = self.wire.bytes_read.load(Ordering::Relaxed);
        self.stage_write_started = self.wire.bytes_written.load(Ordering::Relaxed);
    }

    fn observe_message(&mut self, message: &tds::packet::Message) {
        self.last_packet_type = Some(message.packet_type);
        self.last_first_status = Some(message.first_status);
        self.last_first_packet_id = Some(message.first_packet_id);
        self.last_packet_count = Some(message.packet_count);
        self.last_message_bytes = Some(message.payload.len());
    }

    fn summary(&self, reason: &str) -> Summary {
        Summary {
            reason: reason.into(),
            stage: self.stage,
            session_id: self.session_id,
            requests: self.requests,
            bytes_read: self.wire.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.wire.bytes_written.load(Ordering::Relaxed),
            parser_errors: 0,
            highest_risk: format!("{:?}", self.highest_risk).to_lowercase(),
        }
    }

    fn failure(&self, error: Error) -> Failure {
        let bytes_read = self.wire.bytes_read.load(Ordering::Relaxed);
        let bytes_written = self.wire.bytes_written.load(Ordering::Relaxed);
        Failure {
            error,
            stage: self.stage,
            session_id: self.session_id,
            requests: self.requests,
            bytes_read,
            bytes_written,
            stage_bytes_read: bytes_read.saturating_sub(self.stage_read_started),
            stage_bytes_written: bytes_written.saturating_sub(self.stage_write_started),
            read_prefix: self
                .wire
                .read_prefix
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            last_packet_type: self.last_packet_type,
            last_first_status: self.last_first_status,
            last_first_packet_id: self.last_first_packet_id,
            last_packet_count: self.last_packet_count,
            last_message_bytes: self.last_message_bytes,
            highest_risk: format!("{:?}", self.highest_risk).to_lowercase(),
        }
    }
}

struct MeteredIo<S> {
    inner: S,
    counters: Arc<WireCounters>,
}

impl<S> MeteredIo<S> {
    fn new(inner: S, counters: Arc<WireCounters>) -> Self {
        Self { inner, counters }
    }
}

impl MeteredIo<TcpStream> {
    async fn peek(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.peek(buffer).await
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let newly_read = &buffer.filled()[before..];
            let read = newly_read.len();
            self.counters
                .bytes_read
                .fetch_add(read as u64, Ordering::Relaxed);
            let mut prefix = self
                .counters
                .read_prefix
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let remaining = DIAGNOSTIC_PREFIX_BYTES.saturating_sub(prefix.len());
            prefix.extend_from_slice(&newly_read[..newly_read.len().min(remaining)]);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buffer);
        if let Poll::Ready(Ok(written)) = result {
            self.counters
                .bytes_written
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn handle(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
    connection_id: Uuid,
) -> std::result::Result<Summary, Failure> {
    let wire = Arc::new(WireCounters::default());
    let mut progress = Progress::new(Arc::clone(&wire));
    if let Err(error) = stream.set_nodelay(true) {
        return Err(progress.failure(error.into()));
    }
    let stream = MeteredIo::new(stream, wire);
    progress.enter("initial_probe");
    let mut first = [0_u8; 1];
    let first_len = match timeout(
        shared.config.listener.login_timeout(),
        stream.peek(&mut first),
    )
    .await
    {
        Ok(result) => match result {
            Ok(length) => length,
            Err(error) => return Err(progress.failure(error.into())),
        },
        Err(_) => {
            return Err(progress.failure(Error::Protocol("initial packet timeout".into())));
        }
    };
    if first_len == 0 {
        return Err(
            progress.failure(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into())
        );
    }
    if first[0] == 0x16 {
        return handle_tds8(shared, stream, peer, connection_id, &mut progress)
            .await
            .map_err(|error| progress.failure(error));
    }
    handle_inner(shared, stream, peer, connection_id, &mut progress)
        .await
        .map_err(|error| progress.failure(error))
}

async fn handle_tds8(
    shared: Arc<Shared>,
    stream: MeteredIo<TcpStream>,
    peer: SocketAddr,
    connection_id: Uuid,
    progress: &mut Progress,
) -> Result<Summary> {
    progress.enter("tls8_handshake");
    let acceptor = shared.tls.as_ref().ok_or_else(|| {
        Error::Protocol("TDS 8.0 ClientHello received while TLS is disabled".into())
    })?;
    let mut stream = timeout(
        shared.config.listener.login_timeout(),
        tls::handshake_raw(stream, acceptor),
    )
    .await
    .map_err(|_| Error::Tls("TDS 8.0 handshake timeout".into()))??;
    emit_tls_negotiated(&shared, connection_id, "tds8", stream.get_ref().1);

    progress.enter("prelogin8_read");
    let prelogin_message = timeout(
        shared.config.listener.login_timeout(),
        read_message(
            &mut stream,
            shared.config.limits.max_packet_bytes,
            shared.config.limits.max_message_bytes,
        ),
    )
    .await
    .map_err(|_| Error::Protocol("TDS 8.0 PRELOGIN timeout".into()))??;
    progress.observe_message(&prelogin_message);
    progress.enter("prelogin8_parse");
    if prelogin_message.packet_type != tds::PRELOGIN {
        return Err(Error::Protocol(
            "expected PRELOGIN after TDS 8.0 TLS handshake".into(),
        ));
    }
    let prelogin = tds::prelogin::parse(&prelogin_message.payload)?;
    emit_prelogin(
        &shared,
        peer,
        connection_id,
        &prelogin_message,
        &prelogin,
        Encryption::Required,
        "tds8",
    );
    let response = tds::prelogin::encode_response(
        Encryption::Required,
        &shared.config.personality.instance_name,
    );
    progress.enter("prelogin8_response");
    write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;
    login_and_serve(shared, stream, peer, connection_id, progress).await
}

async fn handle_inner(
    shared: Arc<Shared>,
    mut stream: MeteredIo<TcpStream>,
    peer: SocketAddr,
    connection_id: Uuid,
    progress: &mut Progress,
) -> Result<Summary> {
    progress.enter("prelogin_read");
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
    progress.observe_message(&prelogin_message);
    progress.enter("prelogin_parse");
    if prelogin_message.packet_type != tds::PRELOGIN {
        return Err(Error::Protocol("first message was not PRELOGIN".into()));
    }
    let prelogin = tds::prelogin::parse(&prelogin_message.payload)?;
    let requested_encryption = prelogin.encryption.unwrap_or(Encryption::Off);
    let (response_encryption, use_tls) = negotiate(shared.config.tls.mode, requested_encryption);
    emit_prelogin(
        &shared,
        peer,
        connection_id,
        &prelogin_message,
        &prelogin,
        response_encryption,
        "tds7",
    );
    let response = tds::prelogin::encode_response(
        response_encryption,
        &shared.config.personality.instance_name,
    );
    progress.enter("prelogin_response");
    write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;

    if shared.config.tls.mode == TlsMode::Required
        && requested_encryption == Encryption::NotSupported
    {
        return Ok(progress.summary("client_does_not_support_required_tls"));
    }
    if use_tls {
        progress.enter("tls_handshake");
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
        emit_tls_negotiated(&shared, connection_id, "tds7", connection);
        login_and_serve(shared, tls, peer, connection_id, progress).await
    } else {
        login_and_serve(shared, stream, peer, connection_id, progress).await
    }
}

fn emit_prelogin(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    message: &tds::packet::Message,
    prelogin: &tds::prelogin::Prelogin,
    response_encryption: Encryption,
    transport: &str,
) {
    shared.telemetry.emit(
        Event::new("prelogin", Some(connection_id), None)
            .field("source_ip", peer.ip().to_string())
            .field("transport", transport)
            .field("packet_count", message.packet_count)
            .field("first_packet_status", message.first_status)
            .field("first_packet_id", message.first_packet_id)
            .field("message_bytes", message.payload.len())
            .field("tds_version", prelogin.version.map(hex_version))
            .field(
                "encryption_request",
                prelogin
                    .encryption
                    .map(|value| format!("{value:?}").to_lowercase()),
            )
            .field(
                "encryption_response",
                format!("{response_encryption:?}").to_lowercase(),
            )
            .field("mars_requested", prelogin.mars)
            .field("instance", &prelogin.instance)
            .field("unknown_tokens", &prelogin.unknown_tokens),
    );
}

fn emit_tls_negotiated(
    shared: &Shared,
    connection_id: Uuid,
    transport: &str,
    connection: &rustls::ServerConnection,
) {
    shared.telemetry.emit(
        Event::new("tls_negotiated", Some(connection_id), None)
            .field("transport", transport)
            .field(
                "protocol",
                connection
                    .protocol_version()
                    .map(|value| format!("{value:?}")),
            )
            .field(
                "cipher_suite",
                connection
                    .negotiated_cipher_suite()
                    .map(|suite| format!("{:?}", suite.suite())),
            )
            .field(
                "alpn_protocol",
                connection
                    .alpn_protocol()
                    .map(|value| String::from_utf8_lossy(value).into_owned()),
            ),
    );
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
    progress: &mut Progress,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    progress.enter("login_read");
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
    progress.observe_message(&login_message);
    progress.enter("login_parse");
    if login_message.packet_type != tds::LOGIN7 {
        return Err(Error::Protocol("expected LOGIN7 message".into()));
    }
    let mut login = tds::login7::parse(&login_message.payload)?;
    let session_id = shared.sessions.fetch_add(1, Ordering::Relaxed);
    progress.session_id = Some(session_id);
    shared
        .metrics
        .login_attempts
        .fetch_add(1, Ordering::Relaxed);
    progress.enter("authentication");
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
            .field("packet_count", login_message.packet_count)
            .field("first_packet_status", login_message.first_status)
            .field("first_packet_id", login_message.first_packet_id)
            .field("message_bytes", login_message.payload.len())
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
        progress.enter("login_response");
        let response = tokens::login_failure(
            &shared.config.personality.server_name,
            decision == AuthDecision::Locked,
        )?;
        write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;
        return Ok(progress.summary("login_rejected"));
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
    progress.enter("login_response");
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
            progress.requests = session.request_count;
            return Ok(progress.summary("request_limit"));
        }
        progress.enter("request_read");
        progress.requests = session.request_count;
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
                return Ok(progress.summary("client_closed"));
            }
            Ok(Err(error)) => return Err(error),
            Err(_) if TokioInstant::now() >= deadline => {
                return Ok(progress.summary("session_timeout"));
            }
            Err(_) => {
                return Ok(progress.summary("idle_timeout"));
            }
        };
        progress.observe_message(&message);
        progress.enter("request_parse");
        if !shared.allow_request(peer.ip()) {
            shared.telemetry.emit(
                Event::new("rate_limit", Some(connection_id), Some(session_id))
                    .field("source_ip", peer.ip().to_string()),
            );
            return Ok(progress.summary("rate_limit"));
        }
        session.request_count += 1;
        progress.requests = session.request_count;
        let (outcome, done_proc) = match message.packet_type {
            tds::SQL_BATCH => {
                progress.enter("sql_batch_parse");
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
                progress.enter("rpc_parse");
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
        update_risk(progress, outcome.classification);
        shared.record_classification(outcome.classification);
        process_outcome(&shared, &session, &outcome).await;
        let response = tokens::response(
            &outcome.result_sets,
            &outcome.messages,
            outcome.error.as_ref(),
            &shared.config.personality.server_name,
            done_proc,
        )?;
        progress.enter("response_write");
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

fn update_risk(progress: &mut Progress, classification: Classification) {
    if risk_rank(classification) > risk_rank(progress.highest_risk) {
        progress.highest_risk = classification;
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
fn hex_version(v: [u8; 6]) -> String {
    format!(
        "{:02x}.{:02x}.{:02x}.{:02x}-{:02x}{:02x}",
        v[0], v[1], v[2], v[3], v[4], v[5]
    )
}
