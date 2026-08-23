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

struct MessageCaptureIo<S> {
    inner: S,
    read_capture: Vec<u8>,
    maximum: usize,
    truncated: bool,
}

impl<S> MessageCaptureIo<S> {
    fn new(inner: S, maximum: usize) -> Self {
        Self {
            inner,
            read_capture: Vec::new(),
            maximum,
            truncated: false,
        }
    }

    fn clear_capture(&mut self) {
        self.read_capture.clear();
        self.truncated = false;
    }

    fn captured(&self) -> &[u8] {
        &self.read_capture
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MessageCaptureIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let newly_read = &buffer.filled()[before..];
            let remaining = self.maximum.saturating_sub(self.read_capture.len());
            let retained = newly_read.len().min(remaining);
            if retained > 0 {
                self.read_capture.extend_from_slice(&newly_read[..retained]);
            }
            self.truncated |= retained < newly_read.len();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MessageCaptureIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
    if tds::is_authentication_packet(first[0]) {
        let transport = match first[0] {
            tds::LOGIN => "tds42_direct",
            tds::LOGIN7 => "tds7_direct",
            tds::SSPI => "sspi_direct",
            tds::FEDAUTH_TOKEN => "fedauth_direct",
            _ => unreachable!("authentication packet taxonomy"),
        };
        shared.telemetry.emit(
            Event::new(
                if matches!(first[0], tds::LOGIN | tds::LOGIN7) {
                    "direct_login_candidate"
                } else {
                    "direct_authentication_candidate"
                },
                Some(connection_id),
                None,
            )
            .field("source_ip", peer.ip().to_string())
            .field("source_port", peer.port())
            .field("transport", transport)
            .field("packet_type", first[0]),
        );
        return login_and_serve(
            shared,
            stream,
            peer,
            connection_id,
            &mut progress,
            transport,
        )
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
    observe_inbound_message(
        &shared,
        peer,
        connection_id,
        None,
        "prelogin8_read",
        "tds8",
        &prelogin_message,
    )
    .await;
    progress.enter("prelogin8_parse");
    if prelogin_message.packet_type != tds::PRELOGIN {
        return Err(Error::Protocol(
            "expected PRELOGIN after TDS 8.0 TLS handshake".into(),
        ));
    }
    let prelogin = match tds::prelogin::parse_for_telemetry(&prelogin_message.payload) {
        Ok(value) => value,
        Err(error) => {
            capture_protocol_artifact(
                &shared,
                peer,
                connection_id,
                None,
                "prelogin_parse_failure",
                &prelogin_message,
                "tds8",
            )
            .await;
            return Err(error);
        }
    };
    let instance_matches = instance_matches(
        prelogin.instance.as_deref(),
        &shared.config.personality.instance_name,
    );
    emit_prelogin(
        &shared,
        peer,
        connection_id,
        &prelogin_message,
        &prelogin,
        Encryption::Required,
        "tds8",
    );
    let response = tds::prelogin::encode_response(Encryption::Required, instance_matches);
    progress.enter("prelogin8_response");
    write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;
    login_and_serve(shared, stream, peer, connection_id, progress, "tds8").await
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
    observe_inbound_message(
        &shared,
        peer,
        connection_id,
        None,
        "prelogin_read",
        "tds7",
        &prelogin_message,
    )
    .await;
    progress.enter("prelogin_parse");
    if prelogin_message.packet_type != tds::PRELOGIN {
        return Err(Error::Protocol("first message was not PRELOGIN".into()));
    }
    let prelogin = match tds::prelogin::parse_for_telemetry(&prelogin_message.payload) {
        Ok(value) => value,
        Err(error) => {
            capture_protocol_artifact(
                &shared,
                peer,
                connection_id,
                None,
                "prelogin_parse_failure",
                &prelogin_message,
                "tds7",
            )
            .await;
            return Err(error);
        }
    };
    let requested_encryption = prelogin.encryption.unwrap_or(Encryption::Off);
    let (response_encryption, use_tls) = negotiate(shared.config.tls.mode, requested_encryption);
    let instance_matches = instance_matches(
        prelogin.instance.as_deref(),
        &shared.config.personality.instance_name,
    );
    emit_prelogin(
        &shared,
        peer,
        connection_id,
        &prelogin_message,
        &prelogin,
        response_encryption,
        "tds7",
    );
    let response = tds::prelogin::encode_response(response_encryption, instance_matches);
    progress.enter("prelogin_response");
    write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;

    if shared.config.tls.mode == TlsMode::Required
        && requested_encryption == Encryption::NotSupported
    {
        return Ok(progress.summary("client_does_not_support_required_tls"));
    }
    if use_tls {
        progress.enter("tls_handshake");
        // Some opportunistic scanners send a plaintext LOGIN/LOGIN7 packet even
        // after the server has selected encryption. Peek before handing the
        // stream to rustls so we can capture the complete login message without
        // weakening the TLS path for conforming clients.
        let mut first = [0_u8; 1];
        let first_len = timeout(
            shared.config.listener.login_timeout(),
            stream.peek(&mut first),
        )
        .await
        .map_err(|_| Error::Tls("handshake timeout".into()))?
        .map_err(|error| Error::Tls(error.to_string()))?;
        if first_len == 0 {
            return Err(Error::Tls("unexpected EOF during handshake".into()));
        }
        if tds::is_authentication_packet(first[0]) {
            let transport = match first[0] {
                tds::LOGIN => "tds42_plaintext_after_prelogin",
                tds::LOGIN7 => "tds7_plaintext_after_prelogin",
                tds::SSPI => "sspi_plaintext_after_prelogin",
                tds::FEDAUTH_TOKEN => "fedauth_plaintext_after_prelogin",
                _ => unreachable!("authentication packet taxonomy"),
            };
            shared.telemetry.emit(
                Event::new(
                    if matches!(first[0], tds::LOGIN | tds::LOGIN7) {
                        "plaintext_login_after_prelogin"
                    } else {
                        "plaintext_authentication_after_prelogin"
                    },
                    Some(connection_id),
                    None,
                )
                .field("source_ip", peer.ip().to_string())
                .field("source_port", peer.port())
                .field("transport", transport)
                .field("packet_type", first[0])
                .field(
                    "negotiated_encryption",
                    format!("{response_encryption:?}").to_lowercase(),
                ),
            );
            return login_and_serve(shared, stream, peer, connection_id, progress, transport).await;
        }
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
        login_and_serve(shared, tls, peer, connection_id, progress, "tds7").await
    } else {
        login_and_serve(shared, stream, peer, connection_id, progress, "tds7").await
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
            .field("trace_id_present", prelogin.trace_id.is_some())
            .field("fedauth_required", prelogin.fedauth_required)
            .field("nonce_present", prelogin.nonce.is_some())
            .field("instance", &prelogin.instance)
            .field(
                "instance_matches",
                instance_matches(
                    prelogin.instance.as_deref(),
                    &shared.config.personality.instance_name,
                ),
            )
            .field("unknown_tokens", &prelogin.unknown_tokens)
            .field("unknown_token_lengths", &prelogin.unknown_token_lengths)
            .field("parse_warnings", &prelogin.parse_warnings)
            .field("structurally_valid", prelogin.parse_warnings.is_empty()),
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
        TlsMode::Required => match client {
            Encryption::Off | Encryption::NotSupported => {
                (Encryption::Required, client != Encryption::NotSupported)
            }
            Encryption::On | Encryption::Required => (Encryption::On, true),
        },
    }
}

fn instance_matches(requested: Option<&str>, configured: &str) -> bool {
    requested
        .is_none_or(|requested| requested.is_empty() || requested.eq_ignore_ascii_case(configured))
}

async fn login_and_serve<S>(
    shared: Arc<Shared>,
    stream: S,
    peer: SocketAddr,
    connection_id: Uuid,
    progress: &mut Progress,
    transport: &'static str,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = MessageCaptureIo::new(stream, shared.config.limits.max_payload_bytes);
    progress.enter("login_read");
    let login_result = timeout(
        shared.config.listener.login_timeout(),
        read_message(
            &mut stream,
            shared.config.limits.max_packet_bytes,
            shared.config.limits.max_message_bytes,
        ),
    )
    .await;
    let login_message = match login_result {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => {
            capture_incomplete_ingress(
                &shared,
                peer,
                connection_id,
                None,
                transport,
                stream.captured(),
                stream.truncated,
                error.kind(),
            )
            .await;
            return Err(error);
        }
        Err(_) => {
            capture_incomplete_ingress(
                &shared,
                peer,
                connection_id,
                None,
                transport,
                stream.captured(),
                stream.truncated,
                "timeout",
            )
            .await;
            return Err(Error::Protocol("login message timeout".into()));
        }
    };
    stream.clear_capture();
    progress.observe_message(&login_message);
    observe_inbound_message(
        &shared,
        peer,
        connection_id,
        None,
        "login_read",
        transport,
        &login_message,
    )
    .await;
    if matches!(transport, "tds42_direct" | "tds7_direct") {
        shared
            .metrics
            .direct_login_connections
            .fetch_add(1, Ordering::Relaxed);
        shared.telemetry.emit(
            Event::new("direct_login_detected", Some(connection_id), None)
                .field("source_ip", peer.ip().to_string())
                .field("source_port", peer.port())
                .field("transport", transport)
                .field("packet_type", login_message.packet_type)
                .field("packet_count", login_message.packet_count)
                .field("first_packet_status", login_message.first_status)
                .field("first_packet_id", login_message.first_packet_id)
                .field("message_bytes", login_message.payload.len()),
        );
    }
    let legacy_login = login_message.packet_type == tds::LOGIN;
    let transport = match (transport, login_message.packet_type) {
        ("tds7", tds::LOGIN) => "tds42_after_prelogin",
        ("tds8", tds::LOGIN) => "tds42_over_tds8",
        (value, _) => value,
    };
    progress.enter("login_parse");
    let mut login = match login_message.packet_type {
        tds::LOGIN => tds::login::parse_for_telemetry(&login_message.payload)?,
        tds::LOGIN7 => tds::login7::parse_for_telemetry(&login_message.payload)?,
        tds::SSPI => {
            let token = tds::sspi::parse(&login_message.payload);
            shared.telemetry.emit(
                Event::new("sspi_message", Some(connection_id), None)
                    .field("source_ip", peer.ip().to_string())
                    .field("transport", transport)
                    .field("token_family", token.family)
                    .field("message_type", token.message_type)
                    .field("token_bytes", token.bytes)
                    .field("unexpected_state", true),
            );
            return Err(Error::Protocol("SSPI message arrived before LOGIN7".into()));
        }
        tds::FEDAUTH_TOKEN => {
            let token = tds::fedauth::parse(&login_message.payload, false)?;
            shared.telemetry.emit(
                Event::new("federated_authentication_token", Some(connection_id), None)
                    .field("source_ip", peer.ip().to_string())
                    .field("transport", transport)
                    .field("token_bytes", token.token.len())
                    .field("nonce_present", token.nonce.is_some())
                    .field("unexpected_state", true),
            );
            return Err(Error::Protocol(
                "federated authentication token arrived before LOGIN7".into(),
            ));
        }
        tds::TDS5_NORMAL => {
            let auth = tds::tds5::parse_authentication(
                &login_message.payload,
                shared.config.limits.max_payload_bytes,
            )?;
            capture_protocol_artifact(
                &shared,
                peer,
                connection_id,
                None,
                "tds5_authentication_before_login",
                &login_message,
                transport,
            )
            .await;
            shared.telemetry.emit(
                Event::new("tds5_authentication_stream", Some(connection_id), None)
                    .field("source_ip", peer.ip().to_string())
                    .field("transport", transport)
                    .field("message_types", auth.message_types)
                    .field("parameter_formats", auth.parameter_formats)
                    .field("parameter_sets", auth.parameter_sets)
                    .field("parameter_value_bytes", auth.parameter_value_bytes)
                    .field("commands", &auth.commands)
                    .field("parameter_values", &auth.parameter_values)
                    .field("unexpected_state", true),
            );
            return Err(Error::Protocol(
                "TDS 5 authentication continuation arrived before LOGIN".into(),
            ));
        }
        _ => {
            capture_protocol_artifact(
                &shared,
                peer,
                connection_id,
                None,
                "unexpected_message_before_login",
                &login_message,
                transport,
            )
            .await;
            return Err(Error::Protocol("expected LOGIN or LOGIN7 message".into()));
        }
    };
    let protocol = if legacy_login {
        tokens::Protocol::Tds42
    } else {
        tokens::Protocol::Tds7(login.tds_version)
    };
    let session_id = shared.sessions.fetch_add(1, Ordering::Relaxed);
    progress.session_id = Some(session_id);
    shared
        .metrics
        .login_attempts
        .fetch_add(1, Ordering::Relaxed);
    let source_login_attempt =
        (!login.integrated_security).then(|| shared.record_login_attempt(peer.ip()));
    progress.enter("authentication");
    let bypass_threshold = shared.config.personality.accept_source_after_attempts;
    let source_auth_bypass = matches!(
        (bypass_threshold, source_login_attempt),
        (Some(threshold), Some(attempt)) if attempt > threshold
    );
    let login_structurally_valid = login.parse_warnings.is_empty();
    let decision = if !login_structurally_valid || login.integrated_security {
        AuthDecision::Reject
    } else if source_auth_bypass {
        shared
            .metrics
            .source_auth_bypasses
            .fetch_add(1, Ordering::Relaxed);
        AuthDecision::Accept
    } else {
        shared.config.personality.authenticate(&login)
    };
    let accepted = decision == AuthDecision::Accept;
    let mut login_event = Event::new("login_attempt", Some(connection_id), Some(session_id))
        .field("source_ip", peer.ip().to_string())
        .field("transport", transport)
        .field(
            "login_format",
            if legacy_login {
                "tds42_login"
            } else {
                "login7"
            },
        )
        .field("packet_type", login_message.packet_type)
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
        .field(
            "client_program_version",
            format!("0x{:08x}", login.client_program_version),
        )
        .field("client_pid", login.client_pid)
        .field("connection_id_hint", login.connection_id)
        .field("client_timezone", login.client_timezone)
        .field("client_lcid", login.client_lcid)
        .field("client_id", hex_version(login.client_id))
        .field("password_field_present", login.password_present)
        .field("change_password_field_present", login.new_password_present)
        .field("attach_database_file", &login.attach_database_file)
        .field("integrated_security", login.integrated_security)
        .field("sspi_bytes", login.sspi_bytes)
        .field("sspi_token_family", login.sspi_token_family)
        .field("feature_extensions", &login.features)
        .field("parse_warnings", &login.parse_warnings)
        .field("structurally_valid", login_structurally_valid)
        .field("legacy_security_flags", login.legacy_security_flags)
        .field("legacy_capabilities_bytes", login.legacy_capabilities_bytes)
        .field(
            "legacy_authentication_bytes",
            login.legacy_authentication_bytes,
        )
        .field("accepted", accepted)
        .field("source_login_attempt_number", source_login_attempt)
        .field("source_auth_bypass_threshold", bypass_threshold)
        .field("source_auth_bypass", source_auth_bypass)
        .field(
            "honey_identity",
            shared.config.personality.is_honey_login(&login.username),
        );
    if shared.config.telemetry.capture_login_passwords {
        login_event = login_event
            .field("password", login.password_for_capture())
            .field("new_password", login.new_password_for_capture());
    }
    shared.telemetry.emit(login_event);

    if login.integrated_security {
        let initial_sspi = if legacy_login {
            &[][..]
        } else {
            tds::login7::sspi_token(&login_message.payload).unwrap_or(&[])
        };
        login.discard_password();
        return negotiate_integrated_authentication(
            &shared,
            &mut stream,
            peer,
            connection_id,
            session_id,
            progress,
            transport,
            protocol,
            initial_sspi,
        )
        .await;
    }

    login.discard_password();
    if !accepted {
        progress.enter("login_response");
        let response = tokens::login_failure(
            protocol,
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
        protocol,
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
        stream.clear_capture();
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
                capture_incomplete_ingress(
                    &shared,
                    peer,
                    connection_id,
                    Some(session.session_id),
                    transport,
                    stream.captured(),
                    stream.truncated,
                    "io",
                )
                .await;
                return Ok(progress.summary("client_closed"));
            }
            Ok(Err(error)) => {
                capture_incomplete_ingress(
                    &shared,
                    peer,
                    connection_id,
                    Some(session.session_id),
                    transport,
                    stream.captured(),
                    stream.truncated,
                    error.kind(),
                )
                .await;
                return Err(error);
            }
            Err(_) if TokioInstant::now() >= deadline => {
                return Ok(progress.summary("session_timeout"));
            }
            Err(_) => {
                return Ok(progress.summary("idle_timeout"));
            }
        };
        progress.observe_message(&message);
        observe_inbound_message(
            &shared,
            peer,
            connection_id,
            Some(session.session_id),
            "request_read",
            transport,
            &message,
        )
        .await;
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
                let (sql, headers) = if legacy_login {
                    (
                        tds::batch::decode_legacy(
                            &message.payload,
                            shared.config.limits.max_sql_batch_bytes,
                        )?,
                        Vec::new(),
                    )
                } else {
                    let tds_version = match protocol {
                        tokens::Protocol::Tds7(version) => version >> 24,
                        tokens::Protocol::Tds42 => 0,
                    };
                    let batch = match tds::batch::parse_with_context(
                        &message.payload,
                        shared.config.limits.max_sql_batch_bytes,
                        tds_version >= 0x72,
                        tds_version >= 0x74,
                        tds::enclave::LengthEncoding::None,
                    ) {
                        Ok(value) => value,
                        Err(error) => {
                            capture_protocol_artifact(
                                &shared,
                                peer,
                                connection_id,
                                Some(session_id),
                                "sql_batch_parse_failure",
                                &message,
                                transport,
                            )
                            .await;
                            return Err(error);
                        }
                    };
                    (batch.sql, batch.headers)
                };
                let outcome = handle_sql(&mut session, &shared.config.personality, &sql);
                emit_request(
                    &shared,
                    &session,
                    "sql_batch",
                    outcome.classification,
                    Event::new("sql_batch", Some(connection_id), Some(session_id))
                        .field("raw_sql", &sql)
                        .field("stream_headers", &headers),
                );
                (outcome, false)
            }
            tds::RPC => {
                progress.enter("rpc_parse");
                shared.metrics.rpc_requests.fetch_add(1, Ordering::Relaxed);
                let rpc = match tds::rpc::parse_with_context(
                    &message.payload,
                    shared.config.limits.max_rpc_parameter_bytes,
                    matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x72),
                    matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x74),
                    tds::enclave::LengthEncoding::None,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        capture_protocol_artifact(
                            &shared,
                            peer,
                            connection_id,
                            Some(session_id),
                            "rpc_parse_failure",
                            &message,
                            transport,
                        )
                        .await;
                        return Err(error);
                    }
                };
                let outcome = handle_rpc(&mut session, &shared.config.personality, &rpc);
                emit_request(
                    &shared,
                    &session,
                    "rpc_request",
                    outcome.classification,
                    Event::new("rpc_request", Some(connection_id), Some(session_id))
                        .field("procedure", &rpc.procedure)
                        .field("options", rpc.options)
                        .field(
                            "enclave_package_bytes",
                            rpc.batches
                                .iter()
                                .filter_map(|batch| batch.enclave_package_bytes)
                                .sum::<usize>(),
                        )
                        .field("stream_headers", &rpc.headers)
                        .field("batch_count", rpc.batches.len())
                        .field(
                            "procedures",
                            rpc.batches
                                .iter()
                                .map(|batch| batch.procedure.as_str())
                                .collect::<Vec<_>>(),
                        )
                        .field("parameter_count", rpc.parameters.len())
                        .field(
                            "total_parameter_count",
                            rpc.batches
                                .iter()
                                .map(|batch| batch.parameters.len())
                                .sum::<usize>(),
                        )
                        .field(
                            "no_execute_batch_count",
                            rpc.batches.iter().filter(|batch| batch.no_execute).count(),
                        )
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
                            rpc.batches
                                .iter()
                                .flat_map(|batch| &batch.parameters)
                                .filter(|p| p.status & 1 != 0)
                                .count(),
                        )
                        .field(
                            "encrypted_parameter_count",
                            rpc.batches
                                .iter()
                                .flat_map(|batch| &batch.parameters)
                                .filter(|p| p.encryption.is_some())
                                .count(),
                        ),
                );
                (outcome, true)
            }
            tds::ATTENTION => {
                if !message.payload.is_empty() {
                    capture_protocol_artifact(
                        &shared,
                        peer,
                        connection_id,
                        Some(session_id),
                        "malformed_attention",
                        &message,
                        transport,
                    )
                    .await;
                    return Err(Error::Protocol(
                        "ATTENTION message contains unexpected payload".into(),
                    ));
                }
                shared.telemetry.emit(
                    Event::new("attention", Some(connection_id), Some(session_id))
                        .field("source_ip", peer.ip().to_string())
                        .field("login", &session.login_name),
                );
                (empty_outcome(), false)
            }
            tds::TRANSACTION_MANAGER => {
                progress.enter("transaction_manager_parse");
                let request = match tds::transaction::parse_with_context(
                    &message.payload,
                    matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x72),
                    matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x74),
                    tds::enclave::LengthEncoding::None,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        capture_protocol_artifact(
                            &shared,
                            peer,
                            connection_id,
                            Some(session_id),
                            "transaction_manager_parse_failure",
                            &message,
                            transport,
                        )
                        .await;
                        return Err(error);
                    }
                };
                if request.operation == "unknown" {
                    capture_protocol_artifact(
                        &shared,
                        peer,
                        connection_id,
                        Some(session_id),
                        "unknown_transaction_manager_request",
                        &message,
                        transport,
                    )
                    .await;
                }
                shared.telemetry.emit(
                    Event::new(
                        "transaction_manager_request",
                        Some(connection_id),
                        Some(session_id),
                    )
                    .field("source_ip", peer.ip().to_string())
                    .field("login", &session.login_name)
                    .field("request_type", request.request_type)
                    .field("operation", request.operation)
                    .field("payload_bytes", request.payload_bytes)
                    .field("isolation_level", request.isolation_level)
                    .field("transaction_name", request.name)
                    .field("begin_after", request.begin_after)
                    .field("enclave_package_bytes", request.enclave_package_bytes)
                    .field("stream_headers", &request.headers),
                );
                (empty_outcome(), false)
            }
            tds::BULK_LOAD => {
                progress.enter("bulk_load_parse");
                capture_protocol_artifact(
                    &shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    "bulk_load",
                    &message,
                    transport,
                )
                .await;
                let wide_metadata = matches!(
                    protocol,
                    tokens::Protocol::Tds7(version) if version >> 24 >= 0x72
                );
                let bulk = match tds::bulk::parse_message(
                    &message.payload,
                    shared.config.limits.max_rpc_parameter_bytes,
                    wide_metadata,
                    10,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        shared.telemetry.emit(
                            Event::new(
                                "bulk_load_parse_failure",
                                Some(connection_id),
                                Some(session_id),
                            )
                            .field("source_ip", peer.ip().to_string())
                            .field("login", &session.login_name)
                            .field("message_bytes", message.payload.len())
                            .field("error", error.to_string()),
                        );
                        return Err(error);
                    }
                };
                match bulk {
                    tds::bulk::BulkMessage::Bcp(bulk) => shared.telemetry.emit(
                        Event::new("bulk_load", Some(connection_id), Some(session_id))
                            .field("source_ip", peer.ip().to_string())
                            .field("login", &session.login_name)
                            .field("bulk_format", "bcp")
                            .field("message_bytes", message.payload.len())
                            .field("columns", &bulk.columns)
                            .field("row_count", bulk.row_count)
                            .field("sampled_rows", &bulk.sampled_rows)
                            .field("done_status", bulk.done_status)
                            .field("done_command", bulk.done_command)
                            .field("declared_done_rows", bulk.declared_done_rows),
                    ),
                    tds::bulk::BulkMessage::UpdateText { data_bytes } => shared.telemetry.emit(
                        Event::new("bulk_update_text", Some(connection_id), Some(session_id))
                            .field("source_ip", peer.ip().to_string())
                            .field("login", &session.login_name)
                            .field("bulk_format", "update_text_write_text")
                            .field("message_bytes", message.payload.len())
                            .field("data_bytes", data_bytes),
                    ),
                }
                (empty_outcome(), false)
            }
            tds::SSPI => {
                let token = tds::sspi::parse(&message.payload);
                shared.telemetry.emit(
                    Event::new("sspi_message", Some(connection_id), Some(session_id))
                        .field("source_ip", peer.ip().to_string())
                        .field("token_family", token.family)
                        .field("message_type", token.message_type)
                        .field("token_bytes", token.bytes)
                        .field("unexpected_state", true),
                );
                (empty_outcome(), false)
            }
            tds::FEDAUTH_TOKEN => {
                let token = tds::fedauth::parse(&message.payload, false)?;
                shared.telemetry.emit(
                    Event::new(
                        "federated_authentication_token",
                        Some(connection_id),
                        Some(session_id),
                    )
                    .field("source_ip", peer.ip().to_string())
                    .field("token_bytes", token.token.len())
                    .field("nonce_present", token.nonce.is_some())
                    .field("unexpected_state", true),
                );
                (empty_outcome(), false)
            }
            tds::TDS5_NORMAL => {
                capture_protocol_artifact(
                    &shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    "tds5_token_stream",
                    &message,
                    transport,
                )
                .await;
                let auth = tds::tds5::parse_authentication(
                    &message.payload,
                    shared.config.limits.max_payload_bytes,
                )?;
                shared.telemetry.emit(
                    Event::new(
                        "tds5_authentication_stream",
                        Some(connection_id),
                        Some(session_id),
                    )
                    .field("source_ip", peer.ip().to_string())
                    .field("login", &session.login_name)
                    .field("message_types", auth.message_types)
                    .field("parameter_formats", auth.parameter_formats)
                    .field("parameter_sets", auth.parameter_sets)
                    .field("parameter_value_bytes", auth.parameter_value_bytes)
                    .field("commands", &auth.commands)
                    .field("parameter_values", &auth.parameter_values)
                    .field("unknown_token", auth.unknown_token)
                    .field("trailing_bytes", auth.trailing_bytes),
                );
                let statements = auth
                    .commands
                    .iter()
                    .filter_map(|command| {
                        command.text.clone().or_else(|| {
                            command
                                .identifier
                                .as_ref()
                                .filter(|_| command.name == "dbrpc")
                                .map(|name| format!("EXEC {name}"))
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                let outcome = if statements.is_empty() {
                    empty_outcome()
                } else {
                    handle_sql(&mut session, &shared.config.personality, &statements)
                };
                (outcome, false)
            }
            other => {
                capture_protocol_artifact(
                    &shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    "unhandled_packet_type",
                    &message,
                    transport,
                )
                .await;
                shared.telemetry.emit(
                    Event::new(
                        "unhandled_tds_message",
                        Some(connection_id),
                        Some(session_id),
                    )
                    .field("source_ip", peer.ip().to_string())
                    .field("packet_type", other)
                    .field("packet_type_name", tds::packet_type_name(other))
                    .field("message_bytes", message.payload.len()),
                );
                (empty_outcome(), false)
            }
        };
        update_risk(progress, outcome.classification);
        shared.record_classification(outcome.classification);
        process_outcome(&shared, &session, &outcome).await;
        let response = tokens::response(
            protocol,
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

#[allow(clippy::too_many_arguments)]
async fn capture_protocol_artifact(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    reason: &str,
    message: &tds::packet::Message,
    transport: &str,
) {
    if !shared.config.payloads.enabled || tds::is_authentication_packet(message.packet_type) {
        return;
    }
    match shared.payloads.capture(&message.payload).await {
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
                Event::new("tds_message_artifact", Some(connection_id), session_id)
                    .field("source_ip", peer.ip().to_string())
                    .field("transport", transport)
                    .field("reason", reason)
                    .field("packet_type", message.packet_type)
                    .field(
                        "packet_type_name",
                        tds::packet_type_name(message.packet_type),
                    )
                    .field("sha256", captured.sha256)
                    .field("size", captured.size)
                    .field("storage_id", captured.storage_id),
            );
        }
        Ok(None) => {}
        Err(error) => shared.telemetry.emit(
            Event::new(
                "tds_message_artifact_error",
                Some(connection_id),
                session_id,
            )
            .field("source_ip", peer.ip().to_string())
            .field("reason", reason)
            .field("packet_type", message.packet_type)
            .field("error", error.to_string()),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn negotiate_integrated_authentication<S>(
    shared: &Shared,
    stream: &mut MessageCaptureIo<S>,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: u32,
    progress: &mut Progress,
    transport: &'static str,
    protocol: tokens::Protocol,
    initial_sspi: &[u8],
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let initial = tds::sspi::parse(initial_sspi);
    emit_sspi_message(
        shared,
        peer,
        connection_id,
        Some(session_id),
        transport,
        "login7",
        &initial,
    );
    if initial.message_type == Some(1) && matches!(initial.family, "ntlmssp" | "spnego_ntlmssp") {
        let challenge_id = Uuid::new_v4();
        let mut challenge = [0_u8; 8];
        challenge.copy_from_slice(&challenge_id.as_bytes()[..8]);
        let ntlm = tds::sspi::ntlm_challenge(&shared.config.personality.server_name, challenge);
        let response = tokens::sspi_challenge(&ntlm)?;
        progress.enter("sspi_challenge_write");
        write_message(stream, tds::TABULAR_RESULT, &response, 4096).await?;

        progress.enter("sspi_read");
        stream.clear_capture();
        let continuation = match timeout(
            shared.config.listener.login_timeout(),
            read_message(
                stream,
                shared.config.limits.max_packet_bytes,
                shared.config.limits.max_message_bytes,
            ),
        )
        .await
        {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => {
                capture_incomplete_ingress(
                    shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    transport,
                    stream.captured(),
                    stream.truncated,
                    error.kind(),
                )
                .await;
                return Err(error);
            }
            Err(_) => {
                capture_incomplete_ingress(
                    shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    transport,
                    stream.captured(),
                    stream.truncated,
                    "timeout",
                )
                .await;
                return Err(Error::Protocol("SSPI continuation timeout".into()));
            }
        };
        progress.observe_message(&continuation);
        observe_inbound_message(
            shared,
            peer,
            connection_id,
            Some(session_id),
            "sspi_read",
            transport,
            &continuation,
        )
        .await;
        progress.enter("sspi_parse");
        if continuation.packet_type != tds::SSPI {
            return Err(Error::Protocol(format!(
                "expected SSPI continuation, received {}",
                tds::packet_type_name(continuation.packet_type)
            )));
        }
        let token = tds::sspi::parse(&continuation.payload);
        emit_sspi_message(
            shared,
            peer,
            connection_id,
            Some(session_id),
            transport,
            "continuation",
            &token,
        );
    }

    progress.enter("login_response");
    let response = tokens::login_failure(protocol, &shared.config.personality.server_name, false)?;
    write_message(stream, tds::TABULAR_RESULT, &response, 4096).await?;
    Ok(progress.summary("integrated_authentication_rejected"))
}

fn emit_sspi_message(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    transport: &str,
    phase: &str,
    token: &tds::sspi::SspiToken,
) {
    let mut event = Event::new("sspi_message", Some(connection_id), session_id)
        .field("source_ip", peer.ip().to_string())
        .field("transport", transport)
        .field("phase", phase)
        .field("token_family", token.family)
        .field("message_type", token.message_type)
        .field("token_bytes", token.bytes)
        .field("parse_warnings", &token.parse_warnings);
    if let Some(ntlm) = &token.ntlm {
        event = event
            .field("domain", &ntlm.domain)
            .field("username", &ntlm.username)
            .field("workstation", &ntlm.workstation)
            .field("lm_response_bytes", ntlm.lm_response_bytes)
            .field("nt_response_bytes", ntlm.nt_response_bytes)
            .field("nt_response_variant", ntlm.nt_response_variant)
            .field(
                "encrypted_session_key_bytes",
                ntlm.encrypted_session_key_bytes,
            )
            .field("negotiate_flags", ntlm.negotiate_flags);
    }
    shared.telemetry.emit(event);
}

#[allow(clippy::too_many_arguments)]
async fn capture_incomplete_ingress(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    transport: &str,
    wire_bytes: &[u8],
    capture_truncated: bool,
    error_kind: &str,
) {
    capture_incomplete_authentication_message(
        shared,
        peer,
        connection_id,
        session_id,
        transport,
        wire_bytes,
        capture_truncated,
        error_kind,
    )
    .await;
    let Some(&first_byte) = wire_bytes.first() else {
        return;
    };
    if tds::is_authentication_packet(first_byte) || !shared.config.payloads.enabled {
        return;
    }
    let smp_frames = if first_byte == 0x53 {
        match tds::smp::parse(wire_bytes, shared.config.limits.max_message_bytes) {
            Ok(frames) => Some(frames),
            Err(error) => {
                shared.telemetry.emit(
                    Event::new("smp_parse_failure", Some(connection_id), session_id)
                        .field("source_ip", peer.ip().to_string())
                        .field("transport", transport)
                        .field("wire_bytes", wire_bytes.len())
                        .field("error", error.to_string()),
                );
                None
            }
        }
    } else {
        None
    };
    match shared.payloads.capture(wire_bytes).await {
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
                    "incomplete_tds_message_capture",
                    Some(connection_id),
                    session_id,
                )
                .field("source_ip", peer.ip().to_string())
                .field("transport", transport)
                .field("first_byte", first_byte)
                .field("smp_frames", smp_frames)
                .field("error_kind", error_kind)
                .field("capture_truncated", capture_truncated)
                .field("sha256", captured.sha256)
                .field("size", captured.size)
                .field("storage_id", captured.storage_id),
            );
        }
        Ok(None) => {}
        Err(error) => shared.telemetry.emit(
            Event::new(
                "tds_message_artifact_error",
                Some(connection_id),
                session_id,
            )
            .field("source_ip", peer.ip().to_string())
            .field("reason", "incomplete_ingress")
            .field("first_byte", first_byte)
            .field("error", error.to_string()),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn capture_incomplete_authentication_message(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    transport: &str,
    wire_bytes: &[u8],
    capture_truncated: bool,
    error_kind: &str,
) {
    let Some(&packet_type) = wire_bytes.first() else {
        return;
    };
    if !tds::is_authentication_packet(packet_type)
        || !shared.config.payloads.captures_login_messages()
    {
        return;
    }
    match shared.payloads.capture(wire_bytes).await {
        Ok(Some(captured)) => shared.telemetry.emit(
            Event::new(
                "incomplete_authentication_message_capture",
                Some(connection_id),
                session_id,
            )
            .field("source_ip", peer.ip().to_string())
            .field("transport", transport)
            .field("packet_type", packet_type)
            .field("packet_type_name", tds::packet_type_name(packet_type))
            .field("wire_format", "tds_packets_with_headers")
            .field("error_kind", error_kind)
            .field("capture_truncated", capture_truncated)
            .field("sha256", captured.sha256)
            .field("size", captured.size)
            .field("storage_id", captured.storage_id),
        ),
        Ok(None) => {}
        Err(error) => shared.telemetry.emit(
            Event::new(
                "authentication_message_capture_error",
                Some(connection_id),
                session_id,
            )
            .field("source_ip", peer.ip().to_string())
            .field("packet_type", packet_type)
            .field("incomplete", true)
            .field("error", error.to_string()),
        ),
    }
}

fn empty_outcome() -> Outcome {
    Outcome {
        classification: Classification::Unknown,
        risk_tags: vec![],
        result_sets: vec![],
        messages: vec![],
        error: None,
        state_changes: vec![],
        payload_candidate: None,
        honey_object: None,
    }
}

async fn observe_inbound_message(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    protocol_stage: &str,
    transport: &str,
    message: &tds::packet::Message,
) {
    let packet_type_name = tds::packet_type_name(message.packet_type);
    shared.telemetry.emit(
        Event::new("tds_message", Some(connection_id), session_id)
            .field("source_ip", peer.ip().to_string())
            .field("source_port", peer.port())
            .field("protocol_stage", protocol_stage)
            .field("transport", transport)
            .field("packet_type", message.packet_type)
            .field("packet_type_name", packet_type_name)
            .field("packet_count", message.packet_count)
            .field("first_packet_status", message.first_status)
            .field("first_packet_id", message.first_packet_id)
            .field("message_bytes", message.payload.len())
            .field(
                "authentication_message",
                tds::is_authentication_packet(message.packet_type),
            ),
    );
    if !tds::is_authentication_packet(message.packet_type)
        || !shared.config.payloads.captures_login_messages()
    {
        return;
    }
    match shared.payloads.capture(&message.payload).await {
        Ok(Some(captured)) => {
            let login_message = matches!(message.packet_type, tds::LOGIN | tds::LOGIN7);
            shared.telemetry.emit(
                Event::new(
                    if login_message {
                        "login_message_capture"
                    } else {
                        "authentication_message_capture"
                    },
                    Some(connection_id),
                    session_id,
                )
                .field("source_ip", peer.ip().to_string())
                .field("transport", transport)
                .field("packet_type", message.packet_type)
                .field("packet_type_name", packet_type_name)
                .field(
                    "login_format",
                    login_message.then_some(if message.packet_type == tds::LOGIN {
                        "tds42_login"
                    } else {
                        "login7"
                    }),
                )
                .field("sha256", captured.sha256)
                .field("size", captured.size)
                .field("storage_id", captured.storage_id),
            );
        }
        Ok(None) => {}
        Err(error) => shared.telemetry.emit(
            Event::new(
                "authentication_message_capture_error",
                Some(connection_id),
                session_id,
            )
            .field("source_ip", peer.ip().to_string())
            .field("packet_type", message.packet_type)
            .field("error", error.to_string()),
        ),
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

#[cfg(test)]
mod tests {
    use super::{instance_matches, negotiate};
    use crate::{config::TlsMode, tds::prelogin::Encryption};

    #[test]
    fn instance_matching_follows_prelogin_rules() {
        assert!(instance_matches(None, "MSSQLSERVER"));
        assert!(instance_matches(Some(""), "MSSQLSERVER"));
        assert!(instance_matches(Some("mssqlserver"), "MSSQLSERVER"));
        assert!(!instance_matches(Some("REPORTING"), "MSSQLSERVER"));
    }

    #[test]
    fn required_tls_uses_the_specified_response_matrix() {
        assert_eq!(
            negotiate(TlsMode::Required, Encryption::Off),
            (Encryption::Required, true)
        );
        assert_eq!(
            negotiate(TlsMode::Required, Encryption::On),
            (Encryption::On, true)
        );
        assert_eq!(
            negotiate(TlsMode::Required, Encryption::Required),
            (Encryption::On, true)
        );
        assert_eq!(
            negotiate(TlsMode::Required, Encryption::NotSupported),
            (Encryption::Required, false)
        );
    }
}
