use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

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

#[derive(serde::Serialize)]
struct Tds5EncryptedPacketShape {
    packet_id: u8,
    status: u8,
    body_bytes: usize,
    ciphertext_sha256: String,
    first_block: String,
    last_block: String,
    body_block_aligned: bool,
    body_after_iv_prefix_bytes: Option<usize>,
    body_after_iv_prefix_block_aligned: bool,
}

#[derive(Clone, Copy)]
enum Tds5SecureLoginProtocol {
    ProprietaryV1,
    ExtendedV2,
    ExtendedPlusV3,
    ExtendedPlusV4,
}

impl Tds5SecureLoginProtocol {
    fn challenge_message_type(self) -> u16 {
        match self {
            Self::ProprietaryV1 => 1,
            Self::ExtendedV2 => 14,
            Self::ExtendedPlusV3 => 30,
            Self::ExtendedPlusV4 => 35,
        }
    }

    fn response_message_type(self) -> u16 {
        match self {
            Self::ProprietaryV1 => 2,
            Self::ExtendedV2 => 15,
            Self::ExtendedPlusV3 | Self::ExtendedPlusV4 => 31,
        }
    }

    fn version(self) -> u8 {
        match self {
            Self::ProprietaryV1 => 1,
            Self::ExtendedV2 => 2,
            Self::ExtendedPlusV3 => 3,
            Self::ExtendedPlusV4 => 4,
        }
    }

    fn nonce_bearing(self) -> bool {
        matches!(self, Self::ExtendedPlusV3 | Self::ExtendedPlusV4)
    }

    fn rsa(self) -> bool {
        !matches!(self, Self::ProprietaryV1)
    }
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

    fn into_inner(self) -> S {
        self.inner
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
    if first[0] == 0x53 {
        shared.telemetry.emit(
            Event::new("direct_smp_candidate", Some(connection_id), None)
                .field("source_ip", peer.ip().to_string())
                .field("source_port", peer.port())
                .field("transport", "smp_unnegotiated"),
        );
        return login_and_serve(
            shared,
            stream,
            peer,
            connection_id,
            &mut progress,
            "smp_unnegotiated",
            None,
        )
        .await
        .map_err(|error| progress.failure(error));
    }
    if is_initial_authentication_candidate(first[0]) {
        let transport = match first[0] {
            tds::LOGIN => "tds42_direct",
            tds::LOGIN7 => "tds7_direct",
            tds::SSPI => "sspi_direct",
            tds::FEDAUTH_TOKEN => "fedauth_direct",
            tds::TDS5_NORMAL => "tds50_authentication_direct",
            tds::TDS5_COMMAND_SEQUENCE_LOGIN => "tds50_command_sequence_login_direct",
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
            .field("packet_type", first[0])
            .field(
                "legacy_packet_type_candidate",
                tds::legacy_packet_type_name(first[0]),
            )
            .field(
                "packet_type_ambiguous_before_negotiation",
                matches!(
                    first[0],
                    tds::FEDAUTH_TOKEN | tds::LOGIN7 | tds::SSPI | tds::TDS5_COMMAND_SEQUENCE_LOGIN
                ),
            ),
        );
        return login_and_serve(
            shared,
            stream,
            peer,
            connection_id,
            &mut progress,
            transport,
            None,
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
    // In TDS 8.0 PRELOGIN follows TLS, so certificate-capable clients can be
    // observed only if the initial handshake offers optional client auth.
    let acceptor = shared.client_cert_tls.as_ref().ok_or_else(|| {
        Error::Protocol("TDS 8.0 ClientHello received while TLS is disabled".into())
    })?;
    let stream = timeout(
        shared.config.listener.login_timeout(),
        tls::handshake_raw(stream, acceptor),
    )
    .await
    .map_err(|_| Error::Tls("TDS 8.0 handshake timeout".into()))??;
    emit_tls_negotiated(&shared, connection_id, "tds8", stream.get_ref().1);
    let mut stream = MessageCaptureIo::new(stream, shared.config.limits.max_payload_bytes);

    progress.enter("prelogin8_read");
    let prelogin_result = timeout(
        shared.config.listener.login_timeout(),
        read_message(
            &mut stream,
            shared.config.limits.max_packet_bytes,
            shared.config.limits.max_message_bytes,
        ),
    )
    .await;
    let prelogin_message = match prelogin_result {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => {
            capture_incomplete_ingress(
                &shared,
                peer,
                connection_id,
                None,
                "tds8",
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
                "tds8",
                stream.captured(),
                stream.truncated,
                "timeout",
            )
            .await;
            return Err(Error::Protocol("TDS 8.0 PRELOGIN timeout".into()));
        }
    };
    stream.clear_capture();
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
        if is_initial_authentication_candidate(prelogin_message.packet_type) {
            shared.telemetry.emit(
                Event::new(
                    "authentication_before_tds8_prelogin",
                    Some(connection_id),
                    None,
                )
                .field("source_ip", peer.ip().to_string())
                .field("source_port", peer.port())
                .field("transport", "tds8")
                .field("packet_type", prelogin_message.packet_type)
                .field(
                    "packet_type_name",
                    tds::packet_type_name(prelogin_message.packet_type),
                ),
            );
            return login_and_serve_with_initial_message(
                shared,
                stream.into_inner(),
                peer,
                connection_id,
                progress,
                "tds8",
                None,
                prelogin_message,
            )
            .await;
        }
        capture_protocol_artifact(
            &shared,
            peer,
            connection_id,
            None,
            "unexpected_initial_message_after_tds8_tls",
            &prelogin_message,
            "tds8",
        )
        .await;
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
    let response_nonce = prelogin.nonce.map(|_| {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    });
    let response = tds::prelogin::encode_response_options(
        Encryption::Required,
        instance_matches,
        response_nonce,
        prelogin.client_certificate,
    );
    progress.enter("prelogin8_response");
    write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;
    login_and_serve(
        shared,
        stream.into_inner(),
        peer,
        connection_id,
        progress,
        "tds8",
        response_nonce,
    )
    .await
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
        capture_protocol_artifact(
            &shared,
            peer,
            connection_id,
            None,
            "unexpected_initial_message",
            &prelogin_message,
            "tds7",
        )
        .await;
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
    let (response_encryption, mut use_tls) =
        negotiate(shared.config.tls.mode, requested_encryption);
    if prelogin.client_certificate && shared.config.tls.mode != TlsMode::Disabled {
        use_tls = true;
    }
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
    let response_nonce = prelogin.nonce.map(|_| {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    });
    let response = tds::prelogin::encode_response_options(
        response_encryption,
        instance_matches,
        response_nonce,
        prelogin.client_certificate,
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
            return login_and_serve(
                shared,
                stream,
                peer,
                connection_id,
                progress,
                transport,
                response_nonce,
            )
            .await;
        }
        let acceptor = if prelogin.client_certificate {
            shared.client_cert_tls.as_ref()
        } else {
            shared.tls.as_ref()
        }
        .ok_or_else(|| Error::Config("TLS negotiated without an acceptor".into()))?;
        let tls = timeout(
            shared.config.listener.login_timeout(),
            tls::handshake(stream, acceptor),
        )
        .await
        .map_err(|_| Error::Tls("handshake timeout".into()))??;
        let (_, connection) = tls.get_ref();
        emit_tls_negotiated(&shared, connection_id, "tds7", connection);
        if response_encryption == Encryption::Off {
            progress.enter("tls_login_only");
            let stream = timeout(
                shared.config.listener.login_timeout(),
                tls::finish_login_only(tls, shared.config.limits.max_packet_bytes),
            )
            .await
            .map_err(|_| Error::Tls("login-only packet timeout".into()))??;
            shared.telemetry.emit(
                Event::new("tls_login_only", Some(connection_id), None)
                    .field("source_ip", peer.ip().to_string())
                    .field("source_port", peer.port())
                    .field("transport", "tds7_login_only_tls"),
            );
            login_and_serve(
                shared,
                stream,
                peer,
                connection_id,
                progress,
                "tds7_login_only_tls",
                response_nonce,
            )
            .await
        } else {
            login_and_serve(
                shared,
                tls,
                peer,
                connection_id,
                progress,
                "tds7",
                response_nonce,
            )
            .await
        }
    } else {
        login_and_serve(
            shared,
            stream,
            peer,
            connection_id,
            progress,
            "tds7",
            response_nonce,
        )
        .await
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
            .field("packets", &message.packets)
            .field("message_bytes", message.payload.len())
            .field("tds_version", prelogin.version.map(hex_version))
            .field(
                "encryption_request",
                prelogin
                    .encryption
                    .map(|value| format!("{value:?}").to_lowercase()),
            )
            .field("encryption_request_raw", prelogin.encryption_raw)
            .field("client_certificate_requested", prelogin.client_certificate)
            .field("encryption_extension", prelogin.encryption_extension)
            .field(
                "encryption_response",
                format!("{response_encryption:?}").to_lowercase(),
            )
            .field("mars_requested", prelogin.mars)
            .field("mars_raw", prelogin.mars_raw)
            .field("trace_id_present", prelogin.trace_id.is_some())
            .field("fedauth_required", prelogin.fedauth_required)
            .field("fedauth_required_raw", prelogin.fedauth_required_raw)
            .field("nonce_present", prelogin.nonce.is_some())
            .field("option_order", &prelogin.option_order)
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
    let certificates = connection.peer_certificates().unwrap_or_default();
    let certificate_sha256 = certificates
        .iter()
        .map(|certificate| {
            Sha256::digest(certificate.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let certificate_sizes = certificates
        .iter()
        .map(|certificate| certificate.as_ref().len())
        .collect::<Vec<_>>();
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
            )
            .field("client_certificate_count", certificates.len())
            .field("client_certificate_sha256", certificate_sha256)
            .field("client_certificate_sizes", certificate_sizes),
    );
}

fn negotiate(mode: TlsMode, client: Encryption) -> (Encryption, bool) {
    match mode {
        TlsMode::Disabled => (Encryption::NotSupported, false),
        TlsMode::Optional => match client {
            Encryption::On | Encryption::Required => (Encryption::On, true),
            Encryption::NotSupported => (Encryption::NotSupported, false),
            // ENCRYPT_OFF means login-only TLS, not plaintext LOGIN7.
            Encryption::Off => (Encryption::Off, true),
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
    server_nonce: Option<[u8; 32]>,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    login_and_serve_inner(
        shared,
        stream,
        peer,
        connection_id,
        progress,
        transport,
        server_nonce,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn login_and_serve_with_initial_message<S>(
    shared: Arc<Shared>,
    stream: S,
    peer: SocketAddr,
    connection_id: Uuid,
    progress: &mut Progress,
    transport: &'static str,
    server_nonce: Option<[u8; 32]>,
    initial_message: tds::packet::Message,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    login_and_serve_inner(
        shared,
        stream,
        peer,
        connection_id,
        progress,
        transport,
        server_nonce,
        Some(initial_message),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn login_and_serve_inner<S>(
    shared: Arc<Shared>,
    stream: S,
    peer: SocketAddr,
    connection_id: Uuid,
    progress: &mut Progress,
    transport: &'static str,
    server_nonce: Option<[u8; 32]>,
    initial_message: Option<tds::packet::Message>,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = MessageCaptureIo::new(stream, shared.config.limits.max_payload_bytes);
    let login_message = if let Some(message) = initial_message {
        message
    } else {
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
        let message = match login_result {
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
        progress.observe_message(&message);
        observe_inbound_message(
            &shared,
            peer,
            connection_id,
            None,
            "login_read",
            transport,
            &message,
        )
        .await;
        message
    };
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
        tds::LOGIN => match tds::login::parse_for_telemetry(&login_message.payload) {
            Ok(login) => login,
            Err(error) => {
                emit_login_parse_failure(
                    &shared,
                    peer,
                    connection_id,
                    transport,
                    &login_message,
                    &error,
                );
                return Err(error);
            }
        },
        tds::LOGIN7 => match tds::login7::parse_for_telemetry(&login_message.payload) {
            Ok(login) => login,
            Err(error) => {
                emit_login_parse_failure(
                    &shared,
                    peer,
                    connection_id,
                    transport,
                    &login_message,
                    &error,
                );
                return Err(error);
            }
        },
        tds::SSPI => {
            let token = tds::sspi::parse(&login_message.payload);
            emit_sspi_message(
                &shared,
                peer,
                connection_id,
                None,
                transport,
                "before_login7",
                &token,
                None,
            );
            return Err(Error::Protocol("SSPI message arrived before LOGIN7".into()));
        }
        tds::FEDAUTH_TOKEN => {
            capture_protocol_artifact(
                &shared,
                peer,
                connection_id,
                None,
                "federated_authentication_before_login",
                &login_message,
                transport,
            )
            .await;
            let token = tds::fedauth::parse_for_telemetry(&login_message.payload, false);
            let mut event = Event::new("federated_authentication_token", Some(connection_id), None)
                .field("source_ip", peer.ip().to_string())
                .field("transport", transport)
                .field("token_bytes", token.token.len())
                .field("nonce_present", token.nonce.is_some())
                .field("unclassified_bytes", token.unclassified.len())
                .field("recovery", token.recovery)
                .field("parse_warnings", token.parse_warnings)
                .field("unexpected_state", true);
            if shared.config.telemetry.capture_login_passwords {
                event = event
                    .field("token", authentication_material(token.token))
                    .field(
                        "unclassified_material",
                        authentication_material(token.unclassified),
                    );
            }
            shared.telemetry.emit(event);
            return Err(Error::Protocol(
                "federated authentication token arrived before LOGIN7".into(),
            ));
        }
        tds::TDS5_NORMAL | tds::TDS5_COMMAND_SEQUENCE_LOGIN => {
            let auth = tds::tds5::parse_for_telemetry(
                &login_message.payload,
                shared.config.limits.max_payload_bytes,
            );
            let parameter_material = shared
                .config
                .telemetry
                .capture_login_passwords
                .then(|| tds5_parameter_material(&auth));
            if !is_authentication_packet_for_transport(login_message.packet_type, transport) {
                capture_authentication_message(
                    &shared,
                    peer,
                    connection_id,
                    None,
                    "tds5_authentication_before_login",
                    &login_message,
                    transport,
                )
                .await;
            }
            shared.telemetry.emit(
                Event::new("tds5_authentication_stream", Some(connection_id), None)
                    .field("source_ip", peer.ip().to_string())
                    .field("transport", transport)
                    .field("message_types", auth.message_types)
                    .field("tokens", auth.tokens)
                    .field("unparsed_regions", auth.unparsed_regions)
                    .field("parse_warnings", auth.parse_warnings)
                    .field("parameter_formats", auth.parameter_formats)
                    .field("parameter_sets", auth.parameter_sets)
                    .field("parameter_value_bytes", auth.parameter_value_bytes)
                    .field("row_formats", auth.row_formats)
                    .field("rows", auth.rows)
                    .field("alternate_formats", auth.alternate_formats)
                    .field("alternate_rows", auth.alternate_rows)
                    .field("row_value_bytes", auth.row_value_bytes)
                    .field("row_values", auth.row_values)
                    .field(
                        "remote_password_count",
                        auth.encrypted_remote_passwords.len(),
                    )
                    .field(
                        "encrypted_symmetric_key_bytes",
                        auth.encrypted_symmetric_key_bytes,
                    )
                    .field("commands", &auth.commands)
                    .field("parameter_values", &auth.parameter_values)
                    .field("parameter_material", parameter_material)
                    .field("unexpected_state", true),
            );
            return Err(Error::Protocol(
                "TDS 5 authentication stream arrived before LOGIN".into(),
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
        match login.tds_version >> 16 {
            0x0500..=0x05ff => tokens::Protocol::Tds50,
            0x0406 => tokens::Protocol::Tds46,
            _ => tokens::Protocol::Tds42,
        }
    } else {
        tokens::Protocol::Tds7(negotiated_tds7_version(
            login.tds_version,
            transport == "tds8",
        ))
    };
    let transport = match (transport, protocol) {
        ("tds42_direct", tokens::Protocol::Tds46) => "tds46_direct",
        ("tds42_direct", tokens::Protocol::Tds50) => "tds50_direct",
        ("tds42_after_prelogin", tokens::Protocol::Tds46) => "tds46_after_prelogin",
        ("tds42_after_prelogin", tokens::Protocol::Tds50) => "tds50_after_prelogin",
        (value, _) => value,
    };
    let login_format = match protocol {
        tokens::Protocol::Tds42 => "tds42_login",
        tokens::Protocol::Tds46 => "tds46_login",
        tokens::Protocol::Tds50 => "tds50_login",
        tokens::Protocol::Tds7(_) => "login7",
    };
    let federated_feature = login
        .features
        .iter()
        .find(|feature| feature.id == 0x02)
        .cloned();
    let partial_federated_feature = login
        .feature_extension_remainder
        .as_ref()
        .filter(|remainder| remainder.feature_id == Some(0x02))
        .cloned();
    let federated_authentication_present =
        federated_feature.is_some() || partial_federated_feature.is_some();
    let fedauth_nonce_matches = federated_feature.as_ref().and_then(|feature| {
        feature
            .fedauth_nonce
            .map(|client_nonce| Some(client_nonce) == server_nonce)
    });
    let enclave_capable = login
        .features
        .iter()
        .find(|feature| feature.id == 0x04)
        .and_then(|feature| feature.version)
        .is_some_and(|version| version >= 2);
    let column_encryption_capable = login
        .features
        .iter()
        .any(|feature| feature.id == 0x04 && feature.version.is_some());
    let feature_acks = supported_feature_acks(&login.features);
    let session_id = shared.sessions.fetch_add(1, Ordering::Relaxed);
    progress.session_id = Some(session_id);
    shared
        .metrics
        .login_attempts
        .fetch_add(1, Ordering::Relaxed);
    let tds5_security_flags =
        (protocol == tokens::Protocol::Tds50).then_some(login.legacy_security_flags.unwrap_or(0));
    let tds5_security_modes = tds5_security_flags
        .map(tds::tds5::login_security_modes)
        .unwrap_or_default();
    let tds5_security_unknown_bits = tds5_security_flags.map(|flags| flags & 0x40);
    let tds5_secure_password_requested =
        tds5_security_flags.is_some_and(|flags| flags & (0x01 | 0x20 | 0x80) != 0);
    let tds5_challenge_response_requested =
        tds5_security_flags.is_some_and(|flags| flags & 0x02 != 0);
    let tds5_security_labels_requested = tds5_security_flags.is_some_and(|flags| flags & 0x04 != 0);
    let tds5_application_security_requested =
        tds5_security_flags.is_some_and(|flags| flags & 0x08 != 0);
    let tds5_secure_session_requested = tds5_security_flags.is_some_and(|flags| flags & 0x10 != 0);
    let tds5_external_security_requested =
        tds5_security_flags.is_some_and(requests_tds5_external_security);
    let tds5_command_encryption = login
        .legacy_capabilities
        .as_ref()
        .is_some_and(tds::tds5::Capabilities::supports_command_encryption);
    let tds5_secure_password_protocol = tds5_security_flags.and_then(|flags| {
        if flags & 0x80 != 0 {
            Some(if tds5_command_encryption {
                "rsa_epep_v4"
            } else {
                "rsa_epep_v3"
            })
        } else if flags & 0x20 != 0 {
            Some("rsa_extended_v2")
        } else if flags & 0x01 != 0 {
            Some("proprietary_v1_ciphertext_capture")
        } else {
            None
        }
    });
    let mut tds5_secure_password_recovered = false;
    let mut tds5_symmetric_key = None;
    let tds5_secure_login_protocol = tds5_security_flags.and_then(|flags| {
        if flags & 0x80 != 0 {
            Some(if tds5_command_encryption {
                Tds5SecureLoginProtocol::ExtendedPlusV4
            } else {
                Tds5SecureLoginProtocol::ExtendedPlusV3
            })
        } else if flags & 0x20 != 0 {
            Some(Tds5SecureLoginProtocol::ExtendedV2)
        } else if flags & 0x01 != 0 {
            Some(Tds5SecureLoginProtocol::ProprietaryV1)
        } else {
            None
        }
    });
    if tds5_secure_password_requested
        || tds5_external_security_requested
        || login.legacy_authentication.is_some()
    {
        let embedded_parameter_material = shared
            .config
            .telemetry
            .capture_login_passwords
            .then(|| {
                login
                    .legacy_authentication
                    .as_ref()
                    .map(tds5_parameter_material)
            })
            .flatten();
        let mut event = Event::new(
            "tds5_login_security_request",
            Some(connection_id),
            Some(session_id),
        )
        .field("source_ip", peer.ip().to_string())
        .field("transport", transport)
        .field("username", &login.username)
        .field("client_hostname", &login.client_hostname)
        .field("application_name", &login.application_name)
        .field("client_library", &login.client_library)
        .field("legacy_security_flags", tds5_security_flags)
        .field("tds5_security_modes", &tds5_security_modes)
        .field(
            "tds5_secure_password_protocol",
            tds5_secure_password_protocol,
        )
        .field(
            "tds5_external_security_requested",
            tds5_external_security_requested,
        )
        .field("parse_warnings", &login.parse_warnings)
        .field("legacy_authentication", &login.legacy_authentication)
        .field("embedded_parameter_material", embedded_parameter_material);
        if shared.config.telemetry.capture_login_passwords {
            event = event.field("initial_password", login.password_for_capture());
        }
        shared.telemetry.emit(event);
    }
    if let Some(secure_login_protocol) = tds5_secure_login_protocol {
        let secure_login = negotiate_tds5_secure_password(
            &shared,
            &mut stream,
            peer,
            connection_id,
            session_id,
            progress,
            transport,
            secure_login_protocol,
        )
        .await?;
        if let Some(password) = secure_login.password {
            login.set_recovered_password(password);
            tds5_secure_password_recovered = true;
        }
        tds5_symmetric_key = secure_login.symmetric_key;
    }
    let source_login_attempt = (!login.integrated_security && !federated_authentication_present)
        .then(|| shared.record_login_attempt(peer.ip()));
    progress.enter("authentication");
    let bypass_threshold = shared.config.personality.accept_source_after_attempts;
    let source_auth_bypass = matches!(
        (bypass_threshold, source_login_attempt),
        (Some(threshold), Some(attempt)) if attempt > threshold
    );
    let login_structurally_valid = login.parse_warnings.is_empty();
    let decision = if !login_structurally_valid
        || login.integrated_security
        || federated_authentication_present
        || (tds5_secure_password_requested && !tds5_secure_password_recovered)
        || tds5_external_security_requested
    {
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
        .field("login_format", login_format)
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
        .field(
            "tds5_secure_password_requested",
            tds5_secure_password_requested,
        )
        .field("tds5_security_modes", &tds5_security_modes)
        .field("tds5_security_unknown_bits", tds5_security_unknown_bits)
        .field(
            "tds5_challenge_response_requested",
            tds5_challenge_response_requested,
        )
        .field(
            "tds5_security_labels_requested",
            tds5_security_labels_requested,
        )
        .field(
            "tds5_application_security_requested",
            tds5_application_security_requested,
        )
        .field(
            "tds5_secure_session_requested",
            tds5_secure_session_requested,
        )
        .field(
            "tds5_external_security_requested",
            tds5_external_security_requested,
        )
        .field(
            "tds5_secure_password_protocol",
            tds5_secure_password_protocol,
        )
        .field(
            "tds5_secure_password_recovered",
            tds5_secure_password_recovered,
        )
        .field("tds5_command_encryption", tds5_command_encryption)
        .field("federated_authentication", federated_authentication_present)
        .field("fedauth_partial", partial_federated_feature.is_some())
        .field(
            "fedauth_library",
            federated_feature
                .as_ref()
                .and_then(|feature| feature.fedauth_library)
                .or_else(|| {
                    partial_federated_feature
                        .as_ref()
                        .and_then(|remainder| remainder.first_data_byte)
                        .map(|options| options & 0x7f)
                }),
        )
        .field(
            "fedauth_echo",
            federated_feature
                .as_ref()
                .and_then(|feature| feature.fedauth_echo)
                .or_else(|| {
                    partial_federated_feature
                        .as_ref()
                        .and_then(|remainder| remainder.first_data_byte)
                        .map(|options| options & 0x80 != 0)
                }),
        )
        .field(
            "fedauth_workflow",
            federated_feature
                .as_ref()
                .and_then(|feature| feature.fedauth_workflow),
        )
        .field("fedauth_nonce_matches", fedauth_nonce_matches)
        .field("sspi_bytes", login.sspi_bytes)
        .field("sspi_token_family", login.sspi_token_family)
        .field("feature_extensions", &login.features)
        .field(
            "feature_extension_remainder",
            &login.feature_extension_remainder,
        )
        .field("parse_warnings", &login.parse_warnings)
        .field("structurally_valid", login_structurally_valid)
        .field("legacy_security_flags", login.legacy_security_flags)
        .field("legacy_login", &login.legacy_login)
        .field("legacy_capabilities_bytes", login.legacy_capabilities_bytes)
        .field("legacy_capabilities", &login.legacy_capabilities)
        .field(
            "legacy_authentication_bytes",
            login.legacy_authentication_bytes,
        )
        .field("legacy_authentication", &login.legacy_authentication)
        .field("accepted", accepted)
        .field("source_login_attempt_number", source_login_attempt)
        .field("source_auth_bypass_threshold", bypass_threshold)
        .field("source_auth_bypass", source_auth_bypass)
        .field(
            "honey_identity",
            shared.config.personality.is_honey_login(&login.username),
        );
    if shared.config.telemetry.capture_login_passwords {
        let legacy_authentication_material = login
            .legacy_authentication
            .as_ref()
            .map(tds5_parameter_material);
        let feature_extension_material = login
            .features
            .iter()
            .map(|feature| (feature.id, authentication_material(&feature.raw_data)))
            .collect::<Vec<_>>();
        let feature_extension_remainder_material =
            (!login.feature_extension_remainder_raw.is_empty())
                .then(|| authentication_material(&login.feature_extension_remainder_raw));
        login_event = login_event
            .field("password", login.password_for_capture())
            .field("new_password", login.new_password_for_capture())
            .field(
                "legacy_authentication_material",
                legacy_authentication_material,
            )
            .field(
                "federated_authentication_token",
                federated_feature
                    .as_ref()
                    .and_then(|feature| feature.fedauth_token.as_deref())
                    .map(authentication_material),
            )
            .field("feature_extension_material", feature_extension_material);
        login_event = login_event.field(
            "feature_extension_remainder_material",
            feature_extension_remainder_material,
        );
    }
    shared.telemetry.emit(login_event);

    if let Some(feature) = federated_feature {
        login.discard_password();
        return negotiate_federated_authentication(
            &shared,
            &mut stream,
            peer,
            connection_id,
            session_id,
            progress,
            transport,
            protocol,
            &feature,
            server_nonce,
        )
        .await;
    }

    if login.integrated_security && protocol == tokens::Protocol::Tds50 {
        login.discard_password();
        progress.enter("login_response");
        let response =
            tokens::login_failure(protocol, &shared.config.personality.server_name, false)?;
        write_message(&mut stream, tds::TABULAR_RESULT, &response, 4096).await?;
        return Ok(progress.summary("tds5_secure_session_rejected"));
    }

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
        &feature_acks,
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
        let symmetrically_encrypted_packets = message
            .packets
            .iter()
            .filter(|packet| packet.has_symmetric_encryption())
            .count();
        if protocol == tokens::Protocol::Tds50 && symmetrically_encrypted_packets > 0 {
            let encrypted_packet_shapes = message
                .packets
                .iter()
                .filter(|packet| packet.has_symmetric_encryption())
                .map(|packet| {
                    let end = packet
                        .body_offset
                        .checked_add(packet.body_bytes)
                        .expect("packet descriptors are constructed from the message payload");
                    let body = &message.payload[packet.body_offset..end];
                    let after_iv = packet.body_bytes.checked_sub(16);
                    Tds5EncryptedPacketShape {
                        packet_id: packet.packet_id,
                        status: packet.status,
                        body_bytes: packet.body_bytes,
                        ciphertext_sha256: hex_bytes(&Sha256::digest(body)),
                        first_block: hex_bytes(&body[..body.len().min(16)]),
                        last_block: hex_bytes(&body[body.len().saturating_sub(16)..]),
                        body_block_aligned: packet.body_bytes % 16 == 0,
                        body_after_iv_prefix_bytes: after_iv,
                        body_after_iv_prefix_block_aligned: after_iv
                            .is_some_and(|bytes| bytes > 0 && bytes % 16 == 0),
                    }
                })
                .collect::<Vec<_>>();
            capture_protocol_artifact(
                &shared,
                peer,
                connection_id,
                Some(session.session_id),
                "tds5_symmetrically_encrypted_command",
                &message,
                transport,
            )
            .await;
            shared.telemetry.emit(
                Event::new(
                    "tds5_encrypted_command",
                    Some(connection_id),
                    Some(session.session_id),
                )
                .field("source_ip", peer.ip().to_string())
                .field("packet_type", message.packet_type)
                .field(
                    "packet_type_name",
                    tds::legacy_packet_type_name(message.packet_type),
                )
                .field("message_bytes", message.payload.len())
                .field("packets", &message.packets)
                .field("encrypted_packet_shapes", encrypted_packet_shapes)
                .field(
                    "symmetrically_encrypted_packets",
                    symmetrically_encrypted_packets,
                )
                .field("symmetric_key_available", tds5_symmetric_key.is_some())
                .field(
                    "decryption_status",
                    "ciphertext_preserved_pending_verified_iv_framing",
                ),
            );
            session.request_count += 1;
            progress.requests = session.request_count;
            continue;
        }
        session.request_count += 1;
        progress.requests = session.request_count;
        let (outcome, done_proc) = match message.packet_type {
            tds::SQL_BATCH => {
                progress.enter("sql_batch_parse");
                shared.metrics.sql_batches.fetch_add(1, Ordering::Relaxed);
                let (sql, headers, enclave_package_bytes) = if legacy_login {
                    let sql = match tds::batch::decode_legacy(
                        &message.payload,
                        shared.config.limits.max_sql_batch_bytes,
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
                    (sql, Vec::new(), None)
                } else {
                    let tds_version = match protocol {
                        tokens::Protocol::Tds7(version) => version >> 24,
                        tokens::Protocol::Tds42
                        | tokens::Protocol::Tds46
                        | tokens::Protocol::Tds50 => 0,
                    };
                    let parse_batch = |encoding| {
                        tds::batch::parse_with_context(
                            &message.payload,
                            shared.config.limits.max_sql_batch_bytes,
                            tds_version >= 0x72,
                            tds_version >= 0x74,
                            encoding,
                        )
                    };
                    let parsed = if enclave_capable {
                        parse_batch(tds::enclave::LengthEncoding::MicrosoftU16)
                            .or_else(|_| parse_batch(tds::enclave::LengthEncoding::SpecU32))
                            .or_else(|_| parse_batch(tds::enclave::LengthEncoding::None))
                    } else {
                        parse_batch(tds::enclave::LengthEncoding::None)
                    };
                    let batch = match parsed {
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
                    (batch.sql, batch.headers, batch.enclave_package_bytes)
                };
                let outcome = handle_sql(&mut session, &shared.config.personality, &sql);
                emit_request(
                    &shared,
                    &session,
                    "sql_batch",
                    outcome.classification,
                    Event::new("sql_batch", Some(connection_id), Some(session_id))
                        .field("raw_sql", &sql)
                        .field("stream_headers", &headers)
                        .field("enclave_package_bytes", enclave_package_bytes),
                );
                (outcome, false)
            }
            tds::RPC => {
                progress.enter("rpc_parse");
                shared.metrics.rpc_requests.fetch_add(1, Ordering::Relaxed);
                let legacy_rpc = protocol.is_legacy();
                let parsed_rpc = if legacy_rpc {
                    tds::rpc::parse_legacy42(
                        &message.payload,
                        shared.config.limits.max_rpc_parameter_bytes,
                    )
                } else {
                    let parse_rpc = |encoding| {
                        tds::rpc::parse_with_context(
                            &message.payload,
                            shared.config.limits.max_rpc_parameter_bytes,
                            matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x72),
                            matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x74),
                            encoding,
                        )
                    };
                    if enclave_capable {
                        parse_rpc(tds::enclave::LengthEncoding::MicrosoftU16)
                            .or_else(|_| parse_rpc(tds::enclave::LengthEncoding::SpecU32))
                            .or_else(|_| parse_rpc(tds::enclave::LengthEncoding::None))
                    } else {
                        parse_rpc(tds::enclave::LengthEncoding::None)
                    }
                };
                let rpc = match parsed_rpc {
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
                        .field("wire_format", if legacy_rpc { "tds42" } else { "tds7" })
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
            tds::TRANSACTION_MANAGER if !protocol.is_legacy() => {
                progress.enter("transaction_manager_parse");
                let parse_transaction = |encoding| {
                    tds::transaction::parse_with_context(
                        &message.payload,
                        matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x72),
                        matches!(protocol, tokens::Protocol::Tds7(version) if version >> 24 >= 0x74),
                        encoding,
                    )
                };
                let parsed = if enclave_capable {
                    parse_transaction(tds::enclave::LengthEncoding::MicrosoftU16)
                        .or_else(|_| parse_transaction(tds::enclave::LengthEncoding::SpecU32))
                        .or_else(|_| parse_transaction(tds::enclave::LengthEncoding::None))
                } else {
                    parse_transaction(tds::enclave::LengthEncoding::None)
                };
                let request = match parsed {
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
                    .field("begin_transaction_name", request.begin_name)
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
                let parsed_bulk = match protocol {
                    tokens::Protocol::Tds50 => tds::bulk::parse_tds5_rows(
                        &message.payload,
                        shared.config.limits.max_rpc_parameter_bytes,
                        10,
                    ),
                    tokens::Protocol::Tds42 | tokens::Protocol::Tds46 => {
                        tds::bulk::parse_tds42_message(
                            &message.payload,
                            shared.config.limits.max_rpc_parameter_bytes,
                            10,
                        )
                    }
                    tokens::Protocol::Tds7(_) => tds::bulk::parse_message(
                        &message.payload,
                        shared.config.limits.max_rpc_parameter_bytes,
                        wide_metadata,
                        column_encryption_capable,
                        10,
                    ),
                };
                let bulk = match parsed_bulk {
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
                            .field("cek_table", &bulk.cek_table)
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
                    tds::bulk::BulkMessage::Tds5Rows {
                        row_count,
                        row_lengths,
                        sampled_rows,
                        trailing_bytes,
                    } => shared.telemetry.emit(
                        Event::new("bulk_load", Some(connection_id), Some(session_id))
                            .field("source_ip", peer.ip().to_string())
                            .field("login", &session.login_name)
                            .field("bulk_format", "tds5_row_image")
                            .field("message_bytes", message.payload.len())
                            .field("row_count", row_count)
                            .field("row_lengths", row_lengths)
                            .field("sampled_rows", sampled_rows)
                            .field("trailing_bytes", trailing_bytes),
                    ),
                    tds::bulk::BulkMessage::Tds42Rows {
                        row_count,
                        sampled_rows,
                        text_image_values,
                        text_image_bytes,
                    } => shared.telemetry.emit(
                        Event::new("bulk_load", Some(connection_id), Some(session_id))
                            .field("source_ip", peer.ip().to_string())
                            .field("login", &session.login_name)
                            .field("bulk_format", "tds42_bcp")
                            .field("message_bytes", message.payload.len())
                            .field("row_count", row_count)
                            .field("sampled_rows", sampled_rows)
                            .field("text_image_values", text_image_values)
                            .field("text_image_bytes", text_image_bytes),
                    ),
                }
                (empty_outcome(), false)
            }
            tds::SSPI if !protocol.is_legacy() => {
                let token = tds::sspi::parse(&message.payload);
                emit_sspi_message(
                    &shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    transport,
                    "logged_in_unexpected",
                    &token,
                    None,
                );
                (empty_outcome(), false)
            }
            tds::FEDAUTH_TOKEN if !protocol.is_legacy() => {
                capture_protocol_artifact(
                    &shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    "unexpected_federated_authentication",
                    &message,
                    transport,
                )
                .await;
                let token = tds::fedauth::parse_for_telemetry(&message.payload, false);
                let mut event = Event::new(
                    "federated_authentication_token",
                    Some(connection_id),
                    Some(session_id),
                )
                .field("source_ip", peer.ip().to_string())
                .field("token_bytes", token.token.len())
                .field("nonce_present", token.nonce.is_some())
                .field("unclassified_bytes", token.unclassified.len())
                .field("recovery", token.recovery)
                .field("parse_warnings", token.parse_warnings)
                .field("unexpected_state", true);
                if shared.config.telemetry.capture_login_passwords {
                    event = event
                        .field("token", authentication_material(token.token))
                        .field(
                            "unclassified_material",
                            authentication_material(token.unclassified),
                        );
                }
                shared.telemetry.emit(event);
                (empty_outcome(), false)
            }
            tds::TDS5_NORMAL if protocol.is_legacy() => {
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
                let auth = tds::tds5::parse_for_telemetry(
                    &message.payload,
                    shared.config.limits.max_payload_bytes,
                );
                let parameter_material = shared
                    .config
                    .telemetry
                    .capture_login_passwords
                    .then(|| tds5_parameter_material(&auth));
                if auth.unknown_token.is_some() {
                    capture_protocol_artifact(
                        &shared,
                        peer,
                        connection_id,
                        Some(session_id),
                        "unknown_tds5_token",
                        &message,
                        transport,
                    )
                    .await;
                }
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
                emit_request(
                    &shared,
                    &session,
                    "tds5_token_stream",
                    outcome.classification,
                    Event::new("tds5_token_stream", Some(connection_id), Some(session_id))
                        .field("source_ip", peer.ip().to_string())
                        .field("message_types", auth.message_types)
                        .field("tokens", auth.tokens)
                        .field("unparsed_regions", auth.unparsed_regions)
                        .field("parse_warnings", auth.parse_warnings)
                        .field("parameter_formats", auth.parameter_formats)
                        .field("parameter_sets", auth.parameter_sets)
                        .field("parameter_value_bytes", auth.parameter_value_bytes)
                        .field("row_formats", auth.row_formats)
                        .field("rows", auth.rows)
                        .field("alternate_formats", auth.alternate_formats)
                        .field("alternate_rows", auth.alternate_rows)
                        .field("row_value_bytes", auth.row_value_bytes)
                        .field("row_values", auth.row_values)
                        .field(
                            "remote_password_count",
                            auth.encrypted_remote_passwords.len(),
                        )
                        .field(
                            "encrypted_symmetric_key_bytes",
                            auth.encrypted_symmetric_key_bytes,
                        )
                        .field("commands", &auth.commands)
                        .field("parameter_values", &auth.parameter_values)
                        .field("parameter_material", parameter_material)
                        .field("opaque_security", &auth.opaque_security)
                        .field("unknown_token", auth.unknown_token)
                        .field("trailing_bytes", auth.trailing_bytes)
                        .field("raw_sql", &statements),
                );
                (outcome, false)
            }
            other if protocol.is_legacy() && (0x01..=0x17).contains(&other) => {
                capture_protocol_artifact(
                    &shared,
                    peer,
                    connection_id,
                    Some(session_id),
                    "legacy_control_message",
                    &message,
                    transport,
                )
                .await;
                shared.telemetry.emit(
                    Event::new(
                        "legacy_tds_control_message",
                        Some(connection_id),
                        Some(session_id),
                    )
                    .field("source_ip", peer.ip().to_string())
                    .field("login", &session.login_name)
                    .field("packet_type", other)
                    .field("packet_type_name", tds::legacy_packet_type_name(other))
                    .field("message_bytes", message.payload.len())
                    .field("packets", &message.packets),
                );
                (empty_outcome(), false)
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
    if !shared.config.payloads.enabled
        || is_authentication_packet_for_transport(message.packet_type, transport)
    {
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
                        packet_type_name_for_transport(message.packet_type, transport),
                    )
                    .field("packets", &message.packets)
                    .field(
                        "symmetrically_encrypted_packets",
                        is_legacy_transport(transport).then(|| {
                            message
                                .packets
                                .iter()
                                .filter(|packet| packet.has_symmetric_encryption())
                                .count()
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

struct Tds5SecureLogin {
    password: Option<String>,
    /// Session-only key material. It is deliberately never serialized.
    symmetric_key: Option<[u8; 32]>,
}

#[allow(clippy::too_many_arguments)]
async fn negotiate_tds5_secure_password<S>(
    shared: &Shared,
    stream: &mut MessageCaptureIo<S>,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: u32,
    progress: &mut Progress,
    transport: &'static str,
    protocol: Tds5SecureLoginProtocol,
) -> Result<Tds5SecureLogin>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fresh_key = if matches!(protocol, Tds5SecureLoginProtocol::ExtendedV2) {
        Some(tds::tds5::secure_login_key()?)
    } else {
        None
    };
    let key = if protocol.rsa() {
        Some(match fresh_key.as_ref() {
            Some(key) => key,
            None => tds::tds5::shared_secure_login_key()?,
        })
    } else {
        None
    };
    let mut proprietary_challenge_key = None;
    let (challenge, nonce) = if matches!(protocol, Tds5SecureLoginProtocol::ProprietaryV1) {
        let mut challenge_key = [0_u8; 16];
        OsRng.fill_bytes(&mut challenge_key);
        let challenge = tds::tds5::proprietary_login_challenge(&challenge_key)?;
        proprietary_challenge_key = Some(challenge_key);
        (challenge, None)
    } else if protocol.nonce_bearing() {
        let (challenge, nonce) = key
            .expect("RSA protocol has a key")
            .challenge_with_nonce(protocol.challenge_message_type())?;
        (challenge, Some(nonce))
    } else {
        (
            key.expect("RSA protocol has a key")
                .challenge(protocol.challenge_message_type())?,
            None,
        )
    };
    let challenge = tokens::tds5_login_negotiation(&challenge, "Adaptive Server Enterprise")?;
    progress.enter("tds5_secure_login_challenge_write");
    write_message(stream, tds::TABULAR_RESULT, &challenge, 4096).await?;

    progress.enter("tds5_secure_login_read");
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
            capture_incomplete_authentication_message(
                shared,
                peer,
                connection_id,
                Some(session_id),
                transport,
                stream.captured(),
                stream.truncated,
                true,
                error.kind(),
            )
            .await;
            return Err(error);
        }
        Err(_) => {
            capture_incomplete_authentication_message(
                shared,
                peer,
                connection_id,
                Some(session_id),
                transport,
                stream.captured(),
                stream.truncated,
                true,
                "timeout",
            )
            .await;
            return Err(Error::Protocol(
                "TDS 5 secure-login continuation timeout".into(),
            ));
        }
    };
    stream.clear_capture();
    progress.observe_message(&continuation);
    observe_inbound_message(
        shared,
        peer,
        connection_id,
        Some(session_id),
        "tds5_secure_login_read",
        transport,
        &continuation,
    )
    .await;
    capture_authentication_message(
        shared,
        peer,
        connection_id,
        Some(session_id),
        "tds5_secure_login_read",
        &continuation,
        transport,
    )
    .await;
    if continuation.packet_type != tds::TDS5_NORMAL {
        return Err(Error::Protocol(format!(
            "expected TDS 5 secure-login token stream, received {}",
            tds::packet_type_name(continuation.packet_type)
        )));
    }

    progress.enter("tds5_secure_login_parse");
    let authentication = tds::tds5::parse_for_telemetry(
        &continuation.payload,
        shared.config.limits.max_payload_bytes,
    );
    let expected_response = protocol.response_message_type();
    let response_message_present = authentication
        .message_types
        .iter()
        .any(|message| message.message_type == expected_response);
    let parameter_material = shared
        .config
        .telemetry
        .capture_login_passwords
        .then(|| tds5_parameter_material(&authentication));
    let password = if !response_message_present {
        Err(format!(
            "TDS 5 secure-login response did not contain message type {expected_response}"
        ))
    } else if matches!(protocol, Tds5SecureLoginProtocol::ProprietaryV1) {
        authentication
            .encrypted_login_password
            .as_ref()
            .map(|_| None)
            .ok_or_else(|| "TDS 5 secure-login stream has no encrypted password".to_owned())
    } else if let Some(ciphertext) = authentication.encrypted_login_password.as_deref() {
        match (key, nonce.as_ref()) {
            (Some(key), Some(nonce)) => key.decrypt_password_with_nonce(ciphertext, nonce),
            (Some(key), None) => key.decrypt_password(ciphertext),
            (None, _) => unreachable!("RSA secure-login protocol has a key"),
        }
        .map(Some)
        .map_err(|error| error.to_string())
    } else {
        Err("TDS 5 secure-login stream has no encrypted password".to_owned())
    };
    let mut remote_server_names = Vec::new();
    let mut remote_passwords = Vec::new();
    let mut remote_password_errors = Vec::new();
    for remote in &authentication.encrypted_remote_passwords {
        remote_server_names.push(remote.server_name.clone());
        let recovered = match (key, nonce.as_ref()) {
            (Some(key), Some(nonce)) => key.decrypt_password_with_nonce(&remote.ciphertext, nonce),
            (Some(key), None) => key.decrypt_password(&remote.ciphertext),
            (None, _) => {
                remote_password_errors.push(
                    "proprietary v1 remote-password ciphertext captured but not decrypted"
                        .to_owned(),
                );
                continue;
            }
        };
        match recovered {
            Ok(password) => remote_passwords.push(password),
            Err(error) => remote_password_errors.push(error.to_string()),
        }
    }
    let (symmetric_key, symmetric_key_error) = match (
        nonce.as_ref(),
        authentication.encrypted_symmetric_key.as_deref(),
    ) {
        (Some(nonce), Some(ciphertext)) => {
            match key
                .expect("nonce-bearing RSA protocol has a key")
                .decrypt_symmetric_key_with_nonce(ciphertext, nonce)
            {
                Ok(key) => (Some(key), None),
                Err(error) => (None, Some(error.to_string())),
            }
        }
        (Some(_), None) if matches!(protocol, Tds5SecureLoginProtocol::ExtendedPlusV4) => (
            None,
            Some("EPEP v4 continuation has no encrypted symmetric key".to_owned()),
        ),
        (Some(_), None) => (None, None),
        (None, Some(_)) => (
            None,
            Some("symmetric-key message received without EPEP v4 nonce".to_owned()),
        ),
        (None, None) => (None, None),
    };
    let mut event = Event::new(
        "tds5_secure_login_continuation",
        Some(connection_id),
        Some(session_id),
    )
    .field("source_ip", peer.ip().to_string())
    .field("transport", transport)
    .field("expected_response_message_type", expected_response)
    .field("response_message_present", response_message_present)
    .field("message_types", authentication.message_types)
    .field("tokens", authentication.tokens)
    .field("unparsed_regions", authentication.unparsed_regions)
    .field("parse_warnings", authentication.parse_warnings)
    .field("parameter_formats", authentication.parameter_formats)
    .field("parameter_sets", authentication.parameter_sets)
    .field("parameter_material", parameter_material)
    .field(
        "encrypted_password_bytes",
        authentication.encrypted_login_password_bytes,
    )
    .field("remote_server_names", remote_server_names)
    .field(
        "remote_password_count",
        authentication.encrypted_remote_passwords.len(),
    )
    .field("remote_password_errors", remote_password_errors)
    .field(
        "encrypted_symmetric_key_bytes",
        authentication.encrypted_symmetric_key_bytes,
    )
    .field("symmetric_key_recovered", symmetric_key.is_some())
    .field("symmetric_key_error", symmetric_key_error)
    .field(
        "proprietary_challenge_key_bytes",
        proprietary_challenge_key.as_ref().map(|key| key.len()),
    )
    .field("password_recovered", matches!(&password, Ok(Some(_))))
    .field(
        "password_recovery_status",
        match &password {
            Ok(Some(_)) => "recovered",
            Ok(None) => "ciphertext_captured_proprietary_cipher",
            Err(_) => "failed",
        },
    )
    .field("password_error", password.as_ref().err())
    .field("secure_login_version", protocol.version());
    if shared.config.telemetry.capture_login_passwords {
        event = event.field("remote_passwords", remote_passwords).field(
            "proprietary_challenge_key",
            proprietary_challenge_key
                .as_ref()
                .map(|key| authentication_material(key)),
        );
    }
    shared.telemetry.emit(event);
    let password = password.map_err(Error::Protocol)?;
    Ok(Tds5SecureLogin {
        password,
        symmetric_key,
    })
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
        None,
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
            Some(challenge),
        );
    }

    progress.enter("login_response");
    let response = tokens::login_failure(protocol, &shared.config.personality.server_name, false)?;
    write_message(stream, tds::TABULAR_RESULT, &response, 4096).await?;
    Ok(progress.summary("integrated_authentication_rejected"))
}

#[allow(clippy::too_many_arguments)]
async fn negotiate_federated_authentication<S>(
    shared: &Shared,
    stream: &mut MessageCaptureIo<S>,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: u32,
    progress: &mut Progress,
    transport: &'static str,
    protocol: tokens::Protocol,
    feature: &tds::login7::LoginFeature,
    server_nonce: Option<[u8; 32]>,
) -> Result<Summary>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let requests_information = feature.parse_error.is_none()
        && feature.fedauth_library == Some(0x02)
        && matches!(feature.fedauth_workflow, Some(0x01 | 0x02));
    if requests_information {
        let information = tokens::fedauth_info(
            "https://login.microsoftonline.com/common/oauth2/token",
            "https://database.windows.net/",
        )?;
        progress.enter("fedauth_info_write");
        write_message(stream, tds::TABULAR_RESULT, &information, 4096).await?;

        progress.enter("fedauth_read");
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
                return Err(Error::Protocol(
                    "federated authentication continuation timeout".into(),
                ));
            }
        };
        stream.clear_capture();
        progress.observe_message(&continuation);
        observe_inbound_message(
            shared,
            peer,
            connection_id,
            Some(session_id),
            "fedauth_read",
            transport,
            &continuation,
        )
        .await;
        progress.enter("fedauth_parse");
        if continuation.packet_type != tds::FEDAUTH_TOKEN {
            capture_protocol_artifact(
                shared,
                peer,
                connection_id,
                Some(session_id),
                "unexpected_fedauth_continuation",
                &continuation,
                transport,
            )
            .await;
            return Err(Error::Protocol(format!(
                "expected federated authentication token, received {}",
                tds::packet_type_name(continuation.packet_type)
            )));
        }
        let token =
            tds::fedauth::parse_for_telemetry(&continuation.payload, server_nonce.is_some());
        let nonce_matches = token
            .nonce
            .map(|nonce| Some(nonce) == server_nonce.as_ref().map(|value| value.as_slice()));
        let mut event = Event::new(
            "federated_authentication_token",
            Some(connection_id),
            Some(session_id),
        )
        .field("source_ip", peer.ip().to_string())
        .field("transport", transport)
        .field("phase", "continuation")
        .field("library", feature.fedauth_library)
        .field("workflow", feature.fedauth_workflow)
        .field("token_bytes", token.token.len())
        .field("nonce_present", token.nonce.is_some())
        .field("unclassified_bytes", token.unclassified.len())
        .field("recovery", token.recovery)
        .field("nonce_matches", nonce_matches)
        .field("parse_warnings", token.parse_warnings);
        if shared.config.telemetry.capture_login_passwords {
            event = event
                .field("token", authentication_material(token.token))
                .field(
                    "unclassified_material",
                    authentication_material(token.unclassified),
                );
        }
        shared.telemetry.emit(event);
    }

    progress.enter("login_response");
    let response = tokens::login_failure(protocol, &shared.config.personality.server_name, false)?;
    write_message(stream, tds::TABULAR_RESULT, &response, 4096).await?;
    Ok(progress.summary("federated_authentication_rejected"))
}

#[allow(clippy::too_many_arguments)]
fn emit_sspi_message(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    transport: &str,
    phase: &str,
    token: &tds::sspi::SspiToken,
    server_challenge: Option<[u8; 8]>,
) {
    let mut event = Event::new("sspi_message", Some(connection_id), session_id)
        .field("source_ip", peer.ip().to_string())
        .field("transport", transport)
        .field("phase", phase)
        .field("token_family", token.family)
        .field("message_type", token.message_type)
        .field("token_bytes", token.bytes)
        .field(
            "mechanism_oids",
            token.der.as_ref().map(|der| &der.mechanism_oids),
        )
        .field(
            "principal_hints",
            token.der.as_ref().map(|der| &der.text_values),
        )
        .field("der_nodes", token.der.as_ref().map(|der| der.nodes))
        .field(
            "ber_indefinite_length_nodes",
            token.der.as_ref().map(|der| der.indefinite_length_nodes),
        )
        .field("der_complete", token.der.as_ref().map(|der| der.complete))
        .field(
            "server_challenge",
            server_challenge.map(|value| hex_bytes(&value)),
        )
        .field("parse_warnings", &token.parse_warnings);
    if let Some(negotiate) = &token.ntlm_negotiate {
        event = event
            .field("domain", &negotiate.domain)
            .field("workstation", &negotiate.workstation)
            .field("negotiate_flags", negotiate.negotiate_flags);
    }
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
        if shared.config.telemetry.capture_login_passwords {
            event = event
                .field("lm_response", hex_bytes(&ntlm.lm_response))
                .field("nt_response", hex_bytes(&ntlm.nt_response))
                .field(
                    "encrypted_session_key",
                    hex_bytes(&ntlm.encrypted_session_key),
                );
        }
    }
    shared.telemetry.emit(event);
}

#[allow(clippy::too_many_arguments)]
async fn emit_smp_embedded_authentication(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    transport: &str,
    smp_session_id: Option<u16>,
    smp_sequence: Option<u32>,
    data: &[u8],
) -> bool {
    let Some(&packet_type) = data.first() else {
        return false;
    };
    if !is_initial_authentication_candidate(packet_type) {
        return false;
    }

    let mut reader = data;
    let decoded = read_message(
        &mut reader,
        shared.config.limits.max_packet_bytes,
        shared.config.limits.max_message_bytes,
    )
    .await;
    let mut event = Event::new(
        "smp_embedded_authentication",
        Some(connection_id),
        session_id,
    )
    .field("source_ip", peer.ip().to_string())
    .field("transport", transport)
    .field("smp_session_id", smp_session_id)
    .field("smp_sequence", smp_sequence)
    .field("inner_packet_type", packet_type)
    .field("inner_packet_type_name", tds::packet_type_name(packet_type))
    .field("available_inner_wire_bytes", data.len());

    let message = match decoded {
        Ok(message) => {
            event = event
                .field("inner_message_complete", true)
                .field("inner_message_bytes", message.payload.len())
                .field("inner_packet_count", message.packet_count)
                .field("inner_trailing_wire_bytes", reader.len());
            message
        }
        Err(error) => {
            shared.telemetry.emit(
                event
                    .field("inner_message_complete", false)
                    .field("inner_parse_error", error.to_string()),
            );
            return true;
        }
    };

    match message.packet_type {
        tds::LOGIN | tds::LOGIN7 => {
            let parsed = if message.packet_type == tds::LOGIN {
                tds::login::parse_for_telemetry(&message.payload)
            } else {
                tds::login7::parse_for_telemetry(&message.payload)
            };
            match parsed {
                Ok(login) => {
                    event = event
                        .field(
                            "authentication_kind",
                            if message.packet_type == tds::LOGIN {
                                "legacy_login"
                            } else {
                                "login7"
                            },
                        )
                        .field("username", &login.username)
                        .field("client_hostname", &login.client_hostname)
                        .field("application_name", &login.application_name)
                        .field("password_field_present", login.password_present)
                        .field("change_password_field_present", login.new_password_present)
                        .field("integrated_security", login.integrated_security)
                        .field("feature_extensions", &login.features)
                        .field(
                            "feature_extension_remainder",
                            &login.feature_extension_remainder,
                        )
                        .field("legacy_authentication", &login.legacy_authentication)
                        .field("parse_warnings", &login.parse_warnings);
                    if shared.config.telemetry.capture_login_passwords {
                        event = event
                            .field("password", login.password_for_capture())
                            .field("new_password", login.new_password_for_capture())
                            .field(
                                "legacy_authentication_material",
                                login
                                    .legacy_authentication
                                    .as_ref()
                                    .map(tds5_parameter_material),
                            )
                            .field(
                                "feature_extension_remainder_material",
                                (!login.feature_extension_remainder_raw.is_empty()).then(|| {
                                    authentication_material(&login.feature_extension_remainder_raw)
                                }),
                            );
                    }
                }
                Err(error) => {
                    event = event.field("semantic_parse_error", error.to_string());
                }
            }
        }
        tds::SSPI => {
            let token = tds::sspi::parse(&message.payload);
            emit_sspi_message(
                shared,
                peer,
                connection_id,
                session_id,
                transport,
                "smp_unnegotiated",
                &token,
                None,
            );
            event = event
                .field("authentication_kind", "sspi")
                .field("token_family", token.family)
                .field("token_bytes", token.bytes)
                .field("parse_warnings", token.parse_warnings);
        }
        tds::FEDAUTH_TOKEN => {
            let token = tds::fedauth::parse_for_telemetry(&message.payload, false);
            event = event
                .field("authentication_kind", "fedauth")
                .field("token_bytes", token.token.len())
                .field("nonce_present", token.nonce.is_some())
                .field("unclassified_bytes", token.unclassified.len())
                .field("recovery", token.recovery)
                .field("parse_warnings", token.parse_warnings);
            if shared.config.telemetry.capture_login_passwords {
                event = event
                    .field("token", authentication_material(token.token))
                    .field(
                        "unclassified_material",
                        authentication_material(token.unclassified),
                    );
            }
        }
        tds::TDS5_NORMAL | tds::TDS5_COMMAND_SEQUENCE_LOGIN => {
            let authentication = tds::tds5::parse_for_telemetry(
                &message.payload,
                shared.config.limits.max_payload_bytes,
            );
            let parameter_material = shared
                .config
                .telemetry
                .capture_login_passwords
                .then(|| tds5_parameter_material(&authentication));
            event = event
                .field("authentication_kind", "tds5_token_stream")
                .field("message_types", authentication.message_types)
                .field("tokens", authentication.tokens)
                .field(
                    "parameter_value_bytes",
                    authentication.parameter_value_bytes,
                )
                .field("parameter_material", parameter_material)
                .field("unparsed_regions", authentication.unparsed_regions)
                .field("parse_warnings", authentication.parse_warnings)
                .field("unknown_token", authentication.unknown_token)
                .field("trailing_bytes", authentication.trailing_bytes);
        }
        _ => unreachable!("initial authentication candidate taxonomy"),
    }
    shared.telemetry.emit(event);
    true
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
    let Some(&first_byte) = wire_bytes.first() else {
        return;
    };
    let mut embedded_authentication = false;
    let smp_frames = if first_byte == 0x53 {
        match tds::smp::parse(wire_bytes, shared.config.limits.max_message_bytes) {
            Ok(frames) => {
                for frame in &frames {
                    if frame.flag != 0x08 {
                        continue;
                    }
                    let data_start = frame.offset + tds::smp::HEADER_LEN;
                    let data_end = frame.offset + usize::try_from(frame.length).unwrap_or(0);
                    if let Some(data) = wire_bytes.get(data_start..data_end) {
                        embedded_authentication |= emit_smp_embedded_authentication(
                            shared,
                            peer,
                            connection_id,
                            session_id,
                            transport,
                            Some(frame.session_id),
                            Some(frame.sequence),
                            data,
                        )
                        .await;
                    }
                }
                shared.telemetry.emit(
                    Event::new("smp_ingress", Some(connection_id), session_id)
                        .field("source_ip", peer.ip().to_string())
                        .field("transport", transport)
                        .field("wire_bytes", wire_bytes.len())
                        .field("frames", &frames)
                        .field("embedded_authentication", embedded_authentication)
                        .field("negotiated", false),
                );
                Some(frames)
            }
            Err(error) => {
                let partial_data = wire_bytes
                    .get(tds::smp::HEADER_LEN..)
                    .filter(|_| wire_bytes.get(1) == Some(&0x08));
                if let Some(data) = partial_data {
                    embedded_authentication = emit_smp_embedded_authentication(
                        shared,
                        peer,
                        connection_id,
                        session_id,
                        transport,
                        wire_bytes
                            .get(2..4)
                            .map(|raw| u16::from_le_bytes(raw.try_into().expect("length checked"))),
                        wire_bytes
                            .get(8..12)
                            .map(|raw| u32::from_le_bytes(raw.try_into().expect("length checked"))),
                        data,
                    )
                    .await;
                }
                shared.telemetry.emit(
                    Event::new("smp_parse_failure", Some(connection_id), session_id)
                        .field("source_ip", peer.ip().to_string())
                        .field("transport", transport)
                        .field("wire_bytes", wire_bytes.len())
                        .field("embedded_authentication", embedded_authentication)
                        .field("error", error.to_string()),
                );
                None
            }
        }
    } else {
        None
    };
    capture_incomplete_authentication_message(
        shared,
        peer,
        connection_id,
        session_id,
        transport,
        wire_bytes,
        capture_truncated,
        embedded_authentication,
        error_kind,
    )
    .await;
    if is_authentication_packet_for_transport(first_byte, transport)
        || embedded_authentication
        || !shared.config.payloads.enabled
    {
        return;
    }
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
    force_authentication: bool,
    error_kind: &str,
) {
    let Some(&packet_type) = wire_bytes.first() else {
        return;
    };
    if (!force_authentication && !is_authentication_packet_for_transport(packet_type, transport))
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
            .field(
                "packet_type_name",
                packet_type_name_for_transport(packet_type, transport),
            )
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
    let packet_type_name = packet_type_name_for_transport(message.packet_type, transport);
    let authentication_message =
        is_authentication_packet_for_transport(message.packet_type, transport);
    let legacy_transport = is_legacy_transport(transport);
    let packet_status_flags = message
        .packets
        .iter()
        .map(|packet| {
            if legacy_transport {
                tds::packet::legacy_status_flags(packet.status)
            } else {
                tds::packet::microsoft_status_flags(packet.status)
            }
        })
        .collect::<Vec<_>>();
    let known_status_mask = if legacy_transport { 0x7f } else { 0x1b };
    let packet_status_unknown_bits = message
        .packets
        .iter()
        .map(|packet| packet.status & !known_status_mask)
        .collect::<Vec<_>>();
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
            .field("packets", &message.packets)
            .field("packet_status_flags", packet_status_flags)
            .field("packet_status_unknown_bits", packet_status_unknown_bits)
            .field(
                "symmetrically_encrypted_packets",
                legacy_transport.then(|| {
                    message
                        .packets
                        .iter()
                        .filter(|packet| packet.has_symmetric_encryption())
                        .count()
                }),
            )
            .field("message_bytes", message.payload.len())
            .field("authentication_message", authentication_message),
    );
    if !authentication_message || !shared.config.payloads.captures_login_messages() {
        return;
    }
    capture_authentication_message(
        shared,
        peer,
        connection_id,
        session_id,
        protocol_stage,
        message,
        transport,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn capture_authentication_message(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    session_id: Option<u32>,
    protocol_stage: &str,
    message: &tds::packet::Message,
    transport: &str,
) {
    if !shared.config.payloads.captures_login_messages() {
        return;
    }
    let packet_type_name = packet_type_name_for_transport(message.packet_type, transport);
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
                .field("protocol_stage", protocol_stage)
                .field("packet_type", message.packet_type)
                .field("packet_type_name", packet_type_name)
                .field(
                    "login_format",
                    login_message.then_some(if message.packet_type == tds::LOGIN {
                        legacy_login_format(&message.payload)
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

fn is_legacy_transport(transport: &str) -> bool {
    transport.starts_with("tds42")
        || transport.starts_with("tds46")
        || transport.starts_with("tds50")
}

fn requests_tds5_external_security(flags: u8) -> bool {
    flags & (0x02 | 0x04 | 0x08 | 0x10) != 0
}

fn packet_type_name_for_transport(packet_type: u8, transport: &str) -> &'static str {
    if is_legacy_transport(transport) {
        tds::legacy_packet_type_name(packet_type)
    } else {
        tds::packet_type_name(packet_type)
    }
}

fn is_authentication_packet_for_transport(packet_type: u8, transport: &str) -> bool {
    if is_legacy_transport(transport) {
        packet_type == tds::LOGIN
            || packet_type == tds::TDS5_COMMAND_SEQUENCE_LOGIN
            || (packet_type == tds::TDS5_NORMAL && transport.contains("authentication"))
    } else {
        tds::is_authentication_packet(packet_type)
    }
}

fn is_initial_authentication_candidate(packet_type: u8) -> bool {
    tds::is_authentication_packet(packet_type)
        || matches!(
            packet_type,
            tds::TDS5_NORMAL | tds::TDS5_COMMAND_SEQUENCE_LOGIN
        )
}

fn legacy_login_format(payload: &[u8]) -> &'static str {
    let Some(version) = payload
        .get(458..462)
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_be_bytes)
    else {
        return "legacy_login";
    };
    match version >> 16 {
        0x0402 => "tds42_login",
        0x0406 => "tds46_login",
        0x0500..=0x05ff => "tds50_login",
        _ => "legacy_login",
    }
}

fn negotiated_tds7_version(requested: u32, tds8_transport: bool) -> u32 {
    const TDS74: u32 = 0x7400_0004;
    if tds8_transport || !(0x70..=0x74).contains(&(requested >> 24)) {
        TDS74
    } else {
        requested
    }
}

fn supported_feature_acks(features: &[tds::login7::LoginFeature]) -> Vec<tokens::FeatureAck> {
    features
        .iter()
        .filter(|feature| feature.parse_error.is_none())
        .filter_map(|feature| {
            let data = match feature.id {
                // Encrypted RPC and bulk values are structurally inventoried,
                // but no enclave is implemented, so negotiate baseline v1.
                0x04 => vec![1],
                0x0a if feature.supported == Some(true) => vec![1],
                0x0d if feature.version == Some(1) => vec![1],
                0x0e => vec![feature.version?.min(2)],
                0x10 => vec![1],
                _ => return None,
            };
            Some(tokens::FeatureAck {
                id: feature.id,
                data,
            })
        })
        .collect()
}

fn emit_login_parse_failure(
    shared: &Shared,
    peer: SocketAddr,
    connection_id: Uuid,
    transport: &str,
    message: &tds::packet::Message,
    error: &Error,
) {
    shared.telemetry.emit(
        Event::new("login_parse_failure", Some(connection_id), None)
            .field("source_ip", peer.ip().to_string())
            .field("source_port", peer.port())
            .field("transport", transport)
            .field("packet_type", message.packet_type)
            .field(
                "packet_type_name",
                tds::packet_type_name(message.packet_type),
            )
            .field(
                "login_format",
                if message.packet_type == tds::LOGIN {
                    legacy_login_format(&message.payload)
                } else {
                    "login7"
                },
            )
            .field("packet_count", message.packet_count)
            .field("message_bytes", message.payload.len())
            .field("error_kind", error.kind())
            .field("error", error.to_string())
            .field(
                "raw_artifact_emitted",
                shared.config.payloads.captures_login_messages(),
            ),
    );
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

fn authentication_material(value: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(value)
        && text
            .chars()
            .all(|character| !character.is_control() || character.is_ascii_whitespace())
    {
        return text.to_owned();
    }
    format!("hex:{}", hex_bytes(value))
}

fn tds5_parameter_material(authentication: &tds::tds5::AuthenticationStream) -> Vec<String> {
    (0..authentication.parameter_value_bytes.len())
        .filter_map(|index| authentication.parameter_value(index))
        .map(authentication_material)
        .collect()
}

fn hex_bytes(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    use std::fmt::Write as _;
    for byte in value {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        instance_matches, is_authentication_packet_for_transport, negotiate,
        negotiated_tds7_version, packet_type_name_for_transport, requests_tds5_external_security,
    };
    use crate::{
        config::TlsMode,
        tds::{self, prelogin::Encryption},
    };

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

    #[test]
    fn optional_tls_negotiates_login_only_encryption() {
        assert_eq!(
            negotiate(TlsMode::Optional, Encryption::Off),
            (Encryption::Off, true)
        );
        assert_eq!(
            negotiate(TlsMode::Optional, Encryption::On),
            (Encryption::On, true)
        );
        assert_eq!(
            negotiate(TlsMode::Optional, Encryption::NotSupported),
            (Encryption::NotSupported, false)
        );
    }

    #[test]
    fn normalizes_tds8_and_future_login_versions() {
        assert_eq!(negotiated_tds7_version(0, true), 0x7400_0004);
        assert_eq!(negotiated_tds7_version(0x7500_0001, false), 0x7400_0004);
        assert_eq!(negotiated_tds7_version(0x730b_0003, false), 0x730b_0003);
    }

    #[test]
    fn protocol_state_disambiguates_overlapping_legacy_packet_ids() {
        assert_eq!(
            packet_type_name_for_transport(0x08, "tds50_direct"),
            "setup"
        );
        assert_eq!(
            packet_type_name_for_transport(0x08, "tds7"),
            "federated_authentication_token"
        );
        assert_eq!(
            packet_type_name_for_transport(0x11, "tds50_after_prelogin"),
            "migrate"
        );
        assert_eq!(packet_type_name_for_transport(0x11, "tds7"), "sspi");
        assert_eq!(
            packet_type_name_for_transport(0x12, "tds50_direct"),
            "hello"
        );
        assert_eq!(packet_type_name_for_transport(0x12, "tds7"), "prelogin");

        assert!(!is_authentication_packet_for_transport(
            0x08,
            "tds50_direct"
        ));
        assert!(!is_authentication_packet_for_transport(
            0x11,
            "tds50_direct"
        ));
        assert!(!is_authentication_packet_for_transport(
            tds::TDS5_NORMAL,
            "tds50_direct"
        ));
        assert!(is_authentication_packet_for_transport(
            tds::TDS5_NORMAL,
            "tds50_authentication_direct"
        ));
        assert!(is_authentication_packet_for_transport(
            tds::TDS5_COMMAND_SEQUENCE_LOGIN,
            "tds50_direct"
        ));
        assert!(is_authentication_packet_for_transport(0x08, "tds7"));
        assert!(is_authentication_packet_for_transport(0x11, "tds7"));
    }

    #[test]
    fn every_non_password_tds5_security_mode_requires_its_own_handshake() {
        for flag in [0x02, 0x04, 0x08, 0x10] {
            assert!(requests_tds5_external_security(flag));
        }
        for flag in [0x00, 0x01, 0x20, 0x40, 0x80] {
            assert!(!requests_tds5_external_security(flag));
        }
    }
}
