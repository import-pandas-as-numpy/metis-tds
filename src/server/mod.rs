mod connection;
mod tls;

use std::{
    collections::HashMap,
    fmt::Write as _,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::{
    Config, Error, Result,
    payload::PayloadStore,
    telemetry::{Event, Telemetry},
};

pub struct Server {
    shared: Arc<Shared>,
}

pub(crate) struct Shared {
    pub config: Arc<Config>,
    pub telemetry: Telemetry,
    pub payloads: PayloadStore,
    pub tls: Option<TlsAcceptor>,
    pub sessions: AtomicU32,
    pub metrics: Metrics,
    connection_limit: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    request_rates: Mutex<HashMap<IpAddr, RateWindow>>,
    login_attempts_by_ip: Mutex<HashMap<IpAddr, u64>>,
}

#[derive(Default)]
pub(crate) struct Metrics {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub rejected_connections: AtomicU64,
    pub direct_login_connections: AtomicU64,
    pub login_attempts: AtomicU64,
    pub accepted_logins: AtomicU64,
    pub source_auth_bypasses: AtomicU64,
    pub malformed_messages: AtomicU64,
    pub sql_batches: AtomicU64,
    pub rpc_requests: AtomicU64,
    pub payloads_captured: AtomicU64,
    pub bytes_captured: AtomicU64,
    pub rate_limit_events: AtomicU64,
    pub completed_sessions: AtomicU64,
    pub total_session_duration_ms: AtomicU64,
    pub classifications: Mutex<HashMap<String, u64>>,
}

struct RateWindow {
    since: Instant,
    count: u64,
}

impl Server {
    pub async fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let telemetry = Telemetry::start(
            config.telemetry.clone(),
            config.limits.telemetry_queue_capacity,
        )
        .await?;
        let payloads =
            PayloadStore::new(config.payloads.clone(), config.limits.max_payload_bytes).await?;
        let tls = if config.tls.mode == crate::config::TlsMode::Disabled {
            None
        } else {
            Some(tls::acceptor(&config.tls).await?)
        };
        let max_connections = config.listener.max_connections;
        Ok(Self {
            shared: Arc::new(Shared {
                config: Arc::new(config),
                telemetry,
                payloads,
                tls,
                sessions: AtomicU32::new(50),
                metrics: Metrics::default(),
                connection_limit: Arc::new(Semaphore::new(max_connections)),
                per_ip: Arc::new(Mutex::new(HashMap::new())),
                request_rates: Mutex::new(HashMap::new()),
                login_attempts_by_ip: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.shared.config.listener.address).await?;
        tracing::info!(address = %listener.local_addr()?, "MSSQL TDS honeypot listening");
        self.serve(listener, true).await
    }

    pub async fn serve(self, listener: TcpListener, handle_shutdown_signal: bool) -> Result<()> {
        loop {
            let accepted = if handle_shutdown_signal {
                tokio::select! {
                    result = listener.accept() => Some(result),
                    result = tokio::signal::ctrl_c() => { result?; None }
                }
            } else {
                Some(listener.accept().await)
            };
            let Some(accepted) = accepted else {
                tracing::info!("shutdown signal received");
                return Ok(());
            };
            let (stream, peer) = accepted?;
            let destination = stream.local_addr()?;
            let connection_id = Uuid::new_v4();
            self.shared
                .metrics
                .total_connections
                .fetch_add(1, Ordering::Relaxed);
            let permit = match Arc::clone(&self.shared.connection_limit).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    self.reject(connection_id, peer.ip(), "global_connection_limit");
                    continue;
                }
            };
            let ip_guard = match IpGuard::acquire(
                Arc::clone(&self.shared.per_ip),
                peer.ip(),
                self.shared.config.listener.max_connections_per_ip,
            ) {
                Some(guard) => guard,
                None => {
                    self.reject(connection_id, peer.ip(), "per_ip_connection_limit");
                    continue;
                }
            };
            self.shared
                .metrics
                .active_connections
                .fetch_add(1, Ordering::Relaxed);
            self.shared.telemetry.emit(
                Event::new("connection_open", Some(connection_id), None)
                    .field("source_ip", peer.ip().to_string())
                    .field("source_port", peer.port())
                    .field("destination_port", destination.port()),
            );
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move {
                connection_task(shared, stream, peer, connection_id, permit, ip_guard).await;
            });
        }
    }

    fn reject(&self, connection_id: Uuid, ip: IpAddr, reason: &str) {
        self.shared
            .metrics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        self.shared.telemetry.emit(
            Event::new("connection_rejected", Some(connection_id), None)
                .field("source_ip", ip.to_string())
                .field("reason", reason),
        );
    }
}

async fn connection_task(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    connection_id: Uuid,
    _permit: OwnedSemaphorePermit,
    _ip: IpGuard,
) {
    let started = Instant::now();
    let outcome = connection::handle(Arc::clone(&shared), stream, peer, connection_id).await;
    shared
        .metrics
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    shared
        .metrics
        .completed_sessions
        .fetch_add(1, Ordering::Relaxed);
    shared
        .metrics
        .total_session_duration_ms
        .fetch_add(duration_ms, Ordering::Relaxed);
    let (
        reason,
        stage,
        error_kind,
        session_id,
        requests,
        bytes_read,
        bytes_written,
        parser_errors,
        highest_risk,
    ) = match outcome {
        Ok(summary) => (
            summary.reason,
            summary.stage,
            "none",
            summary.session_id,
            summary.requests,
            summary.bytes_read,
            summary.bytes_written,
            summary.parser_errors,
            summary.highest_risk,
        ),
        Err(failure) => {
            let parser_error = matches!(failure.error, Error::Protocol(_) | Error::Limit(_));
            let prefix_is_safe = diagnostic_prefix_is_safe(failure.stage, &failure.read_prefix);
            let diagnostic_prefix = prefix_is_safe.then(|| hex(&failure.read_prefix));
            shared.telemetry.emit(
                Event::new(
                    "connection_failure",
                    Some(connection_id),
                    failure.session_id,
                )
                .field("source_ip", peer.ip().to_string())
                .field("source_port", peer.port())
                .field("protocol_stage", failure.stage)
                .field("error_kind", failure.error.kind())
                .field("error", failure.error.to_string())
                .field("bytes_read", failure.bytes_read)
                .field("bytes_written", failure.bytes_written)
                .field("stage_bytes_read", failure.stage_bytes_read)
                .field("stage_bytes_written", failure.stage_bytes_written)
                .field("last_packet_type", failure.last_packet_type)
                .field("last_first_status", failure.last_first_status)
                .field("last_first_packet_id", failure.last_first_packet_id)
                .field("last_packet_count", failure.last_packet_count)
                .field("last_message_bytes", failure.last_message_bytes)
                .field("read_prefix_hex", diagnostic_prefix)
                .field(
                    "read_prefix_bytes",
                    prefix_is_safe.then_some(failure.read_prefix.len()),
                )
                .field(
                    "read_prefix_truncated",
                    prefix_is_safe.then_some(
                        failure.bytes_read
                            > u64::try_from(failure.read_prefix.len()).unwrap_or(u64::MAX),
                    ),
                ),
            );
            if parser_error {
                shared
                    .metrics
                    .malformed_messages
                    .fetch_add(1, Ordering::Relaxed);
                shared.telemetry.emit(
                    Event::new(
                        "malformed_tds_message",
                        Some(connection_id),
                        failure.session_id,
                    )
                    .field("source_ip", peer.ip().to_string())
                    .field("source_port", peer.port())
                    .field("protocol_stage", failure.stage)
                    .field("error_kind", failure.error.kind())
                    .field("error", failure.error.to_string())
                    .field("bytes_read", failure.bytes_read)
                    .field("bytes_written", failure.bytes_written)
                    .field("stage_bytes_read", failure.stage_bytes_read)
                    .field("stage_bytes_written", failure.stage_bytes_written)
                    .field("last_packet_type", failure.last_packet_type)
                    .field("last_first_status", failure.last_first_status)
                    .field("last_first_packet_id", failure.last_first_packet_id)
                    .field("last_packet_count", failure.last_packet_count)
                    .field("last_message_bytes", failure.last_message_bytes),
                );
            }
            tracing::debug!(
                %connection_id,
                stage = failure.stage,
                error = %failure.error,
                "connection ended with error"
            );
            (
                failure.error.to_string(),
                failure.stage,
                failure.error.kind(),
                failure.session_id,
                failure.requests,
                failure.bytes_read,
                failure.bytes_written,
                u64::from(parser_error),
                failure.highest_risk,
            )
        }
    };
    shared.telemetry.emit(
        Event::new("connection_close", Some(connection_id), session_id)
            .field("source_ip", peer.ip().to_string())
            .field("source_port", peer.port())
            .field("protocol_stage", stage)
            .field("error_kind", error_kind)
            .field("duration_ms", duration_ms)
            .field("request_count", requests)
            .field("bytes_read", bytes_read)
            .field("bytes_written", bytes_written)
            .field("termination_reason", reason)
            .field("parser_errors", parser_errors)
            .field("highest_risk_classification", highest_risk)
            .field("telemetry_events_dropped_total", shared.telemetry.dropped()),
    );
    let classifications = shared
        .metrics
        .classifications
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let completed = shared.metrics.completed_sessions.load(Ordering::Relaxed);
    shared.telemetry.emit(
        Event::new("metrics_snapshot", None, None)
            .field(
                "active_connections",
                shared.metrics.active_connections.load(Ordering::Relaxed),
            )
            .field(
                "total_connections",
                shared.metrics.total_connections.load(Ordering::Relaxed),
            )
            .field(
                "rejected_connections",
                shared.metrics.rejected_connections.load(Ordering::Relaxed),
            )
            .field(
                "login_attempts",
                shared.metrics.login_attempts.load(Ordering::Relaxed),
            )
            .field(
                "direct_login_connections",
                shared
                    .metrics
                    .direct_login_connections
                    .load(Ordering::Relaxed),
            )
            .field(
                "accepted_logins",
                shared.metrics.accepted_logins.load(Ordering::Relaxed),
            )
            .field(
                "source_auth_bypasses",
                shared.metrics.source_auth_bypasses.load(Ordering::Relaxed),
            )
            .field(
                "malformed_tds_messages",
                shared.metrics.malformed_messages.load(Ordering::Relaxed),
            )
            .field(
                "sql_batches",
                shared.metrics.sql_batches.load(Ordering::Relaxed),
            )
            .field(
                "rpc_requests",
                shared.metrics.rpc_requests.load(Ordering::Relaxed),
            )
            .field(
                "payloads_captured",
                shared.metrics.payloads_captured.load(Ordering::Relaxed),
            )
            .field(
                "bytes_captured",
                shared.metrics.bytes_captured.load(Ordering::Relaxed),
            )
            .field(
                "rate_limit_events",
                shared.metrics.rate_limit_events.load(Ordering::Relaxed),
            )
            .field("telemetry_queue_depth", shared.telemetry.queue_depth())
            .field("telemetry_events_dropped", shared.telemetry.dropped())
            .field("classifications", classifications)
            .field(
                "average_session_duration_ms",
                shared
                    .metrics
                    .total_session_duration_ms
                    .load(Ordering::Relaxed)
                    .checked_div(completed)
                    .unwrap_or(0),
            ),
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn diagnostic_prefix_is_safe(stage: &str, prefix: &[u8]) -> bool {
    let stage_is_safe = matches!(
        stage,
        "connection_setup"
            | "initial_probe"
            | "prelogin_read"
            | "prelogin_parse"
            | "prelogin_response"
            | "tls_handshake"
            | "tls8_handshake"
            | "prelogin8_read"
            | "prelogin8_parse"
            | "prelogin8_response"
    );
    stage_is_safe
        && !matches!(
            prefix.first(),
            Some(&crate::tds::LOGIN) | Some(&crate::tds::LOGIN7)
        )
}

impl Shared {
    pub fn record_login_attempt(&self, ip: IpAddr) -> u64 {
        let mut attempts = self
            .login_attempts_by_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = attempts.entry(ip).or_default();
        *count = count.saturating_add(1);
        *count
    }

    pub fn allow_request(&self, ip: IpAddr) -> bool {
        let mut rates = self
            .request_rates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        rates.retain(|_, window| now.duration_since(window.since) < Duration::from_secs(120));
        let window = rates.entry(ip).or_insert(RateWindow {
            since: now,
            count: 0,
        });
        if now.duration_since(window.since) >= Duration::from_secs(60) {
            *window = RateWindow {
                since: now,
                count: 0,
            };
        }
        if window.count >= self.config.limits.max_requests_per_minute_per_ip {
            self.metrics
                .rate_limit_events
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        window.count += 1;
        true
    }

    pub fn record_classification(&self, classification: crate::semantic::Classification) {
        let key = format!("{classification:?}").to_lowercase();
        let mut counts = self
            .metrics
            .classifications
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *counts.entry(key).or_default() += 1;
    }
}

struct IpGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}
impl IpGuard {
    fn acquire(
        counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
        ip: IpAddr,
        maximum: usize,
    ) -> Option<Self> {
        let mut map = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = map.entry(ip).or_default();
        if *count >= maximum {
            return None;
        }
        *count += 1;
        drop(map);
        Some(Self { counts, ip })
    }
}
impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::diagnostic_prefix_is_safe;

    #[test]
    fn never_treats_login_wire_bytes_as_diagnostic_safe() {
        assert!(!diagnostic_prefix_is_safe("prelogin_parse", &[0x02, 0x01]));
        assert!(!diagnostic_prefix_is_safe("prelogin_parse", &[0x10, 0x01]));
        assert!(diagnostic_prefix_is_safe("prelogin_parse", &[0x12, 0x01]));
        assert!(!diagnostic_prefix_is_safe("login_parse", &[0x10, 0x01]));
    }
}
