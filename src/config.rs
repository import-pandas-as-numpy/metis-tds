use std::{fs, net::SocketAddr, path::Path, time::Duration};

use serde::Deserialize;

use crate::{error::Error, personality::Personality};

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listener: ListenerConfig,
    pub tls: TlsConfig,
    pub limits: Limits,
    pub telemetry: TelemetryConfig,
    pub payloads: PayloadConfig,
    pub personality: Personality,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> crate::Result<Self> {
        let raw = fs::read(path)?;
        let config: Self = serde_json::from_slice(&raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> crate::Result<()> {
        self.listener
            .address
            .parse::<SocketAddr>()
            .map_err(|e| Error::Config(format!("listener.address is not a socket address: {e}")))?;
        if self.listener.max_connections == 0
            || self.listener.max_connections_per_ip == 0
            || self.limits.max_packet_bytes < 8
            || self.limits.max_packet_bytes > u16::MAX as usize
            || self.limits.max_message_bytes < self.limits.max_packet_bytes
            || self.limits.max_sql_batch_bytes > self.limits.max_message_bytes
            || self.limits.telemetry_queue_capacity == 0
        {
            return Err(Error::Config(
                "invalid zero or inconsistent resource limit".into(),
            ));
        }
        match self.tls.mode {
            TlsMode::Disabled => {}
            TlsMode::Optional | TlsMode::Preferred | TlsMode::Required => {
                if self.tls.certificate_der.is_none() || self.tls.private_key_der.is_none() {
                    return Err(Error::Config(
                        "TLS optional/required needs certificate_der and private_key_der".into(),
                    ));
                }
            }
        }
        if self.personality.databases.is_empty() {
            return Err(Error::Config(
                "personality.databases may not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    pub address: String,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub login_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_session_seconds: u64,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:1433".into(),
            max_connections: 256,
            max_connections_per_ip: 20,
            login_timeout_seconds: 15,
            idle_timeout_seconds: 300,
            max_session_seconds: 3600,
        }
    }
}

impl ListenerConfig {
    pub fn login_timeout(&self) -> Duration {
        Duration::from_secs(self.login_timeout_seconds)
    }
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }
    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.max_session_seconds)
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    Disabled,
    Optional,
    Preferred,
    Required,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub mode: TlsMode,
    pub certificate_der: Option<String>,
    pub private_key_der: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::Disabled,
            certificate_der: None,
            private_key_der: None,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_packet_bytes: usize,
    pub max_message_bytes: usize,
    pub max_sql_batch_bytes: usize,
    pub max_rpc_parameter_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_requests_per_session: u64,
    pub max_requests_per_minute_per_ip: u64,
    pub telemetry_queue_capacity: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packet_bytes: 32_768,
            max_message_bytes: 8 * 1024 * 1024,
            max_sql_batch_bytes: 1024 * 1024,
            max_rpc_parameter_bytes: 1024 * 1024,
            max_payload_bytes: 16 * 1024 * 1024,
            max_requests_per_session: 10_000,
            max_requests_per_minute_per_ip: 1200,
            telemetry_queue_capacity: 8192,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub jsonl_path: Option<String>,
    pub stdout: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            jsonl_path: Some("events.jsonl".into()),
            stdout: true,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PayloadConfig {
    pub enabled: bool,
    pub directory: String,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: "payloads".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_configuration_loads_and_validates() {
        Config::load("config/example.json").unwrap();
    }
}
