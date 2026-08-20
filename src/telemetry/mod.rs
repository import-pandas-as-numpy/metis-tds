use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::{
    fs,
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc,
};
use uuid::Uuid;

use crate::{Result, config::TelemetryConfig};

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

impl Event {
    pub fn new(
        event_type: impl Into<String>,
        connection_id: Option<Uuid>,
        session_id: Option<u32>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            timestamp: Utc::now(),
            connection_id,
            session_id,
            fields: BTreeMap::new(),
        }
    }

    pub fn field(mut self, name: impl Into<String>, value: impl Serialize) -> Self {
        let value = serde_json::to_value(value).unwrap_or(Value::Null);
        self.fields.insert(name.into(), value);
        self
    }
}

#[derive(Clone)]
pub struct Telemetry {
    sender: mpsc::Sender<Event>,
    dropped: Arc<AtomicU64>,
}

impl Telemetry {
    pub async fn start(config: TelemetryConfig, capacity: usize) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        tokio::spawn(run_writer(receiver, config, Arc::clone(&dropped)));
        Ok(Self { sender, dropped })
    }

    pub fn emit(&self, event: Event) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn queue_depth(&self) -> usize {
        self.sender.max_capacity() - self.sender.capacity()
    }
}

async fn run_writer(
    mut receiver: mpsc::Receiver<Event>,
    config: TelemetryConfig,
    dropped: Arc<AtomicU64>,
) {
    let mut file = match config.jsonl_path.as_deref() {
        Some(path) => match open_log(path).await {
            Ok(file) => Some(BufWriter::new(file)),
            Err(error) => {
                tracing::error!(%error, path, "unable to open telemetry JSONL sink");
                None
            }
        },
        None => None,
    };
    let mut stdout = BufWriter::new(tokio::io::stdout());
    let mut observed_dropped = 0;
    while let Some(event) = receiver.recv().await {
        let Ok(mut line) = serde_json::to_vec(&event) else {
            continue;
        };
        line.push(b'\n');
        if let Some(sink) = file.as_mut() {
            if let Err(error) = sink.write_all(&line).await {
                tracing::error!(%error, "telemetry file write failed");
                file = None;
            } else {
                let _ = sink.flush().await;
            }
        }
        if config.stdout {
            let _ = stdout.write_all(&line).await;
            let _ = stdout.flush().await;
        }
        let current = dropped.load(Ordering::Relaxed);
        if current > observed_dropped {
            tracing::warn!(
                dropped_events = current,
                "telemetry queue has dropped events"
            );
            observed_dropped = current;
        }
    }
}

async fn open_log(path: &str) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options.open(path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_shape_is_flat_and_has_no_secret_field_by_default() {
        let value = serde_json::to_value(
            Event::new("login_attempt", None, Some(1)).field("username", "sa"),
        )
        .unwrap();
        assert_eq!(value["event_type"], "login_attempt");
        assert_eq!(value["username"], "sa");
        assert!(value.get("password").is_none());
    }
}
