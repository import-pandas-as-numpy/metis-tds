use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("TDS protocol error: {0}")]
    Protocol(String),
    #[error("resource limit exceeded: {0}")]
    Limit(&'static str),
    #[error("authentication rejected")]
    Authentication,
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "configuration",
            Self::Protocol(_) => "protocol",
            Self::Limit(_) => "limit",
            Self::Authentication => "authentication",
            Self::Tls(_) => "tls",
            Self::Io(_) => "io",
            Self::Json(_) => "json",
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
