use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncWriteExt};
use uuid::Uuid;

use crate::{Error, Result, config::PayloadConfig};

#[derive(Clone)]
pub struct PayloadStore {
    config: Arc<PayloadConfig>,
    max_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct CapturedPayload {
    pub storage_id: String,
    pub sha256: String,
    pub size: usize,
}

impl PayloadStore {
    pub async fn new(config: PayloadConfig, max_bytes: usize) -> Result<Self> {
        if config.enabled {
            fs::create_dir_all(&config.directory).await?;
        }
        Ok(Self {
            config: Arc::new(config),
            max_bytes,
        })
    }

    pub async fn capture(&self, bytes: &[u8]) -> Result<Option<CapturedPayload>> {
        if !self.config.enabled {
            return Ok(None);
        }
        if bytes.len() > self.max_bytes {
            return Err(Error::Limit("maximum captured payload size"));
        }
        let storage_id = format!("payload-{}", Uuid::new_v4());
        let path = safe_path(Path::new(&self.config.directory), &storage_id)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options.open(&path).await?;
        file.write_all(bytes).await?;
        file.flush().await?;
        file.sync_data().await?;
        let sha256 = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Some(CapturedPayload {
            storage_id,
            sha256,
            size: bytes.len(),
        }))
    }
}

fn safe_path(root: &Path, generated_id: &str) -> Result<PathBuf> {
    if generated_id
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
    {
        return Err(Error::Config("invalid generated payload identifier".into()));
    }
    Ok(root.join(format!("{generated_id}.bin")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stores_hash_under_generated_name() {
        let temp = tempfile::tempdir().unwrap();
        let store = PayloadStore::new(
            PayloadConfig {
                enabled: true,
                directory: temp.path().to_string_lossy().into_owned(),
            },
            100,
        )
        .await
        .unwrap();
        let capture = store.capture(b"MZ-not-executed").await.unwrap().unwrap();
        assert_eq!(capture.size, 15);
        assert_eq!(capture.sha256.len(), 64);
        assert!(!capture.storage_id.contains("MZ"));
    }
}
