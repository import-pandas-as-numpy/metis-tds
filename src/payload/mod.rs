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
    pub newly_stored: bool,
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
        let sha256: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let storage_id = format!("sha256-{sha256}");
        let root = Path::new(&self.config.directory);
        let path = safe_path(root, &storage_id)?;

        if stored_payload_exists(&path, bytes.len()).await? {
            return Ok(Some(CapturedPayload {
                storage_id,
                sha256,
                size: bytes.len(),
                newly_stored: false,
            }));
        }

        // Write to a private staging file and link it into the content-addressed
        // namespace only after the complete payload has reached disk. A hard link
        // gives us atomic no-clobber publication when identical captures race.
        let staging_id = format!("staging-{}", Uuid::new_v4());
        let staging_path = safe_path(root, &staging_id)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options.open(&staging_path).await?;
        if let Err(error) = async {
            file.write_all(bytes).await?;
            file.flush().await?;
            file.sync_data().await
        }
        .await
        {
            drop(file);
            let _ = fs::remove_file(&staging_path).await;
            return Err(error.into());
        }
        drop(file);

        let publication: Result<bool> = match fs::hard_link(&staging_path, &path).await {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                match stored_payload_exists(&path, bytes.len()).await {
                    Ok(true) => Ok(false),
                    Ok(false) => Err(Error::Config(
                        "content-addressed payload disappeared during capture".into(),
                    )),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error.into()),
        };
        let cleanup = fs::remove_file(&staging_path).await;
        let newly_stored = publication?;
        cleanup?;

        Ok(Some(CapturedPayload {
            storage_id,
            sha256,
            size: bytes.len(),
            newly_stored,
        }))
    }
}

async fn stored_payload_exists(path: &Path, expected_size: usize) -> Result<bool> {
    match fs::metadata(path).await {
        Ok(metadata) if metadata.is_file() && metadata.len() == expected_size as u64 => Ok(true),
        Ok(_) => Err(Error::Config(format!(
            "content-addressed payload path is corrupt: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
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
    async fn stores_once_under_content_address() {
        let temp = tempfile::tempdir().unwrap();
        let store = PayloadStore::new(
            PayloadConfig {
                enabled: true,
                directory: temp.path().to_string_lossy().into_owned(),
                capture_login_messages: false,
                capture_login7: false,
            },
            100,
        )
        .await
        .unwrap();
        let first = store.capture(b"MZ-not-executed").await.unwrap().unwrap();
        let duplicate = store.capture(b"MZ-not-executed").await.unwrap().unwrap();
        assert_eq!(first.size, 15);
        assert_eq!(first.sha256.len(), 64);
        assert_eq!(first.storage_id, format!("sha256-{}", first.sha256));
        assert_eq!(duplicate.storage_id, first.storage_id);
        assert!(first.newly_stored);
        assert!(!duplicate.newly_stored);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(temp.path().join(format!("{}.bin", first.storage_id))).unwrap(),
            b"MZ-not-executed"
        );
    }

    #[tokio::test]
    async fn concurrent_identical_captures_publish_one_file() {
        let temp = tempfile::tempdir().unwrap();
        let store = PayloadStore::new(
            PayloadConfig {
                enabled: true,
                directory: temp.path().to_string_lossy().into_owned(),
                capture_login_messages: false,
                capture_login7: false,
            },
            100,
        )
        .await
        .unwrap();
        let first_store = store.clone();
        let second_store = store.clone();
        let (first, second) = tokio::join!(
            first_store.capture(b"same-payload"),
            second_store.capture(b"same-payload")
        );
        let first = first.unwrap().unwrap();
        let second = second.unwrap().unwrap();

        assert_eq!(first.storage_id, second.storage_id);
        assert_ne!(first.newly_stored, second.newly_stored);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
