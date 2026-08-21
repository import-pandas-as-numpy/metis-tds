use std::{
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::{Error, Result, config::TlsConfig};

const HEADER_LEN: usize = 8;
const HANDSHAKE_PACKET_SIZE: usize = 16_384;

pub async fn acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let certificate_path = config
        .certificate_der
        .as_deref()
        .ok_or_else(|| Error::Config("missing TLS certificate DER".into()))?;
    let key_path = config
        .private_key_der
        .as_deref()
        .ok_or_else(|| Error::Config("missing TLS private key DER".into()))?;
    let certificate = read_bounded(certificate_path, 1024 * 1024).await?;
    let key = read_bounded(key_path, 1024 * 1024).await?;
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .map_err(|error| Error::Tls(error.to_string()))?;
    server.alpn_protocols = vec![b"tds/8.0".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server)))
}

async fn read_bounded(path: impl AsRef<Path>, max: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(&path).await?;
    if metadata.len() > max {
        return Err(Error::Limit("TLS key or certificate file size"));
    }
    Ok(fs::read(path).await?)
}

pub async fn handshake<S>(stream: S, acceptor: &TlsAcceptor) -> Result<TlsStream<TdsTlsIo<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tls = acceptor
        .accept(TdsTlsIo::new(stream))
        .await
        .map_err(|e| Error::Tls(e.to_string()))?;
    tls.get_mut().0.enable_raw_mode();
    tls.flush().await?;
    Ok(tls)
}

pub async fn handshake_raw<S>(stream: S, acceptor: &TlsAcceptor) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tls = acceptor
        .accept(stream)
        .await
        .map_err(|error| Error::Tls(error.to_string()))?;
    tls.flush().await?;
    Ok(tls)
}

/// Adapts TLS handshake bytes to SQL Server's PRELOGIN packet encapsulation.
/// After the handshake, it switches to raw TCP so rustls carries complete TDS messages.
pub struct TdsTlsIo<S> {
    inner: S,
    raw_read: bool,
    raw_write: bool,
    read_header: [u8; HEADER_LEN],
    read_header_pos: usize,
    read_payload: Vec<u8>,
    read_payload_filled: usize,
    read_payload_pos: usize,
    pending_write: Vec<u8>,
    pending_write_pos: usize,
    accepted_write_len: usize,
}

impl<S> TdsTlsIo<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            raw_read: false,
            raw_write: false,
            read_header: [0; HEADER_LEN],
            read_header_pos: 0,
            read_payload: Vec::new(),
            read_payload_filled: 0,
            read_payload_pos: 0,
            pending_write: Vec::new(),
            pending_write_pos: 0,
            accepted_write_len: 0,
        }
    }

    fn enable_raw_mode(&mut self) {
        tracing::trace!("switching TDS TLS transport to raw record mode");
        self.raw_read = true;
        self.raw_write = true;
        self.read_payload.clear();
        self.pending_write.clear();
        self.read_header_pos = 0;
        self.read_payload_filled = 0;
        self.read_payload_pos = 0;
        self.pending_write_pos = 0;
        self.accepted_write_len = 0;
    }
}

impl<S: AsyncWrite + Unpin> TdsTlsIo<S> {
    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_write_pos < self.pending_write.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &self.pending_write[self.pending_write_pos..])
            {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(written)) => self.pending_write_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TdsTlsIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.raw_read {
            return Pin::new(&mut self.inner).poll_read(cx, output);
        }
        loop {
            if !self.read_payload.is_empty()
                && self.read_payload_filled == self.read_payload.len()
                && self.read_payload_pos < self.read_payload.len()
            {
                let take = output
                    .remaining()
                    .min(self.read_payload.len() - self.read_payload_pos);
                output.put_slice(
                    &self.read_payload[self.read_payload_pos..self.read_payload_pos + take],
                );
                self.read_payload_pos += take;
                if self.read_payload_pos == self.read_payload.len() {
                    let handshake_complete = final_client_handshake_flight(&self.read_payload);
                    self.read_payload.clear();
                    self.read_payload_filled = 0;
                    self.read_payload_pos = 0;
                    if handshake_complete {
                        // The client switches to raw TLS records immediately
                        // after its final handshake flight. Switch writes here
                        // as well so post-handshake tickets are not TDS-wrapped.
                        self.raw_read = true;
                        self.raw_write = true;
                    }
                }
                return Poll::Ready(Ok(()));
            }
            while self.read_header_pos < HEADER_LEN && self.read_payload.is_empty() {
                let start = self.read_header_pos;
                let mut temporary = [0_u8; HEADER_LEN];
                let mut buf = ReadBuf::new(&mut temporary[..HEADER_LEN - start]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    Poll::Ready(Ok(())) => {
                        let count = buf.filled().len();
                        self.read_header[start..start + count].copy_from_slice(buf.filled());
                        self.read_header_pos += count;
                    }
                    other => return other,
                }
            }
            if self.read_payload.is_empty() {
                let length = usize::from(u16::from_be_bytes([
                    self.read_header[2],
                    self.read_header[3],
                ]));
                if self.read_header[0] != crate::tds::PRELOGIN
                    || length < HEADER_LEN
                    || length > u16::MAX as usize
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid TDS-wrapped TLS packet",
                    )));
                }
                self.read_payload.resize(length - HEADER_LEN, 0);
                self.read_payload_filled = 0;
            }
            while self.read_payload_filled < self.read_payload.len() {
                let position = self.read_payload_filled;
                let remaining = self.read_payload.len() - position;
                let mut temporary = vec![0_u8; remaining.min(HANDSHAKE_PACKET_SIZE)];
                let mut buf = ReadBuf::new(&mut temporary);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    Poll::Ready(Ok(())) => {
                        let count = buf.filled().len();
                        self.read_payload[position..position + count].copy_from_slice(buf.filled());
                        self.read_payload_filled += count;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
            self.read_header_pos = 0;
            self.read_payload_pos = 0;
        }
    }
}

fn final_client_handshake_flight(payload: &[u8]) -> bool {
    match payload.first().copied() {
        // TLS 1.3 encrypts the client's Finished flight as application data.
        Some(0x17) => true,
        // TLS 1.2 final flights can begin with ChangeCipherSpec.
        Some(0x14) => true,
        // A plaintext handshake record whose first handshake message is not
        // ClientHello is a TLS 1.2 final flight. ClientHello remains wrapped,
        // including a second ClientHello after HelloRetryRequest.
        Some(0x16) if payload.len() > 5 => payload[5] != 0x01,
        _ => false,
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TdsTlsIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.raw_write {
            tracing::trace!(bytes = input.len(), prefix = ?input.get(..input.len().min(5)), "writing raw TLS transport bytes");
            return Pin::new(&mut self.inner).poll_write(cx, input);
        }
        if !self.pending_write.is_empty() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(())) => {
                    let accepted = self.accepted_write_len;
                    self.pending_write.clear();
                    self.pending_write_pos = 0;
                    self.accepted_write_len = 0;
                    return Poll::Ready(Ok(accepted));
                }
                other => return other.map_ok(|()| 0),
            }
        }
        let take = input.len().min(HANDSHAKE_PACKET_SIZE - HEADER_LEN);
        if take == 0 {
            return Poll::Ready(Ok(0));
        }
        self.pending_write.reserve(HEADER_LEN + take);
        self.pending_write
            .extend_from_slice(&[crate::tds::PRELOGIN, 1]);
        self.pending_write.extend_from_slice(
            &u16::try_from(HEADER_LEN + take)
                .expect("bounded")
                .to_be_bytes(),
        );
        self.pending_write.extend_from_slice(&[0, 0, 1, 0]);
        self.pending_write.extend_from_slice(&input[..take]);
        tracing::trace!(bytes = take, prefix = ?input.get(..take.min(5)), "writing TDS-wrapped TLS handshake bytes");
        self.accepted_write_len = take;
        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_write.clear();
                self.pending_write_pos = 0;
                self.accepted_write_len = 0;
                Poll::Ready(Ok(take))
            }
            other => other.map_ok(|()| 0),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.raw_write && !self.pending_write.is_empty() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write.clear();
                    self.pending_write_pos = 0;
                    self.accepted_write_len = 0;
                }
                other => return other,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::final_client_handshake_flight;

    #[test]
    fn distinguishes_client_hello_retries_from_final_tls_flights() {
        assert!(!final_client_handshake_flight(&[0x16, 3, 3, 0, 1, 0x01]));
        assert!(final_client_handshake_flight(&[0x16, 3, 3, 0, 1, 0x10]));
        assert!(final_client_handshake_flight(&[0x17, 3, 3, 0, 1, 0]));
        assert!(final_client_handshake_flight(&[0x14, 3, 3, 0, 1, 1]));
    }
}
