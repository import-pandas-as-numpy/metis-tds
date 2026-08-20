use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

const HEADER_LEN: usize = 8;
const STATUS_EOM: u8 = 0x01;
const VALID_CLIENT_STATUS: u8 = 0x39;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub packet_type: u8,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub window: u8,
}

impl Header {
    pub fn decode(raw: [u8; HEADER_LEN], max_packet: usize) -> Result<Self> {
        let length = u16::from_be_bytes([raw[2], raw[3]]);
        if usize::from(length) < HEADER_LEN || usize::from(length) > max_packet {
            return Err(Error::Protocol(format!(
                "invalid TDS packet length {length}"
            )));
        }
        if raw[1] & !VALID_CLIENT_STATUS != 0 {
            return Err(Error::Protocol(format!(
                "invalid TDS status flags 0x{:02x}",
                raw[1]
            )));
        }
        Ok(Self {
            packet_type: raw[0],
            status: raw[1],
            length,
            spid: u16::from_be_bytes([raw[4], raw[5]]),
            packet_id: raw[6],
            window: raw[7],
        })
    }

    pub fn encode(self) -> [u8; HEADER_LEN] {
        let length = self.length.to_be_bytes();
        let spid = self.spid.to_be_bytes();
        [
            self.packet_type,
            self.status,
            length[0],
            length[1],
            spid[0],
            spid[1],
            self.packet_id,
            self.window,
        ]
    }

    pub fn is_eom(self) -> bool {
        self.status & STATUS_EOM != 0
    }
}

#[derive(Debug)]
pub struct Message {
    pub packet_type: u8,
    pub payload: Vec<u8>,
    pub packet_count: u32,
}

pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_packet: usize,
    max_message: usize,
) -> Result<Message> {
    let mut assembled = Vec::new();
    let mut expected_type = None;
    let mut expected_packet_id = None;
    let mut packet_count = 0_u32;
    loop {
        let mut raw = [0_u8; HEADER_LEN];
        reader.read_exact(&mut raw).await?;
        let header = Header::decode(raw, max_packet)?;
        if let Some(expected) = expected_packet_id
            && header.packet_id != expected
        {
            return Err(Error::Protocol(format!(
                "unexpected TDS packet id {}, expected {expected}",
                header.packet_id
            )));
        }
        expected_packet_id = Some(header.packet_id.wrapping_add(1));
        if let Some(packet_type) = expected_type {
            if packet_type != header.packet_type {
                return Err(Error::Protocol(
                    "packet type changed inside a message".into(),
                ));
            }
        } else {
            expected_type = Some(header.packet_type);
        }
        let body_len = usize::from(header.length) - HEADER_LEN;
        if assembled
            .len()
            .checked_add(body_len)
            .is_none_or(|size| size > max_message)
        {
            return Err(Error::Limit("maximum reassembled TDS message size"));
        }
        let start = assembled.len();
        assembled.resize(start + body_len, 0);
        reader.read_exact(&mut assembled[start..]).await?;
        packet_count = packet_count
            .checked_add(1)
            .ok_or(Error::Limit("TDS packet count"))?;
        if header.is_eom() {
            return Ok(Message {
                packet_type: header.packet_type,
                payload: assembled,
                packet_count,
            });
        }
        if packet_count > 65_536 {
            return Err(Error::Limit("TDS packets per message"));
        }
    }
}

pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet_type: u8,
    payload: &[u8],
    packet_size: usize,
) -> Result<u64> {
    if packet_size <= HEADER_LEN || packet_size > u16::MAX as usize {
        return Err(Error::Config("invalid outbound TDS packet size".into()));
    }
    let body_capacity = packet_size - HEADER_LEN;
    let mut written = 0_u64;
    let mut packet_id = 1_u8;
    let mut offset = 0;
    loop {
        let remaining = payload.len().saturating_sub(offset);
        let take = remaining.min(body_capacity);
        let last = offset + take == payload.len();
        let header = Header {
            packet_type,
            status: if last { STATUS_EOM } else { 0 },
            length: u16::try_from(HEADER_LEN + take)
                .map_err(|_| Error::Limit("outbound packet"))?,
            spid: 0,
            packet_id,
            window: 0,
        };
        writer.write_all(&header.encode()).await?;
        writer.write_all(&payload[offset..offset + take]).await?;
        written += u64::from(header.length);
        if last {
            break;
        }
        offset += take;
        packet_id = packet_id.wrapping_add(1).max(1);
    }
    writer.flush().await?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_oversized_headers() {
        assert!(Header::decode([1, 1, 0, 7, 0, 0, 1, 0], 4096).is_err());
        assert!(Header::decode([1, 1, 0x20, 0, 0, 0, 1, 0], 4096).is_err());
        assert!(Header::decode([1, 0x80, 0, 8, 0, 0, 1, 0], 4096).is_err());
    }

    #[tokio::test]
    async fn reassembles_packets_and_splits_responses() {
        let mut wire = Vec::new();
        write_message(&mut wire, 1, b"abcdefghij", 12)
            .await
            .unwrap();
        let mut input = wire.as_slice();
        let message = read_message(&mut input, 12, 100).await.unwrap();
        assert_eq!(message.payload, b"abcdefghij");
        assert_eq!(message.packet_count, 3);
    }
}
