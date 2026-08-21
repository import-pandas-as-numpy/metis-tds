use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

const HEADER_LEN: usize = 8;
const STATUS_EOM: u8 = 0x01;
const STATUS_IGNORE: u8 = 0x02;
const STATUS_RESET_CONNECTION: u8 = 0x08;
const STATUS_RESET_CONNECTION_SKIP_TRAN: u8 = 0x10;

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
                "invalid TDS packet length {length} (type=0x{:02x}, status=0x{:02x}, packet_id={})",
                raw[0], raw[1], raw[6]
            )));
        }
        // MS-TDS requires receivers to ignore undefined status bits. Validate
        // only combinations that the specification explicitly forbids.
        if raw[1] & STATUS_IGNORE != 0 && raw[1] & STATUS_EOM == 0 {
            return Err(Error::Protocol(format!(
                "TDS IGNORE status requires EOM (type=0x{:02x}, status=0x{:02x}, packet_id={})",
                raw[0], raw[1], raw[6]
            )));
        }
        if raw[1] & STATUS_RESET_CONNECTION != 0 && raw[1] & STATUS_RESET_CONNECTION_SKIP_TRAN != 0
        {
            return Err(Error::Protocol(format!(
                "mutually exclusive TDS reset flags (type=0x{:02x}, status=0x{:02x}, packet_id={})",
                raw[0], raw[1], raw[6]
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
    pub first_status: u8,
    pub first_packet_id: u8,
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
    let mut first_header = None;
    let mut packet_count = 0_u32;
    loop {
        let mut raw = [0_u8; HEADER_LEN];
        reader.read_exact(&mut raw).await?;
        let header = Header::decode(raw, max_packet)?;
        // PacketID is advisory and explicitly ignored by receivers in MS-TDS.
        // Real clients normally increment it, but interoperability must not
        // depend on that behavior.
        if let Some(packet_type) = expected_type {
            if packet_type != header.packet_type {
                return Err(Error::Protocol(
                    "packet type changed inside a message".into(),
                ));
            }
        } else {
            expected_type = Some(header.packet_type);
            first_header = Some(header);
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
            let first = first_header.expect("message contains at least one packet");
            return Ok(Message {
                packet_type: header.packet_type,
                first_status: first.status,
                first_packet_id: first.packet_id,
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
    }

    #[test]
    fn accepts_ignore_and_unknown_status_bits_but_rejects_invalid_combinations() {
        assert!(Header::decode([1, 0x03, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert!(Header::decode([1, 0x41, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert!(Header::decode([1, 0x02, 0, 8, 0, 0, 1, 0], 4096).is_err());
        assert!(Header::decode([1, 0x19, 0, 8, 0, 0, 1, 0], 4096).is_err());
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

    #[tokio::test]
    async fn packet_ids_do_not_affect_reassembly() {
        let mut input = Vec::new();
        input.extend_from_slice(&[1, 0, 0, 9, 0, 0, 42, 0, b'a']);
        input.extend_from_slice(&[1, 1, 0, 9, 0, 0, 7, 0, b'b']);
        let message = read_message(&mut input.as_slice(), 4096, 100)
            .await
            .unwrap();
        assert_eq!(message.payload, b"ab");
        assert_eq!(message.first_packet_id, 42);
    }
}
