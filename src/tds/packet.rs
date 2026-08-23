use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

const HEADER_LEN: usize = 8;
const STATUS_EOM: u8 = 0x01;
pub const STATUS_SYMMETRIC_ENCRYPTION: u8 = 0x40;

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
        // Status bits are protocol-version-specific. For example, 0x02 is
        // IGNORE in MS-TDS but ATTNACK in legacy/ASE TDS, while 0x08 and 0x10
        // are reset flags in MS-TDS but EVENT and SEAL in ASE. The framing
        // reader runs before negotiation has established that context, so it
        // must preserve rather than reject any status combination.
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
    /// Header and payload-boundary metadata for every packet in the message.
    /// Packet status is not necessarily constant across a multi-packet ASE
    /// message, so retaining only the first header can discard encryption and
    /// reset signals needed to interpret the corresponding payload slice.
    pub packets: Vec<PacketDescriptor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PacketDescriptor {
    pub status: u8,
    pub packet_id: u8,
    pub body_offset: usize,
    pub body_bytes: usize,
}

impl PacketDescriptor {
    pub fn has_symmetric_encryption(self) -> bool {
        self.status & STATUS_SYMMETRIC_ENCRYPTION != 0
    }
}

pub fn microsoft_status_flags(status: u8) -> Vec<&'static str> {
    status_flags(
        status,
        &[
            (0x01, "end_of_message"),
            (0x02, "ignore"),
            (0x08, "reset_connection"),
            (0x10, "reset_connection_skip_transaction"),
        ],
    )
}

pub fn legacy_status_flags(status: u8) -> Vec<&'static str> {
    status_flags(
        status,
        &[
            (0x01, "end_of_message"),
            (0x02, "attention_acknowledgement"),
            (0x04, "attention"),
            (0x08, "event"),
            (0x10, "seal"),
            (0x20, "sql_anywhere_encryption"),
            (0x40, "symmetric_command_encryption"),
        ],
    )
}

fn status_flags(status: u8, meanings: &[(u8, &'static str)]) -> Vec<&'static str> {
    meanings
        .iter()
        .filter_map(|(flag, name)| (status & flag != 0).then_some(*name))
        .collect()
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
    let mut packets = Vec::new();
    loop {
        let mut raw = [0_u8; HEADER_LEN];
        reader.read_exact(&mut raw).await?;
        if raw[0] == 0x53 {
            // SMP/MARS is not negotiated by this server, but retain a bounded
            // control-frame prelude through the first DATA or FIN frame. A
            // normal sequence can begin with SYN, and stopping there would
            // hide a complete inner authentication message already queued by
            // a nonconforming peer. The caller's stage timeout still bounds a
            // client that sends SYN and waits for an ACK we intentionally do
            // not provide.
            let mut smp_wire_bytes = 0usize;
            for frame_count in 1..=256 {
                let length = usize::try_from(u32::from_le_bytes(
                    raw[4..8].try_into().expect("length checked"),
                ))
                .map_err(|_| Error::Limit("SMP frame"))?;
                if !(crate::tds::smp::HEADER_LEN..=max_message).contains(&length) {
                    return Err(Error::Protocol(format!(
                        "invalid SMP frame length {length}"
                    )));
                }
                smp_wire_bytes = smp_wire_bytes
                    .checked_add(length)
                    .ok_or(Error::Limit("SMP ingress bytes"))?;
                if smp_wire_bytes > max_message {
                    return Err(Error::Limit("SMP ingress bytes"));
                }
                let mut rest = vec![0u8; length - HEADER_LEN];
                reader.read_exact(&mut rest).await?;
                if matches!(raw[1], 0x04 | 0x08) || !matches!(raw[1], 0x01 | 0x02) {
                    return Err(Error::Protocol(
                        "SMP/MARS frame received without MARS negotiation".into(),
                    ));
                }
                if frame_count == 256 {
                    return Err(Error::Limit("SMP ingress frame count"));
                }
                reader.read_exact(&mut raw).await?;
                if raw[0] != 0x53 {
                    return Err(Error::Protocol(format!(
                        "invalid SMP identifier 0x{:02x}",
                        raw[0]
                    )));
                }
            }
            unreachable!("bounded SMP frame loop always returns");
        }
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
        packets.push(PacketDescriptor {
            status: header.status,
            packet_id: header.packet_id,
            body_offset: start,
            body_bytes: body_len,
        });
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
                packets,
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
    fn preserves_every_status_combination_for_version_aware_interpretation() {
        assert!(Header::decode([1, 0x03, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert!(Header::decode([1, 0x41, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert!(Header::decode([1, 0x02, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert!(Header::decode([1, 0x19, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert!(Header::decode([1, 0xff, 0, 8, 0, 0, 1, 0], 4096).is_ok());
        assert_eq!(
            microsoft_status_flags(0x19),
            [
                "end_of_message",
                "reset_connection",
                "reset_connection_skip_transaction"
            ]
        );
        assert_eq!(
            legacy_status_flags(0x19),
            ["end_of_message", "event", "seal"]
        );
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
        assert_eq!(message.packets.len(), 3);
        assert_eq!(message.packets[0].body_offset, 0);
        assert_eq!(message.packets[0].body_bytes, 4);
        assert_eq!(message.packets[2].body_offset, 8);
        assert_eq!(message.packets[2].body_bytes, 2);
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
        assert_eq!(message.packets[0].packet_id, 42);
        assert_eq!(message.packets[1].packet_id, 7);
    }

    #[tokio::test]
    async fn retains_per_packet_symmetric_encryption_status_and_boundaries() {
        let mut input = Vec::new();
        input.extend_from_slice(&[15, 0x40, 0, 10, 0, 0, 1, 0, b'a', b'b']);
        input.extend_from_slice(&[15, 0x41, 0, 11, 0, 0, 2, 0, b'c', b'd', b'e']);
        let message = read_message(&mut input.as_slice(), 4096, 100)
            .await
            .unwrap();

        assert_eq!(message.payload, b"abcde");
        assert!(
            message
                .packets
                .iter()
                .all(|packet| packet.has_symmetric_encryption())
        );
        assert_eq!(message.packets[0].body_offset, 0);
        assert_eq!(message.packets[0].body_bytes, 2);
        assert_eq!(message.packets[1].body_offset, 2);
        assert_eq!(message.packets[1].body_bytes, 3);
    }
}
