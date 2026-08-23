use serde::Serialize;

use crate::{Error, Result};

pub const HEADER_LEN: usize = 16;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Frame {
    pub flag: u8,
    pub flag_name: &'static str,
    pub session_id: u16,
    pub length: u32,
    pub sequence: u32,
    pub window: u32,
    pub data_bytes: usize,
}

pub fn parse(input: &[u8], max_frame: usize) -> Result<Vec<Frame>> {
    let mut position = 0usize;
    let mut frames = Vec::new();
    while position < input.len() {
        let header = input
            .get(position..position + HEADER_LEN)
            .ok_or_else(|| Error::Protocol("truncated SMP header".into()))?;
        if header[0] != 0x53 {
            return Err(Error::Protocol(format!(
                "invalid SMP identifier 0x{:02x}",
                header[0]
            )));
        }
        let flag = header[1];
        let flag_name = match flag {
            0x01 => "syn",
            0x02 => "ack",
            0x04 => "fin",
            0x08 => "data",
            _ => {
                return Err(Error::Protocol(format!(
                    "invalid combined SMP flags 0x{flag:02x}"
                )));
            }
        };
        let session_id = u16::from_le_bytes([header[2], header[3]]);
        let length = u32::from_le_bytes(header[4..8].try_into().expect("length checked"));
        let length_usize = usize::try_from(length).map_err(|_| Error::Limit("SMP frame"))?;
        if length_usize < HEADER_LEN || length_usize > max_frame {
            return Err(Error::Protocol(format!(
                "invalid SMP frame length {length}"
            )));
        }
        if flag != 0x08 && length_usize != HEADER_LEN {
            return Err(Error::Protocol("SMP control packet contains data".into()));
        }
        let end = position
            .checked_add(length_usize)
            .ok_or(Error::Limit("SMP frame offset"))?;
        input
            .get(position..end)
            .ok_or_else(|| Error::Protocol("truncated SMP frame".into()))?;
        frames.push(Frame {
            flag,
            flag_name,
            session_id,
            length,
            sequence: u32::from_le_bytes(header[8..12].try_into().expect("length checked")),
            window: u32::from_le_bytes(header[12..16].try_into().expect("length checked")),
            data_bytes: length_usize - HEADER_LEN,
        });
        if frames.len() > 65_536 {
            return Err(Error::Limit("SMP frame count"));
        }
        position = end;
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_and_data_frames() {
        let mut raw = vec![0x53, 1, 5, 0, 16, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0];
        raw.extend_from_slice(&[0x53, 8, 5, 0, 19, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0]);
        raw.extend_from_slice(b"tds");
        let frames = parse(&raw, 4096).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].data_bytes, 3);
        assert_eq!(frames[1].sequence, 1);
    }
}
