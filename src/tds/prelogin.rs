use std::collections::BTreeMap;

use crate::{Error, Result};

pub const VERSION: u8 = 0x00;
pub const ENCRYPTION: u8 = 0x01;
pub const INSTOPT: u8 = 0x02;
pub const THREADID: u8 = 0x03;
pub const MARS: u8 = 0x04;
const TERMINATOR: u8 = 0xff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Encryption {
    Off = 0,
    On = 1,
    NotSupported = 2,
    Required = 3,
}

impl Encryption {
    fn parse(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Off),
            1 => Ok(Self::On),
            2 => Ok(Self::NotSupported),
            3 => Ok(Self::Required),
            _ => Err(Error::Protocol(format!(
                "invalid PRELOGIN encryption value {value}"
            ))),
        }
    }
}

#[derive(Debug, Default)]
pub struct Prelogin {
    pub version: Option<[u8; 6]>,
    pub encryption: Option<Encryption>,
    pub instance: Option<String>,
    pub thread_id: Option<u32>,
    pub mars: Option<bool>,
    pub unknown_tokens: Vec<u8>,
}

pub fn parse(payload: &[u8]) -> Result<Prelogin> {
    let mut cursor = 0;
    let mut entries = BTreeMap::new();
    loop {
        let token = *payload
            .get(cursor)
            .ok_or_else(|| Error::Protocol("truncated PRELOGIN option table".into()))?;
        cursor += 1;
        if token == TERMINATOR {
            break;
        }
        let descriptor = payload
            .get(cursor..cursor + 4)
            .ok_or_else(|| Error::Protocol("truncated PRELOGIN descriptor".into()))?;
        cursor += 4;
        let offset = usize::from(u16::from_be_bytes([descriptor[0], descriptor[1]]));
        let length = usize::from(u16::from_be_bytes([descriptor[2], descriptor[3]]));
        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::Protocol("PRELOGIN offset overflow".into()))?;
        if end > payload.len() || offset < cursor {
            return Err(Error::Protocol(
                "PRELOGIN option is out of bounds or overlaps its table".into(),
            ));
        }
        if entries.insert(token, (offset, end)).is_some() {
            return Err(Error::Protocol("duplicate PRELOGIN token".into()));
        }
    }
    let mut result = Prelogin::default();
    let mut intervals: Vec<(usize, usize)> = entries.values().copied().collect();
    intervals.sort_unstable_by_key(|(start, _)| *start);
    let mut previous_end = cursor;
    for (start, end) in intervals {
        if start < previous_end {
            return Err(Error::Protocol("overlapping PRELOGIN option data".into()));
        }
        previous_end = end;
    }
    for (token, (start, end)) in entries {
        let value = &payload[start..end];
        match token {
            VERSION if value.len() == 6 => {
                result.version = Some(value.try_into().expect("length checked"))
            }
            ENCRYPTION if value.len() == 1 => {
                result.encryption = Some(Encryption::parse(value[0])?)
            }
            INSTOPT => {
                result.instance = Some(
                    String::from_utf8_lossy(value)
                        .trim_end_matches('\0')
                        .to_owned(),
                )
            }
            THREADID if value.len() == 4 => {
                result.thread_id = Some(u32::from_be_bytes(
                    value.try_into().expect("length checked"),
                ))
            }
            MARS if value.len() == 1 => result.mars = Some(value[0] != 0),
            VERSION | ENCRYPTION | THREADID | MARS => {
                return Err(Error::Protocol(format!(
                    "invalid PRELOGIN token length for {token}"
                )));
            }
            _ => result.unknown_tokens.push(token),
        }
    }
    Ok(result)
}

pub fn encode_response(encryption: Encryption, instance: &str) -> Vec<u8> {
    let values: [(u8, Vec<u8>); 5] = [
        (VERSION, vec![16, 0, 16, 89, 0, 0]),
        (ENCRYPTION, vec![encryption as u8]),
        (INSTOPT, {
            let mut v = instance.as_bytes().to_vec();
            v.push(0);
            v
        }),
        (THREADID, vec![0, 0, 0, 0]),
        (MARS, vec![0]),
    ];
    let table_len = values.len() * 5 + 1;
    let mut output =
        Vec::with_capacity(table_len + values.iter().map(|(_, v)| v.len()).sum::<usize>());
    let mut offset = table_len;
    for (token, value) in &values {
        output.push(*token);
        output.extend_from_slice(&u16::try_from(offset).unwrap_or(u16::MAX).to_be_bytes());
        output.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        offset += value.len();
    }
    output.push(TERMINATOR);
    for (_, value) in values {
        output.extend_from_slice(&value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_round_trips() {
        let raw = encode_response(Encryption::NotSupported, "MSSQLSERVER");
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.encryption, Some(Encryption::NotSupported));
        assert_eq!(parsed.instance.as_deref(), Some("MSSQLSERVER"));
    }
    #[test]
    fn arbitrary_data_never_panics() {
        for length in 0..128 {
            let _ = parse(&vec![0xa5; length]);
        }
    }
}
