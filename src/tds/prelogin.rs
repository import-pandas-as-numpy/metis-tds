use std::collections::BTreeMap;

use crate::{Error, Result};

pub const VERSION: u8 = 0x00;
pub const ENCRYPTION: u8 = 0x01;
pub const INSTOPT: u8 = 0x02;
pub const THREADID: u8 = 0x03;
pub const MARS: u8 = 0x04;
pub const TRACEID: u8 = 0x05;
pub const FEDAUTHREQUIRED: u8 = 0x06;
pub const NONCEOPT: u8 = 0x07;
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
    /// Tokens in their original descriptor-table order. VERSION has an
    /// ordering requirement, and the order fingerprints nonconforming clients.
    pub option_order: Vec<u8>,
    pub version: Option<[u8; 6]>,
    pub encryption: Option<Encryption>,
    pub encryption_raw: Option<u8>,
    pub client_certificate: bool,
    pub encryption_extension: bool,
    pub instance: Option<String>,
    pub thread_id: Option<u32>,
    pub mars: Option<bool>,
    pub mars_raw: Option<u8>,
    pub trace_id: Option<[u8; 36]>,
    pub fedauth_required: Option<bool>,
    pub fedauth_required_raw: Option<u8>,
    pub nonce: Option<[u8; 32]>,
    pub unknown_tokens: Vec<u8>,
    pub unknown_token_lengths: BTreeMap<u8, usize>,
    pub parse_warnings: Vec<String>,
}

pub fn parse(payload: &[u8]) -> Result<Prelogin> {
    parse_inner(payload, false)
}

pub fn parse_for_telemetry(payload: &[u8]) -> Result<Prelogin> {
    parse_inner(payload, true)
}

fn parse_inner(payload: &[u8], tolerant: bool) -> Result<Prelogin> {
    let mut cursor = 0;
    let mut entries = BTreeMap::new();
    let mut option_order = Vec::new();
    let mut warnings = Vec::new();
    loop {
        let Some(&token) = payload.get(cursor) else {
            let error = Error::Protocol("truncated PRELOGIN option table".into());
            if tolerant {
                warnings.push(error.to_string());
                break;
            }
            return Err(error);
        };
        cursor += 1;
        if token == TERMINATOR {
            break;
        }
        option_order.push(token);
        let Some(descriptor) = payload.get(cursor..cursor + 4) else {
            let error = Error::Protocol("truncated PRELOGIN descriptor".into());
            if tolerant {
                warnings.push(error.to_string());
                break;
            }
            return Err(error);
        };
        cursor += 4;
        let offset = usize::from(u16::from_be_bytes([descriptor[0], descriptor[1]]));
        let length = usize::from(u16::from_be_bytes([descriptor[2], descriptor[3]]));
        let Some(end) = offset.checked_add(length) else {
            let error = Error::Protocol("PRELOGIN offset overflow".into());
            if tolerant {
                warnings.push(error.to_string());
                continue;
            }
            return Err(error);
        };
        if end > payload.len() || offset < cursor {
            let error =
                Error::Protocol("PRELOGIN option is out of bounds or overlaps its table".into());
            if tolerant {
                warnings.push(error.to_string());
                continue;
            }
            return Err(error);
        }
        if entries.contains_key(&token) {
            let error = Error::Protocol("duplicate PRELOGIN token".into());
            if tolerant {
                warnings.push(error.to_string());
                continue;
            }
            return Err(error);
        }
        entries.insert(token, (offset, end));
    }
    let mut result = Prelogin {
        option_order,
        parse_warnings: warnings,
        ..Prelogin::default()
    };
    if result.option_order.first() != Some(&VERSION) {
        let error =
            Error::Protocol("PRELOGIN VERSION is required and must be the first option".into());
        if tolerant {
            result.parse_warnings.push(error.to_string());
        } else {
            return Err(error);
        }
    }
    let mut intervals: Vec<(usize, usize)> = entries.values().copied().collect();
    intervals.sort_unstable_by_key(|(start, _)| *start);
    let mut previous_end = cursor;
    for (start, end) in intervals {
        if start < previous_end {
            let error = Error::Protocol("overlapping PRELOGIN option data".into());
            if tolerant {
                result.parse_warnings.push(error.to_string());
            } else {
                return Err(error);
            }
        }
        previous_end = previous_end.max(end);
    }
    for (token, (start, end)) in entries {
        let value = &payload[start..end];
        match token {
            VERSION if value.len() == 6 => {
                result.version = Some(value.try_into().expect("length checked"))
            }
            ENCRYPTION if value.len() == 1 => {
                let raw = value[0];
                result.encryption_raw = Some(raw);
                result.client_certificate = raw & 0x80 != 0;
                result.encryption_extension = raw & 0x20 != 0;
                let base = raw & !0xa0;
                match Encryption::parse(base) {
                    Ok(encryption)
                        if !(result.client_certificate
                            && encryption == Encryption::NotSupported) =>
                    {
                        result.encryption = Some(encryption)
                    }
                    Ok(encryption) if tolerant => {
                        result.encryption = Some(encryption);
                        result.parse_warnings.push(
                            "TDS protocol error: PRELOGIN client certificate cannot be combined with ENCRYPT_NOT_SUP"
                                .into(),
                        );
                    }
                    Ok(_) => {
                        return Err(Error::Protocol(
                            "PRELOGIN client certificate cannot be combined with ENCRYPT_NOT_SUP"
                                .into(),
                        ));
                    }
                    Err(error) if tolerant => result.parse_warnings.push(error.to_string()),
                    Err(error) => return Err(error),
                }
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
            MARS if value.len() == 1 => {
                result.mars_raw = Some(value[0]);
                match value[0] {
                    0 | 1 => result.mars = Some(value[0] == 1),
                    raw if tolerant => {
                        result.mars = Some(raw != 0);
                        result.parse_warnings.push(
                            Error::Protocol(format!("invalid PRELOGIN MARS value {raw}"))
                                .to_string(),
                        );
                    }
                    raw => {
                        return Err(Error::Protocol(format!(
                            "invalid PRELOGIN MARS value {raw}"
                        )));
                    }
                }
            }
            TRACEID if value.len() == 36 => {
                result.trace_id = Some(value.try_into().expect("length checked"))
            }
            FEDAUTHREQUIRED if value.len() == 1 => {
                result.fedauth_required_raw = Some(value[0]);
                match value[0] {
                    0 | 1 => result.fedauth_required = Some(value[0] == 1),
                    raw if tolerant => {
                        result.fedauth_required = Some(raw != 0);
                        result.parse_warnings.push(
                            Error::Protocol(format!(
                                "invalid PRELOGIN FEDAUTHREQUIRED value {raw}"
                            ))
                            .to_string(),
                        );
                    }
                    raw => {
                        return Err(Error::Protocol(format!(
                            "invalid PRELOGIN FEDAUTHREQUIRED value {raw}"
                        )));
                    }
                }
            }
            NONCEOPT if value.len() == 32 => {
                result.nonce = Some(value.try_into().expect("length checked"))
            }
            VERSION | ENCRYPTION | THREADID | MARS | TRACEID | FEDAUTHREQUIRED | NONCEOPT => {
                let error = Error::Protocol(format!("invalid PRELOGIN token length for {token}"));
                if tolerant {
                    result.parse_warnings.push(error.to_string());
                } else {
                    return Err(error);
                }
            }
            _ => {
                result.unknown_tokens.push(token);
                result.unknown_token_lengths.insert(token, value.len());
            }
        }
    }
    Ok(result)
}

pub fn encode_request(encryption: Encryption, instance: &str) -> Vec<u8> {
    encode_request_with_nonce(encryption, instance, None)
}

/// Encode a client's PRELOGIN request, optionally advertising federated
/// authentication nonce support. This is primarily useful to protocol clients
/// and end-to-end compatibility tests; server responses replace the supplied
/// nonce with a fresh server nonce.
pub fn encode_request_with_nonce(
    encryption: Encryption,
    instance: &str,
    nonce: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut instance = instance.as_bytes().to_vec();
    instance.push(0);
    encode(encryption as u8, instance, nonce)
}

/// Encode the server's PRELOGIN response.
///
/// MS-TDS defines the response INSTOPT value as a single status byte: zero
/// when the requested instance is valid and one when it is not. It is not an
/// echo of the configured instance name.
pub fn encode_response(encryption: Encryption, instance_matches: bool) -> Vec<u8> {
    encode_response_with_nonce(encryption, instance_matches, None)
}

pub fn encode_response_with_nonce(
    encryption: Encryption,
    instance_matches: bool,
    nonce: Option<[u8; 32]>,
) -> Vec<u8> {
    encode_response_options(encryption, instance_matches, nonce, false)
}

pub fn encode_response_options(
    encryption: Encryption,
    instance_matches: bool,
    nonce: Option<[u8; 32]>,
    client_certificate: bool,
) -> Vec<u8> {
    encode(
        encryption as u8 | if client_certificate { 0x80 } else { 0 },
        vec![u8::from(!instance_matches)],
        nonce,
    )
}

fn encode(encryption: u8, instance: Vec<u8>, nonce: Option<[u8; 32]>) -> Vec<u8> {
    let mut values = vec![
        (VERSION, vec![16, 0, 16, 89, 0, 0]),
        (ENCRYPTION, vec![encryption]),
        (INSTOPT, instance),
        (THREADID, vec![0, 0, 0, 0]),
        (MARS, vec![0]),
    ];
    if let Some(nonce) = nonce {
        values.push((NONCEOPT, nonce.to_vec()));
    }
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
    fn request_round_trips() {
        let raw = encode_request(Encryption::NotSupported, "MSSQLSERVER");
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.encryption, Some(Encryption::NotSupported));
        assert_eq!(parsed.instance.as_deref(), Some("MSSQLSERVER"));
    }

    #[test]
    fn response_uses_one_byte_instance_status() {
        let matched = encode_response(Encryption::On, true);
        let mismatched = encode_response(Encryption::On, false);

        assert_eq!(
            matched,
            [
                0x00, 0x00, 0x1a, 0x00, 0x06, // VERSION descriptor
                0x01, 0x00, 0x20, 0x00, 0x01, // ENCRYPTION descriptor
                0x02, 0x00, 0x21, 0x00, 0x01, // INSTOPT descriptor
                0x03, 0x00, 0x22, 0x00, 0x04, // THREADID descriptor
                0x04, 0x00, 0x26, 0x00, 0x01, // MARS descriptor
                0xff, // terminator
                0x10, 0x00, 0x10, 0x59, 0x00, 0x00, // VERSION
                0x01, // ENCRYPT_ON
                0x00, // instance matches
                0x00, 0x00, 0x00, 0x00, // THREADID
                0x00, // MARS disabled
            ]
        );
        assert_eq!(&mismatched[..33], &matched[..33]);
        assert_eq!(mismatched[33], 1);
        assert_eq!(&mismatched[34..], &matched[34..]);
    }

    #[test]
    fn response_includes_a_server_nonce_when_the_client_requests_one() {
        let raw = encode_response_with_nonce(Encryption::On, true, Some([7; 32]));
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.nonce, Some([7; 32]));
        assert_eq!(parsed.option_order.last(), Some(&NONCEOPT));
    }

    #[test]
    fn response_acknowledges_certificate_authentication() {
        let raw = encode_response_options(Encryption::On, true, None, true);
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.encryption, Some(Encryption::On));
        assert!(parsed.client_certificate);
    }
    #[test]
    fn arbitrary_data_never_panics() {
        for length in 0..128 {
            let _ = parse(&vec![0xa5; length]);
        }
    }

    #[test]
    fn parses_every_standard_prelogin_option() {
        let values: [(u8, Vec<u8>); 8] = [
            (VERSION, vec![16, 0, 16, 89, 0, 0]),
            (ENCRYPTION, vec![Encryption::On as u8]),
            (INSTOPT, b"MSSQLSERVER\0".to_vec()),
            (THREADID, 42_u32.to_be_bytes().to_vec()),
            (MARS, vec![1]),
            (TRACEID, vec![2; 36]),
            (FEDAUTHREQUIRED, vec![1]),
            (NONCEOPT, vec![3; 32]),
        ];
        let table_len = values.len() * 5 + 1;
        let mut payload = Vec::new();
        let mut offset = table_len;
        for (token, value) in &values {
            payload.push(*token);
            payload.extend_from_slice(&(offset as u16).to_be_bytes());
            payload.extend_from_slice(&(value.len() as u16).to_be_bytes());
            offset += value.len();
        }
        payload.push(TERMINATOR);
        for (_, value) in values {
            payload.extend(value);
        }
        let parsed = parse(&payload).unwrap();
        assert_eq!(parsed.thread_id, Some(42));
        assert_eq!(parsed.mars, Some(true));
        assert_eq!(parsed.trace_id, Some([2; 36]));
        assert_eq!(parsed.fedauth_required, Some(true));
        assert_eq!(parsed.nonce, Some([3; 32]));
    }

    #[test]
    fn parses_certificate_authentication_and_reserved_encryption_bit() {
        let mut raw = encode_request(Encryption::On, "");
        let encryption_offset = usize::from(u16::from_be_bytes([raw[6], raw[7]]));
        raw[encryption_offset] = 0xa1;
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.encryption, Some(Encryption::On));
        assert_eq!(parsed.encryption_raw, Some(0xa1));
        assert!(parsed.client_certificate);
        assert!(parsed.encryption_extension);

        raw[encryption_offset] = 0x82;
        assert!(parse(&raw).is_err());
        let parsed = parse_for_telemetry(&raw).unwrap();
        assert_eq!(parsed.encryption, Some(Encryption::NotSupported));
        assert!(parsed.client_certificate);
        assert!(!parsed.parse_warnings.is_empty());
    }

    #[test]
    fn enforces_version_order_but_preserves_nonconforming_telemetry() {
        let mut raw = encode_request(Encryption::On, "");
        let version = raw[0..5].to_vec();
        let encryption = raw[5..10].to_vec();
        raw[0..5].copy_from_slice(&encryption);
        raw[5..10].copy_from_slice(&version);

        assert!(parse(&raw).is_err());
        let parsed = parse_for_telemetry(&raw).unwrap();
        assert_eq!(parsed.option_order[..2], [ENCRYPTION, VERSION]);
        assert_eq!(parsed.version, Some([16, 0, 16, 89, 0, 0]));
        assert_eq!(parsed.encryption, Some(Encryption::On));
        assert!(!parsed.parse_warnings.is_empty());
    }

    #[test]
    fn validates_boolean_options_without_losing_their_raw_values() {
        let values: [(u8, Vec<u8>); 3] = [
            (VERSION, vec![16, 0, 16, 89, 0, 0]),
            (MARS, vec![2]),
            (FEDAUTHREQUIRED, vec![0xfe]),
        ];
        let table_len = values.len() * 5 + 1;
        let mut raw = Vec::new();
        let mut offset = table_len;
        for (token, value) in &values {
            raw.push(*token);
            raw.extend_from_slice(&(offset as u16).to_be_bytes());
            raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
            offset += value.len();
        }
        raw.push(TERMINATOR);
        for (_, value) in values {
            raw.extend(value);
        }

        assert!(parse(&raw).is_err());
        let parsed = parse_for_telemetry(&raw).unwrap();
        assert_eq!(parsed.mars_raw, Some(2));
        assert_eq!(parsed.fedauth_required_raw, Some(0xfe));
        assert_eq!(parsed.parse_warnings.len(), 2);
    }

    #[test]
    fn telemetry_salvages_valid_options_around_bad_descriptors() {
        let mut out_of_bounds = vec![
            VERSION, 0, 11, 0, 6, // valid VERSION
            0x80, 0xff, 0xff, 0, 1, // unknown option outside the message
            TERMINATOR,
        ];
        out_of_bounds.extend_from_slice(&[16, 0, 16, 89, 0, 0]);
        assert!(parse(&out_of_bounds).is_err());
        let parsed = parse_for_telemetry(&out_of_bounds).unwrap();
        assert_eq!(parsed.version, Some([16, 0, 16, 89, 0, 0]));
        assert!(!parsed.parse_warnings.is_empty());

        let mut overlapping = vec![VERSION, 0, 11, 0, 6, ENCRYPTION, 0, 16, 0, 1, TERMINATOR];
        overlapping.extend_from_slice(&[16, 0, 16, 89, 0, 0]);
        assert!(parse(&overlapping).is_err());
        let parsed = parse_for_telemetry(&overlapping).unwrap();
        assert_eq!(parsed.version, Some([16, 0, 16, 89, 0, 0]));
        assert_eq!(parsed.encryption, Some(Encryption::Off));
        assert!(
            parsed
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("overlapping PRELOGIN option data"))
        );
    }

    #[test]
    fn telemetry_keeps_the_first_duplicate_option() {
        let mut raw = vec![
            VERSION, 0, 16, 0, 6, ENCRYPTION, 0, 22, 0, 1, ENCRYPTION, 0, 23, 0, 1, TERMINATOR,
        ];
        raw.extend_from_slice(&[16, 0, 16, 89, 0, 0, 1, 3]);
        assert!(parse(&raw).is_err());
        let parsed = parse_for_telemetry(&raw).unwrap();
        assert_eq!(parsed.encryption, Some(Encryption::On));
        assert!(
            parsed
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("duplicate PRELOGIN token"))
        );
    }
}
