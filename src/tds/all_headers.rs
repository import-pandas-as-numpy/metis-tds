use std::collections::BTreeSet;

use serde::Serialize;

use crate::{Error, Result};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StreamHeader {
    pub header_type: u16,
    pub name: &'static str,
    pub data_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outstanding_request_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_broker_deployment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_timeout_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_sequence: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    SqlBatch,
    Rpc,
    TransactionManager,
}

pub fn parse(payload: &[u8]) -> Result<(Vec<StreamHeader>, &[u8])> {
    if payload.len() < 4 {
        return Ok((Vec::new(), payload));
    }
    let total = usize::try_from(le_u32(payload, 0)?)
        .map_err(|_| Error::Protocol("AllHeaders total length overflow".into()))?;
    if total == 0 {
        return Err(Error::Protocol("zero AllHeaders length".into()));
    }
    // A valid stream contains TotalLength plus at least one six-byte header.
    // Other values are ordinary request bytes from pre-7.2 clients.
    if total < 10 || total > payload.len() {
        return Ok((Vec::new(), payload));
    }
    let mut position = 4;
    let mut seen = BTreeSet::new();
    let mut headers = Vec::new();
    while position < total {
        let header_length = usize::try_from(le_u32(payload, position)?)
            .map_err(|_| Error::Protocol("AllHeaders header length overflow".into()))?;
        if header_length < 6 {
            return Err(Error::Protocol(
                "AllHeaders header is shorter than 6 bytes".into(),
            ));
        }
        let end = position
            .checked_add(header_length)
            .ok_or_else(|| Error::Protocol("AllHeaders header offset overflow".into()))?;
        if end > total {
            return Err(Error::Protocol(
                "AllHeaders header exceeds TotalLength".into(),
            ));
        }
        let header_type = le_u16(payload, position + 4)?;
        if !seen.insert(header_type) {
            return Err(Error::Protocol(format!(
                "duplicate AllHeaders type {header_type}"
            )));
        }
        headers.push(parse_header(header_type, &payload[position + 6..end])?);
        position = end;
    }
    if position != total {
        return Err(Error::Protocol("AllHeaders length mismatch".into()));
    }
    Ok((headers, &payload[total..]))
}

/// Parse ALL_HEADERS when the negotiated protocol makes it unambiguous.
/// TDS 7.2+ requires a transaction-descriptor header on each applicable
/// request; older requests have no ALL_HEADERS field at all.
pub fn parse_for_version(
    payload: &[u8],
    tds72_or_later: bool,
    tds74_or_later: bool,
    stream: StreamKind,
) -> Result<(Vec<StreamHeader>, &[u8])> {
    if !tds72_or_later {
        return Ok((Vec::new(), payload));
    }
    let (headers, body) = parse_required(payload)?;
    if !headers.iter().any(|header| header.header_type == 2) {
        return Err(Error::Protocol(
            "missing required transaction-descriptor header".into(),
        ));
    }
    for header in &headers {
        match header.header_type {
            1 if stream == StreamKind::TransactionManager => {
                return Err(Error::Protocol(
                    "query-notification header is invalid for transaction manager".into(),
                ));
            }
            3 if !tds74_or_later => {
                return Err(Error::Protocol(
                    "trace-activity header requires TDS 7.4 or later".into(),
                ));
            }
            1..=3 => {}
            value => {
                return Err(Error::Protocol(format!("unknown ALL_HEADERS type {value}")));
            }
        }
    }
    Ok((headers, body))
}

fn parse_required(payload: &[u8]) -> Result<(Vec<StreamHeader>, &[u8])> {
    if payload.len() < 10 {
        return Err(Error::Protocol("missing or truncated ALL_HEADERS".into()));
    }
    let total = usize::try_from(le_u32(payload, 0)?)
        .map_err(|_| Error::Protocol("AllHeaders total length overflow".into()))?;
    if total < 10 || total > payload.len() {
        return Err(Error::Protocol("invalid required AllHeaders length".into()));
    }
    // `parse` can no longer mistake this for an old request because the
    // negotiated version established that ALL_HEADERS is mandatory.
    parse(payload)
}

fn parse_header(header_type: u16, data: &[u8]) -> Result<StreamHeader> {
    let mut result = StreamHeader {
        header_type,
        name: match header_type {
            1 => "query_notifications",
            2 => "transaction_descriptor",
            3 => "trace_activity",
            _ => "unknown",
        },
        data_bytes: data.len(),
        transaction_descriptor: None,
        outstanding_request_count: None,
        notification_id: None,
        service_broker_deployment: None,
        notification_timeout_ms: None,
        activity_id: None,
        activity_sequence: None,
    };
    match header_type {
        1 => {
            let (notification_id, used) = unicode_byte_string(data)?;
            let (deployment, second_used) = unicode_byte_string(&data[used..])?;
            let position = used + second_used;
            result.notification_id = Some(notification_id);
            result.service_broker_deployment = Some(deployment);
            result.notification_timeout_ms = match data.len().saturating_sub(position) {
                0 => None,
                4 => Some(le_u32(data, position)?),
                _ => {
                    return Err(Error::Protocol(
                        "invalid query-notification header length".into(),
                    ));
                }
            };
        }
        2 => {
            if data.len() != 12 {
                return Err(Error::Protocol(
                    "transaction-descriptor header must be 12 bytes".into(),
                ));
            }
            result.transaction_descriptor = Some(hex(&data[..8]));
            result.outstanding_request_count = Some(le_u32(data, 8)?);
        }
        3 => {
            if data.len() != 20 {
                return Err(Error::Protocol(
                    "trace-activity header must be 20 bytes".into(),
                ));
            }
            result.activity_id = Some(hex(&data[..16]));
            result.activity_sequence = Some(le_u32(data, 16)?);
        }
        _ => {}
    }
    Ok(result)
}

fn unicode_byte_string(input: &[u8]) -> Result<(String, usize)> {
    let bytes = usize::from(le_u16(input, 0)?);
    let end = 2_usize
        .checked_add(bytes)
        .ok_or_else(|| Error::Protocol("AllHeaders Unicode length overflow".into()))?;
    let raw = input
        .get(2..end)
        .ok_or_else(|| Error::Protocol("truncated AllHeaders Unicode string".into()))?;
    if raw.len() % 2 != 0 {
        return Err(Error::Protocol(
            "odd AllHeaders Unicode string length".into(),
        ));
    }
    let value = char::decode_utf16(
        raw.chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
    )
    .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect();
    Ok((value, end))
}

fn le_u16(input: &[u8], offset: usize) -> Result<u16> {
    let raw = input
        .get(offset..offset + 2)
        .ok_or_else(|| Error::Protocol("truncated AllHeaders integer".into()))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn le_u32(input: &[u8], offset: usize) -> Result<u32> {
    let raw = input
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Protocol("truncated AllHeaders integer".into()))?;
    Ok(u32::from_le_bytes(raw.try_into().expect("length checked")))
}

fn hex(input: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(input.len() * 2);
    for byte in input {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_standard_header_types() {
        let mut payload = vec![0, 0, 0, 0];
        let headers = [
            (1_u16, {
                let mut value = Vec::new();
                value.extend_from_slice(&2_u16.to_le_bytes());
                value.extend_from_slice(&[b'n', 0]);
                value.extend_from_slice(&2_u16.to_le_bytes());
                value.extend_from_slice(&[b's', 0]);
                value.extend_from_slice(&100_u32.to_le_bytes());
                value
            }),
            (2, [vec![1; 8], 2_u32.to_le_bytes().to_vec()].concat()),
            (3, [vec![3; 16], 4_u32.to_le_bytes().to_vec()].concat()),
        ];
        for (kind, data) in headers {
            payload.extend_from_slice(&((data.len() + 6) as u32).to_le_bytes());
            payload.extend_from_slice(&kind.to_le_bytes());
            payload.extend(data);
        }
        let total = payload.len() as u32;
        payload[0..4].copy_from_slice(&total.to_le_bytes());
        payload.extend_from_slice(b"body");
        let (headers, body) = parse(&payload).unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].notification_id.as_deref(), Some("n"));
        assert_eq!(headers[1].outstanding_request_count, Some(2));
        assert_eq!(headers[2].activity_sequence, Some(4));
        assert_eq!(body, b"body");
    }

    #[test]
    fn versioned_parser_requires_transaction_header_and_rejects_wrong_version_headers() {
        let sql = [b'S', 0, b'E', 0];
        assert_eq!(
            parse_for_version(&sql, false, false, StreamKind::SqlBatch)
                .unwrap()
                .1,
            sql
        );
        assert!(parse_for_version(&sql, true, false, StreamKind::SqlBatch).is_err());

        let mut payload = vec![22, 0, 0, 0, 18, 0, 0, 0, 2, 0];
        payload.extend_from_slice(&[0; 12]);
        payload.extend_from_slice(&sql);
        let (headers, body) =
            parse_for_version(&payload, true, false, StreamKind::SqlBatch).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(body, sql);
    }
}
