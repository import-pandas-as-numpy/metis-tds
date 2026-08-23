use crate::{
    Error, Result,
    tds::{
        all_headers::{self, StreamHeader, StreamKind},
        enclave::{self, LengthEncoding},
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionRequest {
    pub request_type: u16,
    pub operation: &'static str,
    pub payload_bytes: usize,
    pub isolation_level: Option<u8>,
    pub name: Option<String>,
    pub begin_after: Option<bool>,
    pub begin_name: Option<String>,
    pub headers: Vec<StreamHeader>,
    pub enclave_package_bytes: Option<usize>,
}

pub fn parse(payload: &[u8]) -> Result<TransactionRequest> {
    parse_with_enclave(payload, false)
}

pub fn parse_with_enclave(payload: &[u8], enclave_package: bool) -> Result<TransactionRequest> {
    parse_with_enclave_encoding(
        payload,
        if enclave_package {
            LengthEncoding::MicrosoftU16
        } else {
            LengthEncoding::None
        },
    )
}

pub fn parse_with_enclave_encoding(
    payload: &[u8],
    enclave_encoding: LengthEncoding,
) -> Result<TransactionRequest> {
    parse_inner(payload, enclave_encoding, None)
}

pub fn parse_with_context(
    payload: &[u8],
    tds72_or_later: bool,
    tds74_or_later: bool,
    enclave_encoding: LengthEncoding,
) -> Result<TransactionRequest> {
    parse_inner(
        payload,
        enclave_encoding,
        Some((tds72_or_later, tds74_or_later)),
    )
}

fn parse_inner(
    payload: &[u8],
    enclave_encoding: LengthEncoding,
    version: Option<(bool, bool)>,
) -> Result<TransactionRequest> {
    let (headers, payload) = match version {
        Some((tds72, tds74)) => {
            all_headers::parse_for_version(payload, tds72, tds74, StreamKind::TransactionManager)?
        }
        None => all_headers::parse(payload)?,
    };
    let (enclave_package_bytes, payload) =
        enclave::strip(payload, enclave_encoding, payload.len())?;
    let request_type = le_u16(payload, 0)?;
    let body = &payload[2..];
    let mut result = TransactionRequest {
        request_type,
        operation: operation_name(request_type),
        payload_bytes: body.len(),
        isolation_level: None,
        name: None,
        begin_after: None,
        begin_name: None,
        headers,
        enclave_package_bytes,
    };
    match request_type {
        0 | 1 => {
            let length = usize::from(le_u16(body, 0)?);
            if length != body.len().saturating_sub(2) {
                return Err(Error::Protocol(
                    "transaction US_VARBYTE length mismatch".into(),
                ));
            }
        }
        5 => {
            result.isolation_level = Some(*body.first().ok_or_else(|| {
                Error::Protocol("truncated TM_BEGIN_XACT isolation level".into())
            })?);
            let (name, consumed) = b_varbyte(&body[1..])?;
            ensure_end(body, 1 + consumed)?;
            result.name = Some(String::from_utf8_lossy(name).into_owned());
        }
        6 => ensure_end(body, 0)?,
        7 | 8 => {
            let (name, consumed) = b_varbyte(body)?;
            let flags = *body
                .get(consumed)
                .ok_or_else(|| Error::Protocol("truncated transaction completion flags".into()))?;
            result.name = Some(String::from_utf8_lossy(name).into_owned());
            result.begin_after = Some(flags & 1 != 0);
            let mut position = consumed + 1;
            if flags & 1 != 0 {
                result.isolation_level = Some(*body.get(position).ok_or_else(|| {
                    Error::Protocol("truncated transaction isolation level".into())
                })?);
                position += 1;
                let (begin_name, consumed) = b_varbyte(&body[position..])?;
                result.begin_name = Some(String::from_utf8_lossy(begin_name).into_owned());
                position += consumed;
            }
            ensure_end(body, position)?;
        }
        9 => {
            let (name, consumed) = b_varbyte(body)?;
            ensure_end(body, consumed)?;
            if name.is_empty() {
                return Err(Error::Protocol("TM_SAVE_XACT name is empty".into()));
            }
            result.name = Some(String::from_utf8_lossy(name).into_owned());
        }
        _ => {}
    }
    Ok(result)
}

fn operation_name(value: u16) -> &'static str {
    match value {
        0 => "get_dtc_address",
        1 => "propagate_xact",
        5 => "begin_xact",
        6 => "promote_xact",
        7 => "commit_xact",
        8 => "rollback_xact",
        9 => "save_xact",
        _ => "unknown",
    }
}

fn b_varbyte(input: &[u8]) -> Result<(&[u8], usize)> {
    let length = usize::from(
        *input
            .first()
            .ok_or_else(|| Error::Protocol("truncated transaction B_VARBYTE".into()))?,
    );
    let end = 1_usize
        .checked_add(length)
        .ok_or_else(|| Error::Protocol("transaction B_VARBYTE length overflow".into()))?;
    Ok((
        input
            .get(1..end)
            .ok_or_else(|| Error::Protocol("truncated transaction B_VARBYTE".into()))?,
        end,
    ))
}

fn le_u16(input: &[u8], offset: usize) -> Result<u16> {
    let raw = input
        .get(offset..offset + 2)
        .ok_or_else(|| Error::Protocol("truncated transaction request".into()))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn ensure_end(input: &[u8], position: usize) -> Result<()> {
    if position == input.len() {
        Ok(())
    } else {
        Err(Error::Protocol(
            "unexpected transaction trailing data".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_begin_and_save_requests() {
        let begin = parse(&[5, 0, 2, 3, b'f', b'o', b'o']).unwrap();
        assert_eq!(begin.operation, "begin_xact");
        assert_eq!(begin.isolation_level, Some(2));
        assert_eq!(begin.name.as_deref(), Some("foo"));

        let save = parse(&[9, 0, 2, b's', b'p']).unwrap();
        assert_eq!(save.name.as_deref(), Some("sp"));
    }

    #[test]
    fn retains_commit_begin_after_transaction_name() {
        let parsed = parse(&[7, 0, 3, b'o', b'l', b'd', 1, 2, 3, b'n', b'e', b'w']).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("old"));
        assert_eq!(parsed.begin_after, Some(true));
        assert_eq!(parsed.isolation_level, Some(2));
        assert_eq!(parsed.begin_name.as_deref(), Some("new"));
    }

    #[test]
    fn parses_always_encrypted_v2_enclave_prefix() {
        let parsed = parse_with_enclave(&[2, 0, 0xaa, 0xbb, 6, 0], true).unwrap();
        assert_eq!(parsed.operation, "promote_xact");
        assert_eq!(parsed.enclave_package_bytes, Some(2));
    }
}
