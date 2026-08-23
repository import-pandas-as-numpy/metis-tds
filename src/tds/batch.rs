use crate::{
    Error, Result,
    tds::{
        all_headers::{self, StreamHeader, StreamKind},
        enclave::{self, LengthEncoding},
    },
};

#[derive(Clone, Debug)]
pub struct BatchRequest {
    pub sql: String,
    pub headers: Vec<StreamHeader>,
    pub enclave_package_bytes: Option<usize>,
}

pub fn decode(payload: &[u8], max_bytes: usize) -> Result<String> {
    Ok(parse(payload, max_bytes)?.sql)
}

pub fn parse(payload: &[u8], max_bytes: usize) -> Result<BatchRequest> {
    parse_with_enclave(payload, max_bytes, false)
}

pub fn parse_with_enclave(
    payload: &[u8],
    max_bytes: usize,
    enclave_package: bool,
) -> Result<BatchRequest> {
    parse_with_enclave_encoding(
        payload,
        max_bytes,
        if enclave_package {
            LengthEncoding::MicrosoftU16
        } else {
            LengthEncoding::None
        },
    )
}

pub fn parse_with_enclave_encoding(
    payload: &[u8],
    max_bytes: usize,
    enclave_encoding: LengthEncoding,
) -> Result<BatchRequest> {
    parse_inner(payload, max_bytes, enclave_encoding, None)
}

pub fn parse_with_context(
    payload: &[u8],
    max_bytes: usize,
    tds72_or_later: bool,
    tds74_or_later: bool,
    enclave_encoding: LengthEncoding,
) -> Result<BatchRequest> {
    parse_inner(
        payload,
        max_bytes,
        enclave_encoding,
        Some((tds72_or_later, tds74_or_later)),
    )
}

fn parse_inner(
    payload: &[u8],
    max_bytes: usize,
    enclave_encoding: LengthEncoding,
    version: Option<(bool, bool)>,
) -> Result<BatchRequest> {
    if payload.len() > max_bytes {
        return Err(Error::Limit("maximum SQL batch size"));
    }
    let (headers, sql) = match version {
        Some((tds72, tds74)) => {
            all_headers::parse_for_version(payload, tds72, tds74, StreamKind::SqlBatch)?
        }
        None => all_headers::parse(payload)?,
    };
    let (enclave_package_bytes, sql) = enclave::strip(sql, enclave_encoding, max_bytes)?;
    if sql.len() % 2 != 0 {
        return Err(Error::Protocol(
            "SQL_BATCH contains odd-length UTF-16".into(),
        ));
    }
    let sql = char::decode_utf16(
        sql.chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]])),
    )
    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect();
    Ok(BatchRequest {
        sql,
        headers,
        enclave_package_bytes,
    })
}

pub fn decode_legacy(payload: &[u8], max_bytes: usize) -> Result<String> {
    if payload.len() > max_bytes {
        return Err(Error::Limit("maximum SQL batch size"));
    }
    Ok(String::from_utf8_lossy(payload).into_owned())
}

pub fn strip_all_headers(payload: &[u8]) -> Result<&[u8]> {
    all_headers::parse(payload).map(|(_, body)| body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_utf16() {
        let raw: Vec<u8> = "SELECT @@VERSION"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode(&raw, 1024).unwrap(), "SELECT @@VERSION");
    }

    #[test]
    fn decodes_legacy_single_byte_sql() {
        assert_eq!(
            decode_legacy(b"SELECT @@VERSION", 1024).unwrap(),
            "SELECT @@VERSION"
        );
    }

    #[test]
    fn parses_always_encrypted_v2_enclave_prefix() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&3_u16.to_le_bytes());
        raw.extend_from_slice(&[1, 2, 3]);
        raw.extend("SELECT 1".encode_utf16().flat_map(u16::to_le_bytes));
        let batch = parse_with_enclave(&raw, 1024, true).unwrap();
        assert_eq!(batch.enclave_package_bytes, Some(3));
        assert_eq!(batch.sql, "SELECT 1");
    }

    #[test]
    fn parses_published_l_varbyte_enclave_prefix() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&3_i32.to_le_bytes());
        raw.extend_from_slice(&[1, 2, 3]);
        raw.extend("SELECT 2".encode_utf16().flat_map(u16::to_le_bytes));
        let batch = parse_with_enclave_encoding(&raw, 1024, LengthEncoding::SpecU32).unwrap();
        assert_eq!(batch.enclave_package_bytes, Some(3));
        assert_eq!(batch.sql, "SELECT 2");
    }
}
