use crate::{Error, Result};

pub fn decode(payload: &[u8], max_bytes: usize) -> Result<String> {
    if payload.len() > max_bytes {
        return Err(Error::Limit("maximum SQL batch size"));
    }
    let sql = strip_all_headers(payload)?;
    if sql.len() % 2 != 0 {
        return Err(Error::Protocol(
            "SQL_BATCH contains odd-length UTF-16".into(),
        ));
    }
    Ok(char::decode_utf16(
        sql.chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]])),
    )
    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect())
}

pub fn decode_legacy(payload: &[u8], max_bytes: usize) -> Result<String> {
    if payload.len() > max_bytes {
        return Err(Error::Limit("maximum SQL batch size"));
    }
    Ok(String::from_utf8_lossy(payload).into_owned())
}

pub fn strip_all_headers(payload: &[u8]) -> Result<&[u8]> {
    if payload.len() < 4 {
        return Ok(payload);
    }
    let total = usize::try_from(u32::from_le_bytes(
        payload[..4].try_into().expect("length checked"),
    ))
    .unwrap_or(usize::MAX);
    if total == 0 {
        return Err(Error::Protocol("zero AllHeaders length".into()));
    }
    // AllHeaders begins with its own total length and is at least 18 bytes in normal TDS 7.2 traffic.
    if total >= 18 && total <= payload.len() {
        Ok(&payload[total..])
    } else {
        Ok(payload)
    }
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
}
