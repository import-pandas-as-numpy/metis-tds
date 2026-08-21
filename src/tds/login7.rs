use crate::{Error, Result};

const FIXED_LENGTH: usize = 94;

#[derive(Clone, Debug, Default)]
pub struct LoginRequest {
    pub tds_version: u32,
    pub packet_size: u32,
    pub option_flags_1: u8,
    pub option_flags_2: u8,
    pub type_flags: u8,
    pub option_flags_3: u8,
    pub client_hostname: String,
    pub username: String,
    pub(crate) password: Option<String>,
    pub password_present: bool,
    pub application_name: String,
    pub server_name: String,
    pub client_library: String,
    pub language: String,
    pub database: String,
    pub integrated_security: bool,
}

impl LoginRequest {
    pub(crate) fn discard_password(&mut self) {
        self.password = None;
    }
}

pub fn parse(payload: &[u8]) -> Result<LoginRequest> {
    if payload.len() < FIXED_LENGTH {
        return Err(Error::Protocol("LOGIN7 fixed header is truncated".into()));
    }
    let declared = usize::try_from(le_u32(payload, 0)?)
        .map_err(|_| Error::Protocol("LOGIN7 length overflow".into()))?;
    if declared < FIXED_LENGTH || declared > payload.len() {
        return Err(Error::Protocol("LOGIN7 declared length is invalid".into()));
    }
    let option_flags_2 = payload[25];
    let username = field(payload, 40, declared, false)?;
    let password_raw = raw_field(payload, 44, declared)?;
    let password_present = !password_raw.is_empty();
    let password = if password_present {
        Some(deobfuscate_password(password_raw)?)
    } else {
        None
    };
    Ok(LoginRequest {
        tds_version: le_u32(payload, 4)?,
        packet_size: le_u32(payload, 8)?,
        option_flags_1: payload[24],
        option_flags_2,
        type_flags: payload[26],
        option_flags_3: payload[27],
        client_hostname: field(payload, 36, declared, false)?,
        username,
        password,
        password_present,
        application_name: field(payload, 48, declared, false)?,
        server_name: field(payload, 52, declared, false)?,
        client_library: field(payload, 60, declared, false)?,
        language: field(payload, 64, declared, false)?,
        database: field(payload, 68, declared, false)?,
        integrated_security: option_flags_2 & 0x80 != 0,
    })
}

fn raw_field(payload: &[u8], descriptor_offset: usize, declared: usize) -> Result<&[u8]> {
    let descriptor = payload
        .get(descriptor_offset..descriptor_offset + 4)
        .ok_or_else(|| Error::Protocol("LOGIN7 field descriptor truncated".into()))?;
    let offset = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let chars = usize::from(u16::from_le_bytes([descriptor[2], descriptor[3]]));
    let bytes = chars
        .checked_mul(2)
        .ok_or_else(|| Error::Protocol("LOGIN7 field length overflow".into()))?;
    // MS-TDS explicitly says the offset must be ignored when a variable field
    // has zero length. The hostname descriptor is the sole exception because
    // it identifies the beginning of the variable-length portion.
    if bytes == 0 {
        if descriptor_offset == 36 && !(FIXED_LENGTH..=declared).contains(&offset) {
            return Err(Error::Protocol(
                "LOGIN7 hostname offset does not identify variable data".into(),
            ));
        }
        return Ok(&[]);
    }
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| Error::Protocol("LOGIN7 field offset overflow".into()))?;
    if end > declared || offset < FIXED_LENGTH {
        return Err(Error::Protocol("LOGIN7 field is outside message".into()));
    }
    Ok(&payload[offset..end])
}

fn field(
    payload: &[u8],
    descriptor_offset: usize,
    declared: usize,
    allow_nul: bool,
) -> Result<String> {
    let raw = raw_field(payload, descriptor_offset, declared)?;
    decode_utf16(raw, allow_nul)
}

fn decode_utf16(raw: &[u8], allow_nul: bool) -> Result<String> {
    if raw.len() % 2 != 0 {
        return Err(Error::Protocol("odd-length UTF-16 field".into()));
    }
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let decoded: String = char::decode_utf16(units)
        .map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if !allow_nul && decoded.contains('\0') {
        return Err(Error::Protocol("NUL in LOGIN7 text field".into()));
    }
    Ok(decoded)
}

fn deobfuscate_password(raw: &[u8]) -> Result<String> {
    let clear: Vec<u8> = raw
        .iter()
        .map(|byte| {
            let x = byte ^ 0xa5;
            x.rotate_left(4)
        })
        .collect();
    decode_utf16(&clear, false)
}

fn le_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Protocol("truncated LOGIN7 integer".into()))?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed_offsets_without_panicking() {
        for len in 0..120 {
            let _ = parse(&vec![0xff; len]);
        }
    }
    #[test]
    fn password_transform_matches_tds_obfuscation() {
        let original: Vec<u8> = "Secret".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded: Vec<u8> = original.iter().map(|b| b.rotate_right(4) ^ 0xa5).collect();
        assert_eq!(deobfuscate_password(&encoded).unwrap(), "Secret");
    }

    #[test]
    fn ignores_offsets_for_empty_variable_fields() {
        let mut payload = vec![0_u8; FIXED_LENGTH];
        payload[0..4].copy_from_slice(&(FIXED_LENGTH as u32).to_le_bytes());
        payload[36..38].copy_from_slice(&(FIXED_LENGTH as u16).to_le_bytes());
        for descriptor in [40, 44, 48, 52, 60, 64, 68] {
            payload[descriptor..descriptor + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        }
        let login = parse(&payload).unwrap();
        assert!(login.username.is_empty());
        assert!(!login.password_present);
    }
}
