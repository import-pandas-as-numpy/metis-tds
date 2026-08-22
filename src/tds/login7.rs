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
    pub sspi_bytes: usize,
    pub sspi_token_family: Option<&'static str>,
}

impl LoginRequest {
    pub(crate) fn password_for_capture(&self) -> Option<&str> {
        self.password.as_deref()
    }

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
    let username = field(payload, 40, declared, false, "username")?;
    let password_raw = raw_field(payload, 44, declared, "password")?;
    let password_present = !password_raw.is_empty();
    let password = if password_present {
        Some(deobfuscate_password(password_raw)?)
    } else {
        None
    };
    let sspi = sspi_field(payload, declared)?;
    Ok(LoginRequest {
        tds_version: le_u32(payload, 4)?,
        packet_size: le_u32(payload, 8)?,
        option_flags_1: payload[24],
        option_flags_2,
        type_flags: payload[26],
        option_flags_3: payload[27],
        client_hostname: field(payload, 36, declared, false, "client hostname")?,
        username,
        password,
        password_present,
        application_name: field(payload, 48, declared, false, "application name")?,
        server_name: field(payload, 52, declared, false, "server name")?,
        client_library: field(payload, 60, declared, false, "client library")?,
        language: field(payload, 64, declared, false, "language")?,
        database: field(payload, 68, declared, false, "database")?,
        integrated_security: option_flags_2 & 0x80 != 0,
        sspi_bytes: sspi.len(),
        sspi_token_family: classify_sspi(sspi),
    })
}

fn raw_field<'a>(
    payload: &'a [u8],
    descriptor_offset: usize,
    declared: usize,
    name: &str,
) -> Result<&'a [u8]> {
    let descriptor = payload
        .get(descriptor_offset..descriptor_offset + 4)
        .ok_or_else(|| Error::Protocol("LOGIN7 field descriptor truncated".into()))?;
    let offset = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let chars = usize::from(u16::from_le_bytes([descriptor[2], descriptor[3]]));
    let bytes = chars
        .checked_mul(2)
        .ok_or_else(|| Error::Protocol("LOGIN7 field length overflow".into()))?;
    // Empty fields carry no data, so their offsets cannot safely be validated.
    // Real clients, including legacy direct-LOGIN7 clients, use zero here.
    if bytes == 0 {
        return Ok(&[]);
    }
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| Error::Protocol("LOGIN7 field offset overflow".into()))?;
    if end > declared || offset < FIXED_LENGTH {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} field is outside message (offset={offset}, bytes={bytes}, declared={declared})"
        )));
    }
    Ok(&payload[offset..end])
}

fn sspi_field(payload: &[u8], declared: usize) -> Result<&[u8]> {
    let descriptor = payload
        .get(78..82)
        .ok_or_else(|| Error::Protocol("LOGIN7 SSPI descriptor truncated".into()))?;
    let offset = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let short_length = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    let length = if short_length == u16::MAX {
        usize::try_from(le_u32(payload, 90)?)
            .map_err(|_| Error::Protocol("LOGIN7 SSPI length overflow".into()))?
    } else {
        usize::from(short_length)
    };
    if length == 0 {
        return Ok(&[]);
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::Protocol("LOGIN7 SSPI offset overflow".into()))?;
    if offset < FIXED_LENGTH || end > declared {
        return Err(Error::Protocol(
            "LOGIN7 SSPI field is outside message".into(),
        ));
    }
    Ok(&payload[offset..end])
}

fn classify_sspi(token: &[u8]) -> Option<&'static str> {
    if token.is_empty() {
        None
    } else if token.starts_with(b"NTLMSSP\0") {
        Some("ntlmssp")
    } else if token.first() == Some(&0x60) {
        Some("spnego")
    } else {
        Some("other")
    }
}

fn field(
    payload: &[u8],
    descriptor_offset: usize,
    declared: usize,
    allow_nul: bool,
    name: &str,
) -> Result<String> {
    let raw = raw_field(payload, descriptor_offset, declared, name)?;
    decode_utf16(raw, allow_nul, name)
}

fn decode_utf16(raw: &[u8], allow_nul: bool, name: &str) -> Result<String> {
    if raw.len() % 2 != 0 {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} field has odd-length UTF-16 data"
        )));
    }
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let decoded: String = char::decode_utf16(units)
        .map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if !allow_nul && decoded.contains('\0') {
        return Err(Error::Protocol(format!("LOGIN7 {name} field contains NUL")));
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
    decode_utf16(&clear, false, "password")
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
        for descriptor in [36, 40, 44, 48, 52, 60, 64, 68, 78] {
            payload[descriptor..descriptor + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        }
        let login = parse(&payload).unwrap();
        assert!(login.username.is_empty());
        assert!(!login.password_present);
    }

    #[test]
    fn identifies_the_invalid_variable_field_without_exposing_contents() {
        let mut payload = vec![0_u8; 147];
        payload[0..4].copy_from_slice(&147_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&146_u16.to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());

        let error = parse(&payload).unwrap_err();
        assert_eq!(
            error.to_string(),
            "TDS protocol error: LOGIN7 username field is outside message (offset=146, bytes=4, declared=147)"
        );
    }

    #[test]
    fn identifies_sspi_without_retaining_the_token() {
        let token = b"NTLMSSP\0\x01\0\0\0";
        let mut payload = vec![0_u8; FIXED_LENGTH];
        payload[0..4].copy_from_slice(&((FIXED_LENGTH + token.len()) as u32).to_le_bytes());
        payload[25] = 0x80;
        payload[78..80].copy_from_slice(&(FIXED_LENGTH as u16).to_le_bytes());
        payload[80..82].copy_from_slice(&(token.len() as u16).to_le_bytes());
        payload.extend_from_slice(token);

        let login = parse(&payload).unwrap();
        assert!(login.integrated_security);
        assert_eq!(login.sspi_bytes, token.len());
        assert_eq!(login.sspi_token_family, Some("ntlmssp"));
    }
}
