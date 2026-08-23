#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SspiToken {
    pub family: &'static str,
    pub message_type: Option<u32>,
    pub bytes: usize,
    pub ntlm: Option<NtlmAuthenticate>,
    pub parse_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtlmAuthenticate {
    pub domain: String,
    pub username: String,
    pub workstation: String,
    pub lm_response_bytes: usize,
    pub nt_response_bytes: usize,
    pub nt_response_variant: &'static str,
    pub encrypted_session_key_bytes: usize,
    pub negotiate_flags: Option<u32>,
}

pub fn parse(payload: &[u8]) -> SspiToken {
    let embedded_ntlm = payload
        .windows(8)
        .position(|window| window == b"NTLMSSP\0")
        .map(|offset| &payload[offset..]);
    if let Some(ntlm) = embedded_ntlm {
        let message_type = ntlm
            .get(8..12)
            .map(|raw| u32::from_le_bytes(raw.try_into().expect("length checked")));
        let mut parse_warnings = Vec::new();
        let authenticate = if message_type == Some(3) {
            match parse_ntlm_authenticate(ntlm) {
                Ok(value) => Some(value),
                Err(error) => {
                    parse_warnings.push(error);
                    None
                }
            }
        } else {
            None
        };
        SspiToken {
            family: if ntlm.len() == payload.len() {
                "ntlmssp"
            } else {
                "spnego_ntlmssp"
            },
            message_type,
            bytes: payload.len(),
            ntlm: authenticate,
            parse_warnings,
        }
    } else if payload.first() == Some(&0x60) {
        SspiToken {
            family: "spnego",
            message_type: None,
            bytes: payload.len(),
            ntlm: None,
            parse_warnings: Vec::new(),
        }
    } else if payload.first() == Some(&0x6e) {
        SspiToken {
            family: "kerberos_ap_req",
            message_type: None,
            bytes: payload.len(),
            ntlm: None,
            parse_warnings: Vec::new(),
        }
    } else {
        SspiToken {
            family: if payload.is_empty() {
                "empty"
            } else {
                "unknown"
            },
            message_type: None,
            bytes: payload.len(),
            ntlm: None,
            parse_warnings: Vec::new(),
        }
    }
}

pub fn ntlm_challenge(server_name: &str, challenge: [u8; 8]) -> Vec<u8> {
    const FLAGS: u32 = 0x0088_8205;
    let target = utf16(server_name);
    let mut target_info = Vec::new();
    for id in [1_u16, 2, 3, 4] {
        target_info.extend_from_slice(&id.to_le_bytes());
        target_info.extend_from_slice(&(target.len() as u16).to_le_bytes());
        target_info.extend_from_slice(&target);
    }
    target_info.extend_from_slice(&0_u16.to_le_bytes());
    target_info.extend_from_slice(&0_u16.to_le_bytes());
    let target_offset = 48_u32;
    let info_offset = target_offset + target.len() as u32;
    let mut output = Vec::with_capacity(48 + target.len() + target_info.len());
    output.extend_from_slice(b"NTLMSSP\0");
    output.extend_from_slice(&2_u32.to_le_bytes());
    security_buffer(&mut output, target.len(), target_offset);
    output.extend_from_slice(&FLAGS.to_le_bytes());
    output.extend_from_slice(&challenge);
    output.extend_from_slice(&[0; 8]);
    security_buffer(&mut output, target_info.len(), info_offset);
    output.extend_from_slice(&target);
    output.extend_from_slice(&target_info);
    output
}

fn parse_ntlm_authenticate(input: &[u8]) -> Result<NtlmAuthenticate, String> {
    if input.len() < 60 {
        return Err("truncated NTLM authenticate message".into());
    }
    let flags = input
        .get(60..64)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("four-byte negotiate flags")));
    let unicode = flags.is_none_or(|value| value & 1 != 0);
    let lm = security_buffer_value(input, 12)?;
    let nt = security_buffer_value(input, 20)?;
    let domain = decode_text(security_buffer_value(input, 28)?, unicode);
    let username = decode_text(security_buffer_value(input, 36)?, unicode);
    let workstation = decode_text(security_buffer_value(input, 44)?, unicode);
    let session_key = security_buffer_value(input, 52)?;
    Ok(NtlmAuthenticate {
        domain,
        username,
        workstation,
        lm_response_bytes: lm.len(),
        nt_response_bytes: nt.len(),
        nt_response_variant: match nt.len() {
            24 => "ntlmv1_or_ntlm2_session",
            25.. => "ntlmv2",
            _ => "other",
        },
        encrypted_session_key_bytes: session_key.len(),
        negotiate_flags: flags,
    })
}

fn security_buffer_value(input: &[u8], offset: usize) -> Result<&[u8], String> {
    let descriptor = input
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated NTLM security buffer".to_owned())?;
    let length = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let maximum = usize::from(u16::from_le_bytes([descriptor[2], descriptor[3]]));
    if length > maximum {
        return Err("NTLM security-buffer length exceeds maximum".into());
    }
    let start = usize::try_from(u32::from_le_bytes(
        descriptor[4..8].try_into().expect("length checked"),
    ))
    .map_err(|_| "NTLM security-buffer offset overflow".to_owned())?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| "NTLM security-buffer offset overflow".to_owned())?;
    input
        .get(start..end)
        .ok_or_else(|| "NTLM security buffer is outside message".to_owned())
}

fn decode_text(input: &[u8], unicode: bool) -> String {
    if unicode && input.len() % 2 == 0 {
        char::decode_utf16(
            input
                .chunks_exact(2)
                .map(|raw| u16::from_le_bytes([raw[0], raw[1]])),
        )
        .map(|value| value.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
    } else {
        String::from_utf8_lossy(input).into_owned()
    }
}

fn security_buffer(output: &mut Vec<u8>, length: usize, offset: u32) {
    let length = u16::try_from(length).unwrap_or(u16::MAX);
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&offset.to_le_bytes());
}

fn utf16(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ntlm_message_type() {
        let parsed = parse(b"NTLMSSP\0\x03\0\0\0body");
        assert_eq!(parsed.family, "ntlmssp");
        assert_eq!(parsed.message_type, Some(3));
        assert!(parsed.ntlm.is_none());
        assert_eq!(parsed.parse_warnings.len(), 1);
    }

    #[test]
    fn challenge_has_valid_security_buffers() {
        let challenge = ntlm_challenge("SQL-FIN-01", [7; 8]);
        assert_eq!(&challenge[..12], b"NTLMSSP\0\x02\0\0\0");
        assert_eq!(
            security_buffer_value(&challenge, 12).unwrap(),
            utf16("SQL-FIN-01")
        );
        assert_eq!(&challenge[24..32], &[7; 8]);
    }
}
