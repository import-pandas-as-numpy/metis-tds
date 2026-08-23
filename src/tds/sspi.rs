#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SspiToken {
    pub family: &'static str,
    pub message_type: Option<u32>,
    pub bytes: usize,
    pub ntlm: Option<NtlmAuthenticate>,
    pub ntlm_negotiate: Option<NtlmNegotiate>,
    pub der: Option<DerInventory>,
    pub parse_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerInventory {
    pub mechanism_oids: Vec<String>,
    pub text_values: Vec<String>,
    pub nodes: usize,
    pub indefinite_length_nodes: usize,
    pub complete: bool,
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
    pub(crate) lm_response: Vec<u8>,
    pub(crate) nt_response: Vec<u8>,
    pub(crate) encrypted_session_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtlmNegotiate {
    pub domain: String,
    pub workstation: String,
    pub negotiate_flags: u32,
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
                Ok((value, warnings)) => {
                    parse_warnings.extend(warnings);
                    Some(value)
                }
                Err(error) => {
                    parse_warnings.push(error);
                    None
                }
            }
        } else {
            None
        };
        let negotiate = if message_type == Some(1) {
            match parse_ntlm_negotiate(ntlm) {
                Ok((value, warnings)) => {
                    parse_warnings.extend(warnings);
                    Some(value)
                }
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
            ntlm_negotiate: negotiate,
            der: None,
            parse_warnings,
        }
    } else {
        let family = match payload.first() {
            Some(0x60) => "gss_api",
            Some(0x6e) => "kerberos_ap_req",
            Some(0x6f) => "kerberos_ap_rep",
            Some(0x7e) => "kerberos_error",
            Some(0xa0) => "spnego_neg_token_init",
            Some(0xa1) => "spnego_neg_token_response",
            Some(0x30) => "der_sequence",
            Some(_) => "unknown",
            None => "empty",
        };
        let mut parse_warnings = Vec::new();
        let der = if family != "unknown" && family != "empty" {
            let (inventory, error) = recover_der_inventory(payload);
            parse_warnings.extend(error);
            Some(inventory)
        } else {
            None
        };
        SspiToken {
            family,
            message_type: None,
            bytes: payload.len(),
            ntlm: None,
            ntlm_negotiate: None,
            der,
            parse_warnings,
        }
    }
}

fn recover_der_inventory(input: &[u8]) -> (DerInventory, Option<String>) {
    let mut inventory = DerInventory {
        mechanism_oids: Vec::new(),
        text_values: Vec::new(),
        nodes: 0,
        indefinite_length_nodes: 0,
        complete: false,
    };
    match walk_der(input, 0, &mut inventory) {
        Ok(consumed) if consumed == input.len() => {
            inventory.complete = true;
            (inventory, None)
        }
        Ok(_) => (
            inventory,
            Some("trailing bytes after SSPI DER token".into()),
        ),
        Err(error) => (inventory, Some(error)),
    }
}

fn walk_der(input: &[u8], depth: usize, inventory: &mut DerInventory) -> Result<usize, String> {
    if depth > 32 {
        return Err("SSPI DER nesting exceeds 32 levels".into());
    }
    inventory.nodes += 1;
    if inventory.nodes > 4096 {
        return Err("SSPI DER node count exceeds 4096".into());
    }
    let first = *input
        .first()
        .ok_or_else(|| "truncated SSPI DER tag".to_owned())?;
    let mut header = 1usize;
    if first & 0x1f == 0x1f {
        loop {
            let byte = *input
                .get(header)
                .ok_or_else(|| "truncated SSPI DER high tag number".to_owned())?;
            header += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if header > 8 {
                return Err("SSPI DER tag number is too long".into());
            }
        }
    }
    let initial_length = *input
        .get(header)
        .ok_or_else(|| "truncated SSPI DER length".to_owned())?;
    header += 1;
    let length = if initial_length & 0x80 == 0 {
        usize::from(initial_length)
    } else {
        let octets = usize::from(initial_length & 0x7f);
        if octets == 0 {
            if first & 0x20 == 0 {
                return Err("primitive SSPI BER value has indefinite length".into());
            }
            inventory.indefinite_length_nodes += 1;
            let mut position = header;
            loop {
                let marker = input
                    .get(position..position + 2)
                    .ok_or_else(|| "unterminated indefinite SSPI BER value".to_owned())?;
                if marker == [0, 0] {
                    return position
                        .checked_add(2)
                        .ok_or_else(|| "SSPI BER offset overflow".to_owned());
                }
                position = position
                    .checked_add(walk_der(&input[position..], depth + 1, inventory)?)
                    .ok_or_else(|| "SSPI BER child offset overflow".to_owned())?;
            }
        }
        if octets > std::mem::size_of::<usize>() || octets > 4 {
            return Err("SSPI DER length is too large".into());
        }
        let raw = input
            .get(header..header + octets)
            .ok_or_else(|| "truncated SSPI DER long length".to_owned())?;
        header += octets;
        raw.iter().try_fold(0usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| "SSPI DER length overflow".to_owned())
        })?
    };
    let end = header
        .checked_add(length)
        .ok_or_else(|| "SSPI DER offset overflow".to_owned())?;
    let value = input
        .get(header..end)
        .ok_or_else(|| "truncated SSPI DER value".to_owned())?;

    if first == 0x06 {
        let oid = decode_oid(value)?;
        if !inventory.mechanism_oids.contains(&oid) {
            inventory.mechanism_oids.push(oid);
        }
    } else if matches!(first, 0x0c | 0x13 | 0x16 | 0x1a | 0x1b) {
        retain_der_text(String::from_utf8_lossy(value).into_owned(), inventory);
    } else if first == 0x1e && value.len() % 2 == 0 {
        let text = char::decode_utf16(
            value
                .chunks_exact(2)
                .map(|raw| u16::from_be_bytes([raw[0], raw[1]])),
        )
        .map(|character| character.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
        retain_der_text(text, inventory);
    }

    if first & 0x20 != 0 {
        let mut position = 0usize;
        while position < value.len() {
            position = position
                .checked_add(walk_der(&value[position..], depth + 1, inventory)?)
                .ok_or_else(|| "SSPI DER child offset overflow".to_owned())?;
        }
    }
    Ok(end)
}

fn decode_oid(input: &[u8]) -> Result<String, String> {
    if input.is_empty() {
        return Err("empty SSPI DER object identifier".into());
    }
    let mut arcs = Vec::new();
    let mut value = 0u64;
    let mut continued = false;
    for byte in input {
        value = value
            .checked_mul(128)
            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
            .ok_or_else(|| "SSPI DER object identifier overflow".to_owned())?;
        continued = byte & 0x80 != 0;
        if !continued {
            arcs.push(value);
            value = 0;
        }
    }
    if continued || arcs.is_empty() {
        return Err("truncated SSPI DER object identifier".into());
    }
    let first = arcs.remove(0);
    let first_arc = first.min(80) / 40;
    let second_arc = first - first_arc * 40;
    let mut output = format!("{first_arc}.{second_arc}");
    for arc in arcs {
        use std::fmt::Write as _;
        let _ = write!(output, ".{arc}");
    }
    Ok(output)
}

pub(crate) fn decode_der_oid_tlv(input: &[u8]) -> Result<String, String> {
    let mut inventory = DerInventory {
        mechanism_oids: Vec::new(),
        text_values: Vec::new(),
        nodes: 0,
        indefinite_length_nodes: 0,
        complete: false,
    };
    let consumed = walk_der(input, 0, &mut inventory)?;
    if consumed != input.len() || inventory.nodes != 1 || inventory.mechanism_oids.len() != 1 {
        return Err("value is not one complete DER object identifier".into());
    }
    Ok(inventory.mechanism_oids.remove(0))
}

fn retain_der_text(value: String, inventory: &mut DerInventory) {
    if value.is_empty()
        || value.len() > 1024
        || value
            .chars()
            .any(|character| character.is_control() && !character.is_ascii_whitespace())
        || inventory.text_values.contains(&value)
    {
        return;
    }
    inventory.text_values.push(value);
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

fn parse_ntlm_authenticate(input: &[u8]) -> Result<(NtlmAuthenticate, Vec<String>), String> {
    if input.len() < 60 {
        return Err("truncated NTLM authenticate message".into());
    }
    let mut warnings = Vec::new();
    let flags = input
        .get(60..64)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("four-byte negotiate flags")));
    let unicode = flags.is_none_or(|value| value & 1 != 0);
    let lm = recover_security_buffer(input, 12, "LM response", &mut warnings);
    let nt = recover_security_buffer(input, 20, "NT response", &mut warnings);
    let domain = decode_text(
        recover_security_buffer(input, 28, "domain", &mut warnings),
        unicode,
    );
    let username = decode_text(
        recover_security_buffer(input, 36, "username", &mut warnings),
        unicode,
    );
    let workstation = decode_text(
        recover_security_buffer(input, 44, "workstation", &mut warnings),
        unicode,
    );
    let session_key = recover_security_buffer(input, 52, "session key", &mut warnings);
    let nt_response_variant = if nt.len() == 24 {
        "ntlmv1_or_ntlm2_session"
    } else if nt.len() >= 44 && nt.get(16..20) == Some(&[0x01, 0x01, 0x00, 0x00]) {
        "ntlmv2"
    } else {
        "other"
    };
    Ok((
        NtlmAuthenticate {
            domain,
            username,
            workstation,
            lm_response_bytes: lm.len(),
            nt_response_bytes: nt.len(),
            nt_response_variant,
            encrypted_session_key_bytes: session_key.len(),
            negotiate_flags: flags,
            lm_response: lm.to_vec(),
            nt_response: nt.to_vec(),
            encrypted_session_key: session_key.to_vec(),
        },
        warnings,
    ))
}

fn recover_security_buffer<'a>(
    input: &'a [u8],
    offset: usize,
    name: &str,
    warnings: &mut Vec<String>,
) -> &'a [u8] {
    match security_buffer_value(input, offset) {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!("invalid NTLM {name}: {error}"));
            &[]
        }
    }
}

fn parse_ntlm_negotiate(input: &[u8]) -> Result<(NtlmNegotiate, Vec<String>), String> {
    if input.len() < 32 {
        return Err("truncated NTLM negotiate message".into());
    }
    let mut warnings = Vec::new();
    let flags = u32::from_le_bytes(input[12..16].try_into().expect("length checked"));
    let domain = decode_text(
        recover_security_buffer(input, 16, "negotiate domain", &mut warnings),
        flags & 1 != 0,
    );
    let workstation = decode_text(
        recover_security_buffer(input, 24, "negotiate workstation", &mut warnings),
        flags & 1 != 0,
    );
    Ok((
        NtlmNegotiate {
            domain,
            workstation,
            negotiate_flags: flags,
        },
        warnings,
    ))
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

    #[test]
    fn parses_ntlm_negotiate_domain_and_workstation() {
        let mut token = Vec::new();
        token.extend_from_slice(b"NTLMSSP\0");
        token.extend_from_slice(&1_u32.to_le_bytes());
        token.extend_from_slice(&0_u32.to_le_bytes());
        security_buffer(&mut token, 3, 32);
        security_buffer(&mut token, 4, 35);
        token.extend_from_slice(b"LABHOST");
        let parsed = parse(&token);
        let negotiate = parsed.ntlm_negotiate.unwrap();
        assert_eq!(negotiate.domain, "LAB");
        assert_eq!(negotiate.workstation, "HOST");
    }

    #[test]
    fn inventories_spnego_mechanisms_and_kerberos_names() {
        // GSS-API InitialContextToken containing the SPNEGO OID and a visible
        // Kerberos realm/service fragment. The walker inventories structure;
        // it deliberately does not claim to decrypt the AP-REQ authenticator.
        let token = [
            0x60, 0x20, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x16, 0x30, 0x14,
            0x1b, 0x0b, b'E', b'X', b'A', b'M', b'P', b'L', b'E', b'.', b'C', b'O', b'M', 0x1b,
            0x05, b'M', b'S', b'S', b'Q', b'L',
        ];
        let parsed = parse(&token);
        assert_eq!(parsed.family, "gss_api");
        let inventory = parsed.der.unwrap();
        assert_eq!(inventory.mechanism_oids, ["1.3.6.1.5.5.2"]);
        assert_eq!(inventory.text_values, ["EXAMPLE.COM", "MSSQL"]);
        assert!(inventory.nodes >= 6);
    }

    #[test]
    fn recognizes_bare_spnego_continuation_and_bounds_malformed_der() {
        let parsed = parse(&[0xa1, 0x02, 0x30, 0x00]);
        assert_eq!(parsed.family, "spnego_neg_token_response");
        assert!(parsed.der.is_some());

        let malformed = parse(&[0xa1, 0x82, 0xff, 0xff]);
        assert!(!malformed.der.unwrap().complete);
        assert!(!malformed.parse_warnings.is_empty());
    }

    #[test]
    fn retains_der_identity_inventory_before_a_malformed_nested_suffix() {
        let parsed = parse(&[
            0x60, 0x0b, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x01, 0x30,
        ]);
        let inventory = parsed.der.unwrap();
        assert_eq!(inventory.mechanism_oids, ["1.3.6.1.5.5.2"]);
        assert!(!inventory.complete);
        assert!(!parsed.parse_warnings.is_empty());
    }

    #[test]
    fn parses_bounded_indefinite_ber_security_tokens() {
        let parsed = parse(&[
            0x60, 0x80, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0x1b, 0x03, b'S', b'Q',
            b'L', 0x00, 0x00,
        ]);
        let inventory = parsed.der.unwrap();
        assert_eq!(inventory.mechanism_oids, ["1.3.6.1.5.5.2"]);
        assert_eq!(inventory.text_values, ["SQL"]);
        assert_eq!(inventory.indefinite_length_nodes, 1);
        assert!(inventory.complete);
        assert!(parsed.parse_warnings.is_empty());

        let (primitive, error) = recover_der_inventory(&[0x04, 0x80, 0x00, 0x00]);
        assert!(!primitive.complete);
        assert!(error.is_some());
    }

    #[test]
    fn ntlm_authenticate_recovers_valid_fields_around_a_bad_optional_buffer() {
        fn descriptor(output: &mut [u8], at: usize, length: u16, maximum: u16, offset: u32) {
            output[at..at + 2].copy_from_slice(&length.to_le_bytes());
            output[at + 2..at + 4].copy_from_slice(&maximum.to_le_bytes());
            output[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
        }

        let mut token = vec![0_u8; 64];
        token[..8].copy_from_slice(b"NTLMSSP\0");
        token[8..12].copy_from_slice(&3_u32.to_le_bytes());
        token[60..64].copy_from_slice(&1_u32.to_le_bytes());
        // An invalid optional LM response must not erase the independent NT
        // response or identity security buffers.
        descriptor(&mut token, 12, 1, 0, 64);
        let mut nt = vec![0x55; 48];
        nt[16..20].copy_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        descriptor(&mut token, 20, nt.len() as u16, nt.len() as u16, 64);
        token.extend_from_slice(&nt);
        let username = utf16("scanner");
        descriptor(
            &mut token,
            36,
            username.len() as u16,
            username.len() as u16,
            112,
        );
        token.extend_from_slice(&username);

        let parsed = parse(&token);
        let authenticate = parsed.ntlm.expect("recoverable NTLM authenticate");
        assert_eq!(authenticate.username, "scanner");
        assert_eq!(authenticate.lm_response_bytes, 0);
        assert_eq!(authenticate.nt_response, nt);
        assert_eq!(authenticate.nt_response_variant, "ntlmv2");
        assert_eq!(parsed.parse_warnings.len(), 1);
        assert!(parsed.parse_warnings[0].contains("LM response"));
    }

    #[test]
    fn ntlmv2_classification_requires_a_versioned_client_challenge_blob() {
        let mut token = vec![0_u8; 64];
        token[..8].copy_from_slice(b"NTLMSSP\0");
        token[8..12].copy_from_slice(&3_u32.to_le_bytes());
        token[20..22].copy_from_slice(&25_u16.to_le_bytes());
        token[22..24].copy_from_slice(&25_u16.to_le_bytes());
        token[24..28].copy_from_slice(&64_u32.to_le_bytes());
        token.extend_from_slice(&[0x77; 25]);
        let parsed = parse(&token);
        assert_eq!(parsed.ntlm.unwrap().nt_response_variant, "other");
    }
}
