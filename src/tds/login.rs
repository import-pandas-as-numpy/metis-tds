use crate::{Error, Result};

use super::login7::LoginRequest;

const MIN_LENGTH: usize = 564;

pub fn parse(payload: &[u8]) -> Result<LoginRequest> {
    parse_inner(payload, false)
}

pub fn parse_for_telemetry(payload: &[u8]) -> Result<LoginRequest> {
    parse_inner(payload, true)
}

fn parse_inner(payload: &[u8], tolerant: bool) -> Result<LoginRequest> {
    if payload.len() < MIN_LENGTH {
        return Err(Error::Protocol(
            "legacy LOGIN record must be at least 564 bytes".into(),
        ));
    }

    let mut warnings = Vec::new();
    let client_hostname = recover_field(payload, 0, 30, 30, "hostname", tolerant, &mut warnings)?;
    let username = recover_field(payload, 31, 30, 61, "username", tolerant, &mut warnings)?;
    let primary_password = recover_field(payload, 62, 30, 92, "password", tolerant, &mut warnings)?;
    let application_name = recover_field(
        payload,
        140,
        30,
        170,
        "application name",
        tolerant,
        &mut warnings,
    )?;
    let server_name = recover_field(
        payload,
        171,
        30,
        201,
        "server name",
        tolerant,
        &mut warnings,
    )?;
    let client_library = recover_field(
        payload,
        462,
        10,
        472,
        "program name",
        tolerant,
        &mut warnings,
    )?;
    let language = recover_field(payload, 480, 30, 510, "language", tolerant, &mut warnings)?;
    let packet_size_text =
        recover_field(payload, 557, 6, 563, "packet size", tolerant, &mut warnings)?;
    let packet_size = if packet_size_text.is_empty() {
        4096
    } else {
        match packet_size_text.parse::<u32>() {
            Ok(value) => value,
            Err(_) if tolerant => {
                warnings.push("legacy LOGIN packet size is not decimal".into());
                4096
            }
            Err(_) => {
                return Err(Error::Protocol(
                    "legacy LOGIN packet size is not decimal".into(),
                ));
            }
        }
    };
    let tds_version = u32::from_be_bytes(payload[458..462].try_into().expect("fixed length"));
    let remote_password = if tds_version >> 24 == 0x04 && tds_version >> 16 & 0xff == 0x02 {
        recover_field(
            payload,
            202,
            255,
            457,
            "remote password",
            tolerant,
            &mut warnings,
        )?
    } else {
        recover_tds5_remote_password(payload, tolerant, &mut warnings)?
    };
    let password = if primary_password.is_empty() {
        remote_password
    } else {
        primary_password
    };
    let security_flags = payload[514];
    let integrated_security = security_flags & 0x10 != 0;
    let password_present = !password.is_empty();
    let (capabilities_bytes, authentication_bytes) =
        parse_suffix(payload, tds_version, tolerant, &mut warnings)?;

    Ok(LoginRequest {
        tds_version,
        packet_size,
        option_flags_1: 0,
        option_flags_2: if integrated_security { 0x80 } else { 0 },
        type_flags: 0,
        option_flags_3: 0,
        client_hostname,
        username,
        password: password_present.then_some(password),
        password_present,
        application_name,
        server_name,
        client_library,
        language,
        database: String::new(),
        integrated_security,
        sspi_bytes: 0,
        sspi_token_family: None,
        parse_warnings: warnings,
        legacy_security_flags: Some(security_flags),
        legacy_capabilities_bytes: capabilities_bytes,
        legacy_authentication_bytes: authentication_bytes,
        ..LoginRequest::default()
    })
}

fn recover_field(
    payload: &[u8],
    offset: usize,
    width: usize,
    length_offset: usize,
    name: &str,
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<String> {
    match field(payload, offset, width, length_offset, name) {
        Ok(value) => Ok(value),
        Err(error) if tolerant => {
            warnings.push(error.to_string());
            Ok(String::new())
        }
        Err(error) => Err(error),
    }
}

fn recover_tds5_remote_password(
    payload: &[u8],
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<String> {
    let length = usize::from(payload[203]);
    if length > 253 {
        let error = Error::Protocol("legacy LOGIN remote password exceeds its fixed field".into());
        return if tolerant {
            warnings.push(error.to_string());
            Ok(String::new())
        } else {
            Err(error)
        };
    }
    Ok(String::from_utf8_lossy(&payload[204..204 + length]).into_owned())
}

fn parse_suffix(
    payload: &[u8],
    tds_version: u32,
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<(usize, usize)> {
    if tds_version >> 24 != 0x05 || payload.len() <= 568 {
        return Ok((0, payload.len().saturating_sub(572)));
    }
    if payload.len() < 571 {
        let error = Error::Protocol("truncated TDS 5.0 capability header".into());
        return if tolerant {
            warnings.push(error.to_string());
            Ok((0, payload.len() - 568))
        } else {
            Err(error)
        };
    }
    if payload[568] != 0xe2 {
        let error = Error::Protocol("TDS 5.0 LOGIN suffix does not start with CAPABILITY".into());
        return if tolerant {
            warnings.push(error.to_string());
            Ok((0, payload.len() - 568))
        } else {
            Err(error)
        };
    }
    let length = usize::from(u16::from_le_bytes([payload[569], payload[570]]));
    let end = 571_usize
        .checked_add(length)
        .ok_or_else(|| Error::Protocol("TDS 5.0 capability length overflow".into()))?;
    if end > payload.len() {
        let error = Error::Protocol("truncated TDS 5.0 capability token".into());
        return if tolerant {
            warnings.push(error.to_string());
            Ok((payload.len().saturating_sub(571), 0))
        } else {
            Err(error)
        };
    }
    Ok((length, payload.len() - end))
}

fn field(
    payload: &[u8],
    offset: usize,
    width: usize,
    length_offset: usize,
    name: &str,
) -> Result<String> {
    let length = usize::from(payload[length_offset]);
    if length > width {
        return Err(Error::Protocol(format!(
            "legacy LOGIN {name} length exceeds its fixed field"
        )));
    }
    Ok(String::from_utf8_lossy(&payload[offset..offset + length]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_width_sql_auth_fields() {
        let payload = login("scan-host", "sa", "gold", "pymssql", "203.0.113.10:1433");
        let parsed = parse(&payload).unwrap();
        assert_eq!(parsed.client_hostname, "scan-host");
        assert_eq!(parsed.username, "sa");
        assert_eq!(parsed.password_for_capture(), Some("gold"));
        assert_eq!(parsed.application_name, "pymssql");
        assert_eq!(parsed.server_name, "203.0.113.10:1433");
        assert_eq!(parsed.client_library, "pymssql");
        assert_eq!(parsed.language, "us_english");
        assert_eq!(parsed.packet_size, 4096);
        assert_eq!(parsed.tds_version, 0x0402_0000);
        assert!(!parsed.integrated_security);
    }

    #[test]
    fn rejects_invalid_lengths() {
        let mut payload = login("host", "sa", "gold", "pymssql", "server");
        payload[61] = 31;
        assert!(parse(&payload).is_err());
        assert!(parse(&payload[..563]).is_err());
    }

    fn login(host: &str, user: &str, password: &str, app: &str, server: &str) -> Vec<u8> {
        let mut payload = vec![0_u8; 572];
        put(&mut payload, 0, 30, host);
        put(&mut payload, 31, 61, user);
        put(&mut payload, 62, 92, password);
        payload[123] = 4;
        put(&mut payload, 140, 170, app);
        put(&mut payload, 171, 201, server);
        payload[458..462].copy_from_slice(&0x0402_0000_u32.to_be_bytes());
        put(&mut payload, 462, 472, "pymssql");
        put(&mut payload, 480, 510, "us_english");
        put(&mut payload, 557, 563, "4096");
        payload
    }

    #[test]
    fn parses_tds50_capability_suffix_and_real_security_flag() {
        let mut payload = login("scan-host", "sa", "gold", "isql", "SYBASE");
        payload.truncate(568);
        payload[458..462].copy_from_slice(&0x0500_0000_u32.to_be_bytes());
        payload[514] = 0x10;
        payload.push(0xe2);
        payload.extend_from_slice(&32_u16.to_le_bytes());
        payload.extend_from_slice(&[7; 32]);
        payload.extend_from_slice(b"gss-continuation");
        let parsed = parse(&payload).unwrap();
        assert!(parsed.integrated_security);
        assert_eq!(parsed.legacy_security_flags, Some(0x10));
        assert_eq!(parsed.legacy_capabilities_bytes, 32);
        assert_eq!(parsed.legacy_authentication_bytes, 16);
    }

    fn put(payload: &mut [u8], offset: usize, length_offset: usize, value: &str) {
        payload[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        payload[length_offset] = value.len() as u8;
    }
}
