use crate::{Error, Result};

use super::login7::{LegacyLoginDetails, LoginRequest};

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
    let host_process = recover_field(
        payload,
        93,
        30,
        123,
        "host process",
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
    let client_charset = recover_field(
        payload,
        525,
        30,
        555,
        "character set",
        tolerant,
        &mut warnings,
    )?;
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
    let fixed_record_expected_bytes = match tds_version >> 16 {
        0x0402 => 572,
        0x0406 | 0x0500..=0x05ff => 568,
        _ => MIN_LENGTH,
    };
    if payload.len() < fixed_record_expected_bytes {
        let error = Error::Protocol(format!(
            "legacy LOGIN record for version 0x{tds_version:08x} must be at least {fixed_record_expected_bytes} bytes"
        ));
        if tolerant {
            warnings.push(error.to_string());
        } else {
            return Err(error);
        }
    }
    if tds_version >> 24 == 0x04 && payload.len() > 572 {
        let error = Error::Protocol("TDS 4.x LOGIN record exceeds 572 bytes".into());
        if tolerant {
            warnings.push(error.to_string());
        } else {
            return Err(error);
        }
    }
    let (remote_password, remote_password_encoding) =
        if tds_version >> 24 == 0x04 && tds_version >> 16 & 0xff == 0x02 {
            (
                recover_field(
                    payload,
                    202,
                    255,
                    457,
                    "remote password",
                    tolerant,
                    &mut warnings,
                )?,
                "tds42_fixed_255",
            )
        } else {
            (
                recover_tds5_remote_password(payload, tolerant, &mut warnings)?,
                "tds46_tds50_length_prefixed",
            )
        };
    let remote_password_present = !remote_password.is_empty();
    let password = if primary_password.is_empty() {
        remote_password
    } else {
        primary_password
    };
    let security_flags = payload[514];
    let integrated_security = security_flags & 0x10 != 0;
    let password_present = !password.is_empty();
    let (capabilities_bytes, capabilities, authentication_bytes, authentication) =
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
        legacy_login: Some(LegacyLoginDetails {
            host_process,
            client_charset,
            client_program_version: u32::from_be_bytes(
                payload[473..477].try_into().expect("fixed length"),
            ),
            bulk_copy_raw: payload[130],
            bulk_copy_requested: payload[130] == 0,
            suppress_language_raw: payload[511],
            old_secure: payload[512..514].try_into().expect("fixed length"),
            security_bulk_raw: payload[515],
            ha_login_raw: payload[516],
            ha_session_id: payload[517..523].try_into().expect("fixed length"),
            security_spare: payload[523..525].try_into().expect("fixed length"),
            set_charset_raw: payload[556],
            fixed_record_expected_bytes,
            fixed_record_present_bytes: payload.len().min(fixed_record_expected_bytes),
            fixed_padding: payload
                .get(564..payload.len().min(fixed_record_expected_bytes))
                .unwrap_or_default()
                .to_vec(),
            suffix_bytes: payload.len().saturating_sub(fixed_record_expected_bytes),
            remote_password_encoding,
            remote_password_present,
        }),
        legacy_capabilities_bytes: capabilities_bytes,
        legacy_capabilities: capabilities,
        legacy_authentication_bytes: authentication_bytes,
        legacy_authentication: authentication,
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
) -> Result<(
    usize,
    Option<super::tds5::Capabilities>,
    usize,
    Option<super::tds5::AuthenticationStream>,
)> {
    if tds_version >> 24 != 0x05 || payload.len() <= 568 {
        return Ok((0, None, payload.len().saturating_sub(572), None));
    }
    if payload.len() < 571 {
        let error = Error::Protocol("truncated TDS 5.0 capability header".into());
        return if tolerant {
            warnings.push(error.to_string());
            let suffix = &payload[568..];
            Ok((
                0,
                None,
                suffix.len(),
                recover_suffix_authentication(suffix, payload.len()),
            ))
        } else {
            Err(error)
        };
    }
    if payload[568] != 0xe2 {
        let error = Error::Protocol("TDS 5.0 LOGIN suffix does not start with CAPABILITY".into());
        return if tolerant {
            warnings.push(error.to_string());
            let suffix = &payload[568..];
            Ok((
                0,
                None,
                suffix.len(),
                recover_suffix_authentication(suffix, payload.len()),
            ))
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
            let suffix = &payload[568..];
            Ok((
                payload.len().saturating_sub(571),
                None,
                suffix.len(),
                recover_suffix_authentication(suffix, payload.len()),
            ))
        } else {
            Err(error)
        };
    }
    let capabilities = match super::tds5::parse_capabilities(&payload[571..end]) {
        Ok(value) => Some(value),
        Err(error) if tolerant => {
            warnings.push(error.to_string());
            None
        }
        Err(error) => return Err(error),
    };
    let authentication_bytes = payload.len() - end;
    let authentication = if authentication_bytes == 0 {
        None
    } else {
        match super::tds5::parse_authentication(&payload[end..], payload.len()) {
            Ok(value) => Some(value),
            Err(error) if tolerant => {
                warnings.push(error.to_string());
                Some(super::tds5::parse_for_telemetry(
                    &payload[end..],
                    payload.len(),
                ))
            }
            Err(error) => return Err(error),
        }
    };
    Ok((length, capabilities, authentication_bytes, authentication))
}

fn recover_suffix_authentication(
    suffix: &[u8],
    max_value_bytes: usize,
) -> Option<super::tds5::AuthenticationStream> {
    (!suffix.is_empty()).then(|| super::tds5::parse_for_telemetry(suffix, max_value_bytes))
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
        let mut payload = login("scan-host", "sa", "gold", "pymssql", "203.0.113.10:1433");
        put(&mut payload, 93, 123, "4242");
        put(&mut payload, 525, 555, "iso_1");
        payload[130] = 0;
        payload[473..477].copy_from_slice(&0x0402_0102_u32.to_be_bytes());
        payload[511] = 1;
        payload[515] = 1;
        payload[516] = 2;
        payload[517..523].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
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
        let legacy = parsed.legacy_login.unwrap();
        assert_eq!(legacy.host_process, "4242");
        assert_eq!(legacy.client_charset, "iso_1");
        assert_eq!(legacy.client_program_version, 0x0402_0102);
        assert!(legacy.bulk_copy_requested);
        assert_eq!(legacy.suppress_language_raw, 1);
        assert_eq!(legacy.security_bulk_raw, 1);
        assert_eq!(legacy.ha_login_raw, 2);
        assert_eq!(legacy.ha_session_id, [1, 2, 3, 4, 5, 6]);
        assert_eq!(legacy.fixed_record_expected_bytes, 572);
        assert_eq!(legacy.fixed_record_present_bytes, 572);
        assert_eq!(legacy.fixed_padding.len(), 8);
        assert_eq!(legacy.remote_password_encoding, "tds42_fixed_255");
        assert!(!legacy.remote_password_present);
    }

    #[test]
    fn rejects_invalid_lengths() {
        let mut payload = login("host", "sa", "gold", "pymssql", "server");
        payload[61] = 31;
        assert!(parse(&payload).is_err());
        assert!(parse(&payload[..563]).is_err());
    }

    #[test]
    fn enforces_tds42_record_limit_without_losing_telemetry() {
        let mut payload = login("host", "sa", "gold", "pymssql", "server");
        payload.push(0);
        assert!(parse(&payload).is_err());
        let parsed = parse_for_telemetry(&payload).unwrap();
        assert_eq!(parsed.username, "sa");
        assert_eq!(parsed.password_for_capture(), Some("gold"));
        assert!(!parsed.parse_warnings.is_empty());
    }

    #[test]
    fn enforces_versioned_fixed_record_minimums_without_losing_fields() {
        let mut tds42 = login("host", "sa", "gold", "pymssql", "server");
        tds42.truncate(568);
        assert!(parse(&tds42).is_err());
        let recovered = parse_for_telemetry(&tds42).unwrap();
        assert_eq!(recovered.username, "sa");
        assert_eq!(recovered.password_for_capture(), Some("gold"));
        assert_eq!(
            recovered.legacy_login.unwrap().fixed_record_expected_bytes,
            572
        );
        assert!(!recovered.parse_warnings.is_empty());

        let mut tds46 = tds42;
        tds46[458..462].copy_from_slice(&0x0406_0000_u32.to_be_bytes());
        let parsed = parse(&tds46).unwrap();
        assert_eq!(
            parsed.legacy_login.unwrap().fixed_record_expected_bytes,
            568
        );
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
        let capabilities = [
            1, 7, 7, 97, 65, 207, 255, 255, 230, 2, 7, 0, 0, 2, 0, 0, 0, 0,
        ];
        payload.extend_from_slice(&(capabilities.len() as u16).to_le_bytes());
        payload.extend_from_slice(&capabilities);
        payload.extend_from_slice(&[0x65, 3, 0, 11, 0]);
        let parsed = parse(&payload).unwrap();
        assert!(parsed.integrated_security);
        assert_eq!(parsed.legacy_security_flags, Some(0x10));
        assert_eq!(parsed.legacy_capabilities_bytes, 18);
        assert_eq!(
            parsed.legacy_capabilities.unwrap().request,
            [7, 97, 65, 207, 255, 255, 230]
        );
        assert_eq!(parsed.legacy_authentication_bytes, 5);
        assert_eq!(
            parsed.legacy_authentication.unwrap().message_types[0].name,
            "opaque_security"
        );
    }

    #[test]
    fn telemetry_recovers_tds5_authentication_when_capability_framing_is_missing() {
        let mut payload = login("scan-host", "sa", "", "isql", "SYBASE");
        payload.truncate(568);
        payload[458..462].copy_from_slice(&0x0500_0000_u32.to_be_bytes());
        payload.extend_from_slice(&[0x19, 0xde, 0xad]); // proprietary/unknown prefix
        payload.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        payload.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        payload.extend_from_slice(&[0xd7, 4, 0, 0, 0, 1, 2, 3, 4]);

        assert!(parse(&payload).is_err());
        let parsed = parse_for_telemetry(&payload).unwrap();
        let authentication = parsed.legacy_authentication.unwrap();
        assert_eq!(authentication.message_types[0].message_type, 31);
        assert_eq!(authentication.encrypted_login_password_bytes, Some(4));
        assert_eq!(authentication.unparsed_regions[0].bytes, 3);
        assert_eq!(parsed.legacy_authentication_bytes, payload.len() - 568);
        assert!(
            parsed
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("CAPABILITY"))
        );
    }

    fn put(payload: &mut [u8], offset: usize, length_offset: usize, value: &str) {
        payload[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        payload[length_offset] = value.len() as u8;
    }
}
