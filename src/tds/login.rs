use crate::{Error, Result};

use super::login7::LoginRequest;

const MIN_LENGTH: usize = 564;
const MAX_LENGTH: usize = 572;

pub fn parse(payload: &[u8]) -> Result<LoginRequest> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&payload.len()) {
        return Err(Error::Protocol(
            "legacy LOGIN record length must be between 564 and 572 bytes".into(),
        ));
    }

    let client_hostname = field(payload, 0, 30, 30, "hostname")?;
    let username = field(payload, 31, 30, 61, "username")?;
    let password = field(payload, 62, 30, 92, "password")?;
    let application_name = field(payload, 140, 30, 170, "application name")?;
    let server_name = field(payload, 171, 30, 201, "server name")?;
    let client_library = field(payload, 462, 10, 472, "program name")?;
    let language = field(payload, 480, 30, 510, "language")?;
    let packet_size_text = field(payload, 557, 6, 563, "packet size")?;
    let packet_size = if packet_size_text.is_empty() {
        4096
    } else {
        packet_size_text
            .parse::<u32>()
            .map_err(|_| Error::Protocol("legacy LOGIN packet size is not decimal".into()))?
    };
    let login_type = payload[132];
    let dblib_flags = payload[139];
    let integrated_security = login_type == 8 || dblib_flags & 0x01 != 0;
    let password_present = !password.is_empty();

    Ok(LoginRequest {
        tds_version: u32::from_be_bytes(payload[458..462].try_into().expect("fixed length")),
        packet_size,
        option_flags_1: 0,
        option_flags_2: if integrated_security { 0x80 } else { 0 },
        type_flags: login_type,
        option_flags_3: dblib_flags,
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
    })
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
        let payload = login("scan-host", "sa", "gold", "pymssql", "143.244.215.213:1433");
        let parsed = parse(&payload).unwrap();
        assert_eq!(parsed.client_hostname, "scan-host");
        assert_eq!(parsed.username, "sa");
        assert_eq!(parsed.password_for_capture(), Some("gold"));
        assert_eq!(parsed.application_name, "pymssql");
        assert_eq!(parsed.server_name, "143.244.215.213:1433");
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
        let mut payload = vec![0_u8; MAX_LENGTH];
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

    fn put(payload: &mut [u8], offset: usize, length_offset: usize, value: &str) {
        payload[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        payload[length_offset] = value.len() as u8;
    }
}
