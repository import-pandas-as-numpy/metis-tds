use crate::{Error, Result};

const LOGINACK: u8 = 0xad;
const ENVCHANGE: u8 = 0xe3;
const ERROR: u8 = 0xaa;
const INFO: u8 = 0xab;
const COLMETADATA: u8 = 0x81;
const COLNAME: u8 = 0xa0;
const COLFMT: u8 = 0xa1;
const ROW: u8 = 0xd1;
const DONE: u8 = 0xfd;
const DONEPROC: u8 = 0xfe;
const SSPI: u8 = 0xed;
const DONE_MORE: u16 = 0x0001;
const DONE_ERROR: u16 = 0x0002;
const DONE_COUNT: u16 = 0x0010;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tds42,
    Tds7(u32),
}

impl Protocol {
    fn uses_legacy_strings(self) -> bool {
        self == Self::Tds42
    }

    fn uses_wide_fields(self) -> bool {
        matches!(self, Self::Tds7(version) if version >> 24 >= 0x72)
    }
}

#[derive(Clone, Debug)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
}

impl ResultSet {
    pub fn single(column: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            columns: vec![column.into()],
            rows: vec![vec![Some(value.into())]],
        }
    }
}

#[derive(Clone, Debug)]
pub struct SqlError {
    pub number: u32,
    pub state: u8,
    pub class: u8,
    pub message: String,
}

pub fn login_success(
    protocol: Protocol,
    database: &str,
    language: &str,
    packet_size: u32,
    product_name: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if protocol == Protocol::Tds42 {
        length_prefixed(&mut out, LOGINACK, |body| {
            body.push(1);
            body.extend_from_slice(&0x0402_0000_u32.to_be_bytes());
            legacy_b_varchar(body, product_name);
            body.extend_from_slice(&[95, 16, 0, 89]);
        })?;
        done(&mut out, protocol, DONE, 0, 0);
        return Ok(out);
    }
    envchange(&mut out, 1, database, "")?;
    info(
        &mut out,
        protocol,
        5701,
        2,
        &format!("Changed database context to '{database}'."),
        "",
    )?;
    envchange_binary(&mut out, 7, &[0x09, 0x04, 0xd0, 0x00, 0x34], &[])?;
    envchange(&mut out, 2, language, "")?;
    info(
        &mut out,
        protocol,
        5703,
        1,
        &format!("Changed language setting to {language}."),
        "",
    )?;
    length_prefixed(&mut out, LOGINACK, |body| {
        body.push(1);
        let Protocol::Tds7(version) = protocol else {
            unreachable!("legacy login handled above")
        };
        body.extend_from_slice(&version.to_be_bytes());
        b_varchar(body, product_name);
        body.extend_from_slice(&[16, 0, 16, 89]);
    })?;
    envchange(&mut out, 4, &packet_size.to_string(), "4096")?;
    done(&mut out, protocol, DONE, 0, 0);
    Ok(out)
}

pub fn login_failure(protocol: Protocol, server: &str, locked: bool) -> Result<Vec<u8>> {
    let message = if locked {
        "Login failed for user. Reason: Account is locked out."
    } else {
        "Login failed for user."
    };
    let mut out = Vec::new();
    error(
        &mut out,
        protocol,
        &SqlError {
            number: 18456,
            state: if locked { 23 } else { 1 },
            class: 14,
            message: message.into(),
        },
        server,
    )?;
    done(&mut out, protocol, DONE, DONE_ERROR, 0);
    Ok(out)
}

pub fn sspi_challenge(token: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    length_prefixed(&mut output, SSPI, |body| body.extend_from_slice(token))?;
    Ok(output)
}

pub fn response(
    protocol: Protocol,
    result_sets: &[ResultSet],
    messages: &[String],
    sql_error: Option<&SqlError>,
    server: &str,
    done_proc: bool,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for message in messages {
        info(&mut out, protocol, 0, 1, message, server)?;
    }
    if let Some(err) = sql_error {
        error(&mut out, protocol, err, server)?;
        done(
            &mut out,
            protocol,
            if done_proc { DONEPROC } else { DONE },
            DONE_ERROR,
            0,
        );
        return Ok(out);
    }
    for (index, set) in result_sets.iter().enumerate() {
        if protocol == Protocol::Tds42 {
            legacy_colmetadata(&mut out, &set.columns)?;
        } else {
            colmetadata(&mut out, protocol, &set.columns)?;
        }
        for row in &set.rows {
            if protocol == Protocol::Tds42 {
                legacy_row_token(&mut out, row, set.columns.len())?;
            } else {
                row_token(&mut out, row, set.columns.len())?;
            }
        }
        let more = if index + 1 < result_sets.len() {
            DONE_MORE
        } else {
            0
        };
        done(
            &mut out,
            protocol,
            if done_proc { DONEPROC } else { DONE },
            more | DONE_COUNT,
            set.rows.len() as u64,
        );
    }
    if result_sets.is_empty() {
        done(
            &mut out,
            protocol,
            if done_proc { DONEPROC } else { DONE },
            0,
            0,
        );
    }
    Ok(out)
}

fn colmetadata(out: &mut Vec<u8>, protocol: Protocol, columns: &[String]) -> Result<()> {
    out.push(COLMETADATA);
    out.extend_from_slice(
        &u16::try_from(columns.len())
            .map_err(|_| Error::Limit("result column count"))?
            .to_le_bytes(),
    );
    for name in columns {
        if protocol.uses_wide_fields() {
            out.extend_from_slice(&0_u32.to_le_bytes()); // user type, TDS 7.2+
        } else {
            out.extend_from_slice(&0_u16.to_le_bytes());
        }
        out.extend_from_slice(&1_u16.to_le_bytes()); // nullable
        out.push(0xe7); // NVARCHAR
        out.extend_from_slice(&8000_u16.to_le_bytes());
        out.extend_from_slice(&[0x09, 0x04, 0xd0, 0x00, 0x34]);
        b_varchar(out, name);
    }
    Ok(())
}

fn legacy_colmetadata(out: &mut Vec<u8>, columns: &[String]) -> Result<()> {
    length_prefixed(out, COLNAME, |body| {
        for name in columns {
            legacy_b_varchar(body, name);
        }
    })?;
    length_prefixed(out, COLFMT, |body| {
        for _ in columns {
            body.extend_from_slice(&2_u16.to_le_bytes()); // varchar user type
            body.extend_from_slice(&1_u16.to_le_bytes()); // nullable
            body.push(0x27); // SYBVARCHAR
            body.push(u8::MAX);
        }
    })
}

fn row_token(out: &mut Vec<u8>, row: &[Option<String>], expected: usize) -> Result<()> {
    if row.len() != expected {
        return Err(Error::Protocol("synthetic row width mismatch".into()));
    }
    out.push(ROW);
    for value in row {
        if let Some(value) = value {
            let encoded = utf16(value);
            out.extend_from_slice(
                &u16::try_from(encoded.len())
                    .map_err(|_| Error::Limit("result cell length"))?
                    .to_le_bytes(),
            );
            out.extend_from_slice(&encoded);
        } else {
            out.extend_from_slice(&u16::MAX.to_le_bytes());
        }
    }
    Ok(())
}

fn legacy_row_token(out: &mut Vec<u8>, row: &[Option<String>], expected: usize) -> Result<()> {
    if row.len() != expected {
        return Err(Error::Protocol("synthetic row width mismatch".into()));
    }
    out.push(ROW);
    for value in row {
        if let Some(value) = value {
            let encoded = legacy_string(value, u8::MAX as usize);
            out.push(encoded.len() as u8);
            out.extend_from_slice(&encoded);
        } else {
            out.push(0);
        }
    }
    Ok(())
}

fn envchange(out: &mut Vec<u8>, kind: u8, new: &str, old: &str) -> Result<()> {
    length_prefixed(out, ENVCHANGE, |body| {
        body.push(kind);
        b_varchar(body, new);
        b_varchar(body, old);
    })
}

fn envchange_binary(out: &mut Vec<u8>, kind: u8, new: &[u8], old: &[u8]) -> Result<()> {
    length_prefixed(out, ENVCHANGE, |body| {
        body.push(kind);
        body.push(u8::try_from(new.len()).unwrap_or(u8::MAX));
        body.extend_from_slice(&new[..new.len().min(u8::MAX as usize)]);
        body.push(u8::try_from(old.len()).unwrap_or(u8::MAX));
        body.extend_from_slice(&old[..old.len().min(u8::MAX as usize)]);
    })
}

fn info(
    out: &mut Vec<u8>,
    protocol: Protocol,
    number: u32,
    state: u8,
    message: &str,
    server: &str,
) -> Result<()> {
    message_token(
        out,
        protocol,
        INFO,
        &SqlError {
            number,
            state,
            class: 0,
            message: message.to_owned(),
        },
        server,
    )
}

fn error(out: &mut Vec<u8>, protocol: Protocol, error: &SqlError, server: &str) -> Result<()> {
    message_token(out, protocol, ERROR, error, server)
}

fn message_token(
    out: &mut Vec<u8>,
    protocol: Protocol,
    token: u8,
    message: &SqlError,
    server: &str,
) -> Result<()> {
    length_prefixed(out, token, |body| {
        body.extend_from_slice(&message.number.to_le_bytes());
        body.push(message.state);
        body.push(message.class);
        if protocol.uses_legacy_strings() {
            legacy_us_varchar(body, &message.message);
            legacy_b_varchar(body, server);
            legacy_b_varchar(body, "");
        } else {
            us_varchar(body, &message.message);
            b_varchar(body, server);
            b_varchar(body, "");
        }
        if protocol.uses_wide_fields() {
            body.extend_from_slice(&0_u32.to_le_bytes());
        } else {
            body.extend_from_slice(&0_u16.to_le_bytes());
        }
    })
}

fn done(out: &mut Vec<u8>, protocol: Protocol, token: u8, status: u16, row_count: u64) {
    out.push(token);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    if protocol.uses_wide_fields() {
        out.extend_from_slice(&row_count.to_le_bytes());
    } else {
        out.extend_from_slice(&(row_count.min(u32::MAX as u64) as u32).to_le_bytes());
    }
}

fn length_prefixed<F>(out: &mut Vec<u8>, token: u8, build: F) -> Result<()>
where
    F: FnOnce(&mut Vec<u8>),
{
    let mut body = Vec::new();
    build(&mut body);
    out.push(token);
    out.extend_from_slice(
        &u16::try_from(body.len())
            .map_err(|_| Error::Limit("TDS token length"))?
            .to_le_bytes(),
    );
    out.extend_from_slice(&body);
    Ok(())
}

fn b_varchar(out: &mut Vec<u8>, value: &str) {
    let units: Vec<u16> = value.encode_utf16().take(255).collect();
    out.push(units.len() as u8);
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

fn legacy_b_varchar(out: &mut Vec<u8>, value: &str) {
    let encoded = legacy_string(value, u8::MAX as usize);
    out.push(encoded.len() as u8);
    out.extend_from_slice(&encoded);
}

fn legacy_us_varchar(out: &mut Vec<u8>, value: &str) {
    let encoded = legacy_string(value, u16::MAX as usize);
    out.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
    out.extend_from_slice(&encoded);
}

fn legacy_string(value: &str, max: usize) -> Vec<u8> {
    value
        .chars()
        .take(max)
        .map(|character| {
            if character.is_ascii() {
                character as u8
            } else {
                b'?'
            }
        })
        .collect()
}

fn us_varchar(out: &mut Vec<u8>, value: &str) {
    let units: Vec<u16> = value.encode_utf16().take(u16::MAX as usize).collect();
    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

fn utf16(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodes_login_and_rows() {
        let protocol = Protocol::Tds7(0x7400_0004);
        let login = login_success(
            protocol,
            "master",
            "us_english",
            4096,
            "Microsoft SQL Server",
        )
        .unwrap();
        assert!(login.contains(&LOGINACK));
        let encoded = response(
            protocol,
            &[ResultSet::single("", "ok")],
            &[],
            None,
            "SQL01",
            false,
        )
        .unwrap();
        assert!(encoded.contains(&COLMETADATA));
        assert!(encoded.contains(&ROW));
    }

    #[test]
    fn encodes_tds42_login_and_rows_with_legacy_layouts() {
        let login = login_success(
            Protocol::Tds42,
            "master",
            "us_english",
            4096,
            "Microsoft SQL Server",
        )
        .unwrap();
        assert_eq!(login[0], LOGINACK);
        assert_eq!(u16::from_le_bytes([login[1], login[2]]), 30);
        assert_eq!(login[3], 1);
        assert_eq!(&login[4..8], &[0x04, 0x02, 0x00, 0x00]);
        assert_eq!(login[8], 20);
        assert_eq!(&login[9..29], b"Microsoft SQL Server");
        assert_eq!(&login[29..33], &[95, 16, 0, 89]);
        assert_eq!(&login[33..], &[DONE, 0, 0, 0, 0, 0, 0, 0, 0]);

        let encoded = response(
            Protocol::Tds42,
            &[ResultSet::single("version", "Microsoft SQL Server")],
            &[],
            None,
            "SQL01",
            false,
        )
        .unwrap();
        assert_eq!(encoded[0], COLNAME);
        assert!(encoded.contains(&COLFMT));
        assert!(encoded.contains(&ROW));
        assert!(!encoded.contains(&COLMETADATA));
        assert!(
            encoded
                .windows(20)
                .any(|value| value == b"Microsoft SQL Server")
        );
        assert_eq!(
            encoded.len() - encoded.iter().rposition(|b| *b == DONE).unwrap(),
            9
        );

        let failure = login_failure(Protocol::Tds42, "SQL01", false).unwrap();
        assert_eq!(failure[0], ERROR);
        let error_len = usize::from(u16::from_le_bytes([failure[1], failure[2]]));
        let message_len = usize::from(u16::from_le_bytes([failure[9], failure[10]]));
        assert_eq!(&failure[11..11 + message_len], b"Login failed for user.");
        assert_eq!(failure[3 + error_len], DONE);
        assert_eq!(failure.len() - (3 + error_len), 9);
    }

    #[test]
    fn tds71_uses_narrow_metadata_done_and_line_number_fields() {
        let protocol = Protocol::Tds7(0x7100_0001);
        let login = login_success(
            protocol,
            "master",
            "us_english",
            4096,
            "Microsoft SQL Server",
        )
        .unwrap();
        let login_ack = login.iter().position(|byte| *byte == LOGINACK).unwrap();
        assert_eq!(
            &login[login_ack + 4..login_ack + 8],
            &0x7100_0001_u32.to_be_bytes()
        );
        assert_eq!(
            login.len() - login.iter().rposition(|b| *b == DONE).unwrap(),
            9
        );

        let encoded = response(
            protocol,
            &[ResultSet::single("", "ok")],
            &[],
            None,
            "SQL01",
            false,
        )
        .unwrap();
        assert_eq!(&encoded[3..5], &[0, 0]); // two-byte user type
        assert_eq!(
            encoded.len() - encoded.iter().rposition(|b| *b == DONE).unwrap(),
            9
        );
    }
}
