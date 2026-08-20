use crate::{Error, Result};

const LOGINACK: u8 = 0xad;
const ENVCHANGE: u8 = 0xe3;
const ERROR: u8 = 0xaa;
const INFO: u8 = 0xab;
const COLMETADATA: u8 = 0x81;
const ROW: u8 = 0xd1;
const DONE: u8 = 0xfd;
const DONEPROC: u8 = 0xfe;
const DONE_MORE: u16 = 0x0001;
const DONE_ERROR: u16 = 0x0002;
const DONE_COUNT: u16 = 0x0010;

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
    database: &str,
    language: &str,
    packet_size: u32,
    product_name: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    envchange(&mut out, 1, database, "")?;
    info(
        &mut out,
        5701,
        2,
        &format!("Changed database context to '{database}'."),
        "",
    )?;
    envchange_binary(&mut out, 7, &[0x09, 0x04, 0xd0, 0x00, 0x34], &[])?;
    envchange(&mut out, 2, language, "")?;
    info(
        &mut out,
        5703,
        1,
        &format!("Changed language setting to {language}."),
        "",
    )?;
    length_prefixed(&mut out, LOGINACK, |body| {
        body.push(1);
        body.extend_from_slice(&0x7400_0004_u32.to_be_bytes());
        b_varchar(body, product_name);
        body.extend_from_slice(&[16, 0, 16, 89]);
    })?;
    envchange(&mut out, 4, &packet_size.to_string(), "4096")?;
    done(&mut out, DONE, 0, 0);
    Ok(out)
}

pub fn login_failure(server: &str, locked: bool) -> Result<Vec<u8>> {
    let message = if locked {
        "Login failed for user. Reason: Account is locked out."
    } else {
        "Login failed for user."
    };
    let mut out = Vec::new();
    error(
        &mut out,
        &SqlError {
            number: 18456,
            state: if locked { 23 } else { 1 },
            class: 14,
            message: message.into(),
        },
        server,
    )?;
    done(&mut out, DONE, DONE_ERROR, 0);
    Ok(out)
}

pub fn response(
    result_sets: &[ResultSet],
    messages: &[String],
    sql_error: Option<&SqlError>,
    server: &str,
    done_proc: bool,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for message in messages {
        info(&mut out, 0, 1, message, server)?;
    }
    if let Some(err) = sql_error {
        error(&mut out, err, server)?;
        done(
            &mut out,
            if done_proc { DONEPROC } else { DONE },
            DONE_ERROR,
            0,
        );
        return Ok(out);
    }
    for (index, set) in result_sets.iter().enumerate() {
        colmetadata(&mut out, &set.columns)?;
        for row in &set.rows {
            row_token(&mut out, row, set.columns.len())?;
        }
        let more = if index + 1 < result_sets.len() {
            DONE_MORE
        } else {
            0
        };
        done(
            &mut out,
            if done_proc { DONEPROC } else { DONE },
            more | DONE_COUNT,
            set.rows.len() as u64,
        );
    }
    if result_sets.is_empty() {
        done(&mut out, if done_proc { DONEPROC } else { DONE }, 0, 0);
    }
    Ok(out)
}

fn colmetadata(out: &mut Vec<u8>, columns: &[String]) -> Result<()> {
    out.push(COLMETADATA);
    out.extend_from_slice(
        &u16::try_from(columns.len())
            .map_err(|_| Error::Limit("result column count"))?
            .to_le_bytes(),
    );
    for name in columns {
        out.extend_from_slice(&0_u32.to_le_bytes()); // user type, TDS 7.2+
        out.extend_from_slice(&1_u16.to_le_bytes()); // nullable
        out.push(0xe7); // NVARCHAR
        out.extend_from_slice(&8000_u16.to_le_bytes());
        out.extend_from_slice(&[0x09, 0x04, 0xd0, 0x00, 0x34]);
        b_varchar(out, name);
    }
    Ok(())
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

fn info(out: &mut Vec<u8>, number: u32, state: u8, message: &str, server: &str) -> Result<()> {
    message_token(out, INFO, number, state, 0, message, server)
}

fn error(out: &mut Vec<u8>, error: &SqlError, server: &str) -> Result<()> {
    message_token(
        out,
        ERROR,
        error.number,
        error.state,
        error.class,
        &error.message,
        server,
    )
}

fn message_token(
    out: &mut Vec<u8>,
    token: u8,
    number: u32,
    state: u8,
    class: u8,
    message: &str,
    server: &str,
) -> Result<()> {
    length_prefixed(out, token, |body| {
        body.extend_from_slice(&number.to_le_bytes());
        body.push(state);
        body.push(class);
        us_varchar(body, message);
        b_varchar(body, server);
        b_varchar(body, "");
        body.extend_from_slice(&0_u32.to_le_bytes());
    })
}

fn done(out: &mut Vec<u8>, token: u8, status: u16, row_count: u64) {
    out.push(token);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&row_count.to_le_bytes());
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
        let login = login_success("master", "us_english", 4096, "Microsoft SQL Server").unwrap();
        assert!(login.contains(&LOGINACK));
        let encoded = response(&[ResultSet::single("", "ok")], &[], None, "SQL01", false).unwrap();
        assert!(encoded.contains(&COLMETADATA));
        assert!(encoded.contains(&ROW));
    }
}
