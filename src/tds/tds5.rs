use serde::Serialize;

use crate::{Error, Result};

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticationStream {
    pub commands: Vec<Tds5Command>,
    pub message_types: Vec<Tds5Message>,
    pub parameter_formats: usize,
    pub parameter_sets: usize,
    pub parameter_value_bytes: Vec<usize>,
    pub parameter_values: Vec<Tds5ParameterValue>,
    pub unknown_token: Option<u8>,
    pub trailing_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5Command {
    pub token: u8,
    pub name: &'static str,
    pub body_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5ParameterValue {
    pub name: String,
    pub type_id: u8,
    pub bytes: usize,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5Message {
    pub message_type: u16,
    pub name: &'static str,
    pub status: u8,
    pub extra_bytes: usize,
}

#[derive(Clone, Debug)]
struct Parameter {
    name: String,
    ty: u8,
    max_length: usize,
    encoding: ValueEncoding,
}

#[derive(Clone, Copy, Debug)]
enum ValueEncoding {
    Fixed(usize),
    U8,
    U32,
    Lob,
}

/// Parse the client-side TDS 5 token stream used for encrypted-password,
/// challenge/response, and opaque security-session continuations. Unknown
/// tokens are reported with their exact trailing span so callers can retain
/// the artifact without guessing token boundaries.
pub fn parse_authentication(input: &[u8], max_value_bytes: usize) -> Result<AuthenticationStream> {
    let mut cursor = Cursor { input, position: 0 };
    let mut result = AuthenticationStream {
        commands: Vec::new(),
        message_types: Vec::new(),
        parameter_formats: 0,
        parameter_sets: 0,
        parameter_value_bytes: Vec::new(),
        parameter_values: Vec::new(),
        unknown_token: None,
        trailing_bytes: 0,
    };
    let mut parameters = Vec::new();
    let mut consumed_values = 0usize;
    while !cursor.done() {
        match cursor.u8()? {
            0x21 => {
                let len = usize::try_from(cursor.u32()?)
                    .map_err(|_| Error::Limit("TDS 5 LANGUAGE token"))?;
                let body = cursor.take(len)?;
                if body.is_empty() {
                    return Err(Error::Protocol("empty TDS 5 LANGUAGE token".into()));
                }
                result.commands.push(Tds5Command {
                    token: 0x21,
                    name: "language",
                    body_bytes: len,
                    operation: None,
                    identifier: None,
                    text: Some(String::from_utf8_lossy(&body[1..]).into_owned()),
                });
            }
            0xe6 => {
                let len = usize::from(cursor.u16()?);
                let body = cursor.take(len)?;
                let mut command = parse_dbrpc(body)?;
                command.body_bytes = len;
                result.commands.push(command);
            }
            0xe7 => {
                let len = usize::from(cursor.u16()?);
                let body = cursor.take(len)?;
                let mut command = parse_dynamic(body)?;
                command.body_bytes = len;
                result.commands.push(command);
            }
            token @ (0x80..=0x84 | 0x86 | 0xa6) => {
                let len = usize::from(cursor.u16()?);
                let body = cursor.take(len)?;
                result.commands.push(parse_simple_command(token, body)?);
            }
            0x71 => {
                let len = usize::from(cursor.u8()?);
                cursor.skip(len)?;
                result.commands.push(Tds5Command {
                    token: 0x71,
                    name: "logout",
                    body_bytes: len,
                    operation: None,
                    identifier: None,
                    text: None,
                });
            }
            0x65 => {
                let len = usize::from(cursor.u8()?);
                let body = cursor.take(len)?;
                if len < 3 {
                    return Err(Error::Protocol("short TDS 5 MSG token".into()));
                }
                let message_type = u16::from_le_bytes([body[1], body[2]]);
                result.message_types.push(Tds5Message {
                    message_type,
                    name: message_type_name(message_type),
                    status: body[0],
                    extra_bytes: len - 3,
                });
            }
            token @ (0xec | 0x20) => {
                let wide = token == 0x20;
                let len = if !wide {
                    usize::from(cursor.u16()?)
                } else {
                    usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 PARAMFMT2"))?
                };
                let body = cursor.take(len)?;
                parameters = parse_parameter_format(body, wide)?;
                result.parameter_formats += 1;
            }
            0xd7 => {
                if parameters.is_empty() {
                    return Err(Error::Protocol("TDS 5 PARAMS without PARAMFMT".into()));
                }
                for parameter in &parameters {
                    let len = value_length(&mut cursor, parameter)?;
                    if len > parameter.max_length && parameter.max_length != usize::MAX {
                        return Err(Error::Protocol(
                            "TDS 5 parameter exceeds declared maximum".into(),
                        ));
                    }
                    consumed_values = consumed_values
                        .checked_add(len)
                        .ok_or(Error::Limit("TDS 5 authentication bytes"))?;
                    if consumed_values > max_value_bytes {
                        return Err(Error::Limit("TDS 5 authentication bytes"));
                    }
                    let value = cursor.take(len)?;
                    result.parameter_value_bytes.push(len);
                    result.parameter_values.push(Tds5ParameterValue {
                        name: parameter.name.clone(),
                        type_id: parameter.ty,
                        bytes: len,
                        value: summarize_value(parameter.ty, value),
                    });
                }
                result.parameter_sets += 1;
            }
            token => {
                result.unknown_token = Some(token);
                result.trailing_bytes = cursor.remaining();
                break;
            }
        }
        if result.commands.len()
            + result.message_types.len()
            + result.parameter_formats
            + result.parameter_sets
            > 4096
        {
            return Err(Error::Limit("TDS 5 authentication token count"));
        }
    }
    Ok(result)
}

fn parse_parameter_format(input: &[u8], wide_status: bool) -> Result<Vec<Parameter>> {
    let mut cursor = Cursor { input, position: 0 };
    let count = cursor.u16()?;
    if count > 1024 {
        return Err(Error::Limit("TDS 5 parameter count"));
    }
    let mut parameters = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let name_len = usize::from(cursor.u8()?);
        let name = String::from_utf8_lossy(cursor.take(name_len)?).into_owned();
        cursor.skip(if wide_status { 4 } else { 1 })?; // status
        cursor.skip(4)?; // user type
        let ty = cursor.u8()?;
        let (max_length, encoding) = match ty {
            // Fixed-width Adaptive Server types. Some IDs overlap Microsoft
            // TDS 7 types, so this table deliberately remains TDS-5-specific.
            0x1f => (0, ValueEncoding::Fixed(0)), // void
            0x30 | 0x32 | 0x40 | 0xb0 => (1, ValueEncoding::Fixed(1)),
            0x34 | 0x41 => (2, ValueEncoding::Fixed(2)),
            0x31 | 0x33 | 0x38 | 0x3a | 0x3b | 0x42 | 0x7a => (4, ValueEncoding::Fixed(4)),
            0x2e | 0x3c | 0x3d | 0x3e | 0x43 | 0x7f | 0xbf => (8, ValueEncoding::Fixed(8)),
            // NUMERIC/DECIMAL carry max length, precision, and scale.
            0x6a | 0x6c => {
                let max = usize::from(cursor.u8()?);
                let precision = cursor.u8()?;
                let scale = cursor.u8()?;
                if precision == 0 || precision > 77 || scale > precision {
                    return Err(Error::Protocol("invalid TDS 5 numeric metadata".into()));
                }
                (max, ValueEncoding::U8)
            }
            // BIGDATETIME/BIGTIME carry max length and precision.
            0xbb | 0xbc => {
                let max = usize::from(cursor.u8()?);
                let precision = cursor.u8()?;
                if max != 8 || precision > 6 {
                    return Err(Error::Protocol("invalid TDS 5 big-time metadata".into()));
                }
                (max, ValueEncoding::U8)
            }
            // Ordinary nullable and variable-width Adaptive Server types.
            0x25 | 0x26 | 0x27 | 0x2d | 0x2f | 0x44 | 0x67 | 0x68 | 0x6d | 0x6e | 0x6f | 0x7b
            | 0x93 => (usize::from(cursor.u8()?), ValueEncoding::U8),
            // LONGCHAR/LONGBINARY use a 32-bit declared and actual length.
            0xaf | 0xe1 => (
                usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 long parameter"))?,
                ValueEncoding::U32,
            ),
            // Classic LOB metadata adds a USHORT table-name field. Values
            // carry a text pointer, timestamp, and 32-bit data length.
            0x22 | 0x23 | 0xa3 | 0xae => {
                let max = usize::try_from(cursor.u32()?)
                    .map_err(|_| Error::Limit("TDS 5 LOB parameter"))?;
                let table_name_bytes = usize::from(cursor.u16()?);
                cursor.skip(table_name_bytes)?;
                (max, ValueEncoding::Lob)
            }
            _ => {
                return Err(Error::Protocol(format!(
                    "unknown TDS 5 parameter type 0x{ty:02x}"
                )));
            }
        };
        let locale_len = usize::from(cursor.u8()?);
        cursor.skip(locale_len)?;
        parameters.push(Parameter {
            name,
            ty,
            max_length,
            encoding,
        });
    }
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 PARAMFMT bytes".into()));
    }
    Ok(parameters)
}

fn parse_dbrpc(input: &[u8]) -> Result<Tds5Command> {
    let mut cursor = Cursor { input, position: 0 };
    let name = cursor.b_varbyte()?;
    let _flags = cursor.u16()?;
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 DBRPC bytes".into()));
    }
    Ok(Tds5Command {
        token: 0xe6,
        name: "dbrpc",
        body_bytes: input.len(),
        operation: None,
        identifier: Some(name),
        text: None,
    })
}

fn parse_dynamic(input: &[u8]) -> Result<Tds5Command> {
    let mut cursor = Cursor { input, position: 0 };
    let operation = cursor.u8()?;
    let _status = cursor.u8()?;
    let identifier = cursor.b_varbyte()?;
    let text = if cursor.done() {
        None
    } else {
        Some(cursor.us_varbyte_string()?)
    };
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 DYNAMIC bytes".into()));
    }
    Ok(Tds5Command {
        token: 0xe7,
        name: "dynamic",
        body_bytes: input.len(),
        operation: Some(match operation {
            1 => "prepare",
            2 => "execute",
            3 => "deallocate",
            4 => "execute_immediate",
            5 => "describe_input",
            6 => "describe_output",
            _ => "unknown",
        }),
        identifier: Some(identifier),
        text,
    })
}

fn parse_simple_command(token: u8, input: &[u8]) -> Result<Tds5Command> {
    let mut command = Tds5Command {
        token,
        name: match token {
            0x80 => "cursor_close",
            0x81 => "cursor_delete",
            0x82 => "cursor_fetch",
            0x83 => "cursor_info",
            0x84 => "cursor_open",
            0x86 => "cursor_declare",
            0xa6 => "option_command",
            _ => "unknown",
        },
        body_bytes: input.len(),
        operation: None,
        identifier: None,
        text: None,
    };
    if token == 0x86 {
        let mut cursor = Cursor { input, position: 0 };
        command.identifier = Some(cursor.b_varbyte()?);
        cursor.skip(2)?; // cursor option and status
        command.text = Some(cursor.us_varbyte_string()?);
        // Remaining bytes describe updateable columns. Their extent is
        // already bounded by the token's USHORT length.
    } else if token == 0x84 && input.len() >= 5 {
        let mut cursor = Cursor { input, position: 4 };
        command.identifier = Some(cursor.b_varbyte()?);
    }
    Ok(command)
}

fn summarize_value(ty: u8, value: &[u8]) -> String {
    match ty {
        0x23 | 0x27 | 0x2f | 0x67 | 0xa3 | 0xaf => String::from_utf8_lossy(value).into_owned(),
        0xae if value.len() % 2 == 0 => crate::tds::data::decode_utf16(value)
            .unwrap_or_else(|_| format!("<binary:{} bytes>", value.len())),
        0x30 | 0x40 | 0xb0 if value.len() == 1 => value[0].to_string(),
        _ => format!("<binary:{} bytes>", value.len()),
    }
}

fn value_length(cursor: &mut Cursor<'_>, parameter: &Parameter) -> Result<usize> {
    Ok(match parameter.encoding {
        ValueEncoding::Fixed(size) => size,
        ValueEncoding::U8 => usize::from(cursor.u8()?),
        ValueEncoding::U32 => {
            usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 long value"))?
        }
        ValueEncoding::Lob => {
            let pointer_bytes = usize::from(cursor.u8()?);
            if pointer_bytes == 0 {
                return Ok(0);
            }
            cursor.skip(pointer_bytes)?;
            cursor.skip(8)?; // timestamp
            usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 LOB value"))?
        }
    })
}

pub fn message_type_name(value: u16) -> &'static str {
    match value {
        1 => "secure_encryption",
        2 => "encrypted_login_password",
        3 => "encrypted_remote_password",
        4 => "secure_challenge",
        5 => "secure_response",
        6 => "get_security_label",
        7 => "security_label",
        8 => "table_name",
        9 => "gateway_reserved",
        10 => "omni_capabilities",
        11 => "opaque_security",
        12 => "ha_failover",
        13 => "empty",
        14 => "secure_encryption_v2",
        15 => "encrypted_login_password_v2",
        16 => "supported_ciphers",
        17 => "migration_request",
        18 => "migration_sync",
        19 => "migration_continue",
        20 => "migration_ignore",
        21 => "migration_failure",
        22 => "encrypted_remote_password_v2",
        23 => "migration_resume",
        30 => "secure_encryption_v3",
        31 => "encrypted_login_password_v3",
        32 => "encrypted_remote_password_v3",
        33 => "disaster_recovery_map",
        _ => "unknown",
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn done(&self) -> bool {
        self.position == self.input.len()
    }
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(Error::Limit("TDS 5 token offset"))?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or_else(|| Error::Protocol("truncated TDS 5 token stream".into()))?;
        self.position = end;
        Ok(value)
    }
    fn skip(&mut self, len: usize) -> Result<()> {
        self.take(len).map(|_| ())
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().expect("length checked")))
    }
    fn b_varbyte(&mut self) -> Result<String> {
        let len = usize::from(self.u8()?);
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
    fn us_varbyte_string(&mut self) -> Result<String> {
        let len = usize::from(self.u16()?);
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_freetds_rsa_password_continuation() {
        let encrypted = [0x55; 32];
        let mut raw = vec![0x65, 3, 1, 31, 0];
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        raw.extend_from_slice(&encrypted);
        let parsed = parse_authentication(&raw, 1024).unwrap();
        assert_eq!(parsed.message_types[0].name, "encrypted_login_password_v3");
        assert_eq!(parsed.parameter_value_bytes, [32]);
    }

    #[test]
    fn parses_language_rpc_dynamic_and_wide_parameter_streams() {
        let mut raw = vec![0x21];
        raw.extend_from_slice(&9_u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(b"SELECT 1");
        raw.push(0xe6);
        raw.extend_from_slice(&5_u16.to_le_bytes());
        raw.extend_from_slice(&[2, b's', b'p', 0, 0]);
        raw.push(0xe7);
        raw.extend_from_slice(&6_u16.to_le_bytes());
        raw.extend_from_slice(&[2, 0, 1, b'q', 0, 0]);
        raw.push(0x20);
        raw.extend_from_slice(&15_u32.to_le_bytes());
        raw.extend_from_slice(&1_u16.to_le_bytes());
        raw.extend_from_slice(&[1, b'p', 0, 0, 0, 0]);
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.extend_from_slice(&[0x27, 8, 0]);
        raw.extend_from_slice(&[0xd7, 3, b's', b'q', b'l']);
        let parsed = parse_authentication(&raw, 1024).unwrap();
        assert_eq!(parsed.commands[0].text.as_deref(), Some("SELECT 1"));
        assert_eq!(parsed.commands[1].identifier.as_deref(), Some("sp"));
        assert_eq!(parsed.commands[2].operation, Some("execute"));
        assert_eq!(parsed.parameter_values[0].value, "sql");
    }

    #[test]
    fn parses_sybase_specific_fixed_long_numeric_and_lob_types() {
        let mut raw = vec![0xec];
        let mut format = Vec::new();
        format.extend_from_slice(&4_u16.to_le_bytes());
        // UINT4, which overlaps no nullable Microsoft type.
        format.extend_from_slice(&[1, b'u', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x42, 0]);
        // LONGCHAR with 32-bit max length.
        format.extend_from_slice(&[1, b'l', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.push(0xaf);
        format.extend_from_slice(&32_u32.to_le_bytes());
        format.push(0);
        // NUMERIC(max, precision, scale).
        format.extend_from_slice(&[1, b'n', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x6c, 5, 9, 2, 0]);
        // TEXT(max, empty table name).
        format.extend_from_slice(&[1, b't', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.push(0x23);
        format.extend_from_slice(&64_u32.to_le_bytes());
        format.extend_from_slice(&0_u16.to_le_bytes());
        format.push(0);
        raw.extend_from_slice(&(format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&format);
        raw.push(0xd7);
        raw.extend_from_slice(&7_u32.to_le_bytes());
        raw.extend_from_slice(&4_u32.to_le_bytes());
        raw.extend_from_slice(b"test");
        raw.extend_from_slice(&[3, 1, 2, 3]);
        raw.push(16);
        raw.extend_from_slice(&[0x55; 16]);
        raw.extend_from_slice(&[0x66; 8]);
        raw.extend_from_slice(&5_u32.to_le_bytes());
        raw.extend_from_slice(b"hello");

        let parsed = parse_authentication(&raw, 1024).unwrap();
        assert_eq!(parsed.parameter_value_bytes, [4, 4, 3, 5]);
        assert_eq!(parsed.parameter_values[1].value, "test");
        assert_eq!(parsed.parameter_values[3].value, "hello");
    }
}
