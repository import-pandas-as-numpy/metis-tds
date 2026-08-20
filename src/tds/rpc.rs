use crate::{Error, Result, tds::batch::strip_all_headers};

#[derive(Clone, Debug)]
pub struct RpcRequest {
    pub procedure: String,
    pub options: u16,
    pub parameters: Vec<RpcParameter>,
}

#[derive(Clone, Debug)]
pub struct RpcParameter {
    pub name: String,
    pub status: u8,
    pub value: RpcValue,
}

#[derive(Clone, Debug)]
pub enum RpcValue {
    Null,
    Text(String),
    Binary(Vec<u8>),
    Integer(i64),
    Boolean(bool),
}

impl RpcValue {
    pub fn as_text(&self) -> Option<&str> {
        if let Self::Text(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub fn to_sql_literal(&self) -> String {
        match self {
            Self::Null => "NULL".into(),
            Self::Text(value) => format!("N'{}'", value.replace('\'', "''")),
            Self::Binary(value) => {
                let mut output = String::from("0x");
                for byte in value.iter().take(256) {
                    use std::fmt::Write as _;
                    let _ = write!(output, "{byte:02x}");
                }
                if value.len() > 256 {
                    output.push_str("...");
                }
                output
            }
            Self::Integer(value) => value.to_string(),
            Self::Boolean(value) => u8::from(*value).to_string(),
        }
    }

    pub fn telemetry_value(&self) -> String {
        match self {
            Self::Binary(value) => format!("<binary:{} bytes>", value.len()),
            _ => self.to_sql_literal(),
        }
    }
}

pub fn parse(payload: &[u8], max_parameter_bytes: usize) -> Result<RpcRequest> {
    let payload = strip_all_headers(payload)?;
    let mut cursor = Cursor::new(payload, max_parameter_bytes);
    let name_chars = cursor.u16()?;
    let procedure = if name_chars == 0xffff {
        procedure_name(cursor.u16()?).to_owned()
    } else {
        cursor.utf16(usize::from(name_chars))?
    };
    let options = cursor.u16()?;
    let mut parameters = Vec::new();
    while !cursor.done() {
        let name_len = usize::from(cursor.u8()?);
        let name = cursor.utf16(name_len)?;
        let status = cursor.u8()?;
        // RPC ParamMetaData contains TYPE_INFO directly; unlike COLMETADATA it
        // does not carry UserType or Flags fields.
        let type_id = cursor.u8()?;
        let value = cursor.value(type_id)?;
        parameters.push(RpcParameter {
            name,
            status,
            value,
        });
        if parameters.len() > 1024 {
            return Err(Error::Limit("RPC parameter count"));
        }
    }
    Ok(RpcRequest {
        procedure,
        options,
        parameters,
    })
}

fn procedure_name(id: u16) -> &'static str {
    match id {
        1 => "sp_cursor",
        2 => "sp_cursoropen",
        3 => "sp_cursorprepare",
        4 => "sp_cursorexecute",
        5 => "sp_cursorprepexec",
        6 => "sp_cursorunprepare",
        7 => "sp_cursorfetch",
        8 => "sp_cursoroption",
        9 => "sp_cursorclose",
        10 => "sp_executesql",
        11 => "sp_prepare",
        12 => "sp_execute",
        13 => "sp_prepexec",
        14 => "sp_prepexecrpc",
        15 => "sp_unprepare",
        _ => "unknown_rpc",
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
    consumed_values: usize,
    max_values: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8], max_values: usize) -> Self {
        Self {
            input,
            position: 0,
            consumed_values: 0,
            max_values,
        }
    }
    fn done(&self) -> bool {
        self.position == self.input.len()
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| Error::Protocol("RPC offset overflow".into()))?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or_else(|| Error::Protocol("truncated RPC request".into()))?;
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
    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().expect("length checked")))
    }
    fn utf16(&mut self, chars: usize) -> Result<String> {
        let bytes = chars
            .checked_mul(2)
            .ok_or_else(|| Error::Protocol("RPC string length overflow".into()))?;
        decode_utf16(self.take(bytes)?)
    }
    fn account(&mut self, amount: usize) -> Result<()> {
        self.consumed_values = self
            .consumed_values
            .checked_add(amount)
            .ok_or(Error::Limit("RPC parameter bytes"))?;
        if self.consumed_values > self.max_values {
            return Err(Error::Limit("maximum RPC parameter bytes"));
        }
        Ok(())
    }
    fn nullable_len_u8(&mut self) -> Result<Option<usize>> {
        let len = self.u8()?;
        if len == 0 {
            Ok(None)
        } else {
            Ok(Some(usize::from(len)))
        }
    }
    fn value(&mut self, type_id: u8) -> Result<RpcValue> {
        match type_id {
            0x30 => {
                self.account(1)?;
                Ok(RpcValue::Integer(i64::from(self.u8()?)))
            }
            0x34 => {
                self.account(2)?;
                let b = self.take(2)?;
                Ok(RpcValue::Integer(i64::from(i16::from_le_bytes([
                    b[0], b[1],
                ]))))
            }
            0x38 => {
                self.account(4)?;
                let b = self.take(4)?;
                Ok(RpcValue::Integer(i64::from(i32::from_le_bytes(
                    b.try_into().expect("length checked"),
                ))))
            }
            0x7f => {
                self.account(8)?;
                let b = self.take(8)?;
                Ok(RpcValue::Integer(i64::from_le_bytes(
                    b.try_into().expect("length checked"),
                )))
            }
            0x32 => {
                self.account(1)?;
                Ok(RpcValue::Boolean(self.u8()? != 0))
            }
            0x26 | 0x68 => {
                let max = usize::from(self.u8()?);
                match self.nullable_len_u8()? {
                    None => Ok(RpcValue::Null),
                    Some(len) if len <= max => {
                        self.account(len)?;
                        let b = self.take(len)?;
                        if type_id == 0x68 {
                            Ok(RpcValue::Boolean(b.first().copied().unwrap_or(0) != 0))
                        } else {
                            Ok(RpcValue::Integer(signed_le(b)?))
                        }
                    }
                    _ => Err(Error::Protocol(
                        "RPC nullable numeric exceeds declared size".into(),
                    )),
                }
            }
            0xa5 | 0xa7 | 0xe7 => self.variable(type_id),
            _ => Err(Error::Protocol(format!(
                "unsupported RPC parameter type 0x{type_id:02x}"
            ))),
        }
    }
    fn variable(&mut self, type_id: u8) -> Result<RpcValue> {
        let max_len = self.u16()?;
        if type_id != 0xa5 {
            self.skip(5)?;
        } // collation
        let bytes = if max_len == 0xffff {
            self.plp()?
        } else {
            let len = self.u16()?;
            if len == 0xffff {
                return Ok(RpcValue::Null);
            }
            let len = usize::from(len);
            if len > usize::from(max_len) {
                return Err(Error::Protocol("RPC value exceeds declared maximum".into()));
            }
            self.account(len)?;
            self.take(len)?.to_vec()
        };
        match type_id {
            0xe7 => Ok(RpcValue::Text(decode_utf16(&bytes)?)),
            0xa7 => Ok(RpcValue::Text(String::from_utf8_lossy(&bytes).into_owned())),
            _ => Ok(RpcValue::Binary(bytes)),
        }
    }
    fn plp(&mut self) -> Result<Vec<u8>> {
        let total = self.u64()?;
        if total == u64::MAX {
            return Ok(Vec::new());
        }
        if total != u64::MAX - 1 && total > self.max_values as u64 {
            return Err(Error::Limit("maximum RPC PLP bytes"));
        }
        let mut value = Vec::new();
        loop {
            let chunk = usize::try_from(self.u32()?).map_err(|_| Error::Limit("RPC PLP chunk"))?;
            if chunk == 0 {
                break;
            }
            self.account(chunk)?;
            value.extend_from_slice(self.take(chunk)?);
        }
        if total != u64::MAX - 1 && value.len() as u64 != total {
            return Err(Error::Protocol("RPC PLP total length mismatch".into()));
        }
        Ok(value)
    }
}

fn signed_le(bytes: &[u8]) -> Result<i64> {
    Ok(match bytes {
        [a] => i64::from(i8::from_le_bytes([*a])),
        [a, b] => i64::from(i16::from_le_bytes([*a, *b])),
        [a, b, c, d] => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
        [a, b, c, d, e, f, g, h] => i64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h]),
        _ => return Err(Error::Protocol("invalid RPC integer width".into())),
    })
}

fn decode_utf16(raw: &[u8]) -> Result<String> {
    if raw.len() % 2 != 0 {
        return Err(Error::Protocol("odd RPC UTF-16 length".into()));
    }
    Ok(char::decode_utf16(
        raw.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]])),
    )
    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_rpc_never_panics() {
        for len in 0..256 {
            let _ = parse(&vec![0x7f; len], 1024);
        }
    }

    #[test]
    fn parses_sp_executesql_nvarchar_parameter() {
        let sql: Vec<u8> = "SELECT @@VERSION"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut raw = Vec::new();
        raw.extend_from_slice(&u16::MAX.to_le_bytes());
        raw.extend_from_slice(&10_u16.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.push(0); // empty parameter name
        raw.push(0); // status
        raw.push(0xe7); // NVARCHAR
        raw.extend_from_slice(&4000_u16.to_le_bytes());
        raw.extend_from_slice(&[0x09, 0x04, 0xd0, 0x00, 0x34]);
        raw.extend_from_slice(&u16::try_from(sql.len()).unwrap().to_le_bytes());
        raw.extend_from_slice(&sql);
        let rpc = parse(&raw, 4096).unwrap();
        assert_eq!(rpc.procedure, "sp_executesql");
        assert_eq!(rpc.parameters[0].value.as_text(), Some("SELECT @@VERSION"));
    }
}
