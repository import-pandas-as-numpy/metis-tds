use serde::Serialize;

use crate::{
    Error, Result,
    tds::data::{Cursor, TypeInfo, Value},
};

#[derive(Clone, Debug, Serialize)]
pub struct BulkColumn {
    pub user_type: u32,
    pub flags: u16,
    pub type_id: u8,
    pub type_name: &'static str,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkLoad {
    pub columns: Vec<BulkColumn>,
    pub row_count: usize,
    pub sampled_rows: Vec<Vec<String>>,
    pub done_status: u16,
    pub done_command: u16,
    pub declared_done_rows: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum BulkMessage {
    Bcp(BulkLoad),
    UpdateText { data_bytes: usize },
}

pub fn parse_message(
    payload: &[u8],
    max_value_bytes: usize,
    wide_metadata: bool,
    sample_rows: usize,
) -> Result<BulkMessage> {
    let bcp_error = if payload.first() == Some(&0x81) {
        match parse(payload, max_value_bytes, wide_metadata, sample_rows) {
            Ok(value) => return Ok(BulkMessage::Bcp(value)),
            Err(error) => Some(error),
        }
    } else {
        None
    };
    if payload.len() >= 4 {
        let length = usize::try_from(u32::from_le_bytes(
            payload[..4].try_into().expect("length checked"),
        ))
        .map_err(|_| Error::Limit("bulk update-text data"))?;
        if length > max_value_bytes {
            return Err(Error::Limit("maximum bulk update-text bytes"));
        }
        if payload.len() == 4_usize.saturating_add(length) {
            return Ok(BulkMessage::UpdateText { data_bytes: length });
        }
    }
    Err(bcp_error.unwrap_or_else(|| {
        Error::Protocol("bulk stream is neither BulkLoadBCP nor BulkLoadUTWT".into())
    }))
}

pub fn parse(
    payload: &[u8],
    max_value_bytes: usize,
    wide_metadata: bool,
    sample_rows: usize,
) -> Result<BulkLoad> {
    let mut cursor = Cursor::new(payload, max_value_bytes, "bulk-load stream");
    if cursor.u8()? != 0x81 {
        return Err(Error::Protocol(
            "bulk load does not begin with COLMETADATA".into(),
        ));
    }
    let count = cursor.u16()?;
    if count == u16::MAX {
        return Err(Error::Protocol(
            "bulk load COLMETADATA cannot be null".into(),
        ));
    }
    if count > 1024 {
        return Err(Error::Limit("bulk-load column count"));
    }
    let mut columns = Vec::with_capacity(usize::from(count));
    let mut types = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let user_type = if wide_metadata {
            cursor.u32()?
        } else {
            u32::from(cursor.u16()?)
        };
        let flags = cursor.u16()?;
        let ty = cursor.type_info()?;
        // Legacy LOB metadata contains a multipart table name after TYPE_INFO.
        if matches!(ty.id, 0x22 | 0x23 | 0x63) {
            let parts = cursor.u8()?;
            for _ in 0..parts {
                let _ = cursor.us_varchar()?;
            }
        }
        let name = cursor.b_varchar()?;
        columns.push(BulkColumn {
            user_type,
            flags,
            type_id: ty.id,
            type_name: ty.name,
            name,
        });
        types.push(ty);
    }

    let mut row_count = 0usize;
    let mut sampled_rows = Vec::new();
    let (done_status, done_command, declared_done_rows) = loop {
        match cursor.u8()? {
            0xd1 => {
                row_count = row_count
                    .checked_add(1)
                    .ok_or(Error::Limit("bulk-load row count"))?;
                if row_count > 1_000_000 {
                    return Err(Error::Limit("bulk-load row count"));
                }
                let mut sample =
                    (sampled_rows.len() < sample_rows).then(|| Vec::with_capacity(types.len()));
                for ty in &types {
                    let value = bulk_value(&mut cursor, ty)?;
                    if let Some(values) = &mut sample {
                        values.push(value.telemetry_value());
                    }
                }
                if let Some(sample) = sample {
                    sampled_rows.push(sample);
                }
            }
            0xd2 => return Err(Error::Protocol("NBCROW is forbidden in BulkLoadBCP".into())),
            0xfd => {
                let status = cursor.u16()?;
                let command = cursor.u16()?;
                let rows = if wide_metadata {
                    cursor.u64()?
                } else {
                    u64::from(cursor.u32()?)
                };
                break (status, command, rows);
            }
            token => {
                return Err(Error::Protocol(format!(
                    "unexpected bulk-load token 0x{token:02x}"
                )));
            }
        }
    };
    if !cursor.done() {
        return Err(Error::Protocol(format!(
            "{} trailing bulk-load bytes",
            cursor.remaining()
        )));
    }
    Ok(BulkLoad {
        columns,
        row_count,
        sampled_rows,
        done_status,
        done_command,
        declared_done_rows,
    })
}

fn bulk_value(cursor: &mut Cursor<'_>, ty: &TypeInfo) -> Result<Value> {
    if matches!(ty.id, 0x22 | 0x23 | 0x63) {
        // A null legacy LOB consists only of LONG_NULL. Non-null values carry
        // TextPointer and Timestamp before their LONG length/value.
        if cursor.remaining() >= 4 {
            // Safe lookahead without exposing Cursor internals: a clone-like
            // probe would complicate accounting, so consume the first byte and
            // handle both encodings explicitly.
            let first = cursor.u8()?;
            if first == 0xff {
                let rest = cursor.take(3)?;
                if rest == [0xff, 0xff, 0xff] {
                    return Ok(Value::Null);
                }
                return Err(Error::Protocol("invalid legacy LOB null marker".into()));
            }
            let pointer_len = usize::from(first);
            cursor.skip(pointer_len)?;
            cursor.skip(8)?;
            let len = cursor.u32()?;
            if len == u32::MAX {
                return Ok(Value::Null);
            }
            let len = usize::try_from(len).map_err(|_| Error::Limit("bulk legacy LOB"))?;
            let bytes = cursor.value_bytes(len)?;
            return Ok(if ty.id == 0x22 {
                Value::Binary(bytes)
            } else if ty.id == 0x63 {
                Value::Text(crate::tds::data::decode_utf16(&bytes)?)
            } else {
                Value::Text(String::from_utf8_lossy(&bytes).into_owned())
            });
        }
    }
    cursor.value(ty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_bulk_example() {
        let raw = [
            0x81, 0x01, 0x00, // COLMETADATA, one column
            0, 0, 0, 0, 5, 0, 0x32, 2, b'c', 0, b'1', 0, 0xd1, 0, // ROW, bit false
            0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let parsed = parse(&raw, 1024, true, 4).unwrap();
        assert_eq!(parsed.columns[0].name, "c1");
        assert_eq!(parsed.row_count, 1);
        assert_eq!(parsed.sampled_rows[0][0], "0");
    }

    #[test]
    fn rejects_nbcrow() {
        let raw = [0x81, 0, 0, 0xd2];
        assert!(parse(&raw, 1024, true, 0).is_err());
    }

    #[test]
    fn parses_update_text_l_varbyte_without_confusing_it_with_bcp() {
        let parsed = parse_message(&[3, 0, 0, 0, 1, 2, 3], 1024, true, 0).unwrap();
        assert!(matches!(parsed, BulkMessage::UpdateText { data_bytes: 3 }));
    }
}
