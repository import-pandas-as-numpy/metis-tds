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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<BulkColumnEncryption>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkColumnEncryption {
    pub cek_ordinal: u16,
    pub base_user_type: u32,
    pub base_type_id: u8,
    pub base_type_name: &'static str,
    pub algorithm: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_name: Option<String>,
    pub encryption_type: u8,
    pub normalization_version: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkCekEntry {
    pub database_id: u32,
    pub cek_id: u32,
    pub cek_version: u32,
    pub metadata_version: String,
    pub encrypted_values: Vec<BulkEncryptedKeyValue>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkEncryptedKeyValue {
    pub encrypted_key_bytes: usize,
    pub key_store_name: String,
    pub key_path: String,
    pub asymmetric_algorithm: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkLoad {
    pub columns: Vec<BulkColumn>,
    pub cek_table: Vec<BulkCekEntry>,
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
    UpdateText {
        data_bytes: usize,
    },
    Tds5Rows {
        row_count: usize,
        row_lengths: Vec<usize>,
        sampled_rows: Vec<Tds5BulkRow>,
        trailing_bytes: usize,
    },
    Tds42Rows {
        row_count: usize,
        sampled_rows: Vec<Tds42BulkRow>,
        text_image_values: usize,
        text_image_bytes: usize,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5BulkRow {
    pub bytes: usize,
    pub printable_strings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds42BulkRow {
    pub bytes: usize,
    pub row_number: u8,
    pub variable_columns: u8,
    pub fixed_region_bytes: usize,
    pub variable_value_lengths: Vec<usize>,
    pub printable_strings: Vec<String>,
}

pub fn parse_tds42_message(
    payload: &[u8],
    max_value_bytes: usize,
    sample_rows: usize,
) -> Result<BulkMessage> {
    let bcp_error = match parse_tds42_bcp(payload, max_value_bytes, sample_rows) {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if payload.len() >= 4 {
        let length = usize::try_from(u32::from_le_bytes(
            payload[..4].try_into().expect("length checked"),
        ))
        .map_err(|_| Error::Limit("TDS 4.2 bulk update-text data"))?;
        if length > max_value_bytes {
            return Err(Error::Limit("maximum TDS 4.2 bulk update-text bytes"));
        }
        if payload.len() == 4_usize.saturating_add(length) {
            return Ok(BulkMessage::UpdateText { data_bytes: length });
        }
    }
    Err(bcp_error)
}

fn parse_tds42_bcp(
    payload: &[u8],
    max_value_bytes: usize,
    sample_rows: usize,
) -> Result<BulkMessage> {
    if payload.len() > max_value_bytes {
        return Err(Error::Limit("maximum TDS 4.2 bulk bytes"));
    }
    let mut position = 0usize;
    let mut sampled_rows = Vec::new();
    let mut row_count = 0usize;
    let mut text_image_values = 0usize;
    let mut text_image_bytes = 0usize;
    while position < payload.len() {
        // Text/image values are trailers of the preceding row and begin with
        // the two-byte 0x0000 delimiter. A row length is required to be > 0.
        while payload.get(position..position + 2) == Some(&[0, 0]) {
            position += 2;
            let ty = *payload
                .get(position)
                .ok_or_else(|| Error::Protocol("truncated TDS 4.2 BCP LOB type".into()))?;
            if !matches!(ty, 0x22 | 0x23) {
                return Err(Error::Protocol(format!(
                    "invalid TDS 4.2 BCP LOB type 0x{ty:02x}"
                )));
            }
            position += 1;
            position = position
                .checked_add(3) // column id and reserved USHORT
                .ok_or(Error::Limit("TDS 4.2 BCP LOB offset"))?;
            let length_bytes = payload
                .get(position..position + 4)
                .ok_or_else(|| Error::Protocol("truncated TDS 4.2 BCP LOB length".into()))?;
            position += 4;
            let length = u32::from_le_bytes(length_bytes.try_into().expect("length checked"));
            if length == 0 {
                text_image_values += 1;
                continue;
            }
            let length =
                usize::try_from(length).map_err(|_| Error::Limit("TDS 4.2 BCP LOB value"))?;
            let end = position
                .checked_add(length)
                .ok_or(Error::Limit("TDS 4.2 BCP LOB offset"))?;
            if end > payload.len() {
                return Err(Error::Protocol("truncated TDS 4.2 BCP LOB value".into()));
            }
            position = end;
            text_image_values += 1;
            text_image_bytes = text_image_bytes
                .checked_add(length)
                .ok_or(Error::Limit("TDS 4.2 BCP LOB bytes"))?;
        }
        if position == payload.len() {
            break;
        }
        let length_bytes = payload
            .get(position..position + 2)
            .ok_or_else(|| Error::Protocol("truncated TDS 4.2 BCP row length".into()))?;
        let length = usize::from(u16::from_le_bytes(
            length_bytes.try_into().expect("length checked"),
        ));
        if length == 0 {
            return Err(Error::Protocol("zero-length TDS 4.2 BCP row".into()));
        }
        position += 2;
        let end = position
            .checked_add(length)
            .ok_or(Error::Limit("TDS 4.2 BCP row offset"))?;
        let row = payload
            .get(position..end)
            .ok_or_else(|| Error::Protocol("truncated TDS 4.2 BCP row".into()))?;
        position = end;
        let variable_columns = *row
            .first()
            .ok_or_else(|| Error::Protocol("short TDS 4.2 BCP row".into()))?;
        let row_number = *row
            .get(1)
            .ok_or_else(|| Error::Protocol("short TDS 4.2 BCP row".into()))?;
        let offset_count = usize::from(variable_columns) + 1;
        let adjust_count = length.div_ceil(256).max(1);
        let tail = adjust_count
            .checked_add(offset_count)
            .ok_or(Error::Limit("TDS 4.2 BCP offset table"))?;
        if row.len() < 4 + tail {
            return Err(Error::Protocol("short TDS 4.2 BCP offset table".into()));
        }
        let adjust_start = row.len() - tail;
        let offsets_raw = &row[adjust_start + adjust_count..];
        let mut offsets = offsets_raw
            .iter()
            .rev()
            .map(|value| usize::from(*value))
            .collect::<Vec<_>>();
        let mut high = 0usize;
        for index in 1..offsets.len() {
            if offsets[index] < offsets[index - 1] {
                high = high
                    .checked_add(256)
                    .ok_or(Error::Limit("TDS 4.2 BCP adjusted offset"))?;
            }
            offsets[index] += high;
        }
        let first_variable = offsets[0];
        if first_variable < 4 || first_variable > adjust_start {
            return Err(Error::Protocol("invalid TDS 4.2 BCP first offset".into()));
        }
        let row_len_at = first_variable - 2;
        let declared = u16::from_le_bytes(
            row.get(row_len_at..first_variable)
                .ok_or_else(|| Error::Protocol("missing TDS 4.2 BCP RowLen".into()))?
                .try_into()
                .expect("length checked"),
        );
        if usize::from(declared) != length {
            return Err(Error::Protocol("TDS 4.2 BCP RowLen mismatch".into()));
        }
        if offsets.last().copied() != Some(adjust_start)
            || offsets.windows(2).any(|pair| pair[0] > pair[1])
        {
            return Err(Error::Protocol(
                "invalid TDS 4.2 BCP variable offsets".into(),
            ));
        }
        let variable_value_lengths = offsets
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect::<Vec<_>>();
        row_count = row_count
            .checked_add(1)
            .ok_or(Error::Limit("TDS 4.2 BCP row count"))?;
        if row_count > 1_000_000 {
            return Err(Error::Limit("TDS 4.2 BCP row count"));
        }
        if sampled_rows.len() < sample_rows {
            sampled_rows.push(Tds42BulkRow {
                bytes: length,
                row_number,
                variable_columns,
                fixed_region_bytes: row_len_at.saturating_sub(2),
                variable_value_lengths,
                printable_strings: printable_strings(&row[..adjust_start]),
            });
        }
    }
    if row_count == 0 {
        return Err(Error::Protocol("TDS 4.2 BCP stream has no rows".into()));
    }
    Ok(BulkMessage::Tds42Rows {
        row_count,
        sampled_rows,
        text_image_values,
        text_image_bytes,
    })
}

pub fn parse_tds5_rows(
    payload: &[u8],
    max_value_bytes: usize,
    sample_rows: usize,
) -> Result<BulkMessage> {
    if payload.len() > max_value_bytes {
        return Err(Error::Limit("maximum TDS 5 bulk bytes"));
    }
    let mut position = 0usize;
    let mut row_lengths = Vec::new();
    let mut sampled_rows = Vec::new();
    while position + 2 <= payload.len() {
        let length = usize::from(u16::from_le_bytes([
            payload[position],
            payload[position + 1],
        ]));
        let body_start = position + 2;
        let Some(end) = body_start.checked_add(length) else {
            break;
        };
        if end > payload.len() {
            break;
        }
        let row = &payload[body_start..end];
        row_lengths.push(length);
        if sampled_rows.len() < sample_rows {
            sampled_rows.push(Tds5BulkRow {
                bytes: length,
                printable_strings: printable_strings(row),
            });
        }
        position = end;
        if row_lengths.len() > 1_000_000 {
            return Err(Error::Limit("TDS 5 bulk row count"));
        }
    }
    Ok(BulkMessage::Tds5Rows {
        row_count: row_lengths.len(),
        row_lengths,
        sampled_rows,
        trailing_bytes: payload.len() - position,
    })
}

fn printable_strings(input: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut start = None;
    for (index, byte) in input.iter().copied().chain(std::iter::once(0)).enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take()
            && index - begin >= 4
        {
            strings.push(String::from_utf8_lossy(&input[begin..index]).into_owned());
            if strings.len() == 16 {
                break;
            }
        }
    }
    strings
}

pub fn parse_message(
    payload: &[u8],
    max_value_bytes: usize,
    wide_metadata: bool,
    column_encryption: bool,
    sample_rows: usize,
) -> Result<BulkMessage> {
    let bcp_error = if payload.first() == Some(&0x81) {
        match parse(
            payload,
            max_value_bytes,
            wide_metadata,
            column_encryption,
            sample_rows,
        ) {
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
    column_encryption: bool,
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
    let mut cek_table = Vec::new();
    if column_encryption {
        let cek_count = cursor.u16()?;
        if cek_count > 1024 {
            return Err(Error::Limit("bulk-load CEK count"));
        }
        for _ in 0..cek_count {
            let database_id = cursor.u32()?;
            let cek_id = cursor.u32()?;
            let cek_version = cursor.u32()?;
            let metadata_version = format!("{:016x}", cursor.u64()?);
            let value_count = cursor.u8()?;
            let mut encrypted_values = Vec::with_capacity(usize::from(value_count));
            for _ in 0..value_count {
                let encrypted_key_bytes = usize::from(cursor.u16()?);
                cursor.skip(encrypted_key_bytes)?;
                encrypted_values.push(BulkEncryptedKeyValue {
                    encrypted_key_bytes,
                    key_store_name: cursor.b_varchar()?,
                    key_path: cursor.us_varchar()?,
                    asymmetric_algorithm: cursor.b_varchar()?,
                });
            }
            cek_table.push(BulkCekEntry {
                database_id,
                cek_id,
                cek_version,
                metadata_version,
                encrypted_values,
            });
        }
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
        let encryption = if flags & 0x0800 != 0 {
            if !column_encryption {
                return Err(Error::Protocol(
                    "encrypted bulk column without COLUMNENCRYPTION negotiation".into(),
                ));
            }
            let cek_ordinal = cursor.u16()?;
            if usize::from(cek_ordinal) >= cek_table.len() {
                return Err(Error::Protocol(
                    "encrypted bulk column CEK ordinal is out of range".into(),
                ));
            }
            let base_user_type = cursor.u32()?;
            let base = cursor.type_info()?;
            let algorithm = cursor.u8()?;
            let algorithm_name = (algorithm == 0).then(|| cursor.b_varchar()).transpose()?;
            let encryption_type = cursor.u8()?;
            if !matches!(encryption_type, 1 | 2) {
                return Err(Error::Protocol(
                    "invalid bulk column encryption type".into(),
                ));
            }
            let normalization_version = cursor.u8()?;
            if normalization_version == 0 {
                return Err(Error::Protocol(
                    "invalid bulk column normalization version".into(),
                ));
            }
            Some(BulkColumnEncryption {
                cek_ordinal,
                base_user_type,
                base_type_id: base.id,
                base_type_name: base.name,
                algorithm,
                algorithm_name,
                encryption_type,
                normalization_version,
            })
        } else {
            None
        };
        let name = cursor.b_varchar()?;
        columns.push(BulkColumn {
            user_type,
            flags,
            type_id: ty.id,
            type_name: ty.name,
            name,
            encryption,
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
        cek_table,
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
        let parsed = parse(&raw, 1024, true, false, 4).unwrap();
        assert_eq!(parsed.columns[0].name, "c1");
        assert_eq!(parsed.row_count, 1);
        assert_eq!(parsed.sampled_rows[0][0], "0");
    }

    #[test]
    fn rejects_nbcrow_as_forbidden_by_the_bulkloadbcp_grammar() {
        // NBCROW is a published server-to-client row token, but MS-TDS says
        // it MUST NOT appear in the client-to-server BulkLoadBCP stream.
        let raw = [0x81, 0, 0, 0xd2];
        assert!(parse(&raw, 1024, true, false, 0).is_err());
    }

    #[test]
    fn parses_column_encryption_key_and_crypto_metadata() {
        let mut raw = vec![0x81];
        raw.extend_from_slice(&1_u16.to_le_bytes()); // one column
        raw.extend_from_slice(&1_u16.to_le_bytes()); // one CEK entry
        raw.extend_from_slice(&1_u32.to_le_bytes()); // database id
        raw.extend_from_slice(&2_u32.to_le_bytes()); // CEK id
        raw.extend_from_slice(&3_u32.to_le_bytes()); // CEK version
        raw.extend_from_slice(&4_u64.to_le_bytes()); // metadata version
        raw.push(1); // one encrypted key value
        raw.extend_from_slice(&3_u16.to_le_bytes());
        raw.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        raw.extend_from_slice(&[1, b'M', 0]); // key store
        raw.extend_from_slice(&[1, 0, b'P', 0]); // key path
        raw.extend_from_slice(&[1, b'A', 0]); // asymmetric algorithm
        raw.extend_from_slice(&0_u32.to_le_bytes()); // column user type
        raw.extend_from_slice(&0x0800_u16.to_le_bytes()); // encrypted flag
        raw.push(0xa5); // ciphertext varbinary
        raw.extend_from_slice(&8000_u16.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes()); // CEK ordinal
        raw.extend_from_slice(&0_u32.to_le_bytes()); // plaintext user type
        raw.push(0xe7); // plaintext nvarchar
        raw.extend_from_slice(&20_u16.to_le_bytes());
        raw.extend_from_slice(&[0x09, 0x04, 0xd0, 0x00, 0x34]);
        raw.extend_from_slice(&[1, 1, 1]); // algorithm, deterministic, normalization v1
        raw.extend_from_slice(&[1, b'c', 0]); // column name
        raw.push(0xd1);
        raw.extend_from_slice(&2_u16.to_le_bytes());
        raw.extend_from_slice(&[0x12, 0x34]);
        raw.push(0xfd);
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&1_u64.to_le_bytes());

        let parsed = parse(&raw, 4096, true, true, 1).unwrap();
        assert_eq!(parsed.cek_table.len(), 1);
        assert_eq!(
            parsed.cek_table[0].encrypted_values[0].encrypted_key_bytes,
            3
        );
        assert_eq!(
            parsed.columns[0]
                .encryption
                .as_ref()
                .unwrap()
                .base_type_name,
            "nvarchar"
        );
        assert_eq!(parsed.sampled_rows[0][0], "<binary:2 bytes>");
    }

    #[test]
    fn parses_update_text_l_varbyte_without_confusing_it_with_bcp() {
        let parsed = parse_message(&[3, 0, 0, 0, 1, 2, 3], 1024, true, false, 0).unwrap();
        assert!(matches!(parsed, BulkMessage::UpdateText { data_bytes: 3 }));
    }

    #[test]
    fn inventories_tds5_length_prefixed_rows_and_preserves_trailing_blob_data() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&6_u16.to_le_bytes());
        raw.extend_from_slice(b"admin1");
        raw.extend_from_slice(&8_u16.to_le_bytes());
        raw.extend_from_slice(b"password");
        raw.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let parsed = parse_tds5_rows(&raw, 1024, 2).unwrap();
        let BulkMessage::Tds5Rows {
            row_count,
            row_lengths,
            sampled_rows,
            trailing_bytes,
        } = parsed
        else {
            panic!("expected TDS 5 rows")
        };
        assert_eq!(row_count, 2);
        assert_eq!(row_lengths, [6, 8]);
        assert_eq!(sampled_rows[0].printable_strings, ["admin1"]);
        assert_eq!(sampled_rows[1].printable_strings, ["password"]);
        assert_eq!(trailing_bytes, 3);
    }

    #[test]
    fn parses_the_published_tds42_bcp_row_layout() {
        let raw = [
            0x17, 0x00, // Length
            0x01, 0x00, // NumVarCols, RowNum
            0x0f, 0, 0, 0, // fixed data
            0, 0, 0, 0, 0, 0, 0, // padding
            0x17, 0x00, // RowLen
            b'e', b'b', b'c', b'd', b'e', // variable data
            0x02, // Adjust sentinel
            0x14, 0x0f, // end and start offsets, reverse order
        ];
        let parsed = parse_tds42_message(&raw, 1024, 2).unwrap();
        let BulkMessage::Tds42Rows {
            row_count,
            sampled_rows,
            ..
        } = parsed
        else {
            panic!("expected TDS 4.2 rows")
        };
        assert_eq!(row_count, 1);
        assert_eq!(sampled_rows[0].fixed_region_bytes, 11);
        assert_eq!(sampled_rows[0].variable_value_lengths, [5]);
        assert!(parse_tds42_message(&raw[..raw.len() - 1], 1024, 2).is_err());
    }
}
