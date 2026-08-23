use crate::{
    Error, Result,
    tds::{
        all_headers::{self, StreamHeader, StreamKind},
        data::Cursor,
        enclave::LengthEncoding,
    },
};

pub use crate::tds::data::Value as RpcValue;

#[derive(Clone, Debug)]
pub struct RpcRequest {
    pub procedure: String,
    pub options: u16,
    pub parameters: Vec<RpcParameter>,
    pub batches: Vec<RpcBatch>,
    pub headers: Vec<StreamHeader>,
}

#[derive(Clone, Debug)]
pub struct RpcBatch {
    pub separator: Option<u8>,
    pub procedure: String,
    pub options: u16,
    pub enclave_package_bytes: Option<usize>,
    pub no_execute: bool,
    pub parameters: Vec<RpcParameter>,
}

#[derive(Clone, Debug)]
pub struct RpcParameter {
    pub name: String,
    pub status: u8,
    pub type_id: u8,
    pub type_name: &'static str,
    pub value: RpcValue,
    pub encryption: Option<RpcEncryption>,
}

#[derive(Clone, Debug)]
pub struct RpcEncryption {
    pub base_type_id: u8,
    pub base_type_name: &'static str,
    pub algorithm: u8,
    pub algorithm_name: Option<String>,
    pub encryption_type: u8,
    pub database_id: u32,
    pub cek_id: u32,
    pub cek_version: u32,
    pub normalization_version: u8,
}

pub fn parse(payload: &[u8], max_parameter_bytes: usize) -> Result<RpcRequest> {
    parse_inner(
        payload,
        max_parameter_bytes,
        true,
        LengthEncoding::None,
        None,
    )
}

pub fn parse_with_context(
    payload: &[u8],
    max_parameter_bytes: usize,
    tds72_or_later: bool,
    tds74_or_later: bool,
    enclave_encoding: LengthEncoding,
) -> Result<RpcRequest> {
    parse_inner(
        payload,
        max_parameter_bytes,
        tds72_or_later,
        enclave_encoding,
        Some(tds74_or_later),
    )
}

fn parse_inner(
    payload: &[u8],
    max_parameter_bytes: usize,
    tds72_or_later: bool,
    enclave_encoding: LengthEncoding,
    strict_header_trace: Option<bool>,
) -> Result<RpcRequest> {
    let (headers, payload) = match strict_header_trace {
        Some(tds74) => {
            all_headers::parse_for_version(payload, tds72_or_later, tds74, StreamKind::Rpc)?
        }
        None => all_headers::parse(payload)?,
    };
    let mut cursor = Cursor::new(payload, max_parameter_bytes, "RPC request");
    let mut batches = Vec::new();
    let mut separator = None;
    loop {
        if cursor.done() {
            break;
        }
        let (batch, next_separator) =
            parse_batch(&mut cursor, separator, tds72_or_later, enclave_encoding)?;
        batches.push(batch);
        separator = next_separator;
        if separator.is_none() {
            break;
        }
    }
    let first = batches
        .first()
        .ok_or_else(|| Error::Protocol("empty RPC request".into()))?;
    Ok(RpcRequest {
        procedure: first.procedure.clone(),
        options: first.options,
        parameters: first.parameters.clone(),
        batches,
        headers,
    })
}

fn parse_batch(
    cursor: &mut Cursor<'_>,
    separator: Option<u8>,
    tds72_or_later: bool,
    enclave_encoding: LengthEncoding,
) -> Result<(RpcBatch, Option<u8>)> {
    let name_chars = cursor.u16()?;
    let procedure = if name_chars == 0xffff {
        procedure_name(cursor.u16()?).to_owned()
    } else {
        cursor.utf16(usize::from(name_chars))?
    };
    let options = cursor.u16()?;
    let enclave_package_bytes = match enclave_encoding {
        LengthEncoding::None => None,
        LengthEncoding::MicrosoftU16 => {
            let length = usize::from(cursor.u16()?);
            cursor.skip(length)?;
            Some(length)
        }
        LengthEncoding::SpecU32 => {
            let length = cursor.u32()?;
            if length > i32::MAX as u32 {
                return Err(Error::Protocol(
                    "negative RPC enclave package length".into(),
                ));
            }
            let length =
                usize::try_from(length).map_err(|_| Error::Limit("RPC enclave package"))?;
            cursor.skip(length)?;
            Some(length)
        }
    };
    let mut parameters = Vec::new();
    while !cursor.done() {
        let batch_flag = if tds72_or_later { 0xff } else { 0x80 };
        if cursor.peek() == Some(batch_flag) || (tds72_or_later && cursor.peek() == Some(0xfe)) {
            let next = cursor.u8()?;
            return Ok((
                RpcBatch {
                    separator,
                    procedure,
                    options,
                    enclave_package_bytes,
                    no_execute: next == 0xfe,
                    parameters,
                },
                Some(next),
            ));
        }
        let name_len = usize::from(cursor.u8()?);
        let name = cursor.utf16(name_len)?;
        let status = cursor.u8()?;
        // RPC ParamMetaData contains TYPE_INFO directly; unlike COLMETADATA it
        // does not carry UserType or Flags fields.
        let ty = cursor.type_info()?;
        let value = cursor.value(&ty)?;
        let encryption = if status & 0x08 != 0 {
            let base = cursor.type_info()?;
            let algorithm = cursor.u8()?;
            let algorithm_name = (algorithm == 0).then(|| cursor.b_varchar()).transpose()?;
            let encryption_type = cursor.u8()?;
            let database_id = cursor.u32()?;
            let cek_id = cursor.u32()?;
            let cek_version = cursor.u32()?;
            let _cek_metadata_version = cursor.u64()?;
            let normalization_version = cursor.u8()?;
            Some(RpcEncryption {
                base_type_id: base.id,
                base_type_name: base.name,
                algorithm,
                algorithm_name,
                encryption_type,
                database_id,
                cek_id,
                cek_version,
                normalization_version,
            })
        } else {
            None
        };
        parameters.push(RpcParameter {
            name,
            status,
            type_id: ty.id,
            type_name: ty.name,
            value,
            encryption,
        });
        if parameters.len() > 1024 {
            return Err(Error::Limit("RPC parameter count"));
        }
    }
    Ok((
        RpcBatch {
            separator,
            procedure,
            options,
            enclave_package_bytes,
            no_execute: false,
            parameters,
        },
        None,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn with_transaction_header(body: Vec<u8>) -> Vec<u8> {
        let mut payload = vec![22, 0, 0, 0, 18, 0, 0, 0, 2, 0];
        payload.extend_from_slice(&[0; 12]);
        payload.extend(body);
        payload
    }
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

    #[test]
    fn parses_batched_rpc_requests_without_hiding_later_calls() {
        let mut raw = Vec::new();
        for (separator, id) in [(None, 15_u16), (Some(0xff), 10_u16)] {
            if let Some(separator) = separator {
                raw.push(separator);
            }
            raw.extend_from_slice(&u16::MAX.to_le_bytes());
            raw.extend_from_slice(&id.to_le_bytes());
            raw.extend_from_slice(&0_u16.to_le_bytes());
        }
        let rpc = parse(&raw, 4096).unwrap();
        assert_eq!(rpc.batches.len(), 2);
        assert_eq!(rpc.batches[0].procedure, "sp_unprepare");
        assert_eq!(rpc.batches[1].procedure, "sp_executesql");
        assert_eq!(rpc.batches[1].separator, Some(0xff));
    }

    #[test]
    fn parses_table_valued_parameter_rows() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&u16::MAX.to_le_bytes());
        raw.extend_from_slice(&10_u16.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&[0, 0, 0xf3]); // name, status, TVPTYPE
        raw.push(0); // database
        raw.push(3);
        raw.extend("dbo".encode_utf16().flat_map(u16::to_le_bytes));
        raw.push(4);
        raw.extend("Rows".encode_utf16().flat_map(u16::to_le_bytes));
        raw.extend_from_slice(&1_u16.to_le_bytes());
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&[0x26, 4, 0]); // INTN, max 4, empty column name
        raw.push(0); // end metadata
        raw.extend_from_slice(&[1, 4, 42, 0, 0, 0, 0]); // row, value, end rows
        let rpc = parse(&raw, 4096).unwrap();
        assert_eq!(
            rpc.parameters[0].value.telemetry_value(),
            "<table:1 columns:1 rows>"
        );
    }

    #[test]
    fn parses_versioned_batch_flags_and_enclave_packages() {
        let mut raw = Vec::new();
        for (separator, id, enclave) in [(None, 15_u16, &[1_u8, 2][..]), (Some(0xff), 10, &[][..])]
        {
            if let Some(separator) = separator {
                raw.push(separator);
            }
            raw.extend_from_slice(&u16::MAX.to_le_bytes());
            raw.extend_from_slice(&id.to_le_bytes());
            raw.extend_from_slice(&0_u16.to_le_bytes());
            raw.extend_from_slice(&(enclave.len() as u16).to_le_bytes());
            raw.extend_from_slice(enclave);
        }
        let rpc = parse_with_context(
            &with_transaction_header(raw),
            4096,
            true,
            false,
            LengthEncoding::MicrosoftU16,
        )
        .unwrap();
        assert_eq!(rpc.batches.len(), 2);
        assert_eq!(rpc.batches[0].enclave_package_bytes, Some(2));
        assert_eq!(rpc.batches[1].enclave_package_bytes, Some(0));
    }

    #[test]
    fn tds71_uses_0x80_batch_separator() {
        let mut raw = Vec::new();
        for (separator, id) in [(None, 15_u16), (Some(0x80), 10_u16)] {
            if let Some(separator) = separator {
                raw.push(separator);
            }
            raw.extend_from_slice(&u16::MAX.to_le_bytes());
            raw.extend_from_slice(&id.to_le_bytes());
            raw.extend_from_slice(&0_u16.to_le_bytes());
        }
        assert_eq!(
            parse_with_context(&raw, 4096, false, false, LengthEncoding::None)
                .unwrap()
                .batches
                .len(),
            2
        );
    }

    #[test]
    fn noexec_marks_the_preceding_rpc_and_does_not_require_a_following_rpc() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&u16::MAX.to_le_bytes());
        raw.extend_from_slice(&10_u16.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.push(0xfe);
        let parsed = parse_with_context(
            &with_transaction_header(raw),
            4096,
            true,
            false,
            LengthEncoding::None,
        )
        .unwrap();
        assert_eq!(parsed.batches.len(), 1);
        assert!(parsed.batches[0].no_execute);
    }
}
