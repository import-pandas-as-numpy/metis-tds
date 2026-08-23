//! Bounds-safe parsing for the type-dependent values shared by RPC, TVP, and
//! bulk-load streams.  The wire grammar is MS-TDS TYPE_INFO/TYPE_VARBYTE; this
//! module intentionally keeps unfamiliar values as typed binary telemetry
//! instead of discarding the rest of a message.

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInfo {
    pub id: u8,
    pub name: &'static str,
    pub max_length: Option<u64>,
    pub precision: Option<u8>,
    pub scale: Option<u8>,
    pub collation: Option<[u8; 5]>,
    pub kind: TypeKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Fixed(usize),
    ByteLength,
    UShortLength,
    LongLength,
    Plp,
    Json,
    Variant,
    Tvp(TvpInfo),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TvpInfo {
    pub database: String,
    pub schema: String,
    pub type_name: String,
    pub columns: Vec<TvpColumn>,
    pub row_order: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TvpColumn {
    pub user_type: u32,
    pub flags: u16,
    pub ty: TypeInfo,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Text(String),
    Binary(Vec<u8>),
    Integer(i64),
    Boolean(bool),
    Floating(f64),
    Decimal(String),
    Guid(String),
    Temporal {
        kind: &'static str,
        raw: String,
    },
    Variant {
        base_type: Option<&'static str>,
        bytes: usize,
        properties_bytes: usize,
        value: Option<Box<Value>>,
    },
    Table {
        columns: usize,
        rows: usize,
    },
}

impl Value {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn telemetry_value(&self) -> String {
        match self {
            Self::Null => "NULL".into(),
            Self::Text(value) => format!("N'{}'", value.replace('\'', "''")),
            Self::Binary(value) => format!("<binary:{} bytes>", value.len()),
            Self::Integer(value) => value.to_string(),
            Self::Boolean(value) => u8::from(*value).to_string(),
            Self::Floating(value) => value.to_string(),
            Self::Decimal(value) => value.clone(),
            Self::Guid(value) => value.clone(),
            Self::Temporal { kind, raw } => format!("<{kind}:{raw}>"),
            Self::Variant {
                base_type,
                bytes,
                properties_bytes,
                value,
            } => value.as_ref().map_or_else(
                || {
                    format!(
                        "<sql_variant:{}:{properties_bytes} properties:{bytes} bytes>",
                        base_type.unwrap_or("unknown")
                    )
                },
                |value| {
                    format!(
                        "<sql_variant:{}:{}>",
                        base_type.unwrap_or("unknown"),
                        value.telemetry_value()
                    )
                },
            ),
            Self::Table { columns, rows } => format!("<table:{columns} columns:{rows} rows>"),
        }
    }

    pub fn to_sql_literal(&self) -> String {
        match self {
            Self::Binary(value) => {
                let mut output = String::from("0x");
                use std::fmt::Write as _;
                for byte in value.iter().take(256) {
                    let _ = write!(output, "{byte:02x}");
                }
                if value.len() > 256 {
                    output.push_str("...");
                }
                output
            }
            Self::Guid(value) => format!("'{value}'"),
            Self::Temporal { raw, .. } => format!("0x{raw}"),
            Self::Variant { value, .. } => value
                .as_ref()
                .map_or_else(|| "NULL".into(), |value| value.to_sql_literal()),
            Self::Table { .. } => "NULL".into(),
            _ => self.telemetry_value(),
        }
    }
}

#[derive(Clone)]
pub struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
    consumed_values: usize,
    max_values: usize,
    context: &'static str,
}

impl<'a> Cursor<'a> {
    pub fn new(input: &'a [u8], max_values: usize, context: &'static str) -> Self {
        Self {
            input,
            position: 0,
            consumed_values: 0,
            max_values,
            context,
        }
    }

    pub fn done(&self) -> bool {
        self.position == self.input.len()
    }
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }
    pub fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| Error::Protocol(format!("{} offset overflow", self.context)))?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or_else(|| Error::Protocol(format!("truncated {}", self.context)))?;
        self.position = end;
        Ok(value)
    }

    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.take(len).map(|_| ())
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().expect("length checked")))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().expect("length checked")))
    }

    pub fn utf16(&mut self, chars: usize) -> Result<String> {
        let bytes = chars
            .checked_mul(2)
            .ok_or_else(|| Error::Protocol(format!("{} string length overflow", self.context)))?;
        decode_utf16(self.take(bytes)?)
    }

    pub fn b_varchar(&mut self) -> Result<String> {
        let chars = usize::from(self.u8()?);
        self.utf16(chars)
    }

    pub fn us_varchar(&mut self) -> Result<String> {
        let chars = usize::from(self.u16()?);
        self.utf16(chars)
    }

    fn account(&mut self, amount: usize) -> Result<()> {
        self.consumed_values = self
            .consumed_values
            .checked_add(amount)
            .ok_or(Error::Limit("type-dependent value bytes"))?;
        if self.consumed_values > self.max_values {
            return Err(Error::Limit("maximum type-dependent value bytes"));
        }
        Ok(())
    }

    pub(crate) fn value_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        self.account(len)?;
        Ok(self.take(len)?.to_vec())
    }

    pub fn type_info(&mut self) -> Result<TypeInfo> {
        let id = self.u8()?;
        self.type_info_after_id(id)
    }

    pub fn type_info_after_id(&mut self, id: u8) -> Result<TypeInfo> {
        let mut info = TypeInfo {
            id,
            name: type_name(id),
            max_length: None,
            precision: None,
            scale: None,
            collation: None,
            kind: TypeKind::Fixed(fixed_width(id).unwrap_or(0)),
        };
        if let Some(width) = fixed_width(id) {
            info.kind = TypeKind::Fixed(width);
            return Ok(info);
        }
        match id {
            // DATE has no TYPE_VARLEN. Time-family metadata is SCALE only.
            0x28 => info.kind = TypeKind::ByteLength,
            0x29..=0x2b => {
                let scale = self.u8()?;
                if scale > 7 {
                    return Err(Error::Protocol(format!("{} scale exceeds 7", info.name)));
                }
                info.scale = Some(scale);
                info.kind = TypeKind::ByteLength;
            }
            // Nullable scalar families and pre-7.2 narrow char/binary families.
            0x24 | 0x26 | 0x25 | 0x27 | 0x2d | 0x2f | 0x37 | 0x3f | 0x68 | 0x6a | 0x6c | 0x6d
            | 0x6e | 0x6f => {
                info.max_length = Some(u64::from(self.u8()?));
                if matches!(id, 0x37 | 0x3f | 0x6a | 0x6c) {
                    let precision = self.u8()?;
                    let scale = self.u8()?;
                    if precision > 38 || scale > precision {
                        return Err(Error::Protocol(format!(
                            "invalid {} precision or scale",
                            info.name
                        )));
                    }
                    info.precision = Some(precision);
                    info.scale = Some(scale);
                }
                info.kind = TypeKind::ByteLength;
            }
            // Modern char/binary families.
            0xa5 | 0xa7 | 0xad | 0xaf | 0xe7 | 0xef => {
                let max = self.u16()?;
                info.max_length = Some(u64::from(max));
                if matches!(id, 0xa7 | 0xaf | 0xe7 | 0xef) {
                    info.collation = Some(self.take(5)?.try_into().expect("length checked"));
                }
                info.kind = if max == u16::MAX {
                    TypeKind::Plp
                } else {
                    TypeKind::UShortLength
                };
            }
            // text, image, ntext. Collation is part of textual TYPE_INFO.
            0x22 | 0x23 | 0x63 => {
                info.max_length = Some(u64::from(self.u32()?));
                if id != 0x22 {
                    info.collation = Some(self.take(5)?.try_into().expect("length checked"));
                }
                info.kind = TypeKind::LongLength;
            }
            0x62 => {
                info.max_length = Some(u64::from(self.u32()?));
                info.kind = TypeKind::Variant;
            }
            0xf0 => {
                info.max_length = Some(u64::from(self.u16()?));
                // UDT_INFO: DB, schema, type and assembly-qualified name.
                let _ = self.b_varchar()?;
                let _ = self.b_varchar()?;
                let _ = self.b_varchar()?;
                let _ = self.us_varchar()?;
                info.kind = TypeKind::Plp;
            }
            0xf1 => {
                if self.u8()? != 0 {
                    let _ = self.b_varchar()?;
                    let _ = self.b_varchar()?;
                    let _ = self.us_varchar()?;
                }
                info.kind = TypeKind::Plp;
            }
            0xf3 => {
                info.kind = TypeKind::Tvp(self.tvp_info()?);
            }
            // JSON is PLP. Released specifications omit TYPE_VARLEN, while
            // Microsoft's JDBC writer currently emits an extra 0xffff max
            // marker. Value parsing accepts and validates both encodings.
            0xf4 => info.kind = TypeKind::Json,
            0xf5 => {
                info.max_length = Some(u64::from(self.u16()?));
                let scale = self.u8()?;
                if !matches!(scale, 2 | 4) {
                    return Err(Error::Protocol("invalid vector dimension width".into()));
                }
                info.scale = Some(scale);
                info.kind = TypeKind::UShortLength;
            }
            _ => return Err(Error::Protocol(format!("unknown TDS TYPE_INFO 0x{id:02x}"))),
        }
        Ok(info)
    }

    fn tvp_info(&mut self) -> Result<TvpInfo> {
        let database = self.b_varchar()?;
        let schema = self.b_varchar()?;
        let type_name = self.b_varchar()?;
        let count = self.u16()?;
        let mut columns = Vec::new();
        if count != u16::MAX {
            if count > 1024 {
                return Err(Error::Limit("TVP column count"));
            }
            for _ in 0..count {
                let user_type = self.u32()?;
                let flags = self.u16()?;
                let ty = self.type_info()?;
                if !allowed_tvp_type(ty.id) {
                    return Err(Error::Protocol(format!(
                        "{} type is not allowed in a TVP",
                        ty.name
                    )));
                }
                let name = self.b_varchar()?;
                columns.push(TvpColumn {
                    user_type,
                    flags,
                    ty,
                    name,
                });
            }
        }
        let mut row_order = (0..columns.len()).collect::<Vec<_>>();
        let mut saw_order_unique = false;
        let mut saw_column_ordering = false;
        // Optional metadata tokens end with 0x00. Parse known tokens and
        // reject unknown ones rather than guessing their boundaries.
        loop {
            match self.u8()? {
                0x00 => break,
                0x10 => {
                    if saw_order_unique {
                        return Err(Error::Protocol("duplicate TVP_ORDER_UNIQUE token".into()));
                    }
                    saw_order_unique = true;
                    let entries = usize::from(self.u16()?);
                    if entries > columns.len() {
                        return Err(Error::Protocol("too many TVP_ORDER_UNIQUE entries".into()));
                    }
                    let mut seen = std::collections::BTreeSet::new();
                    for _ in 0..entries {
                        let ordinal = usize::from(self.u16()?);
                        let flags = self.u8()?;
                        if ordinal == 0
                            || ordinal > columns.len()
                            || !seen.insert(ordinal)
                            || columns[ordinal - 1].flags & 0x0200 != 0
                            || flags & !0x07 != 0
                            || flags & 0x07 == 0
                            || flags & 0x03 == 0x03
                        {
                            return Err(Error::Protocol("invalid TVP_ORDER_UNIQUE entry".into()));
                        }
                    }
                }
                0x11 => {
                    if saw_column_ordering {
                        return Err(Error::Protocol(
                            "duplicate TVP_COLUMN_ORDERING token".into(),
                        ));
                    }
                    saw_column_ordering = true;
                    let entries = usize::from(self.u16()?);
                    if entries != columns.len() {
                        return Err(Error::Protocol(
                            "TVP_COLUMN_ORDERING count does not match columns".into(),
                        ));
                    }
                    let mut seen = vec![false; columns.len()];
                    row_order.clear();
                    for _ in 0..entries {
                        let ordinal = usize::from(self.u16()?);
                        if ordinal == 0 || ordinal > columns.len() || seen[ordinal - 1] {
                            return Err(Error::Protocol(
                                "invalid TVP_COLUMN_ORDERING ordinal".into(),
                            ));
                        }
                        seen[ordinal - 1] = true;
                        row_order.push(ordinal - 1);
                    }
                }
                token => {
                    return Err(Error::Protocol(format!(
                        "unknown TVP metadata token 0x{token:02x}"
                    )));
                }
            }
        }
        Ok(TvpInfo {
            database,
            schema,
            type_name,
            columns,
            row_order,
        })
    }

    pub fn value(&mut self, ty: &TypeInfo) -> Result<Value> {
        match &ty.kind {
            TypeKind::Fixed(width) => {
                let bytes = self.value_bytes(*width)?;
                self.decode(ty, bytes)
            }
            TypeKind::ByteLength => {
                let len = usize::from(self.u8()?);
                if len == 0 {
                    return Ok(Value::Null);
                }
                self.validate_max(ty, len)?;
                let bytes = self.value_bytes(len)?;
                self.decode(ty, bytes)
            }
            TypeKind::UShortLength => {
                let len = self.u16()?;
                if len == u16::MAX {
                    return Ok(Value::Null);
                }
                let len = usize::from(len);
                self.validate_max(ty, len)?;
                let bytes = self.value_bytes(len)?;
                self.decode(ty, bytes)
            }
            TypeKind::LongLength => {
                let len = self.u32()?;
                if len == u32::MAX {
                    return Ok(Value::Null);
                }
                let len = usize::try_from(len).map_err(|_| Error::Limit("long TDS value"))?;
                self.validate_max(ty, len)?;
                let bytes = self.value_bytes(len)?;
                self.decode(ty, bytes)
            }
            TypeKind::Plp => match self.plp()? {
                None => Ok(Value::Null),
                Some(bytes) => self.decode(ty, bytes),
            },
            TypeKind::Json => self.json_value(ty),
            TypeKind::Variant => {
                let len = self.u32()?;
                if len == 0 || len == u32::MAX {
                    return Ok(Value::Null);
                }
                let len = usize::try_from(len).map_err(|_| Error::Limit("sql_variant value"))?;
                self.validate_max(ty, len)?;
                let bytes = self.value_bytes(len)?;
                Ok(self.variant(bytes))
            }
            TypeKind::Tvp(info) => self.tvp_value(info),
        }
    }

    fn json_value(&mut self, ty: &TypeInfo) -> Result<Value> {
        // Prefer the canonical JSONTYPE + PLP form. If it cannot form a valid
        // PLP value, accept the 0xffff compatibility prefix emitted by the
        // Microsoft JDBC driver's writeRPCJson implementation.
        let mut canonical = self.clone();
        match canonical.plp() {
            Ok(None) => {
                *self = canonical;
                Ok(Value::Null)
            }
            Ok(Some(bytes)) => {
                *self = canonical;
                self.decode(ty, bytes)
            }
            Err(canonical_error) => {
                if self.remaining() < 2
                    || self.input[self.position..self.position + 2] != [0xff, 0xff]
                {
                    return Err(canonical_error);
                }
                self.skip(2)?;
                match self.plp()? {
                    None => Ok(Value::Null),
                    Some(bytes) => self.decode(ty, bytes),
                }
            }
        }
    }

    fn tvp_value(&mut self, info: &TvpInfo) -> Result<Value> {
        let mut rows = 0usize;
        loop {
            match self.u8()? {
                0x00 => break,
                0x01 => {
                    rows = rows.checked_add(1).ok_or(Error::Limit("TVP row count"))?;
                    if rows > 1_000_000 {
                        return Err(Error::Limit("TVP row count"));
                    }
                    for &index in &info.row_order {
                        let column = &info.columns[index];
                        if column.flags & 0x0200 == 0 {
                            let _ = self.value(&column.ty)?;
                        }
                    }
                }
                token => {
                    return Err(Error::Protocol(format!(
                        "unknown TVP row token 0x{token:02x}"
                    )));
                }
            }
        }
        Ok(Value::Table {
            columns: info.columns.len(),
            rows,
        })
    }

    fn validate_max(&self, ty: &TypeInfo, len: usize) -> Result<()> {
        if let Some(max) = ty.max_length {
            if !matches!(ty.kind, TypeKind::Plp | TypeKind::Json) && len as u64 > max {
                return Err(Error::Protocol(format!(
                    "{} value exceeds declared maximum",
                    ty.name
                )));
            }
        }
        Ok(())
    }

    fn plp(&mut self) -> Result<Option<Vec<u8>>> {
        let total = self.u64()?;
        if total == u64::MAX {
            return Ok(None);
        }
        if total != u64::MAX - 1 && total > self.max_values as u64 {
            return Err(Error::Limit("maximum PLP bytes"));
        }
        let mut value = Vec::new();
        loop {
            let chunk = usize::try_from(self.u32()?).map_err(|_| Error::Limit("PLP chunk"))?;
            if chunk == 0 {
                break;
            }
            self.account(chunk)?;
            value.extend_from_slice(self.take(chunk)?);
        }
        if total != u64::MAX - 1 && value.len() as u64 != total {
            return Err(Error::Protocol("PLP total length mismatch".into()));
        }
        Ok(Some(value))
    }

    fn decode(&self, ty: &TypeInfo, bytes: Vec<u8>) -> Result<Value> {
        validate_value_width(ty, bytes.len())?;
        Ok(match ty.id {
            0x1f => Value::Null,
            0x30 => Value::Integer(i64::from(bytes[0])),
            0x32 | 0x68 => Value::Boolean(bytes.first().copied().unwrap_or(0) != 0),
            0x34 | 0x38 | 0x7f | 0x26 => Value::Integer(signed_le(&bytes)?),
            0x3b | 0x3e | 0x6d => Value::Floating(float_le(&bytes)?),
            0x37 | 0x3f | 0x6a | 0x6c => Value::Decimal(decimal(&bytes, ty.scale.unwrap_or(0))?),
            0x24 if bytes.len() == 16 => Value::Guid(guid(&bytes)),
            0x28 | 0x29 | 0x2a | 0x2b | 0x3a | 0x3c | 0x3d | 0x6e | 0x6f | 0x7a => {
                Value::Temporal {
                    kind: ty.name,
                    raw: hex(&bytes),
                }
            }
            0x23 | 0x27 | 0x2f | 0x63 | 0xa7 | 0xaf | 0xe7 | 0xef | 0xf4 => {
                if ty.id == 0xf4 {
                    Value::Text(decode_json_text(&bytes))
                } else if matches!(ty.id, 0x63 | 0xe7 | 0xef) {
                    Value::Text(decode_utf16(&bytes)?)
                } else {
                    Value::Text(String::from_utf8_lossy(&bytes).into_owned())
                }
            }
            // XMLTYPE values use MS-BINXML on the wire. Preserve binary XML
            // losslessly; tolerate visibly textual UTF-16 from nonconforming
            // clients without interpreting arbitrary binary as text.
            0xf1 if looks_like_utf16_xml(&bytes) => Value::Text(decode_utf16(&bytes)?),
            _ => Value::Binary(bytes),
        })
    }

    fn variant(&self, bytes: Vec<u8>) -> Value {
        let Some((&base_id, remainder)) = bytes.split_first() else {
            return Value::Null;
        };
        let Some((&property_length, remainder)) = remainder.split_first() else {
            return Value::Variant {
                base_type: Some(type_name(base_id)),
                bytes: bytes.len(),
                properties_bytes: 0,
                value: None,
            };
        };
        let property_length = usize::from(property_length);
        let Some((properties, data)) = remainder
            .get(..property_length)
            .zip(remainder.get(property_length..))
        else {
            return Value::Variant {
                base_type: Some(type_name(base_id)),
                bytes: bytes.len(),
                properties_bytes: property_length,
                value: None,
            };
        };
        let value = variant_type_info(base_id, properties)
            .and_then(|ty| self.decode(&ty, data.to_vec()).ok())
            .map(Box::new);
        Value::Variant {
            base_type: Some(type_name(base_id)),
            bytes: bytes.len(),
            properties_bytes: property_length,
            value,
        }
    }
}

fn variant_type_info(id: u8, properties: &[u8]) -> Option<TypeInfo> {
    let (kind, max_length, precision, scale, collation) = match id {
        0x24 | 0x28 | 0x30 | 0x32 | 0x34 | 0x38 | 0x3a | 0x3b | 0x3c | 0x3d | 0x3e | 0x7a
        | 0x7f
            if properties.is_empty() =>
        {
            (
                fixed_width(id).map_or(TypeKind::ByteLength, TypeKind::Fixed),
                None,
                None,
                None,
                None,
            )
        }
        0x29..=0x2b if properties.len() == 1 && properties[0] <= 7 => {
            (TypeKind::ByteLength, None, None, Some(properties[0]), None)
        }
        0xa5 | 0xad if properties.len() == 2 => (
            TypeKind::UShortLength,
            Some(u64::from(u16::from_le_bytes([
                properties[0],
                properties[1],
            ]))),
            None,
            None,
            None,
        ),
        0x6a | 0x6c
            if properties.len() == 2 && properties[0] <= 38 && properties[1] <= properties[0] =>
        {
            (
                TypeKind::ByteLength,
                None,
                Some(properties[0]),
                Some(properties[1]),
                None,
            )
        }
        0xa7 | 0xaf | 0xe7 | 0xef if properties.len() == 7 => (
            TypeKind::UShortLength,
            Some(u64::from(u16::from_le_bytes([
                properties[5],
                properties[6],
            ]))),
            None,
            None,
            Some(properties[..5].try_into().expect("length checked")),
        ),
        _ => return None,
    };
    Some(TypeInfo {
        id,
        name: type_name(id),
        max_length,
        precision,
        scale,
        collation,
        kind,
    })
}

pub fn type_name(id: u8) -> &'static str {
    match id {
        0x1f => "null",
        0x22 => "image",
        0x23 => "text",
        0x24 => "uniqueidentifier",
        0x25 => "varbinary",
        0x26 => "intn",
        0x27 => "varchar",
        0x28 => "date",
        0x29 => "time",
        0x2a => "datetime2",
        0x2b => "datetimeoffset",
        0x2d => "binary",
        0x2f => "char",
        0x30 => "tinyint",
        0x32 => "bit",
        0x34 => "smallint",
        0x37 => "decimal",
        0x38 => "int",
        0x3a => "smalldatetime",
        0x3b => "real",
        0x3c => "money",
        0x3d => "datetime",
        0x3e => "float",
        0x3f => "numeric",
        0x62 => "sql_variant",
        0x63 => "ntext",
        0x68 => "bitn",
        0x6a => "decimaln",
        0x6c => "numericn",
        0x6d => "floatn",
        0x6e => "moneyn",
        0x6f => "datetimen",
        0x7a => "smallmoney",
        0x7f => "bigint",
        0xa5 => "varbinary",
        0xa7 => "varchar",
        0xad => "binary",
        0xaf => "char",
        0xe7 => "nvarchar",
        0xef => "nchar",
        0xf0 => "udt",
        0xf1 => "xml",
        0xf3 => "table",
        0xf4 => "json",
        0xf5 => "vector",
        _ => "unknown",
    }
}

fn fixed_width(id: u8) -> Option<usize> {
    match id {
        0x1f => Some(0),
        0x30 | 0x32 => Some(1),
        0x34 => Some(2),
        0x38 | 0x3a | 0x3b | 0x7a => Some(4),
        0x3c | 0x3d | 0x3e | 0x7f => Some(8),
        _ => None,
    }
}

fn allowed_tvp_type(id: u8) -> bool {
    !matches!(
        id,
        // Legacy fixed and narrow variable forms have nullable/large-form
        // replacements in TVP metadata.
        0x1f | 0x25 | 0x27 | 0x2d | 0x2f | 0x30 | 0x32 | 0x34 | 0x37 | 0x38 | 0x3a
            | 0x3b | 0x3c | 0x3d | 0x3e | 0x3f | 0x7a | 0x7f |
        // A TVP cannot contain another TVP.
        0xf3
    )
}

fn looks_like_utf16_xml(bytes: &[u8]) -> bool {
    bytes.len() >= 2
        && bytes.len() % 2 == 0
        && (bytes.starts_with(&[b'<', 0])
            || bytes.starts_with(&[0xff, 0xfe, b'<', 0])
            || bytes.starts_with(&[0, b'<']))
}

fn signed_le(bytes: &[u8]) -> Result<i64> {
    Ok(match bytes {
        [a] => i64::from(*a),
        [a, b] => i64::from(i16::from_le_bytes([*a, *b])),
        [a, b, c, d] => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
        [a, b, c, d, e, f, g, h] => i64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h]),
        _ => return Err(Error::Protocol("invalid TDS integer width".into())),
    })
}

fn float_le(bytes: &[u8]) -> Result<f64> {
    match bytes {
        [a, b, c, d] => Ok(f64::from(f32::from_le_bytes([*a, *b, *c, *d]))),
        [a, b, c, d, e, f, g, h] => Ok(f64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h])),
        _ => Err(Error::Protocol("invalid TDS floating-point width".into())),
    }
}

fn validate_value_width(ty: &TypeInfo, len: usize) -> Result<()> {
    let valid = match ty.id {
        0x24 => len == 16,
        0x26 => matches!(len, 1 | 2 | 4 | 8),
        0x28 => len == 3,
        0x29 => Some(len) == time_width(ty.scale),
        0x2a => time_width(ty.scale).is_some_and(|width| len == width + 3),
        0x2b => time_width(ty.scale).is_some_and(|width| len == width + 5),
        0x37 | 0x3f | 0x6a | 0x6c => matches!(len, 5 | 9 | 13 | 17),
        0x68 => len == 1,
        0x6d..=0x6f => matches!(len, 4 | 8),
        0xf5 => ty.scale.is_some_and(|width| len % usize::from(width) == 0),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "invalid {} value width {len}",
            ty.name
        )))
    }
}

fn time_width(scale: Option<u8>) -> Option<usize> {
    match scale? {
        0..=2 => Some(3),
        3..=4 => Some(4),
        5..=7 => Some(5),
        _ => None,
    }
}

fn decimal(bytes: &[u8], scale: u8) -> Result<String> {
    let (&sign, magnitude) = bytes
        .split_first()
        .ok_or_else(|| Error::Protocol("empty TDS decimal".into()))?;
    if magnitude.len() > 16 {
        return Ok(format!("<decimal:{} bytes>", bytes.len()));
    }
    let mut raw = [0u8; 16];
    raw[..magnitude.len()].copy_from_slice(magnitude);
    let mut digits = u128::from_le_bytes(raw).to_string();
    let scale = usize::from(scale);
    if scale > 0 {
        if digits.len() <= scale {
            digits.insert_str(0, &"0".repeat(scale + 1 - digits.len()));
        }
        digits.insert(digits.len() - scale, '.');
    }
    if sign == 0 && digits != "0" {
        digits.insert(0, '-');
    }
    Ok(digits)
}

fn guid(bytes: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        hex(&bytes[10..])
    )
}

pub fn decode_utf16(raw: &[u8]) -> Result<String> {
    if raw.len() % 2 != 0 {
        return Err(Error::Protocol("odd TDS UTF-16 length".into()));
    }
    Ok(char::decode_utf16(
        raw.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]])),
    )
    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
    .collect())
}

fn hex(input: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(input.len() * 2);
    for byte in input {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn decode_json_text(raw: &[u8]) -> String {
    // JSONTYPE is UTF-8 on the wire. The Microsoft JDBC mainline writer has
    // also shipped an RPC path that writes UTF-16LE, so retain that telemetry
    // rather than producing a string full of NUL characters.
    if raw.len() >= 2 && raw.len() % 2 == 0 && raw.chunks_exact(2).all(|pair| pair[1] == 0) {
        return decode_utf16(raw).unwrap_or_else(|_| String::from_utf8_lossy(raw).into_owned());
    }
    String::from_utf8_lossy(raw).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_uses_ushort_length_and_dimension_scale() {
        let raw = [0xf5, 12, 0, 4, 12, 0, 0xa9, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut cursor = Cursor::new(&raw, 1024, "test vector");
        let ty = cursor.type_info().unwrap();
        assert_eq!(ty.max_length, Some(12));
        assert_eq!(ty.scale, Some(4));
        assert_eq!(
            cursor.value(&ty).unwrap().telemetry_value(),
            "<binary:12 bytes>"
        );
        assert!(cursor.done());
    }

    #[test]
    fn json_is_plp_utf8() {
        let value = br#"{"probe":true}"#;
        let mut raw = vec![0xf4];
        raw.extend_from_slice(&(value.len() as u64).to_le_bytes());
        raw.extend_from_slice(&(value.len() as u32).to_le_bytes());
        raw.extend_from_slice(value);
        raw.extend_from_slice(&0_u32.to_le_bytes());
        let mut cursor = Cursor::new(&raw, 1024, "test json");
        let ty = cursor.type_info().unwrap();
        assert_eq!(
            cursor.value(&ty).unwrap().as_text(),
            Some(r#"{"probe":true}"#)
        );
    }

    #[test]
    fn json_accepts_microsoft_jdbc_max_marker_and_utf16() {
        let value: Vec<u8> =
            r#"{"probe":true}"#.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut raw = vec![0xf4, 0xff, 0xff];
        raw.extend_from_slice(&(value.len() as u64).to_le_bytes());
        raw.extend_from_slice(&(value.len() as u32).to_le_bytes());
        raw.extend_from_slice(&value);
        raw.extend_from_slice(&0_u32.to_le_bytes());
        let mut cursor = Cursor::new(&raw, 1024, "JDBC JSON");
        let ty = cursor.type_info().unwrap();
        assert_eq!(
            cursor.value(&ty).unwrap().as_text(),
            Some(r#"{"probe":true}"#)
        );
        assert!(cursor.done());
    }

    #[test]
    fn tvp_column_ordering_controls_row_value_boundaries() {
        let mut raw = vec![0xf3, 0, 0, 0]; // type and empty db/schema/name
        raw.extend_from_slice(&2_u16.to_le_bytes());
        // First column is an INTN.
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&[0x26, 4, 0]);
        // Second column is VARCHAR(8).
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&[0xa7, 8, 0, 0x09, 0x04, 0xd0, 0, 0x34, 0]);
        raw.extend_from_slice(&[0x11, 2, 0, 2, 0, 1, 0, 0]);
        // One row: varchar first, then intn, followed by TVP_END_TOKEN.
        raw.extend_from_slice(&[1, 3, 0, b's', b'q', b'l', 4, 42, 0, 0, 0, 0]);
        let mut cursor = Cursor::new(&raw, 1024, "ordered TVP");
        let ty = cursor.type_info().unwrap();
        assert_eq!(
            cursor.value(&ty).unwrap().telemetry_value(),
            "<table:2 columns:1 rows>"
        );
        assert!(cursor.done());
    }

    #[test]
    fn sql_variant_decodes_its_inner_text_value() {
        let text: Vec<u8> = "EXEC xp_cmdshell 'whoami'"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut instance = vec![0xe7, 7, 0x09, 0x04, 0xd0, 0, 0x34];
        instance.extend_from_slice(&(text.len() as u16).to_le_bytes());
        instance.extend_from_slice(&text);
        let mut raw = vec![0x62];
        raw.extend_from_slice(&8016_u32.to_le_bytes());
        raw.extend_from_slice(&(instance.len() as u32).to_le_bytes());
        raw.extend_from_slice(&instance);
        let mut cursor = Cursor::new(&raw, 8192, "sql_variant");
        let ty = cursor.type_info().unwrap();
        assert!(
            cursor
                .value(&ty)
                .unwrap()
                .telemetry_value()
                .contains("xp_cmdshell")
        );
    }

    #[test]
    fn xml_preserves_binary_values_and_accepts_visible_utf16_text() {
        for (value, expected_text) in [
            (vec![0xdf, 0xff, 1], None),
            (
                "<probe/>"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                Some("<probe/>"),
            ),
        ] {
            let mut raw = vec![0xf1, 0];
            raw.extend_from_slice(&(value.len() as u64).to_le_bytes());
            raw.extend_from_slice(&(value.len() as u32).to_le_bytes());
            raw.extend_from_slice(&value);
            raw.extend_from_slice(&0_u32.to_le_bytes());
            let mut cursor = Cursor::new(&raw, 1024, "XML value");
            let ty = cursor.type_info().unwrap();
            let parsed = cursor.value(&ty).unwrap();
            assert_eq!(parsed.as_text(), expected_text);
            assert!(cursor.done());
        }
    }

    #[test]
    fn tvp_rejects_nested_and_legacy_column_types() {
        for forbidden in [0x1f, 0x30, 0x38, 0x3e, 0xf3] {
            let mut raw = vec![0xf3, 0, 0, 0];
            raw.extend_from_slice(&1_u16.to_le_bytes());
            raw.extend_from_slice(&0_u32.to_le_bytes());
            raw.extend_from_slice(&0_u16.to_le_bytes());
            raw.push(forbidden);
            if forbidden == 0xf3 {
                raw.extend_from_slice(&[0, 0, 0]);
                raw.extend_from_slice(&u16::MAX.to_le_bytes());
                raw.push(0);
            }
            raw.push(0); // column name
            raw.push(0); // TVP metadata end
            let mut cursor = Cursor::new(&raw, 1024, "forbidden TVP type");
            assert!(cursor.type_info().is_err(), "type 0x{forbidden:02x}");
        }
    }
}
