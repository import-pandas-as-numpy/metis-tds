use serde::Serialize;

use crate::{Error, Result};

const LEGACY_FIXED_LENGTH: usize = 86;
const EXTENDED_FIXED_LENGTH: usize = 94;
const MAX_LOGIN7_LENGTH: usize = 128 * 1024 - 1;

const PUBLISHED_FEATURE_IDS: &[u8] = &[
    0x01, 0x02, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0d, 0x0e, 0x0f, 0x10,
];

#[derive(Clone, Debug, Default)]
pub struct LoginRequest {
    pub tds_version: u32,
    pub packet_size: u32,
    pub option_flags_1: u8,
    pub option_flags_2: u8,
    pub type_flags: u8,
    pub option_flags_3: u8,
    pub client_program_version: u32,
    pub client_pid: u32,
    pub connection_id: u32,
    pub client_timezone: i32,
    pub client_lcid: u32,
    pub client_id: [u8; 6],
    pub client_hostname: String,
    pub username: String,
    pub(crate) password: Option<String>,
    pub password_present: bool,
    pub application_name: String,
    pub server_name: String,
    pub client_library: String,
    pub language: String,
    pub database: String,
    pub attach_database_file: String,
    pub(crate) new_password: Option<String>,
    pub new_password_present: bool,
    pub integrated_security: bool,
    pub sspi_bytes: usize,
    pub sspi_token_family: Option<&'static str>,
    pub features: Vec<LoginFeature>,
    pub feature_extension_remainder: Option<FeatureExtensionRemainder>,
    pub(crate) feature_extension_remainder_raw: Vec<u8>,
    pub parse_warnings: Vec<String>,
    pub legacy_security_flags: Option<u8>,
    pub legacy_login: Option<LegacyLoginDetails>,
    pub legacy_capabilities_bytes: usize,
    pub legacy_capabilities: Option<super::tds5::Capabilities>,
    pub legacy_authentication_bytes: usize,
    pub legacy_authentication: Option<super::tds5::AuthenticationStream>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FeatureExtensionRemainder {
    pub offset: usize,
    pub bytes: usize,
    pub first_byte: Option<u8>,
    pub feature_id: Option<u8>,
    pub declared_data_bytes: Option<usize>,
    pub available_data_bytes: usize,
    pub first_data_byte: Option<u8>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyLoginDetails {
    pub host_process: String,
    pub client_charset: String,
    pub client_program_version: u32,
    pub bulk_copy_raw: u8,
    pub bulk_copy_requested: bool,
    pub suppress_language_raw: u8,
    pub old_secure: [u8; 2],
    pub security_bulk_raw: u8,
    pub ha_login_raw: u8,
    pub ha_session_id: [u8; 6],
    pub security_spare: [u8; 2],
    pub set_charset_raw: u8,
    pub fixed_record_expected_bytes: usize,
    pub fixed_record_present_bytes: usize,
    pub fixed_padding: Vec<u8>,
    pub suffix_bytes: usize,
    pub remote_password_encoding: &'static str,
    pub remote_password_present: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoginFeature {
    pub id: u8,
    pub name: &'static str,
    pub data_bytes: usize,
    #[serde(skip)]
    pub(crate) raw_data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_library: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_echo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_workflow: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_token_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_nonce_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_channel_binding_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedauth_signature_present: Option<bool>,
    #[serde(skip)]
    pub(crate) fedauth_token: Option<Vec<u8>>,
    #[serde(skip)]
    pub(crate) fedauth_nonce: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovery: Vec<SessionRecovery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionRecovery {
    pub database: String,
    pub language: String,
    pub collation_bytes: usize,
    pub state_bytes: usize,
    pub state_values: Vec<SessionStateValue>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionStateValue {
    pub id: u8,
    pub bytes: usize,
    pub value: String,
}

impl LoginRequest {
    pub(crate) fn password_for_capture(&self) -> Option<&str> {
        self.password.as_deref()
    }

    pub(crate) fn discard_password(&mut self) {
        self.password = None;
        self.new_password = None;
    }

    pub(crate) fn set_recovered_password(&mut self, password: String) {
        self.password = Some(password);
    }

    pub(crate) fn new_password_for_capture(&self) -> Option<&str> {
        self.new_password.as_deref()
    }
}

pub fn parse(payload: &[u8]) -> Result<LoginRequest> {
    parse_inner(payload, false)
}

/// Parses every independently recoverable LOGIN7 field. Invalid optional
/// descriptors become warnings instead of hiding credentials from telemetry.
pub fn parse_for_telemetry(payload: &[u8]) -> Result<LoginRequest> {
    parse_inner(payload, true)
}

pub fn sspi_token(payload: &[u8]) -> Result<&[u8]> {
    if payload.len() < 8 {
        return Err(Error::Protocol("LOGIN7 fixed header is truncated".into()));
    }
    let tds_version = le_u32(payload, 4)?;
    let fixed_length = fixed_length(payload, tds_version);
    let declared = usize::try_from(le_u32(payload, 0)?)
        .map_err(|_| Error::Protocol("LOGIN7 length overflow".into()))?;
    if declared < fixed_length || declared > payload.len() {
        return Err(Error::Protocol("LOGIN7 declared length is invalid".into()));
    }
    sspi_field(payload, declared, fixed_length)
}

fn parse_inner(payload: &[u8], tolerant: bool) -> Result<LoginRequest> {
    if payload.len() < 8 {
        return Err(Error::Protocol("LOGIN7 fixed header is truncated".into()));
    }
    let tds_version = le_u32(payload, 4)?;
    let fixed_length = fixed_length(payload, tds_version);
    if payload.len() < fixed_length {
        return Err(Error::Protocol("LOGIN7 fixed header is truncated".into()));
    }
    let declared_field = usize::try_from(le_u32(payload, 0)?)
        .map_err(|_| Error::Protocol("LOGIN7 length overflow".into()))?;
    let mut warnings = Vec::new();
    let declared = if declared_field < fixed_length || declared_field > payload.len() {
        let error = Error::Protocol(format!(
            "LOGIN7 declared length {declared_field} is invalid for {} received bytes",
            payload.len()
        ));
        if !tolerant {
            return Err(error);
        }
        warnings.push(error.to_string());
        // The complete reassembled message is an authoritative safe bound and
        // still contains independently recoverable offset/length fields.
        payload.len()
    } else {
        declared_field
    };
    if declared_field != payload.len() {
        let error = Error::Protocol(format!(
            "LOGIN7 declared length {declared_field} differs from {} received bytes",
            payload.len()
        ));
        if !tolerant {
            return Err(error);
        }
        if !warnings.iter().any(|warning| warning == &error.to_string()) {
            warnings.push(error.to_string());
        }
    }
    if payload.len() > MAX_LOGIN7_LENGTH {
        let error = Error::Protocol("LOGIN7 exceeds the 128K-1 byte limit".into());
        if !tolerant {
            return Err(error);
        }
        warnings.push(error.to_string());
    }
    for (offset, maximum, name) in [
        (36, 128, "client hostname"),
        (40, 128, "username"),
        (44, 128, "password"),
        (48, 128, "application name"),
        (52, 128, "server name"),
        (60, 128, "client library"),
        (64, 128, "language"),
        (68, 128, "database"),
        (82, 260, "attach database file"),
    ] {
        validate_character_count(payload, offset, maximum, name, tolerant, &mut warnings)?;
    }
    if fixed_length >= EXTENDED_FIXED_LENGTH {
        validate_character_count(payload, 86, 128, "change password", tolerant, &mut warnings)?;
    }
    let option_flags_2 = payload[25];
    let username = recover_field(
        payload,
        40,
        declared,
        fixed_length,
        false,
        "username",
        tolerant,
        &mut warnings,
    )?;
    let password_raw = recover_raw_field(
        payload,
        44,
        declared,
        fixed_length,
        "password",
        tolerant,
        &mut warnings,
    )?;
    let password_present = !password_raw.is_empty();
    let password = if password_present {
        match deobfuscate_password(password_raw) {
            Ok(value) => Some(value),
            Err(error) if tolerant => {
                warnings.push(error.to_string());
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let sspi = match sspi_field(payload, declared, fixed_length) {
        Ok(value) => value,
        Err(error) if tolerant => {
            warnings.push(error.to_string());
            &[]
        }
        Err(error) => return Err(error),
    };
    let new_password_raw = if fixed_length >= EXTENDED_FIXED_LENGTH {
        recover_raw_field(
            payload,
            86,
            declared,
            fixed_length,
            "change password",
            tolerant,
            &mut warnings,
        )?
    } else {
        &[]
    };
    let new_password_present = !new_password_raw.is_empty();
    let new_password = if new_password_present {
        match deobfuscate_password(new_password_raw) {
            Ok(value) => Some(value),
            Err(error) if tolerant => {
                warnings.push(error.to_string());
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let parsed_features = parse_features(
        payload,
        declared,
        fixed_length,
        payload[27],
        tolerant,
        &mut warnings,
    )?;
    let mut client_id = [0_u8; 6];
    client_id.copy_from_slice(&payload[72..78]);
    Ok(LoginRequest {
        tds_version,
        packet_size: le_u32(payload, 8)?,
        option_flags_1: payload[24],
        option_flags_2,
        type_flags: payload[26],
        option_flags_3: payload[27],
        client_program_version: le_u32(payload, 12)?,
        client_pid: le_u32(payload, 16)?,
        connection_id: le_u32(payload, 20)?,
        client_timezone: i32::from_le_bytes(payload[28..32].try_into().expect("fixed length")),
        client_lcid: le_u32(payload, 32)?,
        client_id,
        client_hostname: recover_field(
            payload,
            36,
            declared,
            fixed_length,
            false,
            "client hostname",
            tolerant,
            &mut warnings,
        )?,
        username,
        password,
        password_present,
        application_name: recover_field(
            payload,
            48,
            declared,
            fixed_length,
            false,
            "application name",
            tolerant,
            &mut warnings,
        )?,
        server_name: recover_field(
            payload,
            52,
            declared,
            fixed_length,
            false,
            "server name",
            tolerant,
            &mut warnings,
        )?,
        client_library: recover_field(
            payload,
            60,
            declared,
            fixed_length,
            false,
            "client library",
            tolerant,
            &mut warnings,
        )?,
        language: recover_field(
            payload,
            64,
            declared,
            fixed_length,
            false,
            "language",
            tolerant,
            &mut warnings,
        )?,
        database: recover_field(
            payload,
            68,
            declared,
            fixed_length,
            false,
            "database",
            tolerant,
            &mut warnings,
        )?,
        attach_database_file: recover_field(
            payload,
            82,
            declared,
            fixed_length,
            false,
            "attach database file",
            tolerant,
            &mut warnings,
        )?,
        new_password,
        new_password_present,
        integrated_security: option_flags_2 & 0x80 != 0,
        sspi_bytes: sspi.len(),
        sspi_token_family: classify_sspi(sspi),
        features: parsed_features.features,
        feature_extension_remainder: parsed_features.remainder,
        feature_extension_remainder_raw: parsed_features.remainder_raw,
        parse_warnings: warnings,
        legacy_security_flags: None,
        legacy_login: None,
        legacy_capabilities_bytes: 0,
        legacy_capabilities: None,
        legacy_authentication_bytes: 0,
        legacy_authentication: None,
    })
}

fn validate_character_count(
    payload: &[u8],
    descriptor_offset: usize,
    maximum: u16,
    name: &str,
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let descriptor = payload
        .get(descriptor_offset..descriptor_offset + 4)
        .ok_or_else(|| Error::Protocol("LOGIN7 field descriptor truncated".into()))?;
    let characters = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    if characters <= maximum {
        return Ok(());
    }
    let error = Error::Protocol(format!(
        "LOGIN7 {name} length {characters} exceeds {maximum} characters"
    ));
    if tolerant {
        warnings.push(error.to_string());
        Ok(())
    } else {
        Err(error)
    }
}

fn fixed_length(_payload: &[u8], tds_version: u32) -> usize {
    match tds_version >> 24 {
        0x70 | 0x71 => LEGACY_FIXED_LENGTH,
        0x72..=0x74 => EXTENDED_FIXED_LENGTH,
        // TDS 7.2 and every later LOGIN7 layout use the 94-byte header. The
        // hostname descriptor is not a header-length field and can legally
        // point later when variable fields are reordered.
        _ => EXTENDED_FIXED_LENGTH,
    }
}

fn recover_raw_field<'a>(
    payload: &'a [u8],
    descriptor_offset: usize,
    declared: usize,
    fixed_length: usize,
    name: &str,
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<&'a [u8]> {
    match raw_field(payload, descriptor_offset, declared, fixed_length, name) {
        Ok(value) => Ok(value),
        Err(error) if tolerant => {
            warnings.push(error.to_string());
            Ok(&[])
        }
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn recover_field(
    payload: &[u8],
    descriptor_offset: usize,
    declared: usize,
    fixed_length: usize,
    allow_nul: bool,
    name: &str,
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<String> {
    match field(
        payload,
        descriptor_offset,
        declared,
        fixed_length,
        allow_nul,
        name,
    ) {
        Ok(value) => Ok(value),
        Err(error) if tolerant => {
            warnings.push(error.to_string());
            Ok(String::new())
        }
        Err(error) => Err(error),
    }
}

struct ParsedFeatures {
    features: Vec<LoginFeature>,
    remainder: Option<FeatureExtensionRemainder>,
    remainder_raw: Vec<u8>,
}

struct PartialFeature {
    offset: usize,
    feature_id: Option<u8>,
    declared_data_bytes: Option<usize>,
    data_offset: usize,
}

impl ParsedFeatures {
    fn empty() -> Self {
        Self {
            features: Vec::new(),
            remainder: None,
            remainder_raw: Vec::new(),
        }
    }
}

fn partial_features(
    payload: &[u8],
    declared: usize,
    features: Vec<LoginFeature>,
    partial: PartialFeature,
    reason: String,
) -> ParsedFeatures {
    let bounded_end = declared.min(payload.len());
    let raw = payload
        .get(partial.offset.min(bounded_end)..bounded_end)
        .unwrap_or_default()
        .to_vec();
    ParsedFeatures {
        features,
        remainder: Some(FeatureExtensionRemainder {
            offset: partial.offset,
            bytes: raw.len(),
            first_byte: raw.first().copied(),
            feature_id: partial.feature_id,
            declared_data_bytes: partial.declared_data_bytes,
            available_data_bytes: bounded_end.saturating_sub(partial.data_offset.min(bounded_end)),
            first_data_byte: partial.declared_data_bytes.and_then(|_| {
                payload
                    .get(partial.data_offset)
                    .copied()
                    .filter(|_| partial.data_offset < bounded_end)
            }),
            reason,
        }),
        remainder_raw: raw,
    }
}

fn parse_features(
    payload: &[u8],
    declared: usize,
    fixed_length: usize,
    option_flags_3: u8,
    tolerant: bool,
    warnings: &mut Vec<String>,
) -> Result<ParsedFeatures> {
    if option_flags_3 & 0x10 == 0 || fixed_length < EXTENDED_FIXED_LENGTH {
        return Ok(ParsedFeatures::empty());
    }
    let extension = match raw_byte_field(payload, 56, declared, fixed_length, "extension") {
        Ok(value) => value,
        Err(error) if tolerant => {
            warnings.push(error.to_string());
            return Ok(ParsedFeatures::empty());
        }
        Err(error) => return Err(error),
    };
    if extension.len() != 4 {
        let error = Error::Protocol("LOGIN7 extension pointer must be 4 bytes".into());
        if tolerant {
            warnings.push(error.to_string());
            return Ok(ParsedFeatures::empty());
        }
        return Err(error);
    }
    let mut position = usize::try_from(u32::from_le_bytes(
        extension.try_into().expect("length checked"),
    ))
    .map_err(|_| Error::Protocol("LOGIN7 FeatureExt offset overflow".into()))?;
    if position < fixed_length || position >= declared {
        let error = Error::Protocol("LOGIN7 FeatureExt is outside message".into());
        if tolerant {
            warnings.push(error.to_string());
            return Ok(ParsedFeatures::empty());
        }
        return Err(error);
    }
    let mut features = Vec::new();
    loop {
        let feature_start = position;
        let id = match payload
            .get(position)
            .copied()
            .filter(|_| position < declared)
        {
            Some(id) => id,
            None => {
                let error = Error::Protocol("LOGIN7 FeatureExt lacks terminator".into());
                if !tolerant {
                    return Err(error);
                }
                warnings.push(error.to_string());
                return Ok(partial_features(
                    payload,
                    declared,
                    features,
                    PartialFeature {
                        offset: feature_start,
                        feature_id: None,
                        declared_data_bytes: None,
                        data_offset: feature_start,
                    },
                    error.to_string(),
                ));
            }
        };
        position += 1;
        if id == 0xff {
            break;
        }
        let raw_length = match le_u32(payload, position) {
            Ok(length) if position + 4 <= declared => length,
            Ok(_) | Err(_) => {
                let error = Error::Protocol("truncated LOGIN7 FeatureExt length".into());
                if !tolerant {
                    return Err(error);
                }
                warnings.push(error.to_string());
                return Ok(partial_features(
                    payload,
                    declared,
                    features,
                    PartialFeature {
                        offset: feature_start,
                        feature_id: Some(id),
                        declared_data_bytes: None,
                        data_offset: position,
                    },
                    error.to_string(),
                ));
            }
        };
        let length = usize::try_from(raw_length)
            .map_err(|_| Error::Protocol("LOGIN7 FeatureExt length overflow".into()))?;
        position += 4;
        let Some(end) = position.checked_add(length) else {
            let error = Error::Protocol("LOGIN7 FeatureExt offset overflow".into());
            if !tolerant {
                return Err(error);
            }
            warnings.push(error.to_string());
            return Ok(partial_features(
                payload,
                declared,
                features,
                PartialFeature {
                    offset: feature_start,
                    feature_id: Some(id),
                    declared_data_bytes: Some(length),
                    data_offset: position,
                },
                error.to_string(),
            ));
        };
        let Some(data) = payload.get(position..end).filter(|_| end <= declared) else {
            let error = Error::Protocol("truncated LOGIN7 FeatureExt data".into());
            if !tolerant {
                return Err(error);
            }
            warnings.push(error.to_string());
            return Ok(partial_features(
                payload,
                declared,
                features,
                PartialFeature {
                    offset: feature_start,
                    feature_id: Some(id),
                    declared_data_bytes: Some(length),
                    data_offset: position,
                },
                error.to_string(),
            ));
        };
        let feature = parse_feature(id, data);
        if let Some(error) = &feature.parse_error {
            if !tolerant {
                return Err(Error::Protocol(error.clone()));
            }
            warnings.push(error.clone());
        }
        features.push(feature);
        if features.len() > 256 {
            return Err(Error::Limit("LOGIN7 feature count"));
        }
        position = end;
    }
    Ok(ParsedFeatures {
        features,
        remainder: None,
        remainder_raw: Vec::new(),
    })
}

fn parse_feature(id: u8, data: &[u8]) -> LoginFeature {
    let mut feature = LoginFeature {
        id,
        name: feature_name(id),
        data_bytes: data.len(),
        raw_data: data.to_vec(),
        fedauth_library: None,
        fedauth_echo: None,
        fedauth_workflow: None,
        fedauth_token_bytes: None,
        fedauth_nonce_present: None,
        fedauth_channel_binding_bytes: None,
        fedauth_signature_present: None,
        fedauth_token: None,
        fedauth_nonce: None,
        version: None,
        supported: None,
        user_agent: None,
        recovery: Vec::new(),
        parse_error: None,
    };
    if let Err(error) = populate_feature(&mut feature, id, data) {
        feature.parse_error = Some(error.to_string());
    }
    feature
}

fn feature_name(id: u8) -> &'static str {
    if !PUBLISHED_FEATURE_IDS.contains(&id) {
        return "unknown";
    }
    match id {
        0x01 => "session_recovery",
        0x02 => "fedauth",
        0x04 => "column_encryption",
        0x05 => "global_transactions",
        0x08 => "azure_sql_support",
        0x09 => "data_classification",
        0x0a => "utf8_support",
        0x0b => "azure_sql_dns_caching",
        0x0d => "json_support",
        0x0e => "vector_support",
        0x0f => "enhanced_routing_support",
        0x10 => "user_agent",
        _ => unreachable!("published LOGIN7 feature inventory lacks a name"),
    }
}

fn populate_feature(feature: &mut LoginFeature, id: u8, data: &[u8]) -> Result<()> {
    match id {
        0x01 => feature.recovery = parse_session_recovery(data)?,
        0x02 => {
            let options = *data
                .first()
                .ok_or_else(|| Error::Protocol("empty LOGIN7 FEDAUTH feature".into()))?;
            let library = options & 0x7f;
            feature.fedauth_library = Some(library);
            feature.fedauth_echo = Some(options & 0x80 != 0);
            if library == 0x02 {
                feature.fedauth_workflow = data.get(1).copied();
                if !matches!(feature.fedauth_workflow, Some(0x01 | 0x02)) {
                    return Err(Error::Protocol("invalid LOGIN7 ADAL workflow".into()));
                }
                if data.len() != 2 {
                    return Err(Error::Protocol(
                        "LOGIN7 ADAL feature has trailing data".into(),
                    ));
                }
            } else if matches!(library, 0x00 | 0x01) {
                let token_length = usize::try_from(le_u32(data, 1)?)
                    .map_err(|_| Error::Protocol("LOGIN7 FEDAUTH token length overflow".into()))?;
                if token_length == 0 {
                    return Err(Error::Protocol("empty LOGIN7 FEDAUTH token".into()));
                }
                let token_end = 5_usize.checked_add(token_length).ok_or_else(|| {
                    Error::Protocol("LOGIN7 FEDAUTH token offset overflow".into())
                })?;
                if token_end > data.len() {
                    return Err(Error::Protocol("truncated LOGIN7 FEDAUTH token".into()));
                }
                feature.fedauth_token_bytes = Some(token_length);
                feature.fedauth_token = Some(data[5..token_end].to_vec());
                let trailing = data.len() - token_end;
                if library == 0x00 {
                    if trailing < 64 {
                        return Err(Error::Protocol(
                            "LOGIN7 Live ID FEDAUTH signed data is truncated".into(),
                        ));
                    }
                    feature.fedauth_nonce_present = Some(true);
                    feature.fedauth_nonce = Some(
                        data[token_end..token_end + 32]
                            .try_into()
                            .expect("trailing length checked"),
                    );
                    feature.fedauth_channel_binding_bytes = Some(trailing - 64);
                    feature.fedauth_signature_present = Some(true);
                } else if matches!(trailing, 0 | 32) {
                    feature.fedauth_nonce_present = Some(trailing == 32);
                    feature.fedauth_nonce = (trailing == 32).then(|| {
                        data[token_end..token_end + 32]
                            .try_into()
                            .expect("trailing length checked")
                    });
                    feature.fedauth_channel_binding_bytes = Some(0);
                    feature.fedauth_signature_present = Some(false);
                } else {
                    return Err(Error::Protocol(
                        "LOGIN7 Security Token FEDAUTH trailing data must be an optional nonce"
                            .into(),
                    ));
                }
            } else {
                return Err(Error::Protocol(format!(
                    "reserved LOGIN7 FEDAUTH library {library}"
                )));
            }
        }
        0x04 => {
            let version = one_byte(data, "COLUMNENCRYPTION")?;
            if !(1..=3).contains(&version) {
                return Err(Error::Protocol(
                    "LOGIN7 COLUMNENCRYPTION version must be 1, 2, or 3".into(),
                ));
            }
            feature.version = Some(version);
        }
        0x05 | 0x0b | 0x0f => require_empty(data, feature.name)?,
        0x08 | 0x0a => {
            let supported = one_byte(data, feature.name)?;
            if supported > 1 {
                return Err(Error::Protocol(format!(
                    "LOGIN7 {} feature flag must be 0 or 1",
                    feature.name
                )));
            }
            feature.supported = Some(supported != 0);
        }
        0x09 => {
            let version = one_byte(data, feature.name)?;
            if !matches!(version, 1 | 2) {
                return Err(Error::Protocol(
                    "LOGIN7 data_classification version must be 1 or 2".into(),
                ));
            }
            feature.version = Some(version);
        }
        0x0d => {
            let version = one_byte(data, feature.name)?;
            if version != 1 {
                return Err(Error::Protocol(
                    "LOGIN7 json_support version must be 1".into(),
                ));
            }
            feature.version = Some(version);
        }
        0x0e => {
            let version = one_byte(data, feature.name)?;
            if !matches!(version, 1 | 2) {
                return Err(Error::Protocol(
                    "LOGIN7 vector_support version must be 1 or 2".into(),
                ));
            }
            feature.version = Some(version);
        }
        0x10 => {
            if data.len() < 2 {
                return Err(Error::Protocol("truncated LOGIN7 USERAGENT".into()));
            }
            let chars = usize::from(u16::from_le_bytes([data[0], data[1]]));
            if chars > 256
                || chars.checked_mul(2).and_then(|n| n.checked_add(2)) != Some(data.len())
            {
                return Err(Error::Protocol("invalid LOGIN7 USERAGENT length".into()));
            }
            let value = decode_utf16(&data[2..], false, "USERAGENT")?;
            if !value.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'+' | b'_' | b'-' | b'|')
            }) {
                return Err(Error::Protocol(
                    "LOGIN7 USERAGENT contains a forbidden character".into(),
                ));
            }
            feature.user_agent = Some(value);
        }
        _ => {}
    }
    Ok(())
}

fn one_byte(data: &[u8], name: &str) -> Result<u8> {
    if data.len() != 1 {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} feature must be one byte"
        )));
    }
    Ok(data[0])
}

fn require_empty(data: &[u8], name: &str) -> Result<()> {
    if !data.is_empty() {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} feature must be empty"
        )));
    }
    Ok(())
}

fn parse_session_recovery(data: &[u8]) -> Result<Vec<SessionRecovery>> {
    let mut position = 0usize;
    let mut result = Vec::new();
    while position < data.len() {
        if result.len() == 2 {
            return Err(Error::Protocol(
                "LOGIN7 SESSIONRECOVERY has more than two data sets".into(),
            ));
        }
        let raw_len = data
            .get(position..position + 4)
            .ok_or_else(|| Error::Protocol("truncated LOGIN7 SESSIONRECOVERY length".into()))?;
        let len = usize::try_from(u32::from_le_bytes(
            raw_len.try_into().expect("length checked"),
        ))
        .map_err(|_| Error::Protocol("LOGIN7 SESSIONRECOVERY length overflow".into()))?;
        position += 4;
        let end = position
            .checked_add(len)
            .ok_or_else(|| Error::Protocol("LOGIN7 SESSIONRECOVERY offset overflow".into()))?;
        let body = data
            .get(position..end)
            .ok_or_else(|| Error::Protocol("truncated LOGIN7 SESSIONRECOVERY data".into()))?;
        let mut p = 0usize;
        let database = recovery_b_varchar(body, &mut p)?;
        let collation_bytes = usize::from(
            *body
                .get(p)
                .ok_or_else(|| Error::Protocol("truncated LOGIN7 recovery collation".into()))?,
        );
        p += 1;
        if collation_bytes != 0 && collation_bytes != 5 {
            return Err(Error::Protocol(
                "invalid LOGIN7 recovery collation length".into(),
            ));
        }
        p = p
            .checked_add(collation_bytes)
            .filter(|v| *v <= body.len())
            .ok_or_else(|| Error::Protocol("truncated LOGIN7 recovery collation".into()))?;
        let language = recovery_b_varchar(body, &mut p)?;
        let state_values = parse_session_state_data(&body[p..])?;
        result.push(SessionRecovery {
            database,
            language,
            collation_bytes,
            state_bytes: body.len() - p,
            state_values,
        });
        position = end;
    }
    Ok(result)
}

fn parse_session_state_data(mut input: &[u8]) -> Result<Vec<SessionStateValue>> {
    let mut values = Vec::new();
    while !input.is_empty() {
        if values.len() >= 256 {
            return Err(Error::Limit("LOGIN7 session recovery state count"));
        }
        let id = input[0];
        if id == 0xff {
            return Err(Error::Protocol(
                "LOGIN7 session recovery StateId 0xff is reserved".into(),
            ));
        }
        let first_length = *input
            .get(1)
            .ok_or_else(|| Error::Protocol("truncated LOGIN7 recovery state length".into()))?;
        let (header, bytes) = if first_length == 0xff {
            let raw = input.get(2..6).ok_or_else(|| {
                Error::Protocol("truncated LOGIN7 recovery extended state length".into())
            })?;
            let bytes =
                usize::try_from(u32::from_le_bytes(raw.try_into().expect("length checked")))
                    .map_err(|_| Error::Limit("LOGIN7 recovery state value"))?;
            if bytes < 255 {
                return Err(Error::Protocol(
                    "non-canonical LOGIN7 recovery extended state length".into(),
                ));
            }
            (6_usize, bytes)
        } else {
            (2_usize, usize::from(first_length))
        };
        let end = header
            .checked_add(bytes)
            .ok_or(Error::Limit("LOGIN7 recovery state offset"))?;
        let raw = input
            .get(header..end)
            .ok_or_else(|| Error::Protocol("truncated LOGIN7 recovery state value".into()))?;
        values.push(SessionStateValue {
            id,
            bytes,
            value: telemetry_bytes(raw),
        });
        input = &input[end..];
    }
    Ok(values)
}

fn telemetry_bytes(input: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(input) {
        if text
            .chars()
            .all(|character| !character.is_control() || character.is_ascii_whitespace())
        {
            return text.to_owned();
        }
    }
    let mut output = String::with_capacity(4 + input.len() * 2);
    output.push_str("hex:");
    use std::fmt::Write as _;
    for byte in input {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn recovery_b_varchar(input: &[u8], position: &mut usize) -> Result<String> {
    let chars = usize::from(
        *input
            .get(*position)
            .ok_or_else(|| Error::Protocol("truncated LOGIN7 recovery string".into()))?,
    );
    *position += 1;
    let bytes = chars
        .checked_mul(2)
        .ok_or_else(|| Error::Protocol("LOGIN7 recovery string overflow".into()))?;
    let end = position
        .checked_add(bytes)
        .ok_or_else(|| Error::Protocol("LOGIN7 recovery string overflow".into()))?;
    let raw = input
        .get(*position..end)
        .ok_or_else(|| Error::Protocol("truncated LOGIN7 recovery string".into()))?;
    *position = end;
    decode_utf16(raw, false, "session recovery")
}

fn raw_byte_field<'a>(
    payload: &'a [u8],
    descriptor_offset: usize,
    declared: usize,
    fixed_length: usize,
    name: &str,
) -> Result<&'a [u8]> {
    let descriptor = payload
        .get(descriptor_offset..descriptor_offset + 4)
        .ok_or_else(|| Error::Protocol("LOGIN7 byte field descriptor truncated".into()))?;
    let offset = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let bytes = usize::from(u16::from_le_bytes([descriptor[2], descriptor[3]]));
    if bytes == 0 {
        return Ok(&[]);
    }
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| Error::Protocol("LOGIN7 byte field offset overflow".into()))?;
    if end > declared || offset < fixed_length {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} field is outside message (offset={offset}, bytes={bytes}, declared={declared})"
        )));
    }
    payload
        .get(offset..end)
        .ok_or_else(|| Error::Protocol(format!("truncated LOGIN7 {name} field")))
}

fn raw_field<'a>(
    payload: &'a [u8],
    descriptor_offset: usize,
    declared: usize,
    fixed_length: usize,
    name: &str,
) -> Result<&'a [u8]> {
    let descriptor = payload
        .get(descriptor_offset..descriptor_offset + 4)
        .ok_or_else(|| Error::Protocol("LOGIN7 field descriptor truncated".into()))?;
    let offset = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let chars = usize::from(u16::from_le_bytes([descriptor[2], descriptor[3]]));
    let bytes = chars
        .checked_mul(2)
        .ok_or_else(|| Error::Protocol("LOGIN7 field length overflow".into()))?;
    // Empty fields carry no data, so their offsets cannot safely be validated.
    // Real clients, including legacy direct-LOGIN7 clients, use zero here.
    if bytes == 0 {
        return Ok(&[]);
    }
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| Error::Protocol("LOGIN7 field offset overflow".into()))?;
    if end > declared || offset < fixed_length {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} field is outside message (offset={offset}, bytes={bytes}, declared={declared})"
        )));
    }
    payload
        .get(offset..end)
        .ok_or_else(|| Error::Protocol(format!("truncated LOGIN7 {name} field")))
}

fn sspi_field(payload: &[u8], declared: usize, fixed_length: usize) -> Result<&[u8]> {
    let descriptor = payload
        .get(78..82)
        .ok_or_else(|| Error::Protocol("LOGIN7 SSPI descriptor truncated".into()))?;
    let offset = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let short_length = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    let length = if short_length == u16::MAX {
        if fixed_length < EXTENDED_FIXED_LENGTH {
            return Err(Error::Protocol(
                "LOGIN7 legacy SSPI length cannot use cbSSPILong".into(),
            ));
        }
        usize::try_from(le_u32(payload, 90)?)
            .map_err(|_| Error::Protocol("LOGIN7 SSPI length overflow".into()))?
    } else {
        usize::from(short_length)
    };
    if length == 0 {
        return Ok(&[]);
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::Protocol("LOGIN7 SSPI offset overflow".into()))?;
    if offset < fixed_length || end > declared {
        return Err(Error::Protocol(
            "LOGIN7 SSPI field is outside message".into(),
        ));
    }
    payload
        .get(offset..end)
        .ok_or_else(|| Error::Protocol("truncated LOGIN7 SSPI field".into()))
}

fn classify_sspi(token: &[u8]) -> Option<&'static str> {
    (!token.is_empty()).then(|| super::sspi::parse(token).family)
}

fn field(
    payload: &[u8],
    descriptor_offset: usize,
    declared: usize,
    fixed_length: usize,
    allow_nul: bool,
    name: &str,
) -> Result<String> {
    let raw = raw_field(payload, descriptor_offset, declared, fixed_length, name)?;
    decode_utf16(raw, allow_nul, name)
}

fn decode_utf16(raw: &[u8], allow_nul: bool, name: &str) -> Result<String> {
    if raw.len() % 2 != 0 {
        return Err(Error::Protocol(format!(
            "LOGIN7 {name} field has odd-length UTF-16 data"
        )));
    }
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let decoded: String = char::decode_utf16(units)
        .map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if !allow_nul && decoded.contains('\0') {
        return Err(Error::Protocol(format!("LOGIN7 {name} field contains NUL")));
    }
    Ok(decoded)
}

fn deobfuscate_password(raw: &[u8]) -> Result<String> {
    let clear: Vec<u8> = raw
        .iter()
        .map(|byte| {
            let x = byte ^ 0xa5;
            x.rotate_left(4)
        })
        .collect();
    decode_utf16(&clear, false, "password")
}

fn le_u32(input: &[u8], offset: usize) -> Result<u32> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Protocol("truncated LOGIN7 integer".into()))?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_malformed_offsets_without_panicking() {
        for len in 0..120 {
            let _ = parse(&vec![0xff; len]);
        }
    }
    #[test]
    fn password_transform_matches_tds_obfuscation() {
        let original: Vec<u8> = "Secret".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded: Vec<u8> = original.iter().map(|b| b.rotate_right(4) ^ 0xa5).collect();
        assert_eq!(deobfuscate_password(&encoded).unwrap(), "Secret");
    }

    #[test]
    fn ignores_offsets_for_empty_variable_fields() {
        let mut payload = vec![0_u8; EXTENDED_FIXED_LENGTH];
        payload[0..4].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u32).to_le_bytes());
        for descriptor in [36, 40, 44, 48, 52, 60, 64, 68, 78] {
            payload[descriptor..descriptor + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        }
        let login = parse(&payload).unwrap();
        assert!(login.username.is_empty());
        assert!(!login.password_present);
    }

    #[test]
    fn accepts_tds_71_fields_at_the_legacy_variable_boundary() {
        let mut payload = vec![0_u8; LEGACY_FIXED_LENGTH];
        payload[4..8].copy_from_slice(&0x7100_0001_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&(LEGACY_FIXED_LENGTH as u16).to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());
        payload.extend_from_slice(&[b's', 0, b'a', 0]);
        let declared = payload.len() as u32;
        payload[0..4].copy_from_slice(&declared.to_le_bytes());

        let login = parse(&payload).unwrap();
        assert_eq!(login.tds_version, 0x7100_0001);
        assert_eq!(login.username, "sa");
        assert!(!login.password_present);
    }

    #[test]
    fn keeps_tds_72_fields_out_of_the_extended_fixed_header() {
        let mut payload = vec![0_u8; EXTENDED_FIXED_LENGTH];
        payload[0..4].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&0x7209_0002_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&(LEGACY_FIXED_LENGTH as u16).to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());
        payload[LEGACY_FIXED_LENGTH..LEGACY_FIXED_LENGTH + 4].copy_from_slice(&[b's', 0, b'a', 0]);

        let error = parse(&payload).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("username field is outside message")
        );
    }

    #[test]
    fn identifies_the_invalid_variable_field_without_exposing_contents() {
        let mut payload = vec![0_u8; 147];
        payload[0..4].copy_from_slice(&147_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&146_u16.to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());

        let error = parse(&payload).unwrap_err();
        assert_eq!(
            error.to_string(),
            "TDS protocol error: LOGIN7 username field is outside message (offset=146, bytes=4, declared=147)"
        );
    }

    #[test]
    fn identifies_sspi_without_retaining_the_token() {
        let token = b"NTLMSSP\0\x01\0\0\0";
        let mut payload = vec![0_u8; EXTENDED_FIXED_LENGTH];
        payload[0..4]
            .copy_from_slice(&((EXTENDED_FIXED_LENGTH + token.len()) as u32).to_le_bytes());
        payload[25] = 0x80;
        payload[78..80].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u16).to_le_bytes());
        payload[80..82].copy_from_slice(&(token.len() as u16).to_le_bytes());
        payload.extend_from_slice(token);

        let login = parse(&payload).unwrap();
        assert!(login.integrated_security);
        assert_eq!(login.sspi_bytes, token.len());
        assert_eq!(login.sspi_token_family, Some("ntlmssp"));
    }

    #[test]
    fn parses_feature_extensions_and_future_fixed_headers() {
        let mut payload = vec![0_u8; 98];
        payload[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
        payload[27] = 0x10;
        payload[36..38].copy_from_slice(&94_u16.to_le_bytes());
        payload[56..58].copy_from_slice(&94_u16.to_le_bytes());
        payload[58..60].copy_from_slice(&4_u16.to_le_bytes());
        payload[94..98].copy_from_slice(&98_u32.to_le_bytes());
        payload.extend_from_slice(&[0x02, 2, 0, 0, 0, 0x02, 0x01, 0xff]);
        let declared = payload.len() as u32;
        payload[0..4].copy_from_slice(&declared.to_le_bytes());
        let parsed = parse(&payload).unwrap();
        assert_eq!(parsed.features.len(), 1);
        assert_eq!(parsed.features[0].name, "fedauth");
        assert_eq!(parsed.features[0].fedauth_library, Some(2));
        assert_eq!(parsed.features[0].fedauth_workflow, Some(1));

        let mut future = vec![0_u8; 102];
        future[4..8].copy_from_slice(&0x7500_0001_u32.to_le_bytes());
        future[36..38].copy_from_slice(&102_u16.to_le_bytes());
        future[40..42].copy_from_slice(&102_u16.to_le_bytes());
        future[42..44].copy_from_slice(&2_u16.to_le_bytes());
        future.extend_from_slice(&[b's', 0, b'a', 0]);
        future[0..4].copy_from_slice(&(106_u32).to_le_bytes());
        assert_eq!(parse(&future).unwrap().username, "sa");
    }

    #[test]
    fn telemetry_keeps_valid_features_before_a_truncated_feature() {
        let mut payload = vec![0_u8; 98];
        payload[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
        payload[27] = 0x10;
        payload[36..38].copy_from_slice(&94_u16.to_le_bytes());
        payload[56..58].copy_from_slice(&94_u16.to_le_bytes());
        payload[58..60].copy_from_slice(&4_u16.to_le_bytes());
        payload[94..98].copy_from_slice(&98_u32.to_le_bytes());
        payload.extend_from_slice(&[0x0e, 1, 0, 0, 0, 2, 0x10, 40, 0, 0, 0, b'x']);
        let declared = payload.len() as u32;
        payload[0..4].copy_from_slice(&declared.to_le_bytes());

        assert!(parse(&payload).is_err());
        let parsed = parse_for_telemetry(&payload).unwrap();
        assert_eq!(parsed.features.len(), 1);
        assert_eq!(parsed.features[0].name, "vector_support");
        assert_eq!(parsed.features[0].version, Some(2));
        let remainder = parsed
            .feature_extension_remainder
            .as_ref()
            .expect("truncated feature remainder");
        assert_eq!(remainder.offset, 104);
        assert_eq!(remainder.bytes, 6);
        assert_eq!(remainder.first_byte, Some(0x10));
        assert_eq!(remainder.feature_id, Some(0x10));
        assert_eq!(remainder.declared_data_bytes, Some(40));
        assert_eq!(remainder.available_data_bytes, 1);
        assert_eq!(remainder.first_data_byte, Some(b'x'));
        assert_eq!(
            parsed.feature_extension_remainder_raw,
            [0x10, 40, 0, 0, 0, b'x']
        );
        assert!(
            parsed
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("truncated LOGIN7 FeatureExt"))
        );
    }

    #[test]
    fn parses_current_user_agent_feature() {
        let value: Vec<u8> = "ODBC 18.5|linux"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut data = Vec::new();
        data.extend_from_slice(&u16::try_from(value.len() / 2).unwrap().to_le_bytes());
        data.extend_from_slice(&value);
        let feature = parse_feature(0x10, &data);
        assert_eq!(feature.user_agent.as_deref(), Some("ODBC 18.5|linux"));
        assert!(feature.parse_error.is_none());
    }

    #[test]
    fn validates_all_fedauth_feature_layouts() {
        let mut live_id = vec![0x00];
        live_id.extend_from_slice(&3_u32.to_le_bytes());
        live_id.extend_from_slice(b"jwt");
        live_id.extend_from_slice(&[1; 32]); // nonce
        live_id.extend_from_slice(&[2; 7]); // channel binding token
        live_id.extend_from_slice(&[3; 32]); // signature
        let feature = parse_feature(0x02, &live_id);
        assert!(feature.parse_error.is_none());
        assert_eq!(feature.fedauth_token_bytes, Some(3));
        assert_eq!(feature.fedauth_nonce_present, Some(true));
        assert_eq!(feature.fedauth_channel_binding_bytes, Some(7));
        assert_eq!(feature.fedauth_signature_present, Some(true));

        let mut security_token = vec![0x01];
        security_token.extend_from_slice(&3_u32.to_le_bytes());
        security_token.extend_from_slice(b"jwt");
        let feature = parse_feature(0x02, &security_token);
        assert!(feature.parse_error.is_none());
        assert_eq!(feature.fedauth_nonce_present, Some(false));

        let invalid_trailing = [security_token.as_slice(), &[4][..]].concat();
        assert!(parse_feature(0x02, &invalid_trailing).parse_error.is_some());
        assert!(parse_feature(0x02, &[0x02, 0x03]).parse_error.is_some());
    }

    #[test]
    fn published_feature_inventory_and_semantic_dispatch_cannot_drift() {
        for &id in PUBLISHED_FEATURE_IDS {
            assert_ne!(feature_name(id), "unknown", "feature 0x{id:02x}");
            let data = match id {
                0x01 | 0x05 | 0x0b | 0x0f => Vec::new(),
                0x02 => [vec![0x01], 1_u32.to_le_bytes().to_vec(), vec![b'x']].concat(),
                0x04 | 0x08 | 0x09 | 0x0a | 0x0d | 0x0e => vec![1],
                0x10 => vec![0, 0],
                _ => unreachable!("inventory and fixture dispatch must change together"),
            };
            let feature = parse_feature(id, &data);
            assert!(
                feature.parse_error.is_none(),
                "feature 0x{id:02x}: {:?}",
                feature.parse_error
            );
        }
    }

    #[test]
    fn telemetry_parser_recovers_password_when_an_unrelated_field_is_invalid() {
        let clear: Vec<u8> = "gold".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded: Vec<u8> = clear
            .iter()
            .map(|byte| byte.rotate_right(4) ^ 0xa5)
            .collect();
        let mut payload = vec![0_u8; EXTENDED_FIXED_LENGTH];
        payload[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
        payload[36..38].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u16).to_le_bytes());
        payload[40..42].copy_from_slice(&u16::MAX.to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());
        payload[44..46].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u16).to_le_bytes());
        payload[46..48].copy_from_slice(&4_u16.to_le_bytes());
        payload.extend_from_slice(&encoded);
        let declared = payload.len() as u32;
        payload[0..4].copy_from_slice(&declared.to_le_bytes());

        let parsed = parse_for_telemetry(&payload).unwrap();
        assert_eq!(parsed.password_for_capture(), Some("gold"));
        assert!(!parsed.parse_warnings.is_empty());
    }

    #[test]
    fn telemetry_parser_recovers_credentials_when_declared_length_is_wrong() {
        let mut payload = vec![0_u8; EXTENDED_FIXED_LENGTH];
        payload[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u16).to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());
        let clear: Vec<u8> = "sa".encode_utf16().flat_map(u16::to_le_bytes).collect();
        payload.extend_from_slice(&clear);
        let password_offset = payload.len();
        payload[44..46].copy_from_slice(&(password_offset as u16).to_le_bytes());
        payload[46..48].copy_from_slice(&6_u16.to_le_bytes());
        let clear_password: Vec<u8> = "Secret".encode_utf16().flat_map(u16::to_le_bytes).collect();
        payload.extend(
            clear_password
                .iter()
                .map(|byte| byte.rotate_right(4) ^ 0xa5),
        );
        payload[0..4].copy_from_slice(&1_u32.to_le_bytes());

        assert!(parse(&payload).is_err());
        let parsed = parse_for_telemetry(&payload).unwrap();
        assert_eq!(parsed.username, "sa");
        assert_eq!(parsed.password_for_capture(), Some("Secret"));
        assert!(!parsed.parse_warnings.is_empty());
    }

    #[test]
    fn strict_parser_rejects_trailing_and_oversized_login7_data() {
        let mut trailing = vec![0_u8; EXTENDED_FIXED_LENGTH + 1];
        trailing[0..4].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u32).to_le_bytes());
        trailing[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
        assert!(parse(&trailing).is_err());
        assert!(
            !parse_for_telemetry(&trailing)
                .unwrap()
                .parse_warnings
                .is_empty()
        );

        let mut oversized = vec![0_u8; MAX_LOGIN7_LENGTH + 1];
        let oversized_length = oversized.len() as u32;
        oversized[0..4].copy_from_slice(&oversized_length.to_le_bytes());
        oversized[4..8].copy_from_slice(&0x7400_0004_u32.to_le_bytes());
        assert!(parse(&oversized).is_err());
        assert!(
            !parse_for_telemetry(&oversized)
                .unwrap()
                .parse_warnings
                .is_empty()
        );
    }

    #[test]
    fn future_login_version_allows_reordered_variable_fields() {
        let mut payload = vec![0_u8; EXTENDED_FIXED_LENGTH];
        payload[4..8].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
        payload[40..42].copy_from_slice(&(EXTENDED_FIXED_LENGTH as u16).to_le_bytes());
        payload[42..44].copy_from_slice(&2_u16.to_le_bytes());
        payload.extend("sa".encode_utf16().flat_map(u16::to_le_bytes));
        let hostname_offset = payload.len() as u16;
        payload[36..38].copy_from_slice(&hostname_offset.to_le_bytes());
        payload[38..40].copy_from_slice(&1_u16.to_le_bytes());
        payload.extend("h".encode_utf16().flat_map(u16::to_le_bytes));
        let length = payload.len() as u32;
        payload[0..4].copy_from_slice(&length.to_le_bytes());

        let parsed = parse(&payload).unwrap();
        assert_eq!(parsed.username, "sa");
        assert_eq!(parsed.client_hostname, "h");
    }

    #[test]
    fn inventories_session_recovery_state_values() {
        let mut body = vec![0, 0, 0]; // empty database, collation, and language
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(b"abc");
        body.extend_from_slice(&[4, 0xff]);
        body.extend_from_slice(&255_u32.to_le_bytes());
        body.extend_from_slice(&vec![0xaa; 255]);
        let mut data = Vec::new();
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend_from_slice(&body);

        let feature = parse_feature(0x01, &data);
        assert!(feature.parse_error.is_none());
        assert_eq!(feature.recovery[0].state_values.len(), 2);
        assert_eq!(feature.recovery[0].state_values[0].id, 3);
        assert_eq!(feature.recovery[0].state_values[0].value, "abc");
        assert_eq!(feature.recovery[0].state_values[1].bytes, 255);
        assert!(
            feature.recovery[0].state_values[1]
                .value
                .starts_with("hex:")
        );
    }
}
