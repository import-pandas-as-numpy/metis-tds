use std::sync::OnceLock;

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rsa::{KeyPair, KeySize, OAEP_SHA1_MGF1SHA1, OaepPrivateDecryptingKey, PrivateDecryptingKey},
    signature::KeyPair as _,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::rngs::OsRng;
use serde::Serialize;

use crate::tds::sspi;
use crate::{Error, Result};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Capabilities {
    pub request: Vec<u8>,
    pub request_enabled: Vec<usize>,
    pub response: Vec<u8>,
    pub response_enabled: Vec<usize>,
    pub security: Vec<u8>,
    pub security_enabled: Vec<usize>,
    pub unknown_sections: Vec<CapabilitySection>,
}

impl Capabilities {
    /// TDS_REQ_COMMAND_ENCRYPTION (request capability 106) distinguishes
    /// EPEP/encrypt4 clients from older encrypt3 clients, which use the same
    /// legacy LOGIN security flag.
    pub fn supports_command_encryption(&self) -> bool {
        capability_enabled(&self.request, 106)
    }
}

fn capability_enabled(bitmap: &[u8], capability: usize) -> bool {
    let byte_from_end = capability / 8;
    bitmap
        .len()
        .checked_sub(byte_from_end + 1)
        .and_then(|index| bitmap.get(index))
        .is_some_and(|byte| byte & (1 << (capability % 8)) != 0)
}

fn enabled_capabilities(bitmap: &[u8]) -> Vec<usize> {
    (0..bitmap.len().saturating_mul(8))
        .filter(|capability| capability_enabled(bitmap, *capability))
        .collect()
}

/// Names every defined bit in the TDS 5 LOGIN security byte. Callers retain
/// the raw byte as well, so the reserved 0x40 bit cannot disappear.
pub fn login_security_modes(flags: u8) -> Vec<&'static str> {
    [
        (0x01, "encrypted_login_v1"),
        (0x02, "challenge_response"),
        (0x04, "security_labels"),
        (0x08, "application_defined_security"),
        (0x10, "secure_session"),
        (0x20, "encrypted_login_v2"),
        (0x80, "encrypted_login_v3_or_v4"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (flags & bit != 0).then_some(name))
    .collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct CapabilitySection {
    pub section_type: u8,
    pub bytes: Vec<u8>,
}

pub fn parse_capabilities(input: &[u8]) -> Result<Capabilities> {
    let mut cursor = Cursor { input, position: 0 };
    let mut result = Capabilities::default();
    while !cursor.done() {
        let section_type = cursor.u8()?;
        let length = usize::from(cursor.u8()?);
        let bytes = cursor.take(length)?.to_vec();
        match section_type {
            1 if result.request.is_empty() => {
                result.request_enabled = enabled_capabilities(&bytes);
                result.request = bytes;
            }
            2 if result.response.is_empty() => {
                result.response_enabled = enabled_capabilities(&bytes);
                result.response = bytes;
            }
            3 if result.security.is_empty() => {
                result.security_enabled = enabled_capabilities(&bytes);
                result.security = bytes;
            }
            _ => result.unknown_sections.push(CapabilitySection {
                section_type,
                bytes,
            }),
        }
        if result.unknown_sections.len() > 256 {
            return Err(Error::Limit("TDS 5 capability section count"));
        }
    }
    Ok(result)
}

fn token_summary(
    token: u8,
    name: &'static str,
    body_bytes: usize,
    framing: &'static str,
) -> Tds5Token {
    Tds5Token {
        token,
        name,
        body_bytes,
        framing,
    }
}

fn generic_u32_token_name(token: u8) -> Option<&'static str> {
    Some(match token {
        0x22 => "order_by2",
        _ => return None,
    })
}

fn generic_u16_token_name(token: u8) -> Option<&'static str> {
    Some(match token {
        0x23 => "cursor_declare2",
        0x2a => "column_format_old",
        0x60 => "debug_command",
        0xa0 => "column_name",
        0xa1 => "column_format",
        0xa2 => "event_notice",
        0xa4 => "table_name",
        0xa5 => "column_info",
        0xa7 => "alternate_name",
        0xa8 => "alternate_format",
        0xa9 => "order_by",
        0xaa => "error",
        0xab => "info",
        0xac => "return_value",
        0xad => "login_ack",
        0xae => "control",
        0xaf => "alternate_control",
        0xca => "key",
        0xe0 => "rpc",
        0xe2 => "capability",
        0xe3 => "environment_change",
        0xe5 => "extended_error",
        _ => return None,
    })
}

const PUBLISHED_TDS5_TOKEN_IDS: &[u8] = &[
    0x10, 0x20, 0x21, 0x22, 0x23, 0x2a, 0x60, 0x61, 0x62, 0x65, 0x71, 0x78, 0x79, 0x7c, 0x80, 0x81,
    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xca, 0xd1, 0xd3, 0xd7, 0xe0, 0xe2, 0xe3, 0xe5, 0xe6,
    0xe7, 0xe8, 0xec, 0xee, 0xfd, 0xfe, 0xff,
];

fn is_published_token(token: u8) -> bool {
    PUBLISHED_TDS5_TOKEN_IDS.contains(&token)
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthenticationStream {
    pub commands: Vec<Tds5Command>,
    pub tokens: Vec<Tds5Token>,
    pub message_types: Vec<Tds5Message>,
    pub parameter_formats: usize,
    pub parameter_sets: usize,
    pub parameter_value_bytes: Vec<usize>,
    pub parameter_values: Vec<Tds5ParameterValue>,
    pub row_formats: usize,
    pub rows: usize,
    pub alternate_formats: Vec<Tds5AlternateFormat>,
    pub alternate_rows: usize,
    pub row_value_bytes: Vec<usize>,
    pub row_values: Vec<Tds5ParameterValue>,
    pub encrypted_login_password_bytes: Option<usize>,
    pub encrypted_remote_passwords: Vec<Tds5RemotePassword>,
    pub encrypted_symmetric_key_bytes: Option<usize>,
    pub opaque_security: Vec<Tds5OpaqueSecurity>,
    pub unparsed_regions: Vec<Tds5UnparsedRegion>,
    pub parse_warnings: Vec<String>,
    #[serde(skip)]
    pub(crate) encrypted_login_password: Option<Vec<u8>>,
    #[serde(skip)]
    pub(crate) encrypted_symmetric_key: Option<Vec<u8>>,
    #[serde(skip)]
    raw_parameter_values: Vec<Vec<u8>>,
    pub unknown_token: Option<u8>,
    pub trailing_bytes: usize,
}

impl AuthenticationStream {
    /// Returns an exact parameter value from the token stream. Raw values are
    /// deliberately excluded from serialization because authentication
    /// parameters can contain credentials and bearer material.
    pub fn parameter_value(&self, index: usize) -> Option<&[u8]> {
        self.raw_parameter_values.get(index).map(Vec::as_slice)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5OpaqueSecurity {
    pub security_version: Option<i32>,
    pub security_message_type: Option<i32>,
    pub security_message_name: &'static str,
    pub mechanism_oid: Option<String>,
    pub authentication_token_bytes: usize,
    pub authentication_token_family: &'static str,
    pub authentication_mechanism_oids: Vec<String>,
    pub principal_hints: Vec<String>,
    pub security_flags: Option<u32>,
    pub security_services: Vec<&'static str>,
    pub unknown_security_flags: Option<u32>,
    pub parse_warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5RemotePassword {
    pub server_name: String,
    pub ciphertext_bytes: usize,
    #[serde(skip)]
    pub(crate) ciphertext: Vec<u8>,
}

pub struct SecureLoginKey {
    private: OaepPrivateDecryptingKey,
    public_pem: String,
    public_pkcs1_pem: String,
}

static SHARED_SECURE_LOGIN_KEY: OnceLock<std::result::Result<SecureLoginKey, String>> =
    OnceLock::new();

/// Generate the keypair supplied by an ASE RSA password negotiation.
///
/// The non-nonce protocol requires a unique keypair for each login attempt.
/// Keeping this constructor per-session also prevents a failed v2 attempt from
/// making later ciphertext useful to an observer.
pub fn secure_login_key() -> Result<SecureLoginKey> {
    generate_secure_login_key()
        .map_err(|error| Error::Protocol(format!("cannot initialize TDS 5 RSA key: {error}")))
}

/// Return the reusable keypair used by nonce-bound EPEP v3/v4. The per-login
/// nonce, not key regeneration, provides freshness for these protocols.
pub fn shared_secure_login_key() -> Result<&'static SecureLoginKey> {
    SHARED_SECURE_LOGIN_KEY
        .get_or_init(generate_secure_login_key)
        .as_ref()
        .map_err(|error| Error::Protocol(format!("cannot initialize TDS 5 RSA key: {error}")))
}

fn generate_secure_login_key() -> std::result::Result<SecureLoginKey, String> {
    let key_pair = KeyPair::generate(KeySize::Rsa2048)
        .map_err(|_| "AWS-LC RSA key generation failed".to_owned())?;
    let private_der = AsDer::<Pkcs8V1Der<'static>>::as_der(&key_pair)
        .map_err(|_| "AWS-LC RSA private-key encoding failed".to_owned())?;
    let private = PrivateDecryptingKey::from_pkcs8(private_der.as_ref())
        .map_err(|error| format!("AWS-LC rejected generated RSA key: {error}"))?;
    let private = OaepPrivateDecryptingKey::new(private)
        .map_err(|_| "AWS-LC RSA OAEP initialization failed".to_owned())?;
    let public_der = AsDer::<PublicKeyX509Der<'static>>::as_der(key_pair.public_key())
        .map_err(|_| "AWS-LC RSA public-key encoding failed".to_owned())?;
    let public_pem = encode_pem("PUBLIC KEY", public_der.as_ref());
    let public_pkcs1_pem = encode_pem("RSA PUBLIC KEY", key_pair.public_key().as_ref());
    Ok(SecureLoginKey {
        private,
        public_pem,
        public_pkcs1_pem,
    })
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}

impl SecureLoginKey {
    /// Emit an RSA/OAEP password challenge for the extended (message 14)
    /// protocol. Extended-plus uses a nonce and a PKCS#1 public key, so it must
    /// go through [`Self::challenge_with_nonce`] instead.
    pub fn challenge(&self, message_type: u16) -> Result<Vec<u8>> {
        if message_type != 14 {
            return Err(Error::Protocol(format!(
                "invalid non-nonce TDS 5 secure-login message type {message_type}"
            )));
        }
        let key = self.public_pem.as_bytes();
        let mut format = Vec::new();
        format.extend_from_slice(&2_u16.to_le_bytes());
        // Empty name, input status, zero user type, INTN(4), empty locale.
        format.extend_from_slice(&[0; 6]);
        format.extend_from_slice(&[0x26, 4, 0]);
        // Empty name, input status, zero user type, LONGBINARY(max), locale.
        format.extend_from_slice(&[0; 6]);
        format.push(0xe1);
        format.extend_from_slice(&u32::MAX.to_le_bytes());
        format.push(0);

        let mut output = vec![0x65, 3, 1];
        output.extend_from_slice(&message_type.to_le_bytes());
        output.push(0xec);
        output.extend_from_slice(
            &u16::try_from(format.len())
                .map_err(|_| Error::Limit("TDS 5 secure-login parameter format"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(&format);
        output.push(0xd7);
        output.push(4);
        output.extend_from_slice(&1_i32.to_le_bytes()); // RSA cipher suite
        output.extend_from_slice(
            &u32::try_from(key.len())
                .map_err(|_| Error::Limit("TDS 5 RSA public key"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(key);
        Ok(output)
    }

    pub fn decrypt_password(&self, ciphertext: &[u8]) -> Result<String> {
        let plaintext = self.decrypt_oaep(ciphertext, "password")?;
        String::from_utf8(plaintext)
            .map_err(|_| Error::Protocol("TDS 5 encrypted password is not UTF-8".into()))
    }

    /// Emit an EPEP challenge. Message 30 is the established nonce-bearing
    /// extended-plus exchange; message 35 extends it with the v4 symmetric-key
    /// negotiation used by on-demand command encryption.
    pub fn challenge_with_nonce(&self, message_type: u16) -> Result<(Vec<u8>, [u8; 32])> {
        if !matches!(message_type, 30 | 35) {
            return Err(Error::Protocol(format!(
                "invalid nonce-bearing TDS 5 secure-login message type {message_type}"
            )));
        }
        let mut nonce = [0_u8; 32];
        use rand::RngCore as _;
        OsRng.fill_bytes(&mut nonce);
        let values = [
            SecureChallengeValue::Int(1),
            SecureChallengeValue::Binary(self.public_pkcs1_pem.as_bytes()),
            SecureChallengeValue::Binary(&nonce),
        ];
        Ok((secure_challenge(message_type, &values)?, nonce))
    }

    pub fn decrypt_password_with_nonce(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 32],
    ) -> Result<String> {
        let plaintext = self.decrypt_oaep(ciphertext, "password")?;
        let password = plaintext.strip_prefix(nonce).ok_or_else(|| {
            Error::Protocol("TDS 5 encrypted password did not echo the server nonce".into())
        })?;
        String::from_utf8(password.to_vec())
            .map_err(|_| Error::Protocol("TDS 5 encrypted password is not UTF-8".into()))
    }

    /// Recover the AES-256 session key sent by an EPEP v4 client in
    /// TDS_MSG_SEC_SYMKEY. It uses the same RSA-OAEP-SHA1 and nonce-prefix
    /// construction as the encrypted password, but the post-nonce material is
    /// fixed-width binary rather than UTF-8.
    pub fn decrypt_symmetric_key_with_nonce(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let plaintext = self.decrypt_oaep(ciphertext, "symmetric key")?;
        let key = plaintext.strip_prefix(nonce).ok_or_else(|| {
            Error::Protocol("TDS 5 encrypted symmetric key did not echo the server nonce".into())
        })?;
        key.try_into().map_err(|_| {
            Error::Protocol(format!(
                "TDS 5 symmetric key is {} bytes; expected 32 for AES-256",
                key.len()
            ))
        })
    }

    fn decrypt_oaep(&self, ciphertext: &[u8], material: &str) -> Result<Vec<u8>> {
        let mut plaintext = vec![0_u8; self.private.min_output_size()];
        self.private
            .decrypt(&OAEP_SHA1_MGF1SHA1, ciphertext, &mut plaintext, None)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| Error::Protocol(format!("invalid TDS 5 encrypted {material}")))
    }
}

/// Emit the original TDS 5 encrypted-password negotiation. The v1 protocol
/// deliberately treats the key as opaque: SAP's published wire grammar only
/// specifies one nullable VARBINARY key parameter and one VARBINARY response,
/// while the default cipher itself remains proprietary. Keeping this builder
/// separate from the RSA helpers prevents the two parameter grammars from
/// being conflated.
pub fn proprietary_login_challenge(key: &[u8]) -> Result<Vec<u8>> {
    let key_len =
        u8::try_from(key.len()).map_err(|_| Error::Limit("TDS 5 proprietary encryption key"))?;
    if key.is_empty() {
        return Err(Error::Protocol(
            "TDS 5 proprietary encryption key is empty".into(),
        ));
    }

    let mut output = vec![0x65, 3, 1];
    output.extend_from_slice(&1_u16.to_le_bytes()); // TDS_MSG_SEC_ENCRYPT
    output.push(0xec); // TDS_PARAMFMT
    let format = [
        1,
        0,    // one parameter
        0,    // empty name
        0x08, // CS_CANBENULL
        0,
        0,
        0,
        0,       // user type
        0x25,    // TDS_VARBINARY
        u8::MAX, // maximum value length
        0,       // empty locale
    ];
    output.extend_from_slice(&(format.len() as u16).to_le_bytes());
    output.extend_from_slice(&format);
    output.push(0xd7); // TDS_PARAMS
    output.push(0); // non-null value status for CS_CANBENULL
    output.push(key_len);
    output.extend_from_slice(key);
    Ok(output)
}

enum SecureChallengeValue<'a> {
    Int(i32),
    Binary(&'a [u8]),
}

fn secure_challenge(message_type: u16, values: &[SecureChallengeValue<'_>]) -> Result<Vec<u8>> {
    let mut format = Vec::new();
    format.extend_from_slice(
        &u16::try_from(values.len())
            .map_err(|_| Error::Limit("TDS 5 secure-login parameter count"))?
            .to_le_bytes(),
    );
    for value in values {
        format.extend_from_slice(&[0; 6]); // name, input status, user type
        match value {
            SecureChallengeValue::Int(_) => format.extend_from_slice(&[0x26, 4, 0]),
            SecureChallengeValue::Binary(_) => {
                format.push(0xe1);
                format.extend_from_slice(&u32::MAX.to_le_bytes());
                format.push(0);
            }
        }
    }
    let mut output = vec![0x65, 3, 1];
    output.extend_from_slice(&message_type.to_le_bytes());
    output.push(0xec);
    output.extend_from_slice(
        &u16::try_from(format.len())
            .map_err(|_| Error::Limit("TDS 5 secure-login parameter format"))?
            .to_le_bytes(),
    );
    output.extend_from_slice(&format);
    output.push(0xd7);
    for value in values {
        match value {
            SecureChallengeValue::Int(value) => {
                output.push(4);
                output.extend_from_slice(&value.to_le_bytes());
            }
            SecureChallengeValue::Binary(value) => {
                output.extend_from_slice(
                    &u32::try_from(value.len())
                        .map_err(|_| Error::Limit("TDS 5 secure-login binary value"))?
                        .to_le_bytes(),
                );
                output.extend_from_slice(value);
            }
        }
    }
    Ok(output)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_or_options: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_status: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_rows: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_argument: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5ParameterValue {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_operator: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operand_column: Option<u8>,
    pub type_id: u8,
    pub format_status: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_status: Option<u8>,
    pub bytes: usize,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_serialization: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_class_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_subclass_or_locator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_chunks: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5AlternateFormat {
    pub compute_id: u16,
    pub columns: usize,
    pub operators: Vec<&'static str>,
    pub operand_columns: Vec<u8>,
    pub by_columns: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5Message {
    pub message_type: u16,
    pub name: &'static str,
    pub status: u8,
    pub extra_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5Token {
    pub token: u8,
    pub name: &'static str,
    pub body_bytes: usize,
    pub framing: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Tds5UnparsedRegion {
    pub offset: usize,
    pub bytes: usize,
    pub first_byte: Option<u8>,
}

#[derive(Clone, Debug)]
struct Parameter {
    name: String,
    column_label: Option<String>,
    catalogue: Option<String>,
    schema: Option<String>,
    table: Option<String>,
    compute_id: Option<u16>,
    aggregate_operator: Option<&'static str>,
    operand_column: Option<u8>,
    status: u32,
    ty: u8,
    max_length: usize,
    encoding: ValueEncoding,
    blob_class_id: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum ValueEncoding {
    Fixed(usize),
    U8,
    U32,
    Lob,
    Blob(u8),
}

struct ParsedParameterValue {
    bytes: Vec<u8>,
    blob_serialization: Option<u8>,
    blob_subclass_or_locator: Option<String>,
    blob_chunks: Option<usize>,
}

/// Parse the client-side TDS 5 token stream used for encrypted-password,
/// challenge/response, and opaque security-session continuations. Unknown
/// tokens are reported with their exact trailing span so callers can retain
/// the artifact without guessing token boundaries.
pub fn parse_authentication(input: &[u8], max_value_bytes: usize) -> Result<AuthenticationStream> {
    let mut cursor = Cursor { input, position: 0 };
    let mut result = AuthenticationStream {
        commands: Vec::new(),
        tokens: Vec::new(),
        message_types: Vec::new(),
        parameter_formats: 0,
        parameter_sets: 0,
        parameter_value_bytes: Vec::new(),
        parameter_values: Vec::new(),
        row_formats: 0,
        rows: 0,
        alternate_formats: Vec::new(),
        alternate_rows: 0,
        row_value_bytes: Vec::new(),
        row_values: Vec::new(),
        encrypted_login_password_bytes: None,
        encrypted_remote_passwords: Vec::new(),
        encrypted_symmetric_key_bytes: None,
        encrypted_login_password: None,
        encrypted_symmetric_key: None,
        raw_parameter_values: Vec::new(),
        opaque_security: Vec::new(),
        unparsed_regions: Vec::new(),
        parse_warnings: Vec::new(),
        unknown_token: None,
        trailing_bytes: 0,
    };
    let mut parameters = Vec::new();
    let mut row_parameters = Vec::new();
    let mut alternate_parameters: Vec<(u16, Vec<Parameter>)> = Vec::new();
    let mut consumed_values = 0usize;
    let mut current_message_type = None;
    while !cursor.done() {
        let token = cursor.u8()?;
        if !is_published_token(token) {
            result.unknown_token = Some(token);
            result.trailing_bytes = cursor.remaining();
            break;
        }
        match token {
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
                    cursor_id: None,
                    status_or_options: None,
                    secondary_status: None,
                    table_name: None,
                    row_number: None,
                    total_rows: None,
                    row_count: None,
                    option_code: None,
                    option_argument: None,
                });
                result
                    .tokens
                    .push(token_summary(token, "language", len, "u32"));
            }
            token @ (0xe6 | 0xe8) => {
                let wide = token == 0xe8;
                let len = if wide {
                    usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 DBRPC2"))?
                } else {
                    usize::from(cursor.u16()?)
                };
                let body = cursor.take(len)?;
                let mut command = parse_dbrpc(body, wide)?;
                command.token = token;
                command.name = if wide { "dbrpc2" } else { "dbrpc" };
                command.body_bytes = len;
                result.commands.push(command);
                result.tokens.push(token_summary(
                    token,
                    if wide { "dbrpc2" } else { "dbrpc" },
                    len,
                    if wide { "u32" } else { "u16" },
                ));
            }
            // SAP's current go-dblib assigns DYNAMIC2 to 0x62, while the
            // long-standing FreeTDS token table assigns it to 0xa3. Accept
            // both wire values: in token position they share the same wide,
            // u32-length body grammar and do not conflict with datatype IDs.
            token @ (0x62 | 0xa3 | 0xe7) => {
                let wide = matches!(token, 0x62 | 0xa3);
                let len = if wide {
                    usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 DYNAMIC2"))?
                } else {
                    usize::from(cursor.u16()?)
                };
                let body = cursor.take(len)?;
                let mut command = parse_dynamic(body, wide)?;
                command.token = token;
                command.name = if wide { "dynamic2" } else { "dynamic" };
                command.body_bytes = len;
                result.commands.push(command);
                result.tokens.push(token_summary(
                    token,
                    if wide { "dynamic2" } else { "dynamic" },
                    len,
                    if wide { "u32" } else { "u16" },
                ));
            }
            0x10 => {
                let len = usize::try_from(cursor.u32()?)
                    .map_err(|_| Error::Limit("TDS 5 CURDECLARE3"))?;
                let body = cursor.take(len)?;
                result
                    .commands
                    .push(parse_cursor_declare(token, body, true)?);
                result
                    .tokens
                    .push(token_summary(token, "cursor_declare3", len, "u32"));
            }
            token @ (0x80..=0x88 | 0xa6) => {
                let len = usize::from(cursor.u16()?);
                let body = cursor.take(len)?;
                let command = if token == 0x86 {
                    parse_cursor_declare(token, body, false)?
                } else {
                    parse_simple_command(token, body)?
                };
                let name = command.name;
                result.commands.push(command);
                result.tokens.push(token_summary(token, name, len, "u16"));
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
                    cursor_id: None,
                    status_or_options: None,
                    secondary_status: None,
                    table_name: None,
                    row_number: None,
                    total_rows: None,
                    row_count: None,
                    option_code: None,
                    option_argument: None,
                });
                result
                    .tokens
                    .push(token_summary(token, "logout", len, "u8"));
            }
            0x65 => {
                let len = usize::from(cursor.u8()?);
                let body = cursor.take(len)?;
                if len < 3 {
                    return Err(Error::Protocol("short TDS 5 MSG token".into()));
                }
                let message_type = u16::from_le_bytes([body[1], body[2]]);
                current_message_type = Some(message_type);
                result.message_types.push(Tds5Message {
                    message_type,
                    name: message_type_name(message_type),
                    status: body[0],
                    extra_bytes: len - 3,
                });
                result
                    .tokens
                    .push(token_summary(token, "message", len, "u8"));
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
                result.tokens.push(token_summary(
                    token,
                    if wide {
                        "parameter_format2"
                    } else {
                        "parameter_format"
                    },
                    len,
                    if wide { "u32" } else { "u16" },
                ));
            }
            token @ (0x61 | 0xee) => {
                let wide = token == 0x61;
                let len = if wide {
                    usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 ROWFMT2"))?
                } else {
                    usize::from(cursor.u16()?)
                };
                let body = cursor.take(len)?;
                row_parameters = parse_row_format(body, wide)?;
                result.row_formats += 1;
                result.tokens.push(token_summary(
                    token,
                    if wide { "row_format2" } else { "row_format" },
                    len,
                    if wide { "u32" } else { "u16" },
                ));
            }
            0xd1 => {
                if row_parameters.is_empty() {
                    return Err(Error::Protocol("TDS 5 ROW without ROWFMT/ROWFMT2".into()));
                }
                let row_start = cursor.position;
                for parameter in &row_parameters {
                    let data_status = if parameter.status & 0x08 != 0 {
                        Some(cursor.u8()?)
                    } else {
                        None
                    };
                    let parsed_value = read_parameter_value(
                        &mut cursor,
                        parameter,
                        max_value_bytes.saturating_sub(consumed_values),
                    )?;
                    let len = parsed_value.bytes.len();
                    if len > parameter.max_length && parameter.max_length != usize::MAX {
                        return Err(Error::Protocol(
                            "TDS 5 row value exceeds declared maximum".into(),
                        ));
                    }
                    consumed_values = consumed_values
                        .checked_add(len)
                        .ok_or(Error::Limit("TDS 5 row bytes"))?;
                    if consumed_values > max_value_bytes {
                        return Err(Error::Limit("TDS 5 row bytes"));
                    }
                    result.row_value_bytes.push(len);
                    result.row_values.push(Tds5ParameterValue {
                        name: parameter.name.clone(),
                        column_label: parameter.column_label.clone(),
                        catalogue: parameter.catalogue.clone(),
                        schema: parameter.schema.clone(),
                        table: parameter.table.clone(),
                        compute_id: parameter.compute_id,
                        aggregate_operator: parameter.aggregate_operator,
                        operand_column: parameter.operand_column,
                        type_id: parameter.ty,
                        format_status: parameter.status,
                        data_status,
                        bytes: len,
                        value: summarize_value(
                            parameter.ty,
                            parameter.encoding,
                            parsed_value.blob_serialization,
                            &parsed_value.bytes,
                        ),
                        blob_type: match parameter.encoding {
                            ValueEncoding::Blob(blob_type) => Some(blob_type),
                            _ => None,
                        },
                        blob_serialization: parsed_value.blob_serialization,
                        blob_class_id: parameter.blob_class_id.clone(),
                        blob_subclass_or_locator: parsed_value.blob_subclass_or_locator,
                        blob_chunks: parsed_value.blob_chunks,
                    });
                }
                result.rows += 1;
                result.tokens.push(token_summary(
                    0xd1,
                    "row",
                    cursor.position - row_start,
                    "metadata",
                ));
            }
            0xa8 => {
                let len = usize::from(cursor.u16()?);
                let body = cursor.take(len)?;
                let (format, columns) = parse_alternate_format(body)?;
                if let Some(existing) = alternate_parameters
                    .iter_mut()
                    .find(|(compute_id, _)| *compute_id == format.compute_id)
                {
                    existing.1 = columns;
                } else {
                    if alternate_parameters.len() >= 1024 {
                        return Err(Error::Limit("TDS 5 alternate format count"));
                    }
                    alternate_parameters.push((format.compute_id, columns));
                }
                result.alternate_formats.push(format);
                result
                    .tokens
                    .push(token_summary(0xa8, "alternate_format", len, "u16"));
            }
            0xd3 => {
                let compute_id = cursor.u16()?;
                let columns = alternate_parameters
                    .iter()
                    .find(|(candidate, _)| *candidate == compute_id)
                    .map(|(_, columns)| columns)
                    .ok_or_else(|| {
                        Error::Protocol(format!(
                            "TDS 5 ALTROW references unknown compute id {compute_id}"
                        ))
                    })?;
                let row_start = cursor.position;
                for parameter in columns {
                    let data_status = if parameter.status & 0x08 != 0 {
                        Some(cursor.u8()?)
                    } else {
                        None
                    };
                    let parsed_value = read_parameter_value(
                        &mut cursor,
                        parameter,
                        max_value_bytes.saturating_sub(consumed_values),
                    )?;
                    let len = parsed_value.bytes.len();
                    if len > parameter.max_length && parameter.max_length != usize::MAX {
                        return Err(Error::Protocol(
                            "TDS 5 alternate-row value exceeds declared maximum".into(),
                        ));
                    }
                    consumed_values = consumed_values
                        .checked_add(len)
                        .ok_or(Error::Limit("TDS 5 alternate-row bytes"))?;
                    if consumed_values > max_value_bytes {
                        return Err(Error::Limit("TDS 5 alternate-row bytes"));
                    }
                    result.row_value_bytes.push(len);
                    result.row_values.push(Tds5ParameterValue {
                        name: parameter.name.clone(),
                        column_label: parameter.column_label.clone(),
                        catalogue: parameter.catalogue.clone(),
                        schema: parameter.schema.clone(),
                        table: parameter.table.clone(),
                        compute_id: parameter.compute_id,
                        aggregate_operator: parameter.aggregate_operator,
                        operand_column: parameter.operand_column,
                        type_id: parameter.ty,
                        format_status: parameter.status,
                        data_status,
                        bytes: len,
                        value: summarize_value(
                            parameter.ty,
                            parameter.encoding,
                            parsed_value.blob_serialization,
                            &parsed_value.bytes,
                        ),
                        blob_type: match parameter.encoding {
                            ValueEncoding::Blob(blob_type) => Some(blob_type),
                            _ => None,
                        },
                        blob_serialization: parsed_value.blob_serialization,
                        blob_class_id: parameter.blob_class_id.clone(),
                        blob_subclass_or_locator: parsed_value.blob_subclass_or_locator,
                        blob_chunks: parsed_value.blob_chunks,
                    });
                }
                result.alternate_rows += 1;
                result.tokens.push(token_summary(
                    0xd3,
                    "alternate_row",
                    cursor.position - row_start + 2,
                    "metadata",
                ));
            }
            0xd7 => {
                if parameters.is_empty() {
                    return Err(Error::Protocol("TDS 5 PARAMS without PARAMFMT".into()));
                }
                let mut set_values = Vec::with_capacity(parameters.len());
                for parameter in &parameters {
                    let data_status = if parameter.status & 0x08 != 0 {
                        Some(cursor.u8()?)
                    } else {
                        None
                    };
                    let parsed_value = read_parameter_value(
                        &mut cursor,
                        parameter,
                        max_value_bytes.saturating_sub(consumed_values),
                    )?;
                    let len = parsed_value.bytes.len();
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
                    let value = parsed_value.bytes;
                    set_values.push(value.clone());
                    result.raw_parameter_values.push(value.clone());
                    if matches!(current_message_type, Some(2 | 15 | 31))
                        && result.encrypted_login_password.is_none()
                        && !value.is_empty()
                    {
                        result.encrypted_login_password_bytes = Some(value.len());
                        result.encrypted_login_password = Some(value.clone());
                    }
                    result.parameter_value_bytes.push(len);
                    result.parameter_values.push(Tds5ParameterValue {
                        name: parameter.name.clone(),
                        column_label: parameter.column_label.clone(),
                        catalogue: parameter.catalogue.clone(),
                        schema: parameter.schema.clone(),
                        table: parameter.table.clone(),
                        compute_id: parameter.compute_id,
                        aggregate_operator: parameter.aggregate_operator,
                        operand_column: parameter.operand_column,
                        type_id: parameter.ty,
                        format_status: parameter.status,
                        data_status,
                        bytes: len,
                        value: summarize_value(
                            parameter.ty,
                            parameter.encoding,
                            parsed_value.blob_serialization,
                            &value,
                        ),
                        blob_type: match parameter.encoding {
                            ValueEncoding::Blob(blob_type) => Some(blob_type),
                            _ => None,
                        },
                        blob_serialization: parsed_value.blob_serialization,
                        blob_class_id: parameter.blob_class_id.clone(),
                        blob_subclass_or_locator: parsed_value.blob_subclass_or_locator,
                        blob_chunks: parsed_value.blob_chunks,
                    });
                }
                if current_message_type == Some(11) {
                    result
                        .opaque_security
                        .push(parse_opaque_security(&set_values));
                }
                if matches!(current_message_type, Some(3 | 22 | 32)) {
                    for pair in set_values.chunks_exact(2) {
                        result.encrypted_remote_passwords.push(Tds5RemotePassword {
                            server_name: String::from_utf8_lossy(&pair[0]).into_owned(),
                            ciphertext_bytes: pair[1].len(),
                            ciphertext: pair[1].clone(),
                        });
                    }
                    if set_values.len() % 2 != 0 {
                        result.parse_warnings.push(format!(
                            "TDS 5 remote-password message has {} parameters; expected pairs",
                            set_values.len()
                        ));
                    }
                }
                if current_message_type == Some(34) {
                    if let Some(value) = set_values.first() {
                        result.encrypted_symmetric_key_bytes = Some(value.len());
                        result.encrypted_symmetric_key = Some(value.clone());
                    }
                    if set_values.len() != 1 {
                        result.parse_warnings.push(format!(
                            "TDS 5 symmetric-key message has {} parameters; expected one",
                            set_values.len()
                        ));
                    }
                }
                result.parameter_sets += 1;
                result.tokens.push(token_summary(
                    token,
                    "parameters",
                    set_values.iter().map(Vec::len).sum(),
                    "metadata",
                ));
                // A MSG argument list is one PARAMFMT/PARAMS set. Do not let
                // its semantic type bleed into later unrelated parameter
                // sets when a client omits or delays the next MSG token.
                current_message_type = None;
            }
            token if generic_u32_token_name(token).is_some() => {
                let len =
                    usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 wide token"))?;
                cursor.skip(len)?;
                result.tokens.push(token_summary(
                    token,
                    generic_u32_token_name(token).expect("guarded"),
                    len,
                    "u32",
                ));
            }
            token if generic_u16_token_name(token).is_some() => {
                let len = usize::from(cursor.u16()?);
                cursor.skip(len)?;
                let name = generic_u16_token_name(token).expect("guarded");
                result.commands.push(Tds5Command {
                    token,
                    name,
                    body_bytes: len,
                    operation: None,
                    identifier: None,
                    text: None,
                    cursor_id: None,
                    status_or_options: None,
                    secondary_status: None,
                    table_name: None,
                    row_number: None,
                    total_rows: None,
                    row_count: None,
                    option_code: None,
                    option_argument: None,
                });
                result.tokens.push(token_summary(token, name, len, "u16"));
            }
            token @ (0x78 | 0x79) => {
                cursor.skip(4)?;
                result.tokens.push(token_summary(
                    token,
                    if token == 0x78 {
                        "offset"
                    } else {
                        "return_status"
                    },
                    4,
                    "fixed",
                ));
            }
            0x7c => {
                cursor.skip(8)?;
                result
                    .tokens
                    .push(token_summary(token, "procedure_id", 8, "fixed"));
            }
            token @ 0xfd..=0xff => {
                cursor.skip(8)?;
                result.tokens.push(token_summary(
                    token,
                    match token {
                        0xfd => "done",
                        0xfe => "done_proc",
                        _ => "done_in_proc",
                    },
                    8,
                    "fixed",
                ));
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
            + result.row_formats
            + result.rows
            + result.alternate_formats.len()
            + result.alternate_rows
            > 4096
        {
            return Err(Error::Limit("TDS 5 authentication token count"));
        }
    }
    Ok(result)
}

/// Parse a TDS 5 stream without allowing unfamiliar or malformed regions to
/// hide a self-framed authentication exchange. The strict parser is always
/// attempted first. Recovery requires an exactly framed authentication MSG
/// and either a complete suffix or at least one complete parameter set before
/// a trailing unknown token, which keeps random bytes from being promoted to
/// credentials while retaining valid material between proprietary tokens.
pub fn parse_for_telemetry(input: &[u8], max_value_bytes: usize) -> AuthenticationStream {
    let (mut fallback, first_error) = match parse_authentication(input, max_value_bytes) {
        Ok(parsed) if parsed.unknown_token.is_none() => return parsed,
        Ok(parsed) => (parsed, "unrecognized TDS 5 token".to_owned()),
        Err(error) => (
            AuthenticationStream {
                commands: Vec::new(),
                tokens: Vec::new(),
                message_types: Vec::new(),
                parameter_formats: 0,
                parameter_sets: 0,
                parameter_value_bytes: Vec::new(),
                parameter_values: Vec::new(),
                row_formats: 0,
                rows: 0,
                alternate_formats: Vec::new(),
                alternate_rows: 0,
                row_value_bytes: Vec::new(),
                row_values: Vec::new(),
                encrypted_login_password_bytes: None,
                encrypted_remote_passwords: Vec::new(),
                encrypted_symmetric_key_bytes: None,
                encrypted_login_password: None,
                encrypted_symmetric_key: None,
                raw_parameter_values: Vec::new(),
                opaque_security: Vec::new(),
                unknown_token: input.first().copied(),
                trailing_bytes: input.len().saturating_sub(1),
                unparsed_regions: (!input.is_empty())
                    .then_some(Tds5UnparsedRegion {
                        offset: 0,
                        bytes: input.len(),
                        first_byte: input.first().copied(),
                    })
                    .into_iter()
                    .collect(),
                parse_warnings: Vec::new(),
            },
            error.to_string(),
        ),
    };

    for offset in 1..input.len() {
        if input[offset] != 0x65 || !is_authentication_msg_prefix(&input[offset..]) {
            continue;
        }
        let Ok(mut recovered) = parse_authentication(&input[offset..], max_value_bytes) else {
            continue;
        };
        let has_published_message = recovered
            .message_types
            .iter()
            .any(|message| is_published_message_type(message.message_type));
        let complete_suffix = recovered.unknown_token.is_none() && recovered.trailing_bytes == 0;
        let complete_auth_material_before_unknown = recovered.unknown_token.is_some()
            && recovered.parameter_sets > 0
            && !recovered.raw_parameter_values.is_empty();
        if !has_published_message || !(complete_suffix || complete_auth_material_before_unknown) {
            continue;
        }
        let trailing_region = recovered.unknown_token.map(|_| {
            let bytes = recovered.trailing_bytes.saturating_add(1);
            Tds5UnparsedRegion {
                offset: input.len().saturating_sub(bytes),
                bytes,
                first_byte: recovered.unknown_token,
            }
        });
        let parsed_prefix_end = input
            .len()
            .saturating_sub(fallback.trailing_bytes.saturating_add(1));
        let prefix_has_semantics = !fallback.tokens.is_empty() && parsed_prefix_end <= offset;
        let prefix_value_bytes = fallback
            .parameter_value_bytes
            .iter()
            .chain(&fallback.row_value_bytes)
            .try_fold(0usize, |total, bytes| total.checked_add(*bytes));
        let recovered_value_bytes = recovered
            .parameter_value_bytes
            .iter()
            .chain(&recovered.row_value_bytes)
            .try_fold(0usize, |total, bytes| total.checked_add(*bytes));
        let combined_values_fit = prefix_value_bytes
            .zip(recovered_value_bytes)
            .and_then(|(left, right)| left.checked_add(right))
            .is_some_and(|total| total <= max_value_bytes);
        let unparsed_offset = if prefix_has_semantics && combined_values_fit {
            prepend_authentication_prefix(&mut recovered, fallback.clone());
            parsed_prefix_end
        } else {
            0
        };
        recovered.unparsed_regions.push(Tds5UnparsedRegion {
            offset: unparsed_offset,
            bytes: offset - unparsed_offset,
            first_byte: input.get(unparsed_offset).copied(),
        });
        recovered.unparsed_regions.extend(trailing_region);
        recovered.parse_warnings.push(first_error);
        recovered.parse_warnings.push(format!(
            "recovered TDS 5 authentication suffix after {offset} unparsed bytes"
        ));
        return recovered;
    }

    if fallback.unparsed_regions.is_empty() && !input.is_empty() {
        let offset = input
            .len()
            .saturating_sub(fallback.trailing_bytes.saturating_add(1));
        fallback.unparsed_regions.push(Tds5UnparsedRegion {
            offset,
            bytes: input.len() - offset,
            first_byte: input.get(offset).copied(),
        });
    }
    fallback.parse_warnings.push(first_error);
    fallback
}

fn is_authentication_msg_prefix(input: &[u8]) -> bool {
    let Some((&length, body)) = input.get(1).zip(input.get(2..)) else {
        return false;
    };
    let length = usize::from(length);
    if length < 3 || body.len() < length {
        return false;
    }
    let message_type = u16::from_le_bytes([body[1], body[2]]);
    is_published_message_type(message_type)
}

fn is_published_message_type(message_type: u16) -> bool {
    message_type_name(message_type) != "unknown"
}

fn prepend_authentication_prefix(
    target: &mut AuthenticationStream,
    mut prefix: AuthenticationStream,
) {
    prepend(&mut target.commands, &mut prefix.commands);
    prepend(&mut target.tokens, &mut prefix.tokens);
    prepend(&mut target.message_types, &mut prefix.message_types);
    prepend(
        &mut target.parameter_value_bytes,
        &mut prefix.parameter_value_bytes,
    );
    prepend(&mut target.parameter_values, &mut prefix.parameter_values);
    prepend(&mut target.row_value_bytes, &mut prefix.row_value_bytes);
    prepend(&mut target.row_values, &mut prefix.row_values);
    prepend(&mut target.alternate_formats, &mut prefix.alternate_formats);
    prepend(
        &mut target.encrypted_remote_passwords,
        &mut prefix.encrypted_remote_passwords,
    );
    prepend(&mut target.opaque_security, &mut prefix.opaque_security);
    prepend(
        &mut target.raw_parameter_values,
        &mut prefix.raw_parameter_values,
    );
    target.parameter_formats += prefix.parameter_formats;
    target.parameter_sets += prefix.parameter_sets;
    target.row_formats += prefix.row_formats;
    target.rows += prefix.rows;
    target.alternate_rows += prefix.alternate_rows;
    if prefix.encrypted_login_password.is_some() {
        target.encrypted_login_password_bytes = prefix.encrypted_login_password_bytes;
        target.encrypted_login_password = prefix.encrypted_login_password;
    }
    if prefix.encrypted_symmetric_key.is_some() {
        target.encrypted_symmetric_key_bytes = prefix.encrypted_symmetric_key_bytes;
        target.encrypted_symmetric_key = prefix.encrypted_symmetric_key;
    }
    prepend(&mut target.parse_warnings, &mut prefix.parse_warnings);
}

fn prepend<T>(target: &mut Vec<T>, prefix: &mut Vec<T>) {
    prefix.append(target);
    *target = std::mem::take(prefix);
}

fn parse_opaque_security(values: &[Vec<u8>]) -> Tds5OpaqueSecurity {
    let mut warnings = Vec::new();
    if values.len() != 5 {
        warnings.push(format!(
            "TDS 5 opaque security requires 5 parameters, received {}",
            values.len()
        ));
    }
    let security_version = values.first().and_then(|value| le_i32(value));
    let security_message_type = values.get(1).and_then(|value| le_i32(value));
    let mechanism_oid = values
        .get(2)
        .and_then(|value| match sspi::decode_der_oid_tlv(value) {
            Ok(oid) => Some(oid),
            Err(error) => {
                warnings.push(format!("invalid TDS 5 security mechanism OID: {error}"));
                None
            }
        });
    let authentication = values
        .get(3)
        .map_or_else(|| sspi::parse(&[]), |value| sspi::parse(value));
    warnings.extend(authentication.parse_warnings.iter().cloned());
    let security_flags = values
        .get(4)
        .and_then(|value| le_i32(value))
        .map(|value| value as u32);
    let security_message_name = match security_message_type {
        Some(1) => "security_session",
        Some(2) => "credential_forwarding",
        Some(3) => "packet_signature",
        Some(4) => "other",
        Some(_) => "unknown",
        None => "missing",
    };
    let security_services = security_flags
        .map(|flags| {
            [
                (0x001, "network_authentication"),
                (0x002, "mutual_authentication"),
                (0x004, "delegation"),
                (0x008, "integrity"),
                (0x010, "confidentiality"),
                (0x020, "replay_detection"),
                (0x040, "sequence_detection"),
                (0x080, "data_origin_authentication"),
                (0x100, "channel_binding"),
            ]
            .into_iter()
            .filter_map(|(bit, name)| (flags & bit != 0).then_some(name))
            .collect()
        })
        .unwrap_or_default();
    if security_version != Some(50) {
        warnings.push(format!(
            "unexpected TDS 5 opaque security version {security_version:?}"
        ));
    }
    if security_message_type != Some(1) {
        warnings.push(format!(
            "unexpected TDS 5 opaque security message type {security_message_type:?}"
        ));
    }
    Tds5OpaqueSecurity {
        security_version,
        security_message_type,
        security_message_name,
        mechanism_oid,
        authentication_token_bytes: authentication.bytes,
        authentication_token_family: authentication.family,
        authentication_mechanism_oids: authentication
            .der
            .as_ref()
            .map_or_else(Vec::new, |der| der.mechanism_oids.clone()),
        principal_hints: authentication
            .der
            .as_ref()
            .map_or_else(Vec::new, |der| der.text_values.clone()),
        security_flags,
        security_services,
        unknown_security_flags: security_flags.map(|flags| flags & !0x1ff),
        parse_warnings: warnings,
    }
}

fn le_i32(value: &[u8]) -> Option<i32> {
    (value.len() == 4).then(|| i32::from_le_bytes(value.try_into().expect("length checked")))
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
        let status = if wide_status {
            cursor.u32()?
        } else {
            u32::from(cursor.u8()?)
        };
        cursor.skip(4)?; // user type
        let ty = cursor.u8()?;
        let (max_length, encoding, blob_class_id) = parse_field_type(&mut cursor, ty)?;
        let locale_len = usize::from(cursor.u8()?);
        cursor.skip(locale_len)?;
        parameters.push(Parameter {
            name,
            column_label: None,
            catalogue: None,
            schema: None,
            table: None,
            compute_id: None,
            aggregate_operator: None,
            operand_column: None,
            status,
            ty,
            max_length,
            encoding,
            blob_class_id,
        });
    }
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 PARAMFMT bytes".into()));
    }
    Ok(parameters)
}

fn parse_row_format(input: &[u8], wide: bool) -> Result<Vec<Parameter>> {
    let mut cursor = Cursor { input, position: 0 };
    let count = cursor.u16()?;
    if count > 1024 {
        return Err(Error::Limit("TDS 5 row column count"));
    }
    let mut columns = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (column_label, catalogue, schema, table) = if wide {
            (
                Some(cursor.b_varbyte()?),
                Some(cursor.b_varbyte()?),
                Some(cursor.b_varbyte()?),
                Some(cursor.b_varbyte()?),
            )
        } else {
            (None, None, None, None)
        };
        let name = cursor.b_varbyte()?;
        let status = if wide {
            cursor.u32()?
        } else {
            u32::from(cursor.u8()?)
        };
        cursor.skip(4)?; // user type
        let ty = cursor.u8()?;
        let (max_length, encoding, blob_class_id) = parse_field_type(&mut cursor, ty)?;
        let locale_len = usize::from(cursor.u8()?);
        cursor.skip(locale_len)?;
        columns.push(Parameter {
            name,
            column_label,
            catalogue,
            schema,
            table,
            compute_id: None,
            aggregate_operator: None,
            operand_column: None,
            status,
            ty,
            max_length,
            encoding,
            blob_class_id,
        });
    }
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 ROWFMT bytes".into()));
    }
    Ok(columns)
}

fn parse_alternate_format(input: &[u8]) -> Result<(Tds5AlternateFormat, Vec<Parameter>)> {
    let mut cursor = Cursor { input, position: 0 };
    let compute_id = cursor.u16()?;
    let count = usize::from(cursor.u8()?);
    let mut columns = Vec::with_capacity(count);
    let mut operators = Vec::with_capacity(count);
    let mut operand_columns = Vec::with_capacity(count);
    for _ in 0..count {
        let operator_raw = cursor.u8()?;
        let operator = aggregate_operator_name(operator_raw);
        let operand_column = cursor.u8()?;
        cursor.skip(4)?; // user type
        let ty = cursor.u8()?;
        let (max_length, encoding, blob_class_id) = parse_field_type(&mut cursor, ty)?;
        let locale_len = usize::from(cursor.u8()?);
        cursor.skip(locale_len)?;
        operators.push(operator);
        operand_columns.push(operand_column);
        columns.push(Parameter {
            name: format!("{operator}(column_{operand_column})"),
            column_label: None,
            catalogue: None,
            schema: None,
            table: None,
            compute_id: Some(compute_id),
            aggregate_operator: Some(operator),
            operand_column: Some(operand_column),
            status: 0,
            ty,
            max_length,
            encoding,
            blob_class_id,
        });
    }
    let by_count = usize::from(cursor.u8()?);
    let by_columns = cursor.take(by_count)?.to_vec();
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 ALTFMT bytes".into()));
    }
    Ok((
        Tds5AlternateFormat {
            compute_id,
            columns: count,
            operators,
            operand_columns,
            by_columns,
        },
        columns,
    ))
}

fn aggregate_operator_name(operator: u8) -> &'static str {
    match operator {
        0x09 => "count_big",
        0x30 => "stdev",
        0x31 => "stdevp",
        0x32 => "var",
        0x33 => "varp",
        0x4b | 0x4c => "count",
        0x4d | 0x4e => "sum",
        0x4f | 0x50 => "avg",
        0x51 => "min",
        0x52 => "max",
        0x72 => "checksum_agg",
        _ => "unknown",
    }
}

fn parse_field_type(
    cursor: &mut Cursor<'_>,
    ty: u8,
) -> Result<(usize, ValueEncoding, Option<String>)> {
    let mut blob_class_id = None;
    let (max_length, encoding) = match ty {
        // Fixed-width Adaptive Server types. Some IDs overlap Microsoft TDS 7
        // types, so this table deliberately remains TDS-5-specific.
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
        // Classic LOB metadata adds a USHORT table-name field. Values carry a
        // text pointer, timestamp, and 32-bit data length.
        0x22 | 0x23 | 0xa3 | 0xae => {
            let max =
                usize::try_from(cursor.u32()?).map_err(|_| Error::Limit("TDS 5 LOB parameter"))?;
            let table_name_bytes = usize::from(cursor.u16()?);
            cursor.skip(table_name_bytes)?;
            (max, ValueEncoding::Lob)
        }
        // ASE BLOB metadata carries a one-byte declared length followed by a
        // blob kind. Java object kinds add a USHORT class identifier.
        0x24 => {
            let _declared_length = cursor.u8()?;
            let blob_type = cursor.u8()?;
            if !(1..=8).contains(&blob_type) {
                return Err(Error::Protocol(format!(
                    "invalid TDS 5 BLOB type {blob_type}"
                )));
            }
            blob_class_id = if matches!(blob_type, 1 | 2) {
                let length = usize::from(cursor.u16()?);
                Some(String::from_utf8_lossy(cursor.take(length)?).into_owned())
            } else {
                None
            };
            (usize::MAX, ValueEncoding::Blob(blob_type))
        }
        _ => {
            return Err(Error::Protocol(format!(
                "unknown TDS 5 parameter type 0x{ty:02x}"
            )));
        }
    };
    Ok((max_length, encoding, blob_class_id))
}

fn parse_dbrpc(input: &[u8], wide: bool) -> Result<Tds5Command> {
    let name = if wide {
        // DBRPC2 widens the token body, but clients in the field disagree on
        // whether the procedure-name prefix is widened with it. Select only a
        // layout that consumes the complete body (including the two flags
        // bytes), so a guessed prefix can never shift the following token.
        parse_exact_dbrpc2_name(input)?
    } else {
        let mut cursor = Cursor { input, position: 0 };
        let name = cursor.b_varbyte()?;
        cursor.skip(2)?; // flags
        if !cursor.done() {
            return Err(Error::Protocol("trailing TDS 5 DBRPC bytes".into()));
        }
        name
    };
    Ok(Tds5Command {
        token: 0xe6,
        name: "dbrpc",
        body_bytes: input.len(),
        operation: None,
        identifier: Some(name),
        text: None,
        cursor_id: None,
        status_or_options: None,
        secondary_status: None,
        table_name: None,
        row_number: None,
        total_rows: None,
        row_count: None,
        option_code: None,
        option_argument: None,
    })
}

fn parse_exact_dbrpc2_name(input: &[u8]) -> Result<String> {
    fn candidate(input: &[u8], prefix: usize, length: usize) -> Option<String> {
        (prefix.checked_add(length)?.checked_add(2)? == input.len())
            .then(|| String::from_utf8_lossy(&input[prefix..prefix + length]).into_owned())
    }

    if let Some(length) = input.first().copied().map(usize::from) {
        if let Some(name) = candidate(input, 1, length) {
            return Ok(name);
        }
    }
    if input.len() >= 2 {
        let length = usize::from(u16::from_le_bytes([input[0], input[1]]));
        if let Some(name) = candidate(input, 2, length) {
            return Ok(name);
        }
    }
    if input.len() >= 4 {
        let length = usize::try_from(u32::from_le_bytes(input[..4].try_into().expect("checked")))
            .map_err(|_| Error::Limit("TDS 5 DBRPC2 procedure name"))?;
        if let Some(name) = candidate(input, 4, length) {
            return Ok(name);
        }
    }
    Err(Error::Protocol(
        "TDS 5 DBRPC2 procedure name has no exact length framing".into(),
    ))
}

fn parse_dynamic(input: &[u8], wide: bool) -> Result<Tds5Command> {
    let mut cursor = Cursor { input, position: 0 };
    let operation = cursor.u8()?;
    let _status = cursor.u8()?;
    let identifier = cursor.b_varbyte()?;
    let text = if cursor.done() {
        None
    } else {
        Some(if wide {
            cursor.ul_varbyte_string()?
        } else {
            cursor.us_varbyte_string()?
        })
    };
    if !cursor.done() {
        return Err(Error::Protocol("trailing TDS 5 DYNAMIC bytes".into()));
    }
    Ok(Tds5Command {
        token: 0xe7,
        name: "dynamic",
        body_bytes: input.len(),
        operation: Some(match operation {
            0 => "invalid",
            1 => "prepare",
            2 => "execute",
            4 => "deallocate",
            8 => "execute_immediate",
            16 => "procedure_name",
            32 => "acknowledge",
            64 => "describe_input",
            128 => "describe_output",
            _ => "unknown",
        }),
        identifier: Some(identifier),
        text,
        cursor_id: None,
        status_or_options: None,
        secondary_status: None,
        table_name: None,
        row_number: None,
        total_rows: None,
        row_count: None,
        option_code: None,
        option_argument: None,
    })
}

fn parse_cursor_declare(token: u8, input: &[u8], wide: bool) -> Result<Tds5Command> {
    let mut cursor = Cursor { input, position: 0 };
    let identifier = cursor.b_varbyte()?;
    let options = if wide {
        cursor.u32()?
    } else {
        u32::from(cursor.u8()?)
    };
    let status = u32::from(cursor.u8()?);
    let text = if wide {
        cursor.ul_varbyte_string()?
    } else {
        cursor.us_varbyte_string()?
    };
    let column_count = usize::from(cursor.u16()?);
    if column_count > 1024 {
        return Err(Error::Limit("TDS 5 cursor update column count"));
    }
    for _ in 0..column_count {
        let _ = cursor.b_varbyte()?;
    }
    if !cursor.done() {
        return Err(Error::Protocol(
            "trailing TDS 5 cursor declaration bytes".into(),
        ));
    }
    Ok(Tds5Command {
        token,
        name: if wide {
            "cursor_declare3"
        } else {
            "cursor_declare"
        },
        body_bytes: input.len(),
        operation: None,
        identifier: Some(identifier),
        text: Some(text),
        cursor_id: None,
        status_or_options: Some(options),
        secondary_status: Some(status),
        table_name: None,
        row_number: None,
        total_rows: None,
        row_count: None,
        option_code: None,
        option_argument: None,
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
            0x85 => "cursor_update",
            0x86 => "cursor_declare",
            0x87 => "cursor_info2",
            0x88 => "cursor_info3",
            0xa6 => "option_command",
            _ => "unknown",
        },
        body_bytes: input.len(),
        operation: None,
        identifier: None,
        text: None,
        cursor_id: None,
        status_or_options: None,
        secondary_status: None,
        table_name: None,
        row_number: None,
        total_rows: None,
        row_count: None,
        option_code: None,
        option_argument: None,
    };
    if token == 0x87 {
        // CURINFO2 is self-framed by the token's USHORT body length, but its
        // payload layout is not published with the other cursor structures.
        return Ok(command);
    }
    if token == 0xa6 {
        let mut cursor = Cursor { input, position: 0 };
        let operation = cursor.u8()?;
        let option = cursor.u8()?;
        let argument_length = usize::from(cursor.u8()?);
        let argument = cursor.take(argument_length)?;
        if !cursor.done() {
            return Err(Error::Protocol("trailing TDS 5 OPTIONCMD bytes".into()));
        }
        command.operation = Some(match operation {
            1 => "set",
            2 => "default",
            3 => "list",
            4 => "info",
            _ => "unknown",
        });
        command.option_code = Some(option);
        command.option_argument = Some(String::from_utf8_lossy(argument).into_owned());
        return Ok(command);
    }

    let mut cursor = Cursor { input, position: 0 };
    let cursor_id = cursor.u32()? as i32;
    command.cursor_id = Some(cursor_id);
    if cursor_id == 0 {
        command.identifier = Some(cursor.b_varbyte()?);
    }
    match token {
        0x80 => command.status_or_options = Some(u32::from(cursor.u8()?)),
        0x81 => {
            command.status_or_options = Some(u32::from(cursor.u8()?));
            command.table_name = Some(cursor.b_varbyte()?);
        }
        0x82 => {
            let fetch_type = cursor.u8()?;
            command.operation = Some(match fetch_type {
                1 => "next",
                2 => "previous",
                3 => "first",
                4 => "last",
                5 => "absolute",
                6 => "relative",
                _ => "unknown",
            });
            if matches!(fetch_type, 5 | 6) {
                command.row_number = Some(cursor.u32()? as i32);
            }
        }
        0x83 => {
            command.operation = Some(cursor_command_name(cursor.u8()?));
            let status = u32::from(cursor.u16()?);
            command.status_or_options = Some(status);
            if status & 0x20 != 0 {
                command.row_count = Some(cursor.u32()? as i32);
            }
        }
        0x84 => command.status_or_options = Some(u32::from(cursor.u8()?)),
        0x85 => {
            command.status_or_options = Some(u32::from(cursor.u8()?));
            command.table_name = Some(cursor.b_varbyte()?);
            command.text = Some(cursor.us_varbyte_string()?);
        }
        0x88 => {
            command.operation = Some(cursor_command_name(cursor.u8()?));
            let status = cursor.u32()?;
            command.status_or_options = Some(status);
            command.row_number = Some(cursor.u32()? as i32);
            command.total_rows = Some(cursor.u32()? as i32);
            if status & 0x20 != 0 {
                command.row_count = Some(cursor.u32()? as i32);
            }
        }
        _ => {}
    }
    if !cursor.done() {
        return Err(Error::Protocol(format!(
            "trailing TDS 5 {} bytes",
            command.name
        )));
    }
    Ok(command)
}

fn cursor_command_name(command: u8) -> &'static str {
    match command {
        1 => "set_cursor_rows",
        2 => "inquire",
        3 => "inform",
        4 => "list_all",
        _ => "unknown",
    }
}

fn summarize_value(
    ty: u8,
    encoding: ValueEncoding,
    blob_serialization: Option<u8>,
    value: &[u8],
) -> String {
    if let ValueEncoding::Blob(blob_type) = encoding {
        return match (blob_type, blob_serialization) {
            (3, Some(0)) | (5, Some(1)) => String::from_utf8_lossy(value).into_owned(),
            (5, Some(0)) if value.len() % 2 == 0 => crate::tds::data::decode_utf16(value)
                .unwrap_or_else(|_| format!("<binary:{} bytes>", value.len())),
            _ => format!("<binary:{} bytes>", value.len()),
        };
    }
    match ty {
        0x23 | 0x27 | 0x2f | 0x67 | 0xa3 | 0xaf => String::from_utf8_lossy(value).into_owned(),
        0xae if value.len() % 2 == 0 => crate::tds::data::decode_utf16(value)
            .unwrap_or_else(|_| format!("<binary:{} bytes>", value.len())),
        0x30 | 0x40 if value.len() == 1 => value[0].to_string(),
        0xb0 if value.len() == 1 => i8::from_le_bytes([value[0]]).to_string(),
        0x34 | 0x26 if value.len() == 2 => {
            i16::from_le_bytes(value.try_into().expect("length checked")).to_string()
        }
        0x38 | 0x26 if value.len() == 4 => {
            i32::from_le_bytes(value.try_into().expect("length checked")).to_string()
        }
        0xbf | 0x26 if value.len() == 8 => {
            i64::from_le_bytes(value.try_into().expect("length checked")).to_string()
        }
        0x26 if value.len() == 1 => i8::from_le_bytes([value[0]]).to_string(),
        0x41 | 0x44 if value.len() == 2 => {
            u16::from_le_bytes(value.try_into().expect("length checked")).to_string()
        }
        0x42 | 0x44 if value.len() == 4 => {
            u32::from_le_bytes(value.try_into().expect("length checked")).to_string()
        }
        0x43 | 0x44 if value.len() == 8 => {
            u64::from_le_bytes(value.try_into().expect("length checked")).to_string()
        }
        0x44 if value.len() == 1 => value[0].to_string(),
        _ => format!("<binary:{} bytes>", value.len()),
    }
}

fn read_parameter_value(
    cursor: &mut Cursor<'_>,
    parameter: &Parameter,
    remaining_limit: usize,
) -> Result<ParsedParameterValue> {
    if let ValueEncoding::Blob(blob_type) = parameter.encoding {
        return read_blob_value(cursor, blob_type, remaining_limit);
    }
    let len = value_length(cursor, parameter)?;
    if len > remaining_limit {
        return Err(Error::Limit("TDS 5 authentication bytes"));
    }
    Ok(ParsedParameterValue {
        bytes: cursor.take(len)?.to_vec(),
        blob_serialization: None,
        blob_subclass_or_locator: None,
        blob_chunks: None,
    })
}

fn read_blob_value(
    cursor: &mut Cursor<'_>,
    blob_type: u8,
    remaining_limit: usize,
) -> Result<ParsedParameterValue> {
    let serialization = cursor.u8()?;
    if serialization > 2 || (serialization != 0 && blob_type != 5) {
        return Err(Error::Protocol(format!(
            "invalid TDS 5 BLOB serialization {serialization} for type {blob_type}"
        )));
    }
    let subclass_or_locator = if matches!(blob_type, 1 | 2 | 6 | 7 | 8) {
        let length = usize::from(cursor.u16()?);
        Some(String::from_utf8_lossy(cursor.take(length)?).into_owned())
    } else {
        None
    };

    let mut bytes = Vec::new();
    let mut chunks = 0usize;
    loop {
        let framed_length = cursor.u32()?;
        let final_chunk = framed_length & 0x8000_0000 != 0;
        let length = usize::try_from(framed_length & 0x7fff_ffff)
            .map_err(|_| Error::Limit("TDS 5 BLOB chunk"))?;
        let total = bytes
            .len()
            .checked_add(length)
            .ok_or(Error::Limit("TDS 5 BLOB bytes"))?;
        if total > remaining_limit {
            return Err(Error::Limit("TDS 5 authentication bytes"));
        }
        bytes.extend_from_slice(cursor.take(length)?);
        chunks += 1;
        if chunks > 4096 {
            return Err(Error::Limit("TDS 5 BLOB chunk count"));
        }
        if final_chunk {
            break;
        }
    }

    Ok(ParsedParameterValue {
        bytes,
        blob_serialization: Some(serialization),
        blob_subclass_or_locator: subclass_or_locator,
        blob_chunks: Some(chunks),
    })
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
        ValueEncoding::Blob(_) => unreachable!("BLOB values use read_blob_value"),
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
        24 => "hello",
        25 => "login_parameters",
        26 => "grid_migration_request",
        27 => "grid_quiesce",
        28 => "grid_unquiesce",
        29 => "grid_event",
        30 => "secure_encryption_v3",
        31 => "encrypted_login_password_v3",
        32 => "encrypted_remote_password_v3",
        33 => "disaster_recovery_map",
        34 => "secure_symmetric_key",
        35 => "secure_encryption_v4",
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
    fn ul_varbyte_string(&mut self) -> Result<String> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::Limit("TDS 5 UL_VARBYTE"))?;
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rsa::{
        OaepPublicEncryptingKey, PublicEncryptingKey, PublicKey, PublicKeyComponents,
    };

    fn encrypt_oaep_pem(pem: &str, pkcs1: bool, plaintext: &[u8]) -> Vec<u8> {
        let encoded = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let der = BASE64.decode(encoded).unwrap();
        let public = if pkcs1 {
            let parsed = PublicKey::from_der(&der).unwrap();
            let components = PublicKeyComponents::from(&parsed);
            components.try_into().unwrap()
        } else {
            PublicEncryptingKey::from_der(&der).unwrap()
        };
        let public = OaepPublicEncryptingKey::new(public).unwrap();
        let mut ciphertext = vec![0_u8; public.ciphertext_size()];
        public
            .encrypt(&OAEP_SHA1_MGF1SHA1, plaintext, &mut ciphertext, None)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn every_published_ase_parameter_type_has_a_format_fixture() {
        let fixed = [
            0x1f, 0x30, 0x32, 0x40, 0xb0, 0x34, 0x41, 0x31, 0x33, 0x38, 0x3a, 0x3b, 0x42, 0x7a,
            0x2e, 0x3c, 0x3d, 0x3e, 0x43, 0x7f, 0xbf,
        ];
        for ty in fixed {
            let mut format = vec![1, 0, 0, 0]; // count, name, status
            format.extend_from_slice(&0_u32.to_le_bytes());
            format.extend_from_slice(&[ty, 0]); // type, locale
            assert_eq!(
                parse_parameter_format(&format, false).unwrap()[0].ty,
                ty,
                "type 0x{ty:02x}"
            );
        }

        let mut cases: Vec<(u8, Vec<u8>)> = vec![
            (0x6a, vec![17, 38, 10, 0]),
            (0x6c, vec![17, 38, 10, 0]),
            (0xbb, vec![8, 6, 0]),
            (0xbc, vec![8, 6, 0]),
            (0x25, vec![8, 0]),
            (0x26, vec![8, 0]),
            (0x27, vec![8, 0]),
            (0x2d, vec![8, 0]),
            (0x2f, vec![8, 0]),
            (0x44, vec![8, 0]),
            (0x67, vec![8, 0]),
            (0x68, vec![8, 0]),
            (0x6d, vec![8, 0]),
            (0x6e, vec![8, 0]),
            (0x6f, vec![8, 0]),
            (0x7b, vec![4, 0]),
            (0x93, vec![4, 0]),
            (0xaf, [32_u32.to_le_bytes().as_slice(), &[0]].concat()),
            (0xe1, [32_u32.to_le_bytes().as_slice(), &[0]].concat()),
            (0x24, vec![0xff, 3, 0]),
        ];
        for ty in [0x22, 0x23, 0xa3, 0xae] {
            let mut metadata = 64_u32.to_le_bytes().to_vec();
            metadata.extend_from_slice(&0_u16.to_le_bytes());
            metadata.push(0);
            cases.push((ty, metadata));
        }
        for (ty, metadata) in cases {
            let mut format = vec![1, 0, 0]; // count, name
            format.push(0); // status
            format.extend_from_slice(&0_u32.to_le_bytes());
            format.push(ty);
            format.extend_from_slice(&metadata);
            assert_eq!(
                parse_parameter_format(&format, false).unwrap()[0].ty,
                ty,
                "type 0x{ty:02x}"
            );
        }
    }

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
    fn parses_rowfmt_rows_and_following_auth_without_losing_boundaries() {
        let mut row_format = 2_u16.to_le_bytes().to_vec();
        row_format.extend_from_slice(&[4]);
        row_format.extend_from_slice(b"user");
        row_format.extend_from_slice(&[0]); // status
        row_format.extend_from_slice(&0_i32.to_le_bytes()); // user type
        row_format.extend_from_slice(&[0x27, 32, 0]); // VARCHAR(32), locale
        row_format.extend_from_slice(&[7]);
        row_format.extend_from_slice(b"attempt");
        row_format.extend_from_slice(&[0x08]); // column-status byte precedes value
        row_format.extend_from_slice(&0_i32.to_le_bytes());
        row_format.extend_from_slice(&[0x26, 4, 0]); // INTN(4), locale

        let mut raw = vec![0xee];
        raw.extend_from_slice(&(row_format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&row_format);
        raw.push(0xd1);
        raw.extend_from_slice(&[5]);
        raw.extend_from_slice(b"alice");
        raw.extend_from_slice(&[0, 4]); // data status, length
        raw.extend_from_slice(&2_i32.to_le_bytes());

        let encrypted = [0x55; 32];
        raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        raw.extend_from_slice(&encrypted);

        let parsed = parse_authentication(&raw, 4096).unwrap();
        assert_eq!(parsed.row_formats, 1);
        assert_eq!(parsed.rows, 1);
        assert_eq!(parsed.row_value_bytes, [5, 4]);
        assert_eq!(parsed.row_values[0].name, "user");
        assert_eq!(parsed.row_values[0].value, "alice");
        assert_eq!(parsed.row_values[1].data_status, Some(0));
        assert_eq!(parsed.row_values[1].value, "2");
        assert_eq!(parsed.encrypted_login_password_bytes, Some(32));
        assert!(parsed.unknown_token.is_none());
    }

    #[test]
    fn parses_wide_rowfmt2_source_metadata_and_row() {
        let mut row_format = 1_u16.to_le_bytes().to_vec();
        for value in ["display", "finance", "dbo", "accounts", "balance"] {
            row_format.push(value.len() as u8);
            row_format.extend_from_slice(value.as_bytes());
        }
        row_format.extend_from_slice(&0x20_u32.to_le_bytes());
        row_format.extend_from_slice(&17_i32.to_le_bytes());
        row_format.extend_from_slice(&[0x27, 32, 0]);

        let mut raw = vec![0x61];
        raw.extend_from_slice(&(row_format.len() as u32).to_le_bytes());
        raw.extend_from_slice(&row_format);
        raw.extend_from_slice(&[0xd1, 6]);
        raw.extend_from_slice(b"125.50");

        let parsed = parse_authentication(&raw, 4096).unwrap();
        assert_eq!(parsed.row_formats, 1);
        assert_eq!(parsed.rows, 1);
        let value = &parsed.row_values[0];
        assert_eq!(value.name, "balance");
        assert_eq!(value.column_label.as_deref(), Some("display"));
        assert_eq!(value.catalogue.as_deref(), Some("finance"));
        assert_eq!(value.schema.as_deref(), Some("dbo"));
        assert_eq!(value.table.as_deref(), Some("accounts"));
        assert_eq!(value.value, "125.50");
    }

    #[test]
    fn parses_alternate_format_and_compute_row_without_shifting_auth() {
        let mut alternate_format = 7_u16.to_le_bytes().to_vec();
        alternate_format.push(1); // one aggregate column
        alternate_format.extend_from_slice(&[0x4d, 2]); // SUM(column 2)
        alternate_format.extend_from_slice(&0_i32.to_le_bytes());
        alternate_format.extend_from_slice(&[0x38, 0]); // INT4, empty locale
        alternate_format.extend_from_slice(&[1, 2]); // BY column count and index

        let mut raw = vec![0xa8];
        raw.extend_from_slice(&(alternate_format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&alternate_format);
        raw.push(0xd3);
        raw.extend_from_slice(&7_u16.to_le_bytes());
        raw.extend_from_slice(&99_i32.to_le_bytes());

        let encrypted = [0x77; 24];
        raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        raw.extend_from_slice(&encrypted);

        let parsed = parse_authentication(&raw, 4096).unwrap();
        assert_eq!(parsed.alternate_formats.len(), 1);
        assert_eq!(parsed.alternate_formats[0].compute_id, 7);
        assert_eq!(parsed.alternate_formats[0].operators, ["sum"]);
        assert_eq!(parsed.alternate_formats[0].by_columns, [2]);
        assert_eq!(parsed.alternate_rows, 1);
        assert_eq!(parsed.row_values[0].compute_id, Some(7));
        assert_eq!(parsed.row_values[0].aggregate_operator, Some("sum"));
        assert_eq!(parsed.row_values[0].operand_column, Some(2));
        assert_eq!(parsed.row_values[0].value, "99");
        assert_eq!(parsed.encrypted_login_password_bytes, Some(24));
        assert!(parsed.unknown_token.is_none());
    }

    #[test]
    fn parses_request_response_and_vendor_capability_sections() {
        let parsed =
            parse_capabilities(&[1, 2, 0xaa, 0xbb, 2, 1, 0xcc, 3, 1, 0x81, 9, 1, 0xdd]).unwrap();
        assert_eq!(parsed.request, [0xaa, 0xbb]);
        assert_eq!(parsed.request_enabled, [0, 1, 3, 4, 5, 7, 9, 11, 13, 15]);
        assert_eq!(parsed.response, [0xcc]);
        assert_eq!(parsed.response_enabled, [2, 3, 6, 7]);
        assert_eq!(parsed.security, [0x81]);
        assert_eq!(parsed.security_enabled, [0, 7]);
        assert_eq!(parsed.unknown_sections[0].section_type, 9);
        assert_eq!(parsed.unknown_sections[0].bytes, [0xdd]);
        assert!(parse_capabilities(&[1, 4, 0xaa]).is_err());
    }

    #[test]
    fn inventories_all_tds5_login_security_modes_without_hiding_reserved_bits() {
        assert_eq!(
            login_security_modes(0xbf),
            [
                "encrypted_login_v1",
                "challenge_response",
                "security_labels",
                "application_defined_security",
                "secure_session",
                "encrypted_login_v2",
                "encrypted_login_v3_or_v4",
            ]
        );
        assert!(login_security_modes(0x40).is_empty());
    }

    #[test]
    fn every_published_ase_tds5_token_has_a_boundary_fixture() {
        for &token in PUBLISHED_TDS5_TOKEN_IDS {
            let raw = minimal_token_fixture(token);
            let parsed = parse_authentication(&raw, 4096)
                .unwrap_or_else(|error| panic!("token 0x{token:02x}: {error}"));
            assert_eq!(parsed.unknown_token, None, "token 0x{token:02x}");
            assert_eq!(parsed.trailing_bytes, 0, "token 0x{token:02x}");
        }
    }

    #[test]
    fn every_published_tds5_message_type_is_named_and_recoverable() {
        for message_type in 1..=35 {
            assert_ne!(message_type_name(message_type), "unknown");
            assert!(is_published_message_type(message_type));
        }
        assert_eq!(message_type_name(0), "unknown");
        assert_eq!(message_type_name(36), "unknown");
        assert!(!is_published_message_type(0));
        assert!(!is_published_message_type(36));
    }

    fn minimal_token_fixture(token: u8) -> Vec<u8> {
        match token {
            0x10 => {
                let body = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                [
                    vec![token],
                    (body.len() as u32).to_le_bytes().to_vec(),
                    body.to_vec(),
                ]
                .concat()
            }
            0x20 => [vec![token], 2_u32.to_le_bytes().to_vec(), vec![0, 0]].concat(),
            0x21 => [vec![token], 1_u32.to_le_bytes().to_vec(), vec![0]].concat(),
            0x22 => [vec![token], 0_u32.to_le_bytes().to_vec()].concat(),
            0x61 => [vec![token], 2_u32.to_le_bytes().to_vec(), vec![0, 0]].concat(),
            0x62 | 0xa3 => [vec![token], 3_u32.to_le_bytes().to_vec(), vec![1, 0, 0]].concat(),
            0x65 => vec![token, 3, 0, 13, 0],
            0x71 => vec![token, 0],
            0x78 | 0x79 => vec![token, 0, 0, 0, 0],
            0x7c => vec![token, 0, 0, 0, 0, 0, 0, 0, 0],
            0x80 => vec![token, 5, 0, 1, 0, 0, 0, 0],
            0x81 => vec![token, 6, 0, 1, 0, 0, 0, 0, 0],
            0x82 => vec![token, 5, 0, 1, 0, 0, 0, 1],
            0x83 => vec![token, 7, 0, 1, 0, 0, 0, 2, 0, 0],
            0x84 => vec![token, 5, 0, 1, 0, 0, 0, 0],
            0x85 => vec![token, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            0x86 => {
                let body = [0, 0, 0, 0, 0, 0, 0];
                [
                    vec![token],
                    (body.len() as u16).to_le_bytes().to_vec(),
                    body.to_vec(),
                ]
                .concat()
            }
            0x88 => vec![
                token, 17, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            0xa6 => vec![token, 3, 0, 1, 1, 0],
            0xa8 => {
                let body = [1, 0, 0, 0]; // compute id, zero columns, zero BY columns
                [
                    vec![token],
                    (body.len() as u16).to_le_bytes().to_vec(),
                    body.to_vec(),
                ]
                .concat()
            }
            0xd1 => vec![0xee, 11, 0, 1, 0, 1, b'x', 0, 0, 0, 0, 0, 0x1f, 0, 0xd1],
            0xd3 => vec![
                0xa8, 12, 0, 1, 0, 1, 0x4b, 0, 0, 0, 0, 0, 0x1f, 0, 0, 0xd3, 1, 0,
            ],
            0xd7 => vec![0xec, 11, 0, 1, 0, 1, b'p', 0, 0, 0, 0, 0, 0x1f, 0, 0xd7],
            0xe6 | 0xe8 => {
                let length = if token == 0xe6 {
                    3_u16.to_le_bytes().to_vec()
                } else {
                    3_u32.to_le_bytes().to_vec()
                };
                [vec![token], length, vec![0, 0, 0]].concat()
            }
            0xe7 => vec![token, 3, 0, 1, 0, 0],
            0xec | 0xee => vec![token, 2, 0, 0, 0],
            0xfd..=0xff => vec![token, 0, 0, 0, 0, 0, 0, 0, 0],
            // All remaining published tokens carry a USHORT-sized body. The
            // parser deliberately inventories the exact framing even where
            // the token is server-oriented and has no inbound semantics.
            _ => vec![token, 0, 0],
        }
    }

    #[test]
    fn emits_the_extended_v2_rsa_oaep_challenge() {
        let key = secure_login_key().unwrap();
        let challenge = key.challenge(14).unwrap();
        let parsed = parse_authentication(&challenge, 64 * 1024).unwrap();
        assert_eq!(parsed.message_types[0].message_type, 14);
        assert_eq!(parsed.message_types[0].name, "secure_encryption_v2");
        assert_eq!(parsed.parameter_values[0].value, "1");
        assert!(parsed.parameter_values[1].bytes > 256);
        assert!(key.challenge(15).is_err());
    }

    #[test]
    fn emits_the_published_v1_varbinary_challenge_without_claiming_a_cipher() {
        let key = [0x5a; 16];
        let challenge = proprietary_login_challenge(&key).unwrap();
        let parsed = parse_authentication(&challenge, 1024).unwrap();

        assert_eq!(parsed.message_types[0].message_type, 1);
        assert_eq!(parsed.message_types[0].name, "secure_encryption");
        assert_eq!(parsed.parameter_formats, 1);
        assert_eq!(parsed.parameter_sets, 1);
        assert_eq!(parsed.parameter_values[0].type_id, 0x25);
        assert_eq!(parsed.parameter_values[0].format_status, 0x08);
        assert_eq!(parsed.parameter_values[0].data_status, Some(0));
        assert_eq!(parsed.parameter_value(0), Some(key.as_slice()));
        assert!(proprietary_login_challenge(&[]).is_err());
        assert!(proprietary_login_challenge(&[0; 256]).is_err());
    }

    #[test]
    fn non_nonce_secure_login_keys_are_unique_per_attempt() {
        let first = secure_login_key().unwrap();
        let second = secure_login_key().unwrap();
        assert_ne!(first.public_pem, second.public_pem);
    }

    #[test]
    fn nonce_bound_secure_login_key_is_reused() {
        let first = shared_secure_login_key().unwrap();
        let second = shared_secure_login_key().unwrap();
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn emits_and_decrypts_nonce_bearing_epep_challenge() {
        let key = secure_login_key().unwrap();
        let (challenge, nonce) = key.challenge_with_nonce(30).unwrap();
        let parsed = parse_authentication(&challenge, 64 * 1024).unwrap();
        assert_eq!(parsed.message_types[0].message_type, 30);
        assert_eq!(parsed.parameter_value_bytes.len(), 3);
        assert_eq!(parsed.parameter_value_bytes[2], 32);

        let plaintext = [nonce.as_slice(), b"spring2027"].concat();
        let encrypted = encrypt_oaep_pem(&key.public_pkcs1_pem, true, &plaintext);
        assert_eq!(
            key.decrypt_password_with_nonce(&encrypted, &nonce).unwrap(),
            "spring2027"
        );
        assert_eq!(
            parse_authentication(&key.challenge_with_nonce(35).unwrap().0, 64 * 1024)
                .unwrap()
                .message_types[0]
                .message_type,
            35
        );
        assert!(key.challenge_with_nonce(14).is_err());
    }

    #[test]
    fn detects_epep_command_encryption_capability() {
        let mut capabilities = Capabilities {
            request: vec![0; 14],
            ..Capabilities::default()
        };
        capabilities.request[0] = 0x04; // capability 106 in reversed ASE bitmap order
        assert!(capabilities.supports_command_encryption());
        capabilities.request[0] = 0;
        assert!(!capabilities.supports_command_encryption());
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
        assert_eq!(parsed.tokens.len(), 5);
    }

    #[test]
    fn parses_wide_dynamic_cursor_and_framed_tokens_without_losing_following_auth() {
        let mut raw = vec![0x62];
        let mut dynamic = vec![8, 0, 1, b'q'];
        dynamic.extend_from_slice(&8_u32.to_le_bytes());
        dynamic.extend_from_slice(b"SELECT 1");
        raw.extend_from_slice(&(dynamic.len() as u32).to_le_bytes());
        raw.extend_from_slice(&dynamic);

        raw.push(0x10);
        let mut cursor = vec![1, b'c'];
        cursor.extend_from_slice(&0x100_u32.to_le_bytes());
        cursor.push(0);
        cursor.extend_from_slice(&8_u32.to_le_bytes());
        cursor.extend_from_slice(b"SELECT 2");
        cursor.extend_from_slice(&0_u16.to_le_bytes());
        raw.extend_from_slice(&(cursor.len() as u32).to_le_bytes());
        raw.extend_from_slice(&cursor);

        raw.extend_from_slice(&[0xa2, 3, 0, 1, 2, 3]);
        raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&4_u32.to_le_bytes());
        raw.extend_from_slice(&[1, 2, 3, 4]);

        let parsed = parse_authentication(&raw, 4096).unwrap();
        assert_eq!(parsed.commands[0].name, "dynamic2");
        assert_eq!(parsed.commands[0].operation, Some("execute_immediate"));
        assert_eq!(parsed.commands[0].text.as_deref(), Some("SELECT 1"));
        assert_eq!(parsed.commands[1].identifier.as_deref(), Some("c"));
        assert_eq!(parsed.commands[1].text.as_deref(), Some("SELECT 2"));
        assert_eq!(parsed.commands[2].name, "event_notice");
        assert_eq!(parsed.encrypted_login_password_bytes, Some(4));
        assert!(parsed.unknown_token.is_none());
    }

    #[test]
    fn accepts_both_published_dynamic2_token_assignments() {
        for token in [0x62, 0xa3] {
            let mut body = vec![8, 0, 1, b'q'];
            body.extend_from_slice(&8_u32.to_le_bytes());
            body.extend_from_slice(b"SELECT 1");
            let mut raw = vec![token];
            raw.extend_from_slice(&(body.len() as u32).to_le_bytes());
            raw.extend_from_slice(&body);
            raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
            raw.extend_from_slice(&[
                0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
            ]);
            raw.extend_from_slice(&[0xd7, 4, 0, 0, 0, 1, 2, 3, 4]);

            let parsed = parse_authentication(&raw, 4096).unwrap();
            assert_eq!(parsed.commands[0].name, "dynamic2");
            assert_eq!(parsed.commands[0].text.as_deref(), Some("SELECT 1"));
            assert_eq!(parsed.encrypted_login_password_bytes, Some(4));
            assert!(parsed.unknown_token.is_none());
        }
    }

    #[test]
    fn dbrpc2_accepts_exact_name_prefix_variants_without_shifting_auth() {
        for (prefix, name) in [
            (vec![2], "sp"),
            (2_u16.to_le_bytes().to_vec(), "sp"),
            (2_u32.to_le_bytes().to_vec(), "sp"),
        ] {
            let mut body = prefix;
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&0_u16.to_le_bytes());
            let mut raw = vec![0xe8];
            raw.extend_from_slice(&(body.len() as u32).to_le_bytes());
            raw.extend_from_slice(&body);
            raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
            raw.extend_from_slice(&[
                0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
            ]);
            raw.push(0xd7);
            raw.extend_from_slice(&4_u32.to_le_bytes());
            raw.extend_from_slice(&[1, 2, 3, 4]);

            let parsed = parse_authentication(&raw, 4096).unwrap();
            assert_eq!(parsed.commands[0].identifier.as_deref(), Some(name));
            assert_eq!(parsed.encrypted_login_password_bytes, Some(4));
            assert!(parsed.unknown_token.is_none());
        }
    }

    #[test]
    fn recovers_authentication_after_an_unrecognized_prefix() {
        let encrypted = [0x55; 32];
        let mut raw = vec![0x19, 0xde, 0xad, 0xbe, 0xef];
        raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        raw.extend_from_slice(&encrypted);

        let parsed = parse_for_telemetry(&raw, 1024);
        assert_eq!(parsed.encrypted_login_password_bytes, Some(32));
        assert_eq!(parsed.message_types[0].message_type, 31);
        assert_eq!(parsed.unparsed_regions[0].bytes, 5);
        assert!(parsed.parse_warnings[1].contains("recovered"));
    }

    #[test]
    fn recovery_retains_valid_semantic_prefix_around_unknown_region() {
        let mut raw = vec![0x21];
        raw.extend_from_slice(&9_u32.to_le_bytes());
        raw.extend_from_slice(b"\0SELECT 1");
        let unknown_offset = raw.len();
        raw.extend_from_slice(&[0x99, 0x98, 0x97]);

        let encrypted = [0x55; 16];
        raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        raw.extend_from_slice(&encrypted);

        let parsed = parse_for_telemetry(&raw, 4096);
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].text.as_deref(), Some("SELECT 1"));
        assert_eq!(parsed.encrypted_login_password_bytes, Some(16));
        assert_eq!(parsed.unparsed_regions.len(), 1);
        assert_eq!(parsed.unparsed_regions[0].offset, unknown_offset);
        assert_eq!(parsed.unparsed_regions[0].bytes, 3);
        assert!(parsed.unknown_token.is_none());
    }

    #[test]
    fn recovery_retains_authentication_between_unknown_regions() {
        let encrypted = [0x55; 16];
        let mut raw = vec![0x19, 0xde, 0xad];
        raw.extend_from_slice(&[0x65, 3, 1, 31, 0]);
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.push(0xd7);
        raw.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        raw.extend_from_slice(&encrypted);
        let trailing_offset = raw.len();
        raw.extend_from_slice(&[0x19, 0xbe, 0xef]);

        let parsed = parse_for_telemetry(&raw, 4096);
        assert_eq!(parsed.encrypted_login_password_bytes, Some(16));
        assert_eq!(parsed.message_types[0].message_type, 31);
        assert_eq!(parsed.unknown_token, Some(0x19));
        assert_eq!(parsed.trailing_bytes, 2);
        assert_eq!(parsed.unparsed_regions.len(), 2);
        assert_eq!(parsed.unparsed_regions[0].offset, 0);
        assert_eq!(parsed.unparsed_regions[0].bytes, 3);
        assert_eq!(parsed.unparsed_regions[1].offset, trailing_offset);
        assert_eq!(parsed.unparsed_regions[1].bytes, 3);
        assert!(
            parsed
                .parse_warnings
                .iter()
                .any(|warning| warning.contains("recovered"))
        );
    }

    #[test]
    fn recovery_recognizes_every_published_message_type_not_only_password_messages() {
        let mut raw = vec![0x19, 0xde, 0xad];
        raw.extend_from_slice(&[0x65, 3, 1, 25, 0]); // TDS_MSG_LOGINPARAMS
        raw.extend_from_slice(&[
            0xec, 0x0e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xff, 0xff, 0x7f, 0,
        ]);
        raw.extend_from_slice(&[0xd7, 4, 0, 0, 0, b'u', b's', b'e', b'r']);

        let parsed = parse_for_telemetry(&raw, 4096);
        assert_eq!(parsed.message_types.len(), 1);
        assert_eq!(parsed.message_types[0].message_type, 25);
        assert_eq!(parsed.message_types[0].name, "login_parameters");
        assert_eq!(parsed.parameter_value(0), Some(b"user".as_slice()));
        assert_eq!(parsed.unparsed_regions[0].offset, 0);
        assert_eq!(parsed.unparsed_regions[0].bytes, 3);
    }

    #[test]
    fn recovery_does_not_promote_a_bare_authentication_msg_before_unknown_data() {
        let raw = [0x19, 0x65, 3, 1, 31, 0, 0x19, 0xde, 0xad];
        let parsed = parse_for_telemetry(&raw, 4096);
        assert!(parsed.message_types.is_empty());
        assert_eq!(parsed.encrypted_login_password_bytes, None);
    }

    #[test]
    fn inventories_remote_password_and_symmetric_key_messages() {
        let mut raw = secure_challenge(
            32,
            &[
                SecureChallengeValue::Binary(b"reporting"),
                SecureChallengeValue::Binary(&[0x55; 32]),
            ],
        )
        .unwrap();
        raw.extend_from_slice(
            &secure_challenge(34, &[SecureChallengeValue::Binary(&[0x66; 48])]).unwrap(),
        );

        let parsed = parse_authentication(&raw, 4096).unwrap();
        assert_eq!(parsed.encrypted_remote_passwords.len(), 1);
        assert_eq!(
            parsed.encrypted_remote_passwords[0].server_name,
            "reporting"
        );
        assert_eq!(parsed.encrypted_remote_passwords[0].ciphertext_bytes, 32);
        assert_eq!(parsed.encrypted_symmetric_key_bytes, Some(48));
    }

    #[test]
    fn authentication_message_type_does_not_bleed_into_later_parameter_sets() {
        let mut raw = secure_challenge(
            32,
            &[
                SecureChallengeValue::Binary(b"reporting"),
                SecureChallengeValue::Binary(&[0x55; 32]),
            ],
        )
        .unwrap();
        let unrelated = secure_challenge(
            13,
            &[
                SecureChallengeValue::Binary(b"ordinary"),
                SecureChallengeValue::Binary(b"value"),
            ],
        )
        .unwrap();
        raw.extend_from_slice(&unrelated[5..]); // omit the second MSG token

        let parsed = parse_authentication(&raw, 4096).unwrap();
        assert_eq!(parsed.parameter_sets, 2);
        assert_eq!(parsed.encrypted_remote_passwords.len(), 1);
        assert_eq!(
            parsed.encrypted_remote_passwords[0].server_name,
            "reporting"
        );
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

    #[test]
    fn parameter_column_status_does_not_shift_following_values() {
        let mut format = Vec::new();
        format.extend_from_slice(&2_u16.to_le_bytes());
        format.extend_from_slice(&[1, b'a', 0x08]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x27, 8, 0]);
        format.extend_from_slice(&[1, b'b', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x27, 8, 0]);

        let mut raw = vec![0xec];
        raw.extend_from_slice(&(format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&format);
        raw.extend_from_slice(&[0xd7, 2, 3, b'o', b'n', b'e', 0]);

        let parsed = parse_authentication(&raw, 1024).unwrap();
        assert_eq!(parsed.parameter_values[0].data_status, Some(2));
        assert_eq!(parsed.parameter_values[0].value, "one");
        assert_eq!(parsed.parameter_values[1].data_status, None);
        assert_eq!(parsed.parameter_values[1].value, "");
    }

    #[test]
    fn parses_chunked_blob_parameters_without_shifting_following_values() {
        let mut format = Vec::new();
        format.extend_from_slice(&2_u16.to_le_bytes());
        format.extend_from_slice(&[1, b'b', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x24, 0xff, 3, 0]); // BLOB CHAR, empty locale
        format.extend_from_slice(&[1, b'v', 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x27, 8, 0]);

        let mut raw = vec![0xec];
        raw.extend_from_slice(&(format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&format);
        raw.push(0xd7);
        raw.push(0); // native character serialization
        raw.extend_from_slice(&3_u32.to_le_bytes());
        raw.extend_from_slice(b"abc");
        raw.extend_from_slice(&(0x8000_0000_u32 | 2).to_le_bytes());
        raw.extend_from_slice(b"de");
        raw.extend_from_slice(&[3, b's', b'q', b'l']);

        let parsed = parse_authentication(&raw, 1024).unwrap();
        assert_eq!(parsed.parameter_values[0].value, "abcde");
        assert_eq!(parsed.parameter_values[0].blob_type, Some(3));
        assert_eq!(parsed.parameter_values[0].blob_serialization, Some(0));
        assert_eq!(parsed.parameter_values[0].blob_chunks, Some(2));
        assert_eq!(parsed.parameter_values[1].value, "sql");
        assert!(parsed.unknown_token.is_none());
    }

    #[test]
    fn parses_blob_class_and_locator_prefixes() {
        let mut format = Vec::new();
        format.extend_from_slice(&2_u16.to_le_bytes());
        format.extend_from_slice(&[0, 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x24, 0xff, 1]);
        format.extend_from_slice(&4_u16.to_le_bytes());
        format.extend_from_slice(b"java");
        format.push(0);
        format.extend_from_slice(&[0, 0]);
        format.extend_from_slice(&0_u32.to_le_bytes());
        format.extend_from_slice(&[0x24, 0xff, 7, 0]);

        let mut raw = vec![0xec];
        raw.extend_from_slice(&(format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&format);
        raw.push(0xd7);
        raw.push(0);
        raw.extend_from_slice(&3_u16.to_le_bytes());
        raw.extend_from_slice(b"sub");
        raw.extend_from_slice(&0x8000_0000_u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&3_u16.to_le_bytes());
        raw.extend_from_slice(b"loc");
        raw.extend_from_slice(&0x8000_0000_u32.to_le_bytes());

        let parsed = parse_authentication(&raw, 1024).unwrap();
        assert_eq!(
            parsed.parameter_values[0].blob_class_id.as_deref(),
            Some("java")
        );
        assert_eq!(
            parsed.parameter_values[0]
                .blob_subclass_or_locator
                .as_deref(),
            Some("sub")
        );
        assert_eq!(
            parsed.parameter_values[1]
                .blob_subclass_or_locator
                .as_deref(),
            Some("loc")
        );
    }

    #[test]
    fn parses_tds5_opaque_gss_security_session() {
        let mut format = Vec::new();
        format.extend_from_slice(&5_u16.to_le_bytes());
        for ty in [0x26_u8, 0x26, 0x25] {
            format.extend_from_slice(&[0; 6]); // name, status, user type
            format.extend_from_slice(&[ty, if ty == 0x25 { 255 } else { 4 }, 0]);
        }
        format.extend_from_slice(&[0; 6]);
        format.push(0xe1);
        format.extend_from_slice(&u32::MAX.to_le_bytes());
        format.push(0);
        format.extend_from_slice(&[0; 6]);
        format.extend_from_slice(&[0x26, 4, 0]);

        let mechanism = [
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x01, 0x04, 0x06, 0x06,
        ];
        let token = [0x60, 0x08, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        let mut raw = vec![0x65, 3, 1, 11, 0, 0xec];
        raw.extend_from_slice(&(format.len() as u16).to_le_bytes());
        raw.extend_from_slice(&format);
        raw.push(0xd7);
        raw.push(4);
        raw.extend_from_slice(&50_i32.to_le_bytes());
        raw.push(4);
        raw.extend_from_slice(&1_i32.to_le_bytes());
        raw.push(mechanism.len() as u8);
        raw.extend_from_slice(&mechanism);
        raw.extend_from_slice(&(token.len() as u32).to_le_bytes());
        raw.extend_from_slice(&token);
        raw.push(4);
        raw.extend_from_slice(&0x13_u32.to_le_bytes());

        let parsed = parse_authentication(&raw, 4096).unwrap();
        let opaque = &parsed.opaque_security[0];
        assert_eq!(opaque.security_version, Some(50));
        assert_eq!(opaque.security_message_type, Some(1));
        assert_eq!(
            opaque.mechanism_oid.as_deref(),
            Some("1.3.6.1.4.1.897.4.6.6")
        );
        assert_eq!(opaque.authentication_token_family, "gss_api");
        assert_eq!(opaque.authentication_mechanism_oids, ["1.3.6.1.5.5.2"]);
        assert_eq!(opaque.security_flags, Some(0x13));
        assert_eq!(opaque.security_message_name, "security_session");
        assert_eq!(
            opaque.security_services,
            [
                "network_authentication",
                "mutual_authentication",
                "confidentiality"
            ]
        );
        assert_eq!(opaque.unknown_security_flags, Some(0));
        assert!(opaque.parse_warnings.is_empty());
    }

    #[test]
    fn recovers_only_a_nonce_bound_32_byte_epep_symmetric_key() {
        let server_key = secure_login_key().unwrap();
        let nonce = [0x3a; 32];
        let expected_key = [0x91; 32];
        let plaintext = [nonce.as_slice(), expected_key.as_slice()].concat();
        let ciphertext = encrypt_oaep_pem(&server_key.public_pkcs1_pem, true, &plaintext);

        assert_eq!(
            server_key
                .decrypt_symmetric_key_with_nonce(&ciphertext, &nonce)
                .unwrap(),
            expected_key
        );

        let wrong_nonce = [0x3b; 32];
        assert!(
            server_key
                .decrypt_symmetric_key_with_nonce(&ciphertext, &wrong_nonce)
                .is_err()
        );

        let short_plaintext = [nonce.as_slice(), &[0x91; 31]].concat();
        let short_ciphertext =
            encrypt_oaep_pem(&server_key.public_pkcs1_pem, true, &short_plaintext);
        assert!(
            server_key
                .decrypt_symmetric_key_with_nonce(&short_ciphertext, &nonce)
                .is_err()
        );
    }
}
