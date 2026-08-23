use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedAuthToken<'a> {
    pub token: &'a [u8],
    pub nonce: Option<&'a [u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedAuthTelemetry<'a> {
    pub token: &'a [u8],
    pub nonce: Option<&'a [u8]>,
    pub unclassified: &'a [u8],
    pub recovery: &'static str,
    pub parse_warnings: Vec<String>,
}

pub fn parse(payload: &[u8], nonce_expected: bool) -> Result<FederatedAuthToken<'_>> {
    let declared = usize::try_from(le_u32(payload, 0)?)
        .map_err(|_| Error::Protocol("FEDAUTH length overflow".into()))?;
    if declared != payload.len().saturating_sub(4) {
        return Err(Error::Protocol(format!(
            "FEDAUTH DataLen {declared} does not match {} trailing bytes",
            payload.len().saturating_sub(4)
        )));
    }
    let token_len = usize::try_from(le_u32(payload, 4)?)
        .map_err(|_| Error::Protocol("FEDAUTH token length overflow".into()))?;
    let token_start = 8_usize;
    let token_end = token_start
        .checked_add(token_len)
        .ok_or_else(|| Error::Protocol("FEDAUTH token offset overflow".into()))?;
    let token = payload
        .get(token_start..token_end)
        .ok_or_else(|| Error::Protocol("truncated FEDAUTH token".into()))?;
    let trailing = &payload[token_end..];
    let nonce = match (nonce_expected, trailing.len()) {
        (true, 32) => Some(trailing),
        (true, _) => return Err(Error::Protocol("FEDAUTH nonce must be 32 bytes".into())),
        (false, 0) => None,
        (false, 32) => Some(trailing),
        (false, _) => return Err(Error::Protocol("unexpected FEDAUTH trailing data".into())),
    };
    Ok(FederatedAuthToken { token, nonce })
}

/// Recover independently bounded FEDAUTH fields even when an outer length is
/// non-canonical. This is intentionally telemetry-only: callers can retain the
/// presented token while still seeing why the strict grammar rejected it.
pub fn parse_for_telemetry(payload: &[u8], nonce_expected: bool) -> FederatedAuthTelemetry<'_> {
    match parse(payload, nonce_expected) {
        Ok(parsed) => FederatedAuthTelemetry {
            token: parsed.token,
            nonce: parsed.nonce,
            unclassified: &[],
            recovery: "strict",
            parse_warnings: Vec::new(),
        },
        Err(error) => {
            let body = payload.get(8..);
            let declared_token = payload
                .get(4..8)
                .map(|raw| u32::from_le_bytes(raw.try_into().expect("length checked")))
                .and_then(|length| usize::try_from(length).ok());
            let (token, trailing, recovery) = body
                .and_then(|body| {
                    declared_token.and_then(|length| body.get(..length).zip(body.get(length..)))
                })
                .map(|(token, trailing)| (token, trailing, "declared_token_length"))
                .unwrap_or_else(|| match body {
                    Some(body) if nonce_expected && body.len() >= 32 => {
                        let (token, trailing) = body.split_at(body.len() - 32);
                        (token, trailing, "inferred_nonce_suffix")
                    }
                    Some(body) => (body, &[][..], "body_after_headers"),
                    None => (payload, &[][..], "raw_payload"),
                });
            let nonce = (trailing.len() == 32).then_some(trailing);
            FederatedAuthTelemetry {
                token,
                nonce,
                unclassified: if nonce.is_some() { &[] } else { trailing },
                recovery,
                parse_warnings: vec![error.to_string()],
            }
        }
    }
}

fn le_u32(input: &[u8], offset: usize) -> Result<u32> {
    let value = input
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Protocol("truncated FEDAUTH length".into()))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_token_with_optional_nonce() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&39_u32.to_le_bytes());
        payload.extend_from_slice(&3_u32.to_le_bytes());
        payload.extend_from_slice(b"jwt");
        payload.extend_from_slice(&[7; 32]);
        let parsed = parse(&payload, true).unwrap();
        assert_eq!(parsed.token, b"jwt");
        assert_eq!(parsed.nonce, Some([7; 32].as_slice()));
    }

    #[test]
    fn telemetry_recovers_token_and_nonce_despite_bad_outer_length() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&999_u32.to_le_bytes());
        payload.extend_from_slice(&3_u32.to_le_bytes());
        payload.extend_from_slice(b"jwt");
        payload.extend_from_slice(&[7; 32]);
        let parsed = parse_for_telemetry(&payload, true);
        assert_eq!(parsed.token, b"jwt");
        assert_eq!(parsed.nonce, Some([7; 32].as_slice()));
        assert!(parsed.unclassified.is_empty());
        assert_eq!(parsed.recovery, "declared_token_length");
        assert_eq!(parsed.parse_warnings.len(), 1);
    }

    #[test]
    fn telemetry_never_drops_short_or_unexpected_authentication_material() {
        let short = parse_for_telemetry(b"bearer", false);
        assert_eq!(short.token, b"bearer");
        assert_eq!(short.recovery, "raw_payload");

        let mut payload = Vec::new();
        payload.extend_from_slice(&99_u32.to_le_bytes());
        payload.extend_from_slice(&3_u32.to_le_bytes());
        payload.extend_from_slice(b"jwt");
        payload.extend_from_slice(b"extra");
        let trailing = parse_for_telemetry(&payload, false);
        assert_eq!(trailing.token, b"jwt");
        assert_eq!(trailing.unclassified, b"extra");
        assert_eq!(trailing.recovery, "declared_token_length");
    }
}
