use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedAuthToken<'a> {
    pub token: &'a [u8],
    pub nonce: Option<&'a [u8]>,
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
}
