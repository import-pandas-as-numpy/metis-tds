use crate::{Error, Result};

/// The published MS-TDS grammar calls EnclavePackage an L_VARBYTE (four-byte
/// length), while both Microsoft.Data.SqlClient and mssql-jdbc write a
/// two-byte length. Keep the distinction explicit so neither wire form is
/// inferred from attacker-controlled package bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthEncoding {
    None,
    MicrosoftU16,
    SpecU32,
}

pub fn strip(
    input: &[u8],
    encoding: LengthEncoding,
    max_bytes: usize,
) -> Result<(Option<usize>, &[u8])> {
    let (prefix, length) = match encoding {
        LengthEncoding::None => return Ok((None, input)),
        LengthEncoding::MicrosoftU16 => {
            let raw = input
                .get(..2)
                .ok_or_else(|| Error::Protocol("truncated enclave package length".into()))?;
            (2, usize::from(u16::from_le_bytes([raw[0], raw[1]])))
        }
        LengthEncoding::SpecU32 => {
            let raw = input
                .get(..4)
                .ok_or_else(|| Error::Protocol("truncated enclave package length".into()))?;
            let signed = i32::from_le_bytes(raw.try_into().expect("length checked"));
            if signed < 0 {
                return Err(Error::Protocol("negative enclave package length".into()));
            }
            (
                4,
                usize::try_from(signed).map_err(|_| Error::Limit("enclave package"))?,
            )
        }
    };
    if length > max_bytes {
        return Err(Error::Limit("maximum enclave package bytes"));
    }
    let body = input
        .get(prefix..prefix + length)
        .ok_or_else(|| Error::Protocol("truncated enclave package".into()))?;
    debug_assert_eq!(body.len(), length);
    let remaining = input
        .get(prefix + length..)
        .ok_or_else(|| Error::Protocol("truncated enclave package".into()))?;
    Ok((Some(length), remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_published_and_microsoft_length_encodings() {
        let (_, body) = strip(&[2, 0, 1, 2, 9], LengthEncoding::MicrosoftU16, 8).unwrap();
        assert_eq!(body, [9]);
        let (_, body) = strip(&[2, 0, 0, 0, 1, 2, 9], LengthEncoding::SpecU32, 8).unwrap();
        assert_eq!(body, [9]);
    }
}
