use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey, sha2::Sha256};
use x509_parser::parse_x509_certificate;

use super::certificate::sha256_fingerprint;

const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

pub const CAC_KEY_MANAGEMENT_SLOT: &str = "9D";
pub const CAC_WRAP_ALGORITHM_RSA_OAEP_SHA256: &str = "rsa-oaep-sha256";

#[derive(Debug, Clone)]
pub struct WrappedCacKey {
    pub slot: String,
    pub certificate_sha256: String,
    pub algorithm: String,
    pub wrapped_key: String,
}

pub fn wrap_key_with_cac_certificate(
    certificate_der: &[u8],
    vault_key: &[u8],
) -> Result<WrappedCacKey> {
    if vault_key.is_empty() {
        bail!("vault key cannot be empty");
    }

    let (remaining, certificate) = parse_x509_certificate(certificate_der).map_err(|error| {
        anyhow::anyhow!("failed to parse CAC key-management certificate: {error}")
    })?;

    if !remaining.is_empty() {
        bail!(
            "{} trailing byte(s) remained after parsing the CAC certificate",
            remaining.len()
        );
    }

    let subject_public_key_info = certificate.public_key();

    let public_key_algorithm = subject_public_key_info.algorithm.algorithm.to_string();

    if public_key_algorithm != RSA_ENCRYPTION_OID {
        bail!(
            "unsupported CAC public-key algorithm {}; expected RSA ({})",
            public_key_algorithm,
            RSA_ENCRYPTION_OID
        );
    }

    let public_key = RsaPublicKey::from_public_key_der(subject_public_key_info.raw)
        .context("failed to decode RSA public key from CAC certificate")?;

    let wrapped_key = public_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), vault_key)
        .context("failed to wrap vault key with CAC RSA public key")?;

    Ok(WrappedCacKey {
        slot: CAC_KEY_MANAGEMENT_SLOT.to_string(),
        certificate_sha256: sha256_fingerprint(certificate_der),
        algorithm: CAC_WRAP_ALGORITHM_RSA_OAEP_SHA256.to_string(),
        wrapped_key: STANDARD_NO_PAD.encode(wrapped_key),
    })
}

/// Removes RSAES-PKCS1-v1_5 encryption padding from the encoded message
/// returned by the PIV card's RSA private-key operation.
///
/// Expected structure:
///
/// `00 02 PS 00 M`
///
/// where PS contains at least eight non-zero random bytes.
pub fn decode_pkcs1_v15_encoded_message(encoded_message: &[u8]) -> Result<Vec<u8>> {
    if encoded_message.len() < 11 {
        bail!(
            "PKCS#1 encoded message is too short: {} bytes",
            encoded_message.len()
        );
    }

    if encoded_message[0] != 0x00 || encoded_message[1] != 0x02 {
        bail!("PIV RSA result does not contain PKCS#1 v1.5 encryption padding");
    }

    let separator = encoded_message[2..]
        .iter()
        .position(|byte| *byte == 0x00)
        .map(|offset| offset + 2)
        .context("PKCS#1 encoded message does not contain a padding separator")?;

    let padding_length = separator - 2;

    if padding_length < 8 {
        bail!("PKCS#1 padding contains only {padding_length} byte(s); expected at least 8");
    }

    let message = &encoded_message[separator + 1..];

    if message.is_empty() {
        bail!("PKCS#1 encoded message contains an empty plaintext");
    }

    Ok(message.to_vec())
}

#[cfg(test)]
mod pkcs1_v15_tests {
    use super::decode_pkcs1_v15_encoded_message;

    #[test]
    fn decodes_valid_pkcs1_v15_encoded_message() {
        let vault_key = [0x42_u8; 32];

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&[0x00, 0x02]);
        encoded.extend_from_slice(&[0xA5; 221]);
        encoded.push(0x00);
        encoded.extend_from_slice(&vault_key);

        assert_eq!(encoded.len(), 256);

        let decoded = decode_pkcs1_v15_encoded_message(&encoded)
            .expect("valid PKCS#1 v1.5 message should decode");

        assert_eq!(decoded, vault_key);
    }

    #[test]
    fn rejects_invalid_pkcs1_v15_prefix() {
        let mut encoded = vec![0x00, 0x01];
        encoded.extend_from_slice(&[0xA5; 221]);
        encoded.push(0x00);
        encoded.extend_from_slice(&[0x42; 32]);

        let result = decode_pkcs1_v15_encoded_message(&encoded);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_pkcs1_v15_padding_shorter_than_eight_bytes() {
        let mut encoded = vec![0x00, 0x02];
        encoded.extend_from_slice(&[0xA5; 7]);
        encoded.push(0x00);
        encoded.extend_from_slice(&[0x42; 32]);

        let result = decode_pkcs1_v15_encoded_message(&encoded);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_pkcs1_v15_message_without_separator() {
        let mut encoded = vec![0x00, 0x02];
        encoded.extend_from_slice(&[0xA5; 254]);

        let result = decode_pkcs1_v15_encoded_message(&encoded);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_pkcs1_v15_message_with_empty_plaintext() {
        let mut encoded = vec![0x00, 0x02];
        encoded.extend_from_slice(&[0xA5; 253]);
        encoded.push(0x00);

        assert_eq!(encoded.len(), 256);

        let result = decode_pkcs1_v15_encoded_message(&encoded);

        assert!(result.is_err());
    }
}
