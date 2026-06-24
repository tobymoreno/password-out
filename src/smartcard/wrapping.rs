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
