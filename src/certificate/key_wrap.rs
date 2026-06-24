use openssl::encrypt::Encrypter;
use openssl::hash::MessageDigest;
use openssl::rsa::Padding;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    #[serde(rename = "rsa-oaep-sha256")]
    RsaOaepSha256,
}

/// Wraps a vault key using the public key contained in an X.509 certificate.
///
/// The certificate may come from a software PFX file, a CAC/PIV card, or any
/// future provider. Only the public certificate is required for wrapping.
pub fn wrap_key_with_certificate(
    certificate_der: &[u8],
    algorithm: KeyWrapAlgorithm,
    plaintext_key: &[u8],
) -> Result<Vec<u8>, String> {
    if plaintext_key.is_empty() {
        return Err("vault key cannot be empty".to_string());
    }

    let certificate = X509::from_der(certificate_der)
        .map_err(|error| format!("failed to parse X.509 certificate: {error}"))?;

    let public_key = certificate
        .public_key()
        .map_err(|error| format!("failed to read certificate public key: {error}"))?;

    match algorithm {
        KeyWrapAlgorithm::RsaOaepSha256 => {
            let mut encrypter = Encrypter::new(&public_key)
                .map_err(|error| format!("failed to initialize RSA encrypter: {error}"))?;

            encrypter
                .set_rsa_padding(Padding::PKCS1_OAEP)
                .map_err(|error| format!("failed to configure RSA-OAEP padding: {error}"))?;

            encrypter
                .set_rsa_oaep_md(MessageDigest::sha256())
                .map_err(|error| format!("failed to configure RSA-OAEP SHA-256: {error}"))?;

            encrypter
                .set_rsa_mgf1_md(MessageDigest::sha256())
                .map_err(|error| format!("failed to configure RSA MGF1 SHA-256: {error}"))?;

            let output_length = encrypter
                .encrypt_len(plaintext_key)
                .map_err(|error| format!("failed to determine wrapped-key length: {error}"))?;

            let mut wrapped_key = vec![0_u8; output_length];

            let written = encrypter
                .encrypt(plaintext_key, &mut wrapped_key)
                .map_err(|error| format!("failed to wrap vault key: {error}"))?;

            wrapped_key.truncate(written);

            Ok(wrapped_key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyWrapAlgorithm, wrap_key_with_certificate};
    use crate::certificate::{SelfSignedCertificateOptions, create_self_signed_pfx};

    #[test]
    fn rejects_empty_plaintext_key() {
        let generated = create_self_signed_pfx(
            &SelfSignedCertificateOptions {
                rsa_bits: 2048,
                validity_days: 30,
                ..SelfSignedCertificateOptions::default()
            },
            "test-password",
        )
        .expect("certificate generation should succeed");

        let certificate_der = generated
            .certificate
            .to_der()
            .expect("certificate DER encoding should succeed");

        let result =
            wrap_key_with_certificate(&certificate_der, KeyWrapAlgorithm::RsaOaepSha256, &[]);

        assert!(result.is_err());
    }
}
