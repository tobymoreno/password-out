use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::x509::X509;
use zeroize::Zeroizing;

use super::{CertificatePrivateKey, CertificateSource, KeyWrapAlgorithm, LoadedPfx};

pub struct PfxKeyProvider {
    certificate: X509,
    private_key: PKey<Private>,
}

impl PfxKeyProvider {
    pub fn new(certificate: X509, private_key: PKey<Private>) -> Result<Self, String> {
        let public_key = certificate
            .public_key()
            .map_err(|error| format!("failed to read PFX certificate public key: {error}"))?;

        if !public_key.public_eq(&private_key) {
            return Err("PFX certificate does not match its private key".to_string());
        }

        Ok(Self {
            certificate,
            private_key,
        })
    }

    pub fn from_loaded_pfx(loaded: LoadedPfx) -> Result<Self, String> {
        Self::new(loaded.certificate, loaded.private_key)
    }
}

impl CertificateSource for PfxKeyProvider {
    fn certificate_der(&self) -> Result<Vec<u8>, String> {
        self.certificate
            .to_der()
            .map_err(|error| format!("failed to encode PFX certificate: {error}"))
    }
}

impl CertificatePrivateKey for PfxKeyProvider {
    fn unwrap_key(
        &mut self,
        algorithm: KeyWrapAlgorithm,
        wrapped_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if wrapped_key.is_empty() {
            return Err("wrapped vault key cannot be empty".to_string());
        }

        match algorithm {
            KeyWrapAlgorithm::RsaOaepSha256 => {
                let mut decrypter = Decrypter::new(&self.private_key)
                    .map_err(|error| format!("failed to initialize RSA decrypter: {error}"))?;

                decrypter
                    .set_rsa_padding(Padding::PKCS1_OAEP)
                    .map_err(|error| format!("failed to configure RSA-OAEP padding: {error}"))?;

                decrypter
                    .set_rsa_oaep_md(MessageDigest::sha256())
                    .map_err(|error| format!("failed to configure RSA-OAEP SHA-256: {error}"))?;

                decrypter
                    .set_rsa_mgf1_md(MessageDigest::sha256())
                    .map_err(|error| format!("failed to configure RSA MGF1 SHA-256: {error}"))?;

                let output_length = decrypter.decrypt_len(wrapped_key).map_err(|error| {
                    format!("failed to determine unwrapped-key length: {error}")
                })?;

                let mut plaintext = Zeroizing::new(vec![0_u8; output_length]);

                let written = decrypter
                    .decrypt(wrapped_key, plaintext.as_mut_slice())
                    .map_err(|error| format!("failed to unwrap vault key: {error}"))?;

                plaintext.truncate(written);

                Ok(plaintext)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PfxKeyProvider;
    use crate::certificate::{
        CertificatePrivateKey, CertificateSource, KeyWrapAlgorithm, SelfSignedCertificateOptions,
        create_self_signed_pfx, load_pfx_der, wrap_key_with_certificate,
    };

    #[test]
    fn wraps_and_unwraps_vault_key_with_pfx_provider() {
        let generated = create_self_signed_pfx(
            &SelfSignedCertificateOptions {
                rsa_bits: 2048,
                validity_days: 30,
                ..SelfSignedCertificateOptions::default()
            },
            "test-password",
        )
        .expect("PFX generation should succeed");

        let loaded =
            load_pfx_der(&generated.pfx_der, "test-password").expect("PFX loading should succeed");

        let mut provider =
            PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider creation should succeed");

        let certificate_der = provider
            .certificate_der()
            .expect("certificate encoding should succeed");

        let vault_key = [0x42_u8; 32];

        let wrapped_key = wrap_key_with_certificate(
            &certificate_der,
            KeyWrapAlgorithm::RsaOaepSha256,
            &vault_key,
        )
        .expect("vault-key wrapping should succeed");

        assert_ne!(wrapped_key, vault_key);

        let unwrapped_key = provider
            .unwrap_key(KeyWrapAlgorithm::RsaOaepSha256, &wrapped_key)
            .expect("vault-key unwrapping should succeed");

        assert_eq!(unwrapped_key.as_slice(), vault_key);
    }

    #[test]
    fn rejects_tampered_wrapped_key() {
        let generated = create_self_signed_pfx(
            &SelfSignedCertificateOptions {
                rsa_bits: 2048,
                validity_days: 30,
                ..SelfSignedCertificateOptions::default()
            },
            "test-password",
        )
        .expect("PFX generation should succeed");

        let loaded =
            load_pfx_der(&generated.pfx_der, "test-password").expect("PFX loading should succeed");

        let mut provider =
            PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider creation should succeed");

        let certificate_der = provider
            .certificate_der()
            .expect("certificate encoding should succeed");

        let vault_key = [0x24_u8; 32];

        let mut wrapped_key = wrap_key_with_certificate(
            &certificate_der,
            KeyWrapAlgorithm::RsaOaepSha256,
            &vault_key,
        )
        .expect("vault-key wrapping should succeed");

        wrapped_key[0] ^= 0xff;

        let result = provider.unwrap_key(KeyWrapAlgorithm::RsaOaepSha256, &wrapped_key);

        assert!(result.is_err());
    }
}
