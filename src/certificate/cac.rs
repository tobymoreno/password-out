use pcsc::Card;
use zeroize::Zeroizing;

use crate::smartcard::{
    certificate::decode_certificate,
    pcsc::connect_first_card,
    piv::{PivSlot, read_certificate, rsa_key_transport, select_piv, verify_pin},
    wrapping::decode_pkcs1_v15_encoded_message,
};

use super::{CertificatePrivateKey, CertificateSource, KeyWrapAlgorithm};

/// Public certificate source used while creating a CAC-backed vault.
///
/// Vault initialization needs only the public slot-9D certificate. The CAC PIN
/// and private-key operation are not needed until the vault is unlocked.
pub struct CacCertificateSource {
    certificate_der: Vec<u8>,
}

impl CacCertificateSource {
    pub fn new(certificate_der: Vec<u8>) -> Result<Self, String> {
        if certificate_der.is_empty() {
            return Err("CAC certificate cannot be empty".to_string());
        }

        Ok(Self { certificate_der })
    }
}

impl CertificateSource for CacCertificateSource {
    fn certificate_der(&self) -> Result<Vec<u8>, String> {
        Ok(self.certificate_der.clone())
    }
}

/// Hardware-backed certificate provider using the PIV key-management key.
///
/// Construction connects to the first available card, selects the PIV
/// application, reads slot 9D, and verifies the supplied PIN once. The card
/// connection remains open while the certificate vault session is loaded.
pub struct CacKeyProvider {
    card: Card,
    certificate_der: Vec<u8>,
}

impl CacKeyProvider {
    pub fn connect(pin: &str) -> Result<Self, String> {
        let card =
            connect_first_card().map_err(|error| format!("failed to connect to CAC: {error}"))?;

        select_piv(&card)
            .map_err(|error| format!("failed to select the PIV application: {error}"))?;

        let piv_certificate = read_certificate(&card, PivSlot::KeyManagement).map_err(|error| {
            format!("failed to read the CAC key-management certificate: {error}")
        })?;

        let certificate_der = decode_certificate(&piv_certificate).map_err(|error| {
            format!("failed to decode the CAC key-management certificate: {error}")
        })?;

        verify_pin(&card, pin).map_err(|error| format!("CAC PIN verification failed: {error}"))?;

        Ok(Self {
            card,
            certificate_der,
        })
    }
}

impl CertificateSource for CacKeyProvider {
    fn certificate_der(&self) -> Result<Vec<u8>, String> {
        Ok(self.certificate_der.clone())
    }
}

impl CertificatePrivateKey for CacKeyProvider {
    fn unwrap_key(
        &mut self,
        algorithm: KeyWrapAlgorithm,
        wrapped_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if wrapped_key.is_empty() {
            return Err("wrapped vault key cannot be empty".to_string());
        }

        match algorithm {
            KeyWrapAlgorithm::RsaPkcs1v15 => {
                let encoded_message =
                    rsa_key_transport(&self.card, PivSlot::KeyManagement, wrapped_key).map_err(
                        |error| format!("CAC RSA key-management operation failed: {error}"),
                    )?;

                let plaintext = decode_pkcs1_v15_encoded_message(&encoded_message)
                    .map_err(|error| format!("failed to decode CAC RSA result: {error}"))?;

                Ok(Zeroizing::new(plaintext))
            }

            KeyWrapAlgorithm::RsaOaepSha256 => {
                Err("CAC/PIV vaults do not support RSA-OAEP-SHA256; \
                 expected RSA-PKCS1-v1_5"
                    .to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CacCertificateSource;
    use crate::certificate::CertificateSource;

    #[test]
    fn certificate_source_returns_original_der() {
        let der = vec![0x30, 0x03, 0x01, 0x01, 0x00];

        let source = CacCertificateSource::new(der.clone())
            .expect("non-empty certificate should be accepted");

        assert_eq!(
            source
                .certificate_der()
                .expect("certificate should be returned"),
            der
        );
    }

    #[test]
    fn certificate_source_rejects_empty_der() {
        let result = CacCertificateSource::new(Vec::new());

        assert!(result.is_err());
    }
}
