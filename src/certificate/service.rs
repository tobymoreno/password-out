use zeroize::Zeroizing;

use super::{
    CertificateIdentity, CertificateKeyProvider, KeyWrapAlgorithm, verify_certificate_identity,
};

pub fn unwrap_key_with_provider(
    provider: &mut dyn CertificateKeyProvider,
    expected_identity: &CertificateIdentity,
    algorithm: KeyWrapAlgorithm,
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if wrapped_key.is_empty() {
        return Err("wrapped vault key cannot be empty".to_string());
    }

    let certificate_der = provider.certificate_der()?;

    verify_certificate_identity(expected_identity, &certificate_der)?;

    provider.unwrap_key(algorithm, wrapped_key)
}

#[cfg(test)]
mod tests {
    use super::unwrap_key_with_provider;
    use crate::certificate::{
        CertificateSource, KeyWrapAlgorithm, PfxKeyProvider, SelfSignedCertificateOptions,
        certificate_identity_from_der, create_self_signed_pfx, load_pfx_der,
        wrap_key_with_certificate,
    };

    fn create_provider(common_name: &str) -> PfxKeyProvider {
        let generated = create_self_signed_pfx(
            &SelfSignedCertificateOptions {
                common_name: common_name.to_string(),
                friendly_name: common_name.to_string(),
                rsa_bits: 2048,
                validity_days: 30,
            },
            "test-password",
        )
        .expect("PFX generation should succeed");

        let loaded =
            load_pfx_der(&generated.pfx_der, "test-password").expect("PFX loading should succeed");

        PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider creation should succeed")
    }

    #[test]
    fn unwraps_key_when_certificate_matches() {
        let mut provider = create_provider("PasswordOut Matching Provider");

        let certificate_der = provider
            .certificate_der()
            .expect("certificate DER encoding should succeed");

        let identity = certificate_identity_from_der(&certificate_der)
            .expect("certificate identity extraction should succeed");

        let vault_key = [0x77_u8; 32];

        let wrapped_key = wrap_key_with_certificate(
            &certificate_der,
            KeyWrapAlgorithm::RsaOaepSha256,
            &vault_key,
        )
        .expect("vault-key wrapping should succeed");

        let unwrapped = unwrap_key_with_provider(
            &mut provider,
            &identity,
            KeyWrapAlgorithm::RsaOaepSha256,
            &wrapped_key,
        )
        .expect("vault-key unwrapping should succeed");

        assert_eq!(unwrapped.as_slice(), vault_key);
    }

    #[test]
    fn rejects_provider_with_wrong_certificate() {
        let correct_provider = create_provider("PasswordOut Correct Provider");

        let correct_certificate_der = correct_provider
            .certificate_der()
            .expect("certificate DER encoding should succeed");

        let expected_identity = certificate_identity_from_der(&correct_certificate_der)
            .expect("certificate identity extraction should succeed");

        let vault_key = [0x33_u8; 32];

        let wrapped_key = wrap_key_with_certificate(
            &correct_certificate_der,
            KeyWrapAlgorithm::RsaOaepSha256,
            &vault_key,
        )
        .expect("vault-key wrapping should succeed");

        let mut wrong_provider = create_provider("PasswordOut Wrong Provider");

        let result = unwrap_key_with_provider(
            &mut wrong_provider,
            &expected_identity,
            KeyWrapAlgorithm::RsaOaepSha256,
            &wrapped_key,
        );

        assert!(result.is_err());
    }
}
