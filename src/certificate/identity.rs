use openssl::hash::MessageDigest;
use openssl::x509::{X509, X509NameRef};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateIdentity {
    pub sha256_fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
}

pub fn certificate_identity_from_der(
    certificate_der: &[u8],
) -> Result<CertificateIdentity, String> {
    let certificate = X509::from_der(certificate_der)
        .map_err(|error| format!("failed to parse X.509 certificate: {error}"))?;

    certificate_identity(&certificate)
}

pub fn certificate_identity(certificate: &X509) -> Result<CertificateIdentity, String> {
    let fingerprint = certificate
        .digest(MessageDigest::sha256())
        .map_err(|error| format!("failed to calculate certificate fingerprint: {error}"))?;

    let serial_number = certificate
        .serial_number()
        .to_bn()
        .and_then(|serial| serial.to_hex_str())
        .map_err(|error| format!("failed to read certificate serial number: {error}"))?
        .to_string();

    Ok(CertificateIdentity {
        sha256_fingerprint: hex_upper(fingerprint.as_ref()),
        subject: format_name(certificate.subject_name()),
        issuer: format_name(certificate.issuer_name()),
        serial_number,
        not_before: certificate.not_before().to_string(),
        not_after: certificate.not_after().to_string(),
    })
}

pub fn verify_certificate_identity(
    expected: &CertificateIdentity,
    certificate_der: &[u8],
) -> Result<CertificateIdentity, String> {
    let actual = certificate_identity_from_der(certificate_der)?;

    if actual.sha256_fingerprint != expected.sha256_fingerprint {
        return Err(format!(
            "certificate fingerprint mismatch: expected {}, received {}",
            expected.sha256_fingerprint, actual.sha256_fingerprint,
        ));
    }

    Ok(actual)
}

fn format_name(name: &X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let field = entry.object().nid().short_name().unwrap_or("UNKNOWN");

            let value = entry
                .data()
                .to_string()
                .unwrap_or_else(|_| hex_upper(entry.data().as_slice()));

            format!("{field}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::{certificate_identity_from_der, verify_certificate_identity};
    use crate::certificate::{SelfSignedCertificateOptions, create_self_signed_pfx};

    fn test_certificate(common_name: &str) -> Vec<u8> {
        let generated = create_self_signed_pfx(
            &SelfSignedCertificateOptions {
                common_name: common_name.to_string(),
                friendly_name: common_name.to_string(),
                rsa_bits: 2048,
                validity_days: 30,
            },
            "test-password",
        )
        .expect("certificate generation should succeed");

        generated
            .certificate
            .to_der()
            .expect("certificate DER encoding should succeed")
    }

    #[test]
    fn extracts_certificate_identity() {
        let certificate_der = test_certificate("PasswordOut Identity Test");

        let identity = certificate_identity_from_der(&certificate_der)
            .expect("certificate identity extraction should succeed");

        assert!(!identity.sha256_fingerprint.is_empty());
        assert!(identity.subject.contains("PasswordOut Identity Test"));
        assert!(identity.issuer.contains("PasswordOut Identity Test"));
        assert!(!identity.serial_number.is_empty());
        assert!(!identity.not_before.is_empty());
        assert!(!identity.not_after.is_empty());
    }

    #[test]
    fn accepts_matching_certificate() {
        let certificate_der = test_certificate("PasswordOut Matching Certificate");

        let expected = certificate_identity_from_der(&certificate_der)
            .expect("certificate identity extraction should succeed");

        let actual = verify_certificate_identity(&expected, &certificate_der)
            .expect("matching certificate should be accepted");

        assert_eq!(actual.sha256_fingerprint, expected.sha256_fingerprint,);
    }

    #[test]
    fn rejects_different_certificate() {
        let expected_der = test_certificate("PasswordOut Expected Certificate");
        let actual_der = test_certificate("PasswordOut Different Certificate");

        let expected = certificate_identity_from_der(&expected_der)
            .expect("expected certificate identity should load");

        let result = verify_certificate_identity(&expected, &actual_der);

        assert!(result.is_err());
    }
}
