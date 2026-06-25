use std::fs;
use std::path::Path;

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509NameBuilder};

pub const DEFAULT_RSA_BITS: u32 = 3072;
pub const DEFAULT_VALIDITY_DAYS: u32 = 1_825;
pub const DEFAULT_COMMON_NAME: &str = "PasswordOut Vault Key";
pub const DEFAULT_FRIENDLY_NAME: &str = "PasswordOut Vault Key";

#[derive(Debug, Clone)]
pub struct SelfSignedCertificateOptions {
    pub common_name: String,
    pub friendly_name: String,
    pub validity_days: u32,
    pub rsa_bits: u32,
}

impl Default for SelfSignedCertificateOptions {
    fn default() -> Self {
        Self {
            common_name: DEFAULT_COMMON_NAME.to_string(),
            friendly_name: DEFAULT_FRIENDLY_NAME.to_string(),
            validity_days: DEFAULT_VALIDITY_DAYS,
            rsa_bits: DEFAULT_RSA_BITS,
        }
    }
}

pub struct GeneratedCertificate {
    pub certificate: X509,
    pub private_key: PKey<Private>,
    pub pfx_der: Vec<u8>,
}

pub struct LoadedPfx {
    pub certificate: X509,
    pub private_key: PKey<Private>,
}

pub fn create_self_signed_pfx(
    options: &SelfSignedCertificateOptions,
    password: &str,
) -> Result<GeneratedCertificate, String> {
    validate_options(options)?;
    validate_password(password)?;

    let rsa = Rsa::generate(options.rsa_bits)
        .map_err(|error| format!("failed to generate RSA private key: {error}"))?;

    let private_key =
        PKey::from_rsa(rsa).map_err(|error| format!("failed to create private key: {error}"))?;

    let mut name_builder = X509NameBuilder::new()
        .map_err(|error| format!("failed to create X.509 subject: {error}"))?;

    name_builder
        .append_entry_by_nid(Nid::COMMONNAME, &options.common_name)
        .map_err(|error| format!("failed to set certificate common name: {error}"))?;

    let subject_name = name_builder.build();

    let mut certificate_builder =
        X509::builder().map_err(|error| format!("failed to create X.509 certificate: {error}"))?;

    certificate_builder
        .set_version(2)
        .map_err(|error| format!("failed to set certificate version: {error}"))?;

    let serial_number = generate_serial_number()?;

    certificate_builder
        .set_serial_number(&serial_number)
        .map_err(|error| format!("failed to set certificate serial number: {error}"))?;

    certificate_builder
        .set_subject_name(&subject_name)
        .map_err(|error| format!("failed to set certificate subject: {error}"))?;

    certificate_builder
        .set_issuer_name(&subject_name)
        .map_err(|error| format!("failed to set certificate issuer: {error}"))?;

    certificate_builder
        .set_pubkey(&private_key)
        .map_err(|error| format!("failed to set certificate public key: {error}"))?;

    let not_before = Asn1Time::days_from_now(0)
        .map_err(|error| format!("failed to set certificate start date: {error}"))?;

    let not_after = Asn1Time::days_from_now(options.validity_days)
        .map_err(|error| format!("failed to set certificate expiration date: {error}"))?;

    certificate_builder
        .set_not_before(&not_before)
        .map_err(|error| format!("failed to apply certificate start date: {error}"))?;

    certificate_builder
        .set_not_after(&not_after)
        .map_err(|error| format!("failed to apply certificate expiration date: {error}"))?;

    let basic_constraints = BasicConstraints::new()
        .critical()
        .build()
        .map_err(|error| format!("failed to build basic constraints: {error}"))?;

    certificate_builder
        .append_extension(basic_constraints)
        .map_err(|error| format!("failed to add basic constraints: {error}"))?;

    let key_usage = KeyUsage::new()
        .critical()
        .key_encipherment()
        .build()
        .map_err(|error| format!("failed to build key usage: {error}"))?;

    certificate_builder
        .append_extension(key_usage)
        .map_err(|error| format!("failed to add key usage: {error}"))?;

    let subject_key_identifier = {
        let context = certificate_builder.x509v3_context(None, None);

        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(|error| format!("failed to build subject key identifier: {error}"))?
    };

    certificate_builder
        .append_extension(subject_key_identifier)
        .map_err(|error| format!("failed to add subject key identifier: {error}"))?;

    let authority_key_identifier = {
        let context = certificate_builder.x509v3_context(None, None);

        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .map_err(|error| format!("failed to build authority key identifier: {error}"))?
    };

    certificate_builder
        .append_extension(authority_key_identifier)
        .map_err(|error| format!("failed to add authority key identifier: {error}"))?;

    certificate_builder
        .sign(&private_key, MessageDigest::sha256())
        .map_err(|error| format!("failed to self-sign certificate: {error}"))?;

    let certificate = certificate_builder.build();

    let public_key = certificate
        .public_key()
        .map_err(|error| format!("failed to read generated certificate public key: {error}"))?;

    if !public_key.public_eq(&private_key) {
        return Err("generated certificate does not match generated private key".to_string());
    }

    let pfx_der = create_pfx_der(&certificate, &private_key, &options.friendly_name, password)?;

    Ok(GeneratedCertificate {
        certificate,
        private_key,
        pfx_der,
    })
}

#[allow(dead_code)]
pub fn write_pfx(path: &Path, pfx_der: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create PFX directory: {error}"))?;
    }

    fs::write(path, pfx_der)
        .map_err(|error| format!("failed to write PFX file {}: {error}", path.display()))
}

pub fn load_pfx(path: &Path, password: &str) -> Result<LoadedPfx, String> {
    let pfx_der = fs::read(path)
        .map_err(|error| format!("failed to read PFX file {}: {error}", path.display()))?;

    load_pfx_der(&pfx_der, password)
}

pub fn load_pfx_der(pfx_der: &[u8], password: &str) -> Result<LoadedPfx, String> {
    validate_password(password)?;

    let pfx =
        Pkcs12::from_der(pfx_der).map_err(|error| format!("failed to parse PFX data: {error}"))?;

    let parsed = pfx
        .parse2(password)
        .map_err(|error| format!("failed to unlock PFX: {error}"))?;

    let certificate = parsed
        .cert
        .ok_or_else(|| "PFX does not contain a certificate".to_string())?;

    let private_key = parsed
        .pkey
        .ok_or_else(|| "PFX does not contain a private key".to_string())?;

    let public_key = certificate
        .public_key()
        .map_err(|error| format!("failed to read certificate public key: {error}"))?;

    if !public_key.public_eq(&private_key) {
        return Err("PFX certificate does not match its private key".to_string());
    }

    Ok(LoadedPfx {
        certificate,
        private_key,
    })
}

fn create_pfx_der(
    certificate: &X509,
    private_key: &PKey<Private>,
    friendly_name: &str,
    password: &str,
) -> Result<Vec<u8>, String> {
    let mut builder = Pkcs12::builder();

    builder
        .name(friendly_name)
        .pkey(private_key)
        .cert(certificate);

    let pfx = builder
        .build2(password)
        .map_err(|error| format!("failed to create PFX archive: {error}"))?;

    pfx.to_der()
        .map_err(|error| format!("failed to encode PFX archive: {error}"))
}

fn generate_serial_number() -> Result<Asn1Integer, String> {
    let mut serial = BigNum::new()
        .map_err(|error| format!("failed to allocate certificate serial number: {error}"))?;

    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .map_err(|error| format!("failed to generate certificate serial number: {error}"))?;

    serial
        .to_asn1_integer()
        .map_err(|error| format!("failed to encode certificate serial number: {error}"))
}

fn validate_options(options: &SelfSignedCertificateOptions) -> Result<(), String> {
    if options.common_name.trim().is_empty() {
        return Err("certificate common name cannot be empty".to_string());
    }

    if options.friendly_name.trim().is_empty() {
        return Err("PFX friendly name cannot be empty".to_string());
    }

    if options.validity_days == 0 {
        return Err("certificate validity must be at least one day".to_string());
    }

    if options.rsa_bits < 2048 {
        return Err("RSA key size must be at least 2048 bits".to_string());
    }

    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("PFX password cannot be empty".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SelfSignedCertificateOptions, create_self_signed_pfx, load_pfx_der};

    #[test]
    fn creates_and_loads_password_protected_pfx() {
        let options = SelfSignedCertificateOptions {
            rsa_bits: 2048,
            validity_days: 30,
            ..SelfSignedCertificateOptions::default()
        };

        let generated = create_self_signed_pfx(&options, "test-password")
            .expect("PFX generation should succeed");

        assert!(!generated.pfx_der.is_empty());

        let loaded =
            load_pfx_der(&generated.pfx_der, "test-password").expect("PFX loading should succeed");

        let certificate_public_key = loaded
            .certificate
            .public_key()
            .expect("certificate should contain a public key");

        assert!(certificate_public_key.public_eq(&loaded.private_key));
    }

    #[test]
    fn rejects_wrong_pfx_password() {
        let options = SelfSignedCertificateOptions {
            rsa_bits: 2048,
            validity_days: 30,
            ..SelfSignedCertificateOptions::default()
        };

        let generated = create_self_signed_pfx(&options, "correct-password")
            .expect("PFX generation should succeed");

        let result = load_pfx_der(&generated.pfx_der, "wrong-password");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_password() {
        let options = SelfSignedCertificateOptions::default();

        let result = create_self_signed_pfx(&options, "");

        assert!(result.is_err());
    }
}
