use sha2::{Digest, Sha256};
use std::io::Read;

use anyhow::{Context as _, Result, bail};
use flate2::read::GzDecoder;
use x509_parser::parse_x509_certificate;

use crate::smartcard::piv::{PivCertificate, PivSlot};

const MAX_DECOMPRESSED_CERTIFICATE_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub slot: PivSlot,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_until: String,
    pub currently_valid: bool,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_size_bytes: usize,
    pub digital_signature: bool,
    pub key_encipherment: bool,
    pub key_agreement: bool,
    pub certificate_sha256: String,
}

impl CertificateInfo {
    pub fn suitable_for_key_management(&self) -> bool {
        self.slot == PivSlot::KeyManagement
            && self.currently_valid
            && (self.key_encipherment || self.key_agreement)
    }
}

pub fn decode_certificate(piv_certificate: &PivCertificate) -> Result<Vec<u8>> {
    if !piv_certificate.compressed {
        return Ok(piv_certificate.encoded_certificate.clone());
    }

    let decoder = GzDecoder::new(piv_certificate.encoded_certificate.as_slice());
    let mut limited_decoder = decoder.take(MAX_DECOMPRESSED_CERTIFICATE_SIZE);
    let mut certificate_der = Vec::new();

    limited_decoder
        .read_to_end(&mut certificate_der)
        .context("failed to decompress the PIV certificate")?;

    if certificate_der.is_empty() {
        bail!("decompressed PIV certificate was empty");
    }

    Ok(certificate_der)
}

pub fn parse_certificate_info(slot: PivSlot, certificate_der: &[u8]) -> Result<CertificateInfo> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("failed to parse DER X.509 certificate: {error}"))?;

    if !remaining.is_empty() {
        bail!(
            "{} trailing byte(s) remained after X.509 parsing",
            remaining.len()
        );
    }

    let validity = certificate.validity();
    let public_key = certificate.public_key();

    let key_usage = certificate
        .key_usage()
        .context("failed to parse X.509 key-usage extension")?;

    let digital_signature = key_usage
        .as_ref()
        .is_some_and(|usage| usage.value.digital_signature());

    let key_encipherment = key_usage
        .as_ref()
        .is_some_and(|usage| usage.value.key_encipherment());

    let key_agreement = key_usage
        .as_ref()
        .is_some_and(|usage| usage.value.key_agreement());

    let certificate_sha256 = sha256_fingerprint(certificate_der);

    Ok(CertificateInfo {
        slot,
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        serial_number: certificate.tbs_certificate.raw_serial_as_string(),
        valid_from: validity.not_before.to_string(),
        valid_until: validity.not_after.to_string(),
        currently_valid: validity.is_valid(),
        signature_algorithm: certificate.signature_algorithm.algorithm.to_string(),
        public_key_algorithm: public_key.algorithm.algorithm.to_string(),
        public_key_size_bytes: public_key.subject_public_key.data.len(),
        digital_signature,
        key_encipherment,
        key_agreement,
        certificate_sha256,
    })
}

pub fn display_certificate(info: &CertificateInfo) {
    println!();
    println!(
        "{} certificate — slot {:02X}",
        info.slot.name(),
        info.slot.key_reference()
    );
    println!("--------------------------------");
    println!("Subject: {}", info.subject);
    println!("Issuer: {}", info.issuer);
    println!("Serial number: {}", info.serial_number);
    println!("Valid from: {}", info.valid_from);
    println!("Valid until: {}", info.valid_until);
    println!("Currently valid: {}", info.currently_valid);
    println!("Signature algorithm: {}", info.signature_algorithm);
    println!("Public-key algorithm: {}", info.public_key_algorithm);
    println!("Public-key data size: {} bytes", info.public_key_size_bytes);
    println!("Digital signature: {}", info.digital_signature);
    println!("Key encipherment: {}", info.key_encipherment);
    println!("Key agreement: {}", info.key_agreement);

    println!("SHA-256 fingerprint: {}", info.certificate_sha256);
}

pub fn sha256_fingerprint(certificate_der: &[u8]) -> String {
    let digest = Sha256::digest(certificate_der);

    digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
