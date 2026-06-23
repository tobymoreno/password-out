use std::io::Read;

use anyhow::{Context as _, Result, bail};
use flate2::read::GzDecoder;
use x509_parser::parse_x509_certificate;

use crate::smartcard::piv::PivCertificate;

const MAX_DECOMPRESSED_CERTIFICATE_SIZE: u64 = 1024 * 1024;

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

pub fn display_certificate(certificate_der: &[u8]) -> Result<()> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("failed to parse DER X.509 certificate: {error}"))?;

    if !remaining.is_empty() {
        println!(
            "Warning: {} trailing byte(s) remained after X.509 parsing.",
            remaining.len()
        );
    }

    let validity = certificate.validity();
    let public_key = certificate.public_key();

    println!();
    println!("PIV Authentication certificate");
    println!("--------------------------------");
    println!("Subject: {}", certificate.subject());
    println!("Issuer: {}", certificate.issuer());
    println!(
        "Serial number: {}",
        certificate.tbs_certificate.raw_serial_as_string()
    );
    println!("Valid from: {}", validity.not_before);
    println!("Valid until: {}", validity.not_after);
    println!(
        "Signature algorithm: {}",
        certificate.signature_algorithm.algorithm
    );
    println!("Public-key algorithm: {}", public_key.algorithm.algorithm);
    println!(
        "Public-key data size: {} bytes",
        public_key.subject_public_key.data.len()
    );

    Ok(())
}
