use std::io::{self, Write};

use anyhow::{Context as _, Result, bail};
use rand::{RngCore, rngs::OsRng};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use password_out::smartcard::{
    certificate::{
        CertificateInfo, decode_certificate, display_certificate, parse_certificate_info,
    },
    pcsc::connect_first_card,
    piv::{PivCertificate, PivSlot, read_certificate, rsa_key_transport, select_piv, verify_pin},
    wrapping::decode_pkcs1_v15_encoded_message,
};

struct CertificateCandidate {
    piv_certificate: PivCertificate,
    certificate_der: Vec<u8>,
    info: CertificateInfo,
}

fn main() -> Result<()> {
    let card = connect_first_card()?;

    println!();
    println!("Selecting PIV application...");

    let select_response = select_piv(&card)?;

    println!("PIV SELECT response size: {} bytes", select_response.len());
    println!("PIV application selected.");

    let mut certificates = Vec::new();

    println!();
    println!("Reading standard PIV certificate slots...");

    for slot in PivSlot::ALL {
        println!();
        println!(
            "Checking {} certificate — slot {:02X}...",
            slot.name(),
            slot.key_reference()
        );

        let piv_certificate = match read_certificate(&card, slot) {
            Ok(certificate) => certificate,
            Err(error) => {
                println!("Not available: {error}");
                continue;
            }
        };

        let certificate_der = match decode_certificate(&piv_certificate) {
            Ok(certificate) => certificate,
            Err(error) => {
                println!("Unable to decode certificate: {error}");
                continue;
            }
        };

        let info = match parse_certificate_info(slot, &certificate_der) {
            Ok(info) => info,
            Err(error) => {
                println!("Unable to parse certificate: {error}");
                continue;
            }
        };

        println!(
            "Certificate encoding: {}",
            if piv_certificate.compressed {
                "gzip-compressed DER"
            } else {
                "DER"
            }
        );

        println!("Certificate DER size: {} bytes", certificate_der.len());

        display_certificate(&info);

        certificates.push(CertificateCandidate {
            piv_certificate,
            certificate_der,
            info,
        });
    }

    println!();
    println!("Certificate scan complete.");
    println!("Certificates found: {}", certificates.len());

    let suitable_indices: Vec<usize> = certificates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            candidate
                .info
                .suitable_for_key_management()
                .then_some(index)
        })
        .collect();

    println!(
        "Valid key-management candidates: {}",
        suitable_indices.len()
    );

    let selected_index = select_key_management_candidate(&certificates, &suitable_indices)?;

    let selected = &certificates[selected_index];

    println!();
    println!("Selected certificate");
    println!("--------------------");
    println!(
        "Slot: {:02X} ({})",
        selected.info.slot.key_reference(),
        selected.info.slot.name()
    );
    println!("Subject: {}", selected.info.subject);
    println!("Issuer: {}", selected.info.issuer);
    println!("Serial number: {}", selected.info.serial_number);
    println!("Valid until: {}", selected.info.valid_until);
    println!(
        "Public-key algorithm: {}",
        selected.info.public_key_algorithm
    );
    println!(
        "Certificate DER size: {} bytes",
        selected.certificate_der.len()
    );
    println!(
        "Certificate compressed on card: {}",
        selected.piv_certificate.compressed
    );

    println!();
    println!("The CAC PIN will be verified once.");
    println!("An incorrect PIN will not be retried automatically.");

    let pin = prompt_cac_pin()?;

    verify_pin(&card, pin.as_str()).context("CAC PIN verification failed")?;

    drop(pin);

    println!();
    println!("CAC PIN verified successfully.");

    run_rsa_key_transport_round_trip(&card, &selected.certificate_der)?;

    println!();
    println!("Certificate-chain trust has not yet been evaluated.");

    Ok(())
}

fn run_rsa_key_transport_round_trip(card: &pcsc::Card, certificate_der: &[u8]) -> Result<()> {
    println!();
    println!("Testing CAC RSA key transport...");
    println!("Generating a temporary random 256-bit test key.");

    let (remaining, certificate) = parse_x509_certificate(certificate_der).map_err(|error| {
        anyhow::anyhow!("failed to parse slot-9D certificate for RSA test: {error}")
    })?;

    if !remaining.is_empty() {
        bail!(
            "{} trailing byte(s) remained after parsing the slot-9D certificate",
            remaining.len()
        );
    }

    let public_key = RsaPublicKey::from_public_key_der(certificate.public_key().raw)
        .context("failed to decode RSA public key from slot-9D certificate")?;

    if public_key.size() != 256 {
        bail!(
            "CAC RSA key has a modulus size of {} bytes; \
             this test currently supports RSA-2048 only",
            public_key.size()
        );
    }

    let mut original_key = Zeroizing::new(vec![0_u8; 32]);
    OsRng.fill_bytes(original_key.as_mut_slice());

    let ciphertext = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, original_key.as_slice())
        .context("failed to encrypt the temporary key with the slot-9D public key")?;

    if ciphertext.len() != public_key.size() {
        bail!(
            "RSA ciphertext has invalid length {}; expected {}",
            ciphertext.len(),
            public_key.size()
        );
    }

    println!(
        "Encrypted temporary key into a {}-byte RSA ciphertext.",
        ciphertext.len()
    );
    println!("Requesting the slot-9D private-key operation from the CAC...");

    let encoded_message = rsa_key_transport(card, PivSlot::KeyManagement, &ciphertext)
        .context("CAC RSA key-transport operation failed")?;

    let recovered_key = Zeroizing::new(
        decode_pkcs1_v15_encoded_message(&encoded_message)
            .context("failed to decode the CAC RSA result")?,
    );

    if recovered_key.len() != 32 {
        bail!(
            "CAC recovered a key containing {} bytes; expected 32",
            recovered_key.len()
        );
    }

    if recovered_key.as_slice() != original_key.as_slice() {
        bail!(
            "CAC RSA key-transport test failed: recovered key does not match \
             the original temporary key"
        );
    }

    println!();
    println!("CAC RSA key-transport test passed.");
    println!("  Slot: 9D");
    println!("  Algorithm: RSAES-PKCS1-v1_5");
    println!("  Temporary key size: 256 bits");
    println!("  Recovered key matched: yes");
    println!("  Temporary key value was not displayed.");

    Ok(())
}

fn select_key_management_candidate(
    certificates: &[CertificateCandidate],
    suitable_indices: &[usize],
) -> Result<usize> {
    match suitable_indices {
        [] => {
            bail!(
                "no valid PIV key-management certificate was found \
                 in the standard slots"
            );
        }

        [only_index] => {
            let candidate = &certificates[*only_index];

            println!();
            println!(
                "Automatically selected the only valid key-management \
                 certificate in slot {:02X}.",
                candidate.info.slot.key_reference()
            );

            Ok(*only_index)
        }

        _ => prompt_for_candidate(certificates, suitable_indices),
    }
}

fn prompt_for_candidate(
    certificates: &[CertificateCandidate],
    suitable_indices: &[usize],
) -> Result<usize> {
    println!();
    println!("Available key-management certificates");
    println!("-------------------------------------");

    for (choice, certificate_index) in suitable_indices.iter().enumerate() {
        let candidate = &certificates[*certificate_index];

        println!();
        println!(
            "{}. Slot {:02X} — {}",
            choice + 1,
            candidate.info.slot.key_reference(),
            candidate.info.slot.name()
        );
        println!("   Subject: {}", candidate.info.subject);
        println!("   Issuer: {}", candidate.info.issuer);
        println!("   Serial: {}", candidate.info.serial_number);
        println!("   Expires: {}", candidate.info.valid_until);
        println!("   Algorithm: {}", candidate.info.public_key_algorithm);
    }

    loop {
        println!();
        println!("Select a certificate [1-{}]: ", suitable_indices.len());

        io::stdout()
            .flush()
            .context("failed to flush selection prompt")?;

        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .context("failed to read certificate selection")?;

        let choice = match input.trim().parse::<usize>() {
            Ok(choice) => choice,
            Err(_) => {
                println!("Enter a number from 1 to {}.", suitable_indices.len());
                continue;
            }
        };

        if !(1..=suitable_indices.len()).contains(&choice) {
            println!("Enter a number from 1 to {}.", suitable_indices.len());
            continue;
        }

        return Ok(suitable_indices[choice - 1]);
    }
}

fn prompt_cac_pin() -> Result<Zeroizing<String>> {
    print!("CAC PIN: ");

    io::stdout()
        .flush()
        .context("failed to flush CAC PIN prompt")?;

    let pin = rpassword::read_password().context("failed to read CAC PIN")?;

    if !(6..=8).contains(&pin.len()) {
        bail!("CAC PIN must contain between 6 and 8 digits");
    }

    if !pin.bytes().all(|value| value.is_ascii_digit()) {
        bail!("CAC PIN must contain only ASCII digits");
    }

    Ok(Zeroizing::new(pin))
}
