use std::io::{self, Write};

use anyhow::{Context as _, Result, bail};

use zeroize::Zeroizing;

use password_out::smartcard::{
    certificate::{
        CertificateInfo, decode_certificate, display_certificate, parse_certificate_info,
    },
    pcsc::connect_first_card,
    piv::{PivCertificate, PivSlot, read_certificate, select_piv, verify_pin},
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
    println!("No vault key was encrypted or decrypted.");
    println!("Certificate-chain trust has not yet been evaluated.");

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
