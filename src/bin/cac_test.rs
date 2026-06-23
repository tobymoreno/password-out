use anyhow::Result;

use password_out::smartcard::{
    certificate::{decode_certificate, display_certificate},
    pcsc::connect_first_card,
    piv::{read_authentication_certificate, select_piv},
};

fn main() -> Result<()> {
    let card = connect_first_card()?;

    println!();
    println!("Selecting PIV application...");

    let select_response = select_piv(&card)?;

    println!("PIV SELECT response size: {} bytes", select_response.len());
    println!("PIV application selected.");

    println!();
    println!("Reading PIV Authentication certificate object 5FC105...");

    let piv_certificate = read_authentication_certificate(&card)?;

    println!(
        "Certificate encoding: {}",
        if piv_certificate.compressed {
            "gzip-compressed DER"
        } else {
            "DER"
        }
    );

    let certificate_der = decode_certificate(&piv_certificate)?;

    println!("Certificate DER size: {} bytes", certificate_der.len());

    display_certificate(&certificate_der)?;

    println!();
    println!("Phase 1 completed successfully.");
    println!("No PIN operation was performed.");
    println!("Certificate-chain trust has not yet been evaluated.");

    Ok(())
}
