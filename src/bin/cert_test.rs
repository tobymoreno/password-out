use std::path::PathBuf;

use password_out::certificate::{
    SelfSignedCertificateOptions, certificate_identity, create_self_signed_pfx, load_pfx, write_pfx,
};

fn main() -> Result<(), String> {
    let output_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("build/test/password-out-test.pfx"));

    let password = rpassword::prompt_password("PFX password: ")
        .map_err(|error| format!("failed to read PFX password: {error}"))?;

    if password.is_empty() {
        return Err("PFX password cannot be empty".to_string());
    }

    let options = SelfSignedCertificateOptions {
        common_name: "PasswordOut Test Vault Key".to_string(),
        friendly_name: "PasswordOut Test Vault Key".to_string(),
        validity_days: 30,
        rsa_bits: 2048,
    };

    let generated = create_self_signed_pfx(&options, &password)?;

    write_pfx(&output_path, &generated.pfx_der)?;

    let loaded = load_pfx(&output_path, &password)?;

    let identity = certificate_identity(&loaded.certificate)?;

    println!("Created PFX: {}", output_path.display());
    println!("Subject: {}", identity.subject);
    println!("Issuer: {}", identity.issuer);
    println!("Serial: {}", identity.serial_number);
    println!("Valid from: {}", identity.not_before);
    println!("Valid until: {}", identity.not_after);
    println!("SHA-256: {}", identity.sha256_fingerprint);

    Ok(())
}
