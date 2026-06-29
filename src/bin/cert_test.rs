// src/bin/cert_test.rs
//
// Developer milestone harness for the PasswordOut software-certificate flow.
// This is intentionally separate from the production CLI.

use std::env;
use std::path::{Path, PathBuf};

use password_out::certificate::{
    PfxKeyProvider, SelfSignedCertificateOptions, certificate_identity, create_self_signed_pfx,
    load_pfx, write_pfx,
};

use password_out::vault_core::{
    CertificateBackend, initialize_certificate_vault, load_certificate_vault,
};

const DEFAULT_PFX_PATH: &str = "build/test/password-out-test.pfx";
const DEFAULT_VAULT_PATH: &str = "build/test/password-out-test.vault";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| {
            PathBuf::from(value)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "cert_test".to_string());

    let Some(command) = arguments.next() else {
        print_usage(&program);
        return Ok(());
    };

    match command.to_string_lossy().as_ref() {
        "create-pfx" => {
            let pfx_path = next_path(&mut arguments, DEFAULT_PFX_PATH);
            reject_extra_arguments(arguments)?;
            create_pfx(&pfx_path)
        }

        "inspect" => {
            let pfx_path = next_path(&mut arguments, DEFAULT_PFX_PATH);
            reject_extra_arguments(arguments)?;
            inspect_pfx(&pfx_path)
        }

        "create-vault" => {
            let pfx_path = next_path(&mut arguments, DEFAULT_PFX_PATH);
            let vault_path = next_path(&mut arguments, DEFAULT_VAULT_PATH);
            reject_extra_arguments(arguments)?;
            create_vault(&pfx_path, &vault_path)
        }

        "open-vault" => {
            let pfx_path = next_path(&mut arguments, DEFAULT_PFX_PATH);
            let vault_path = next_path(&mut arguments, DEFAULT_VAULT_PATH);
            reject_extra_arguments(arguments)?;
            open_vault(&pfx_path, &vault_path)
        }

        "milestone" => {
            let pfx_path = next_path(&mut arguments, DEFAULT_PFX_PATH);
            let vault_path = next_path(&mut arguments, DEFAULT_VAULT_PATH);
            reject_extra_arguments(arguments)?;
            run_milestone(&pfx_path, &vault_path)
        }

        "help" | "--help" | "-h" => {
            print_usage(&program);
            Ok(())
        }

        unknown => Err(format!(
            "unknown command '{unknown}'\n\nRun '{program} help' for usage."
        )),
    }
}

fn create_pfx(path: &Path) -> Result<(), String> {
    ensure_parent_directory(path)?;

    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing PFX: {}",
            path.display()
        ));
    }

    let password = prompt_confirmed_password("New PFX password: ", "Confirm PFX password: ")?;

    let options = SelfSignedCertificateOptions {
        common_name: "PasswordOut Test Vault Key".to_string(),
        friendly_name: "PasswordOut Test Vault Key".to_string(),
        validity_days: 30,
        rsa_bits: 2048,
    };

    let generated = create_self_signed_pfx(&options, &password)?;
    write_pfx(path, &generated.pfx_der)?;

    println!("Created PFX: {}", path.display());
    print_loaded_identity(path, &password)
}

fn inspect_pfx(path: &Path) -> Result<(), String> {
    ensure_file_exists(path, "PFX")?;

    let password = prompt_password("PFX password: ")?;
    print_loaded_identity(path, &password)
}

fn create_vault(pfx_path: &Path, vault_path: &Path) -> Result<(), String> {
    ensure_file_exists(pfx_path, "PFX")?;
    ensure_parent_directory(vault_path)?;

    if vault_path.exists() {
        return Err(format!(
            "refusing to overwrite existing vault: {}",
            vault_path.display()
        ));
    }

    let pfx_password = prompt_password("PFX password: ")?;
    let backup_password = prompt_confirmed_password(
        "New vault backup password: ",
        "Confirm vault backup password: ",
    )?;

    let loaded = load_pfx(pfx_path, &pfx_password)?;
    let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    let suggested_filename = pfx_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());

    initialize_certificate_vault(
        vault_path,
        &backup_password,
        &provider,
        CertificateBackend::Pfx { suggested_filename },
    )?;

    println!(
        "Created certificate-protected vault: {}",
        vault_path.display()
    );
    println!("Certificate source: {}", pfx_path.display());
    println!("Backup-password wrapper: present");

    Ok(())
}

fn open_vault(pfx_path: &Path, vault_path: &Path) -> Result<(), String> {
    ensure_file_exists(pfx_path, "PFX")?;
    ensure_file_exists(vault_path, "vault")?;

    let pfx_password = prompt_password("PFX password: ")?;

    let loaded = load_pfx(pfx_path, &pfx_password)?;
    let mut provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    let payload = load_certificate_vault(vault_path, &mut provider)?;

    println!(
        "Opened certificate-protected vault: {}",
        vault_path.display()
    );
    println!("Credential entries: {}", payload.entries.len());

    for entry in &payload.entries {
        match entry.expires_on.as_deref() {
            Some(expires_on) => {
                println!(
                    "- {}\\{} (expires {})",
                    entry.domain, entry.username, expires_on
                );
            }
            None => {
                println!("- {}\\{}", entry.domain, entry.username);
            }
        }
    }

    Ok(())
}

fn run_milestone(pfx_path: &Path, vault_path: &Path) -> Result<(), String> {
    if pfx_path.exists() {
        return Err(format!(
            "milestone PFX already exists: {}\nRemove it first or choose another path.",
            pfx_path.display()
        ));
    }

    if vault_path.exists() {
        return Err(format!(
            "milestone vault already exists: {}\nRemove it first or choose another path.",
            vault_path.display()
        ));
    }

    ensure_parent_directory(pfx_path)?;
    ensure_parent_directory(vault_path)?;

    println!("Milestone step 1/4: generate a password-protected PFX");
    let pfx_password = prompt_confirmed_password("New PFX password: ", "Confirm PFX password: ")?;

    let options = SelfSignedCertificateOptions {
        common_name: "PasswordOut Test Vault Key".to_string(),
        friendly_name: "PasswordOut Test Vault Key".to_string(),
        validity_days: 30,
        rsa_bits: 2048,
    };

    let generated = create_self_signed_pfx(&options, &pfx_password)?;
    write_pfx(pfx_path, &generated.pfx_der)?;
    println!("Created PFX: {}", pfx_path.display());

    println!("Milestone step 2/4: inspect certificate identity");
    print_loaded_identity(pfx_path, &pfx_password)?;

    println!("Milestone step 3/4: create a certificate-protected vault");
    let backup_password = prompt_confirmed_password(
        "New vault backup password: ",
        "Confirm vault backup password: ",
    )?;

    let loaded = load_pfx(pfx_path, &pfx_password)?;
    let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    initialize_certificate_vault(
        vault_path,
        &backup_password,
        &provider,
        CertificateBackend::Pfx {
            suggested_filename: pfx_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        },
    )?;
    println!("Created vault: {}", vault_path.display());

    println!("Milestone step 4/4: reopen and decrypt the vault");
    let loaded = load_pfx(pfx_path, &pfx_password)?;
    let mut provider = PfxKeyProvider::from_loaded_pfx(loaded)?;
    let payload = load_certificate_vault(vault_path, &mut provider)?;

    println!("Milestone passed.");
    println!("Decrypted credential entries: {}", payload.entries.len());

    Ok(())
}

fn print_loaded_identity(path: &Path, password: &str) -> Result<(), String> {
    let loaded = load_pfx(path, password)?;
    let identity = certificate_identity(&loaded.certificate)?;

    println!("Subject: {}", identity.subject);
    println!("Issuer: {}", identity.issuer);
    println!("Serial: {}", identity.serial_number);
    println!("Valid from: {}", identity.not_before);
    println!("Valid until: {}", identity.not_after);
    println!("SHA-256: {}", identity.sha256_fingerprint);

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String, String> {
    let password = rpassword::prompt_password(prompt)
        .map_err(|error| format!("failed to read password: {error}"))?;

    if password.is_empty() {
        return Err("password cannot be empty".to_string());
    }

    Ok(password)
}

fn prompt_confirmed_password(
    first_prompt: &str,
    confirmation_prompt: &str,
) -> Result<String, String> {
    let password = prompt_password(first_prompt)?;
    let confirmation = prompt_password(confirmation_prompt)?;

    if password != confirmation {
        return Err("passwords do not match".to_string());
    }

    Ok(password)
}

fn next_path(arguments: &mut impl Iterator<Item = std::ffi::OsString>, default: &str) -> PathBuf {
    arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn reject_extra_arguments(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), String> {
    if let Some(argument) = arguments.next() {
        return Err(format!(
            "unexpected argument: {}",
            argument.to_string_lossy()
        ));
    }

    Ok(())
}

fn ensure_parent_directory(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!("failed to create directory '{}': {error}", parent.display())
        })?;
    }

    Ok(())
}

fn ensure_file_exists(path: &Path, description: &str) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!(
            "{description} file does not exist: {}",
            path.display()
        ));
    }

    Ok(())
}

fn print_usage(program: &str) {
    println!(
        "\
PasswordOut software-certificate milestone harness

Usage:
  {program} create-pfx [PFX_PATH]
  {program} inspect [PFX_PATH]
  {program} create-vault [PFX_PATH] [VAULT_PATH]
  {program} open-vault [PFX_PATH] [VAULT_PATH]
  {program} milestone [PFX_PATH] [VAULT_PATH]

Defaults:
  PFX_PATH    {DEFAULT_PFX_PATH}
  VAULT_PATH  {DEFAULT_VAULT_PATH}

Examples:
  cargo run --bin cert_test -- create-pfx
  cargo run --bin cert_test -- inspect
  cargo run --bin cert_test -- create-vault
  cargo run --bin cert_test -- open-vault
  cargo run --bin cert_test -- milestone
"
    );
}
