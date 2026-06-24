use std::io::{self, Write};
use std::path::Path;

use zeroize::Zeroizing;

use password_out::smartcard::{
    certificate::{decode_certificate, parse_certificate_info},
    pcsc::connect_first_card,
    piv::{PivSlot, read_certificate, select_piv},
    wrapping::wrap_key_with_cac_certificate,
};

use crate::entries::{add_entry, list_entries, remove_entry};
use crate::hotkey;

use super::format::CacKeyWrapper;

use super::service::{initialize_cac_vault, initialize_password_vault};
use super::{load_vault, prompt_master_password, prompt_new_master_password, save_vault};

pub fn run_init(path: &Path) -> Result<(), String> {
    println!("Choose the vault unlock method:");
    println!("  1. Password");
    println!("  2. CAC");

    let choice = prompt_text("Selection [1-2]: ")?;

    match choice.as_str() {
        "1" => run_init_password(path)?,
        "2" => run_init_cac(path)?,
        _ => {
            return Err("selection must be 1 or 2".to_string());
        }
    }

    println!();
    println!("PasswordOut vault created at:");
    println!("  {}", path.display());

    Ok(())
}

fn run_init_password(path: &Path) -> Result<(), String> {
    let password = prompt_new_master_password()?;

    initialize_password_vault(path, password.as_str())
}

fn run_init_cac(path: &Path) -> Result<(), String> {
    println!();
    println!("Connecting to CAC...");

    let card =
        connect_first_card().map_err(|error| format!("failed to connect to CAC: {error}"))?;

    select_piv(&card).map_err(|error| format!("failed to select the PIV application: {error}"))?;

    println!();
    println!("Reading the current key-management certificate from slot 9D...");

    let piv_certificate = read_certificate(&card, PivSlot::KeyManagement)
        .map_err(|error| format!("failed to read the CAC key-management certificate: {error}"))?;

    let certificate_der = decode_certificate(&piv_certificate)
        .map_err(|error| format!("failed to decode the CAC key-management certificate: {error}"))?;

    let certificate_info = parse_certificate_info(PivSlot::KeyManagement, &certificate_der)
        .map_err(|error| format!("failed to parse the CAC key-management certificate: {error}"))?;

    if !certificate_info.suitable_for_key_management() {
        return Err(
            "the certificate in CAC slot 9D is not suitable for vault-key protection".to_string(),
        );
    }

    println!();
    println!("Selected CAC certificate:");
    println!("  Slot: 9D");
    println!("  Subject: {}", certificate_info.subject);
    println!("  Issuer: {}", certificate_info.issuer);
    println!("  Expires: {}", certificate_info.valid_until);
    println!("  SHA-256: {}", certificate_info.certificate_sha256);

    println!();
    println!("Create a backup password.");
    println!("This password is required if the CAC is lost, replaced, or unavailable.");

    let backup_password = prompt_new_master_password()?;

    initialize_cac_vault(path, backup_password.as_str(), |vault_key| {
        let wrapped =
            wrap_key_with_cac_certificate(&certificate_der, vault_key).map_err(|error| {
                format!("failed to wrap the vault key with the CAC certificate: {error}")
            })?;

        Ok(CacKeyWrapper {
            slot: wrapped.slot,
            certificate_sha256: wrapped.certificate_sha256,
            algorithm: wrapped.algorithm,
            wrapped_key: wrapped.wrapped_key,
        })
    })
}

pub fn run_add(path: &Path) -> Result<(), String> {
    let master_password = prompt_master_password("Master password: ")?;
    let mut payload = load_vault(path, master_password.as_str())?;

    let name = prompt_text("Entry name: ")?;
    let hotkey = hotkey::capture()?;
    let secret = prompt_secret("Password: ")?;

    add_entry(
        &mut payload,
        name.clone(),
        hotkey.clone(),
        secret.to_string(),
    )?;

    save_vault(path, &payload, master_password.as_str())?;

    println!("Added entry:");
    println!("  {name}  {hotkey}");

    Ok(())
}

pub fn run_list(path: &Path) -> Result<(), String> {
    let master_password = prompt_master_password("Master password: ")?;
    let payload = load_vault(path, master_password.as_str())?;
    let entries = list_entries(&payload);

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("PasswordOut entries:");

    for (name, hotkey) in entries {
        println!("  {name:<20} {hotkey}");
    }

    Ok(())
}

pub fn run_remove(path: &Path) -> Result<(), String> {
    let master_password = prompt_master_password("Master password: ")?;
    let mut payload = load_vault(path, master_password.as_str())?;

    if payload.entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("PasswordOut entries:");

    for (name, hotkey) in list_entries(&payload) {
        println!("  {name:<20} {hotkey}");
    }

    println!();

    let name = prompt_text("Entry name to remove: ")?;

    let entry = payload
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| format!("entry '{name}' was not found"))?;

    let confirmation = prompt_text(&format!(
        "Type REMOVE to delete '{}' ({}) permanently: ",
        entry.name, entry.hotkey
    ))?;

    if confirmation != "REMOVE" {
        println!("Removal cancelled.");
        return Ok(());
    }

    let removed = remove_entry(&mut payload, &name)?;

    save_vault(path, &payload, master_password.as_str())?;

    println!("Removed entry:");
    println!("  {}  {}", removed.name, removed.hotkey);

    Ok(())
}

fn prompt_text(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let mut value = String::new();

    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("failed to read input: {error}"))?;

    let value = value.trim().to_string();

    if value.is_empty() {
        return Err(format!(
            "{} cannot be empty",
            prompt.trim_end_matches(':').trim()
        ));
    }

    Ok(value)
}

fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let value =
        rpassword::read_password().map_err(|error| format!("failed to read password: {error}"))?;

    if value.is_empty() {
        return Err("password cannot be empty".to_string());
    }

    Ok(Zeroizing::new(value))
}
