use std::io::{self, Write};
use std::path::Path;

use zeroize::Zeroizing;

use crate::entries::{add_entry, list_entries, remove_entry};
use crate::hotkey;

use super::{
    initialize_vault, load_vault, prompt_master_password, prompt_new_master_password, save_vault,
};

pub fn run_init(path: &Path) -> Result<(), String> {
    let password = prompt_new_master_password()?;

    initialize_vault(path, password.as_str())?;

    println!("PasswordOut vault created at:");
    println!("  {}", path.display());

    Ok(())
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
