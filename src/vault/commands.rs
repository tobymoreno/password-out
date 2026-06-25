use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use password_out::certificate::{
    PfxKeyProvider, SelfSignedCertificateOptions, create_self_signed_pfx, load_pfx, write_pfx,
};
use password_out::smartcard::{
    certificate::{decode_certificate, parse_certificate_info},
    pcsc::connect_first_card,
    piv::{PivSlot, read_certificate, select_piv},
    wrapping::wrap_key_with_cac_certificate,
};

use crate::hotkey;

use super::access::{CertificateVaultAccess, PasswordVaultAccess, VaultAccess};
use super::format::{CacKeyWrapper, CertificateBackend, VaultEnvelope, VaultUnlockMethod};
use super::service::{
    initialize_cac_vault, initialize_certificate_vault, initialize_password_vault,
    rotate_certificate_with_backup_password,
};
use super::{
    add_entry_with_access, list_entries_with_access, prompt_master_password,
    prompt_new_master_password, read_envelope, recover_vault_with_backup_password,
    remove_entry_with_access,
};

pub fn run_init(path: &Path) -> Result<(), String> {
    println!("Choose the vault unlock method:");
    println!("  1. Master password");
    println!("  2. CAC / PIV smart card");
    println!("  3. Software X.509 certificate (PFX)");

    let choice = prompt_text("Selection [1-3]: ")?;

    match choice.as_str() {
        "1" => run_init_password(path)?,
        "2" => run_init_cac(path)?,
        "3" => run_init_software_certificate(path)?,
        _ => {
            return Err("selection must be 1, 2, or 3".to_string());
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

fn run_init_software_certificate(path: &Path) -> Result<(), String> {
    println!();
    println!("Choose the software-certificate source:");
    println!("  1. Generate a new self-signed PFX");
    println!("  2. Use an existing PFX");

    let choice = prompt_text("Selection [1-2]: ")?;

    match choice.as_str() {
        "1" => run_init_generated_pfx(path),
        "2" => run_init_existing_pfx(path),
        _ => Err("selection must be 1 or 2".to_string()),
    }
}

fn run_init_generated_pfx(path: &Path) -> Result<(), String> {
    println!();

    let default_pfx_path = default_generated_pfx_path(path);
    let prompt = format!("PFX output path [{}]: ", default_pfx_path.display());
    let pfx_path = prompt_path_with_default(&prompt, &default_pfx_path)?;

    if pfx_path.exists() {
        return Err(format!(
            "refusing to overwrite existing PFX: {}",
            pfx_path.display()
        ));
    }

    ensure_parent_directory(&pfx_path)?;

    let common_name = prompt_text_with_default(
        "Certificate common name [PasswordOut Vault Key]: ",
        "PasswordOut Vault Key",
    )?;

    println!();
    println!("Create a password for the new PFX private key.");

    let pfx_password = prompt_new_secret("PFX password: ", "Confirm PFX password: ")?;

    let options = SelfSignedCertificateOptions {
        common_name: common_name.clone(),
        friendly_name: common_name,
        validity_days: 3650,
        rsa_bits: 3072,
    };

    let generated = create_self_signed_pfx(&options, pfx_password.as_str())?;
    write_pfx(&pfx_path, &generated.pfx_der)?;

    let loaded = load_pfx(&pfx_path, pfx_password.as_str())?;
    let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    println!();
    println!("Create a backup password.");
    println!("This password is required if the PFX is lost, damaged, or unavailable.");

    let backup_password = prompt_new_master_password()?;

    let result = initialize_certificate_vault(
        path,
        backup_password.as_str(),
        &provider,
        CertificateBackend::Pfx {
            suggested_filename: pfx_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        },
    );

    if result.is_err() {
        let _ = std::fs::remove_file(&pfx_path);
    }

    result?;

    println!();
    println!("Software certificate created at:");
    println!("  {}", pfx_path.display());
    println!("Keep the PFX and its password secure.");

    Ok(())
}

fn run_init_existing_pfx(path: &Path) -> Result<(), String> {
    println!();

    let pfx_path = PathBuf::from(prompt_text("Existing PFX path: ")?);

    if !pfx_path.is_file() {
        return Err(format!("PFX file does not exist: {}", pfx_path.display()));
    }

    let pfx_password = prompt_secret("PFX password: ")?;
    let loaded = load_pfx(&pfx_path, pfx_password.as_str())?;
    let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    println!();
    println!("Create a backup password.");
    println!("This password is required if the PFX is lost, damaged, or unavailable.");

    let backup_password = prompt_new_master_password()?;

    initialize_certificate_vault(
        path,
        backup_password.as_str(),
        &provider,
        CertificateBackend::Pfx {
            suggested_filename: pfx_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        },
    )
}

pub fn run_info(path: &Path) -> Result<(), String> {
    let envelope = read_envelope(path)?;
    envelope.validate()?;

    println!("PasswordOut vault information:");
    println!("  Path: {}", path.display());

    match envelope {
        VaultEnvelope::V1(version_1) => {
            println!("  Format version: {}", version_1.version);
            println!("  Unlock method: Master password");
            println!("  Payload cipher: {}", version_1.cipher.algorithm);
            println!("  Password KDF: {}", version_1.kdf.algorithm);
            println!("  Backup recovery: Not configured");
        }

        VaultEnvelope::V2(version_2) => {
            println!("  Format version: {}", version_2.version);
            println!("  Payload cipher: {}", version_2.cipher.algorithm);

            match version_2.unlock {
                VaultUnlockMethod::Password { wrapper } => {
                    println!("  Unlock method: Master password");
                    println!("  Password KDF: {}", wrapper.kdf.algorithm);
                    println!("  Backup recovery: Not configured");
                }

                VaultUnlockMethod::Cac {
                    cac_wrapper,
                    backup_wrapper,
                } => {
                    println!("  Unlock method: CAC / PIV smart card (legacy format)");
                    println!("  Certificate backend: CAC / PIV");
                    println!("  PIV slot: {}", cac_wrapper.slot);
                    println!("  Certificate SHA-256: {}", cac_wrapper.certificate_sha256);
                    println!("  Key-wrap algorithm: {}", cac_wrapper.algorithm);
                    println!("  Backup recovery: Configured");
                    println!("  Backup KDF: {}", backup_wrapper.kdf.algorithm);
                }

                VaultUnlockMethod::Certificate {
                    certificate_wrapper,
                    backup_wrapper,
                } => {
                    println!("  Unlock method: X.509 certificate");

                    match certificate_wrapper.backend {
                        CertificateBackend::Pfx { suggested_filename } => {
                            println!("  Certificate backend: Software PFX");

                            match suggested_filename {
                                Some(filename) => {
                                    println!("  Suggested PFX: {filename}");
                                }

                                None => {
                                    println!("  Suggested PFX: Not recorded");
                                }
                            }
                        }

                        CertificateBackend::Cac { slot } => {
                            println!("  Certificate backend: CAC / PIV");
                            println!("  PIV slot: {slot}");
                        }
                    }

                    println!(
                        "  Key-wrap algorithm: {}",
                        match certificate_wrapper.algorithm {
                            password_out::certificate::KeyWrapAlgorithm::RsaOaepSha256 => {
                                "rsa-oaep-sha256"
                            }
                        }
                    );

                    print_certificate_identity(&certificate_wrapper.identity)?;

                    println!("  Backup recovery: Configured");
                    println!("  Backup KDF: {}", backup_wrapper.kdf.algorithm);
                }
            }
        }
    }

    println!("  Entry count: Encrypted; unlock the vault to inspect entries");

    Ok(())
}

fn print_certificate_identity<T>(identity: &T) -> Result<(), String>
where
    T: serde::Serialize,
{
    let value = serde_json::to_value(identity)
        .map_err(|error| format!("failed to format certificate identity: {error}"))?;

    let object = value.as_object().ok_or_else(|| {
        "certificate identity has an invalid serialized representation".to_string()
    })?;

    print_identity_field(object, &["subject"], "Certificate subject");

    print_identity_field(object, &["issuer"], "Certificate issuer");

    print_identity_field(object, &["serial", "serial_number"], "Certificate serial");

    print_identity_field(
        object,
        &[
            "sha256",
            "sha256_fingerprint",
            "fingerprint_sha256",
            "certificate_sha256",
        ],
        "Certificate SHA-256",
    );

    print_identity_field(
        object,
        &["not_before", "valid_from"],
        "Certificate valid from",
    );

    print_identity_field(
        object,
        &["not_after", "valid_until"],
        "Certificate valid until",
    );

    Ok(())
}

fn print_identity_field(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    label: &str,
) {
    for key in keys {
        if let Some(value) = object.get(*key) {
            if let Some(text) = value.as_str() {
                println!("  {label}: {text}");
                return;
            }

            println!("  {label}: {value}");
            return;
        }
    }
}

pub fn run_rotate_certificate(path: &Path) -> Result<(), String> {
    println!("Rotate the certificate protecting this vault.");
    println!("The credential payload and backup password will remain unchanged.");
    println!();

    let backup_password = prompt_master_password("Backup password: ")?;

    println!();
    println!("Choose the replacement software-certificate source:");
    println!("  1. Generate a new self-signed PFX");
    println!("  2. Use an existing PFX");

    let choice = prompt_text("Selection [1-2]: ")?;

    match choice.as_str() {
        "1" => run_rotate_generated_pfx(path, backup_password.as_str()),

        "2" => run_rotate_existing_pfx(path, backup_password.as_str()),

        _ => Err("selection must be 1 or 2".to_string()),
    }
}

fn run_rotate_generated_pfx(vault_path: &Path, backup_password: &str) -> Result<(), String> {
    println!();

    let default_pfx_path = default_rotated_pfx_path(vault_path);

    let prompt = format!(
        "Replacement PFX output path [{}]: ",
        default_pfx_path.display()
    );

    let pfx_path = prompt_path_with_default(&prompt, &default_pfx_path)?;

    if pfx_path.exists() {
        return Err(format!(
            "refusing to overwrite existing PFX: {}",
            pfx_path.display()
        ));
    }

    ensure_parent_directory(&pfx_path)?;

    let common_name = prompt_text_with_default(
        "Certificate common name [PasswordOut Vault Key]: ",
        "PasswordOut Vault Key",
    )?;

    println!();
    println!("Create a password for the replacement PFX private key.");

    let pfx_password = prompt_new_secret("PFX password: ", "Confirm PFX password: ")?;

    let options = SelfSignedCertificateOptions {
        common_name: common_name.clone(),
        friendly_name: common_name,
        validity_days: 3650,
        rsa_bits: 3072,
    };

    let generated = create_self_signed_pfx(&options, pfx_password.as_str())?;

    write_pfx(&pfx_path, &generated.pfx_der)?;

    let loaded = load_pfx(&pfx_path, pfx_password.as_str())?;

    let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    let result = rotate_certificate_with_backup_password(
        vault_path,
        backup_password,
        &provider,
        CertificateBackend::Pfx {
            suggested_filename: pfx_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        },
    );

    if result.is_err() {
        let _ = std::fs::remove_file(&pfx_path);
    }

    result?;

    println!();
    println!("Certificate rotation successful.");
    println!("Replacement PFX:");
    println!("  {}", pfx_path.display());
    println!("The previous certificate no longer unlocks this vault.");
    println!("The backup password remains unchanged.");

    Ok(())
}

fn run_rotate_existing_pfx(vault_path: &Path, backup_password: &str) -> Result<(), String> {
    println!();

    let pfx_path = PathBuf::from(prompt_text("Replacement PFX path: ")?);

    if !pfx_path.is_file() {
        return Err(format!("PFX file does not exist: {}", pfx_path.display()));
    }

    let pfx_password = prompt_secret("Replacement PFX password: ")?;

    let loaded = load_pfx(&pfx_path, pfx_password.as_str())?;

    let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

    rotate_certificate_with_backup_password(
        vault_path,
        backup_password,
        &provider,
        CertificateBackend::Pfx {
            suggested_filename: pfx_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        },
    )?;

    println!();
    println!("Certificate rotation successful.");
    println!("Replacement PFX:");
    println!("  {}", pfx_path.display());
    println!("The previous certificate no longer unlocks this vault.");
    println!("The backup password remains unchanged.");

    Ok(())
}

pub fn run_recover(path: &Path) -> Result<(), String> {
    println!("Recovering the vault through its backup-password wrapper.");
    println!("The existing certificate/CAC protection will remain unchanged.");
    println!();

    let backup_password = prompt_master_password("Backup password: ")?;

    let payload = recover_vault_with_backup_password(path, backup_password.as_str())?;

    println!();
    println!("Vault recovery successful.");
    println!("  Entries recovered: {}", payload.entries.len());
    println!("  Vault protection: unchanged");

    Ok(())
}

pub fn run_add(path: &Path) -> Result<(), String> {
    let mut access = create_vault_access(path)?;

    let name = prompt_text("Entry name: ")?;
    let hotkey = hotkey::capture()?;
    let secret = prompt_secret("Password: ")?;

    add_entry_with_access(
        path,
        access.as_mut(),
        name.clone(),
        hotkey.clone(),
        secret.to_string(),
    )?;

    println!("Added entry:");
    println!("  {name}  {hotkey}");

    Ok(())
}

pub fn run_list(path: &Path) -> Result<(), String> {
    let mut access = create_vault_access(path)?;

    let entries = list_entries_with_access(path, access.as_mut())?;

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
    let mut access = create_vault_access(path)?;

    let entries = list_entries_with_access(path, access.as_mut())?;

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!("PasswordOut entries:");

    for (name, hotkey) in &entries {
        println!("  {name:<20} {hotkey}");
    }

    println!();

    let name = prompt_text("Entry name to remove: ")?;

    let (_, hotkey) = entries
        .iter()
        .find(|(entry_name, _)| entry_name == &name)
        .ok_or_else(|| format!("entry '{name}' was not found"))?;

    let confirmation = prompt_text(&format!(
        "Type REMOVE to delete '{}' ({}) permanently: ",
        name, hotkey
    ))?;

    if confirmation != "REMOVE" {
        println!("Removal cancelled.");
        return Ok(());
    }

    let (removed_name, removed_hotkey) = remove_entry_with_access(path, access.as_mut(), &name)?;

    println!("Removed entry:");
    println!("  {removed_name}  {removed_hotkey}");

    Ok(())
}

fn create_vault_access(path: &Path) -> Result<Box<dyn VaultAccess>, String> {
    let envelope = read_envelope(path)?;

    match envelope {
        VaultEnvelope::V1(_) => {
            let password = prompt_master_password("Master password: ")?;
            Ok(Box::new(PasswordVaultAccess::new(password)))
        }

        VaultEnvelope::V2(version_2) => match version_2.unlock {
            VaultUnlockMethod::Password { .. } => {
                let password = prompt_master_password("Master password: ")?;
                Ok(Box::new(PasswordVaultAccess::new(password)))
            }

            VaultUnlockMethod::Certificate {
                certificate_wrapper,
                ..
            } => create_certificate_vault_access(path, certificate_wrapper.backend),

            VaultUnlockMethod::Cac { .. } => Err(
                "this vault uses the legacy CAC format; CAC entry operations are not connected yet"
                    .to_string(),
            ),
        },
    }
}

fn create_certificate_vault_access(
    vault_path: &Path,
    backend: CertificateBackend,
) -> Result<Box<dyn VaultAccess>, String> {
    match backend {
        CertificateBackend::Pfx { suggested_filename } => {
            let default_path = suggested_pfx_path(vault_path, suggested_filename.as_deref());

            let prompt = format!("PFX path [{}]: ", default_path.display());
            let pfx_path = prompt_path_with_default(&prompt, &default_path)?;

            if !pfx_path.is_file() {
                return Err(format!("PFX file does not exist: {}", pfx_path.display()));
            }

            let password = prompt_secret("PFX password: ")?;
            let loaded = load_pfx(&pfx_path, password.as_str())?;
            let provider = PfxKeyProvider::from_loaded_pfx(loaded)?;

            Ok(Box::new(CertificateVaultAccess::new(provider)))
        }

        CertificateBackend::Cac { slot } => Err(format!(
            "this vault uses CAC slot {slot}; CAC entry operations are not connected yet"
        )),
    }
}

fn suggested_pfx_path(vault_path: &Path, suggested_filename: Option<&str>) -> PathBuf {
    match suggested_filename {
        Some(filename) => vault_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(filename),

        None => default_generated_pfx_path(vault_path),
    }
}

fn default_generated_pfx_path(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("pfx")
}

fn default_rotated_pfx_path(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("rotated.pfx")
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

fn prompt_path_with_default(prompt: &str, default: &Path) -> Result<PathBuf, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let mut value = String::new();

    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("failed to read input: {error}"))?;

    let value = value.trim();

    if value.is_empty() {
        return Ok(default.to_path_buf());
    }

    Ok(PathBuf::from(value))
}

fn prompt_text_with_default(prompt: &str, default: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let mut value = String::new();

    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("failed to read input: {error}"))?;

    let value = value.trim();

    if value.is_empty() {
        return Ok(default.to_string());
    }

    Ok(value.to_string())
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

fn prompt_new_secret(
    first_prompt: &str,
    confirmation_prompt: &str,
) -> Result<Zeroizing<String>, String> {
    let first = prompt_secret(first_prompt)?;
    let confirmation = prompt_secret(confirmation_prompt)?;

    if first.as_str() != confirmation.as_str() {
        return Err("passwords do not match".to_string());
    }

    Ok(first)
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
