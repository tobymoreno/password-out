use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use password_out::certificate::{
    CacCertificateSource, CacKeyProvider, PfxKeyProvider, SelfSignedCertificateOptions,
    create_self_signed_pfx, load_pfx, write_pfx,
};
use password_out::smartcard::{
    certificate::{decode_certificate, parse_certificate_info},
    pcsc::connect_first_card,
    piv::{PivSlot, read_certificate, select_piv},
};

use crate::hotkey;

use super::access::{CertificateVaultAccess, PasswordVaultAccess, VaultAccess};
use super::format::{CertificateBackend, VaultEnvelope, VaultUnlockMethod};
use super::service::{
    initialize_certificate_vault, initialize_password_vault,
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

    let backup_password = prompt_new_secret("Backup password: ", "Confirm backup password: ")?;

    let certificate_source = CacCertificateSource::new(certificate_der)?;

    initialize_certificate_vault(
        path,
        backup_password.as_str(),
        &certificate_source,
        CertificateBackend::Cac {
            slot: "9D".to_string(),
        },
    )
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
    print!("{}", format_vault_info(path)?);
    Ok(())
}

fn format_vault_info(path: &Path) -> Result<String, String> {
    use std::fmt::Write as _;

    let envelope = read_envelope(path)?;
    envelope.validate()?;

    let mut output = String::new();

    writeln!(output, "PasswordOut vault information:")
        .map_err(|error| format!("failed to format vault information: {error}"))?;

    writeln!(output, "  Path: {}", path.display())
        .map_err(|error| format!("failed to format vault information: {error}"))?;

    match envelope {
        VaultEnvelope::V1(version_1) => {
            writeln!(output, "  Format version: {}", version_1.version)
                .map_err(|error| format!("failed to format vault information: {error}"))?;

            writeln!(output, "  Unlock method: Master password")
                .map_err(|error| format!("failed to format vault information: {error}"))?;

            writeln!(output, "  Payload cipher: {}", version_1.cipher.algorithm)
                .map_err(|error| format!("failed to format vault information: {error}"))?;

            writeln!(output, "  Password KDF: {}", version_1.kdf.algorithm)
                .map_err(|error| format!("failed to format vault information: {error}"))?;

            writeln!(output, "  Backup recovery: Not configured")
                .map_err(|error| format!("failed to format vault information: {error}"))?;
        }

        VaultEnvelope::V2(version_2) => {
            writeln!(output, "  Format version: {}", version_2.version)
                .map_err(|error| format!("failed to format vault information: {error}"))?;

            writeln!(output, "  Payload cipher: {}", version_2.cipher.algorithm)
                .map_err(|error| format!("failed to format vault information: {error}"))?;

            match version_2.unlock {
                VaultUnlockMethod::Password { wrapper } => {
                    writeln!(output, "  Unlock method: Master password")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Password KDF: {}", wrapper.kdf.algorithm)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Backup recovery: Not configured")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;
                }

                VaultUnlockMethod::Cac {
                    cac_wrapper,
                    backup_wrapper,
                } => {
                    writeln!(
                        output,
                        "  Unlock method: CAC / PIV smart card (legacy format)"
                    )
                    .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Certificate backend: CAC / PIV")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  PIV slot: {}", cac_wrapper.slot)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(
                        output,
                        "  Certificate SHA-256: {}",
                        cac_wrapper.certificate_sha256
                    )
                    .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Key-wrap algorithm: {}", cac_wrapper.algorithm)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Backup recovery: Configured")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Backup KDF: {}", backup_wrapper.kdf.algorithm)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;
                }

                VaultUnlockMethod::Certificate {
                    certificate_wrapper,
                    backup_wrapper,
                } => {
                    writeln!(output, "  Unlock method: X.509 certificate")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    match certificate_wrapper.backend {
                        CertificateBackend::Pfx { suggested_filename } => {
                            writeln!(output, "  Certificate backend: Software PFX").map_err(
                                |error| format!("failed to format vault information: {error}"),
                            )?;

                            match suggested_filename {
                                Some(filename) => {
                                    writeln!(output, "  Suggested PFX: {filename}").map_err(
                                        |error| {
                                            format!("failed to format vault information: {error}")
                                        },
                                    )?;
                                }

                                None => {
                                    writeln!(output, "  Suggested PFX: Not recorded").map_err(
                                        |error| {
                                            format!("failed to format vault information: {error}")
                                        },
                                    )?;
                                }
                            }
                        }

                        CertificateBackend::Cac { slot } => {
                            writeln!(output, "  Certificate backend: CAC / PIV").map_err(
                                |error| format!("failed to format vault information: {error}"),
                            )?;

                            writeln!(output, "  PIV slot: {slot}").map_err(|error| {
                                format!("failed to format vault information: {error}")
                            })?;
                        }
                    }

                    let algorithm = match certificate_wrapper.algorithm {
                        password_out::certificate::KeyWrapAlgorithm::RsaOaepSha256 => {
                            "rsa-oaep-sha256"
                        }
                        password_out::certificate::KeyWrapAlgorithm::RsaPkcs1v15 => {
                            "RSA-PKCS1-v1_5"
                        }
                    };

                    writeln!(output, "  Key-wrap algorithm: {algorithm}")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    let identity = certificate_wrapper.identity;

                    writeln!(output, "  Certificate subject: {}", identity.subject)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Certificate issuer: {}", identity.issuer)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Certificate serial: {}", identity.serial_number)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(
                        output,
                        "  Certificate SHA-256: {}",
                        identity.sha256_fingerprint
                    )
                    .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Certificate valid from: {}", identity.not_before)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Certificate valid until: {}", identity.not_after)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Backup recovery: Configured")
                        .map_err(|error| format!("failed to format vault information: {error}"))?;

                    writeln!(output, "  Backup KDF: {}", backup_wrapper.kdf.algorithm)
                        .map_err(|error| format!("failed to format vault information: {error}"))?;
                }
            }
        }
    }

    writeln!(
        output,
        "  Entry count: Encrypted; unlock the vault to inspect entries"
    )
    .map_err(|error| format!("failed to format vault information: {error}"))?;

    Ok(output)
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

pub fn load_payload_for_cli(path: &Path) -> Result<super::VaultPayload, String> {
    let mut access = create_vault_access(path)?;
    load_payload_with_access(path, access.as_mut())
}

fn load_payload_with_access(
    path: &Path,
    access: &mut dyn VaultAccess,
) -> Result<super::VaultPayload, String> {
    access.load(path)
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

        CertificateBackend::Cac { slot } => {
            if !slot.eq_ignore_ascii_case("9D") {
                return Err(format!("unsupported CAC slot '{slot}'; expected 9D"));
            }

            println!("Connecting to CAC slot 9D...");
            println!("The PIN will be verified once. Incorrect PINs are not retried.");

            let pin = prompt_secret("CAC PIN: ")?;
            let provider = CacKeyProvider::connect(pin.as_str())?;

            Ok(Box::new(CertificateVaultAccess::new(provider)))
        }
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

#[cfg(test)]
mod vault_info_tests {
    use super::*;
    use crate::vault::{VaultEntry, VaultPayload};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_directory(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();

        std::env::temp_dir().join(format!(
            "password-out-{name}-{}-{timestamp}",
            std::process::id()
        ))
    }

    #[test]
    fn listener_loader_returns_payload_from_injected_access() {
        let path = PathBuf::from("unused-test-vault.json");

        let expected = VaultPayload {
            entries: vec![VaultEntry {
                name: "listener-user".to_string(),
                hotkey: "CTRL+ALT+1".to_string(),
                secret: "listener-secret".to_string(),
            }],
        };

        let mut access = crate::vault::access::InMemoryVaultAccess::new(expected.clone());

        let loaded =
            load_payload_with_access(&path, &mut access).expect("listener payload should load");

        assert_eq!(loaded, expected);
        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 0);
    }

    #[test]
    fn listener_loader_propagates_access_failure() {
        let path = PathBuf::from("unused-test-vault.json");

        let mut access = crate::vault::access::InMemoryVaultAccess::new(VaultPayload::default());

        access.fail_next_load("listener unlock failed");

        let error = load_payload_with_access(&path, &mut access)
            .expect_err("listener load failure should propagate");

        assert_eq!(error, "listener unlock failed");
        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 0);
    }

    #[test]
    fn formats_password_vault_information_without_exposing_password() {
        let test_directory = unique_test_directory("vault-info-password");
        let vault_path = test_directory.join("vault.json");
        let master_password = "master-password-must-not-appear";

        initialize_password_vault(&vault_path, master_password)
            .expect("password vault initialization should succeed");

        let output = format_vault_info(&vault_path).expect("vault information should format");

        assert!(output.contains("PasswordOut vault information:"));
        assert!(output.contains("Format version: 2"));
        assert!(output.contains("Unlock method: Master password"));
        assert!(output.contains("Payload cipher: xchacha20poly1305"));
        assert!(output.contains("Password KDF: argon2id"));
        assert!(output.contains("Backup recovery: Not configured"));
        assert!(output.contains("Entry count: Encrypted; unlock the vault to inspect entries"));

        assert!(!output.contains(master_password));

        let _ = std::fs::remove_dir_all(test_directory);
    }

    #[test]
    fn formats_pfx_vault_information_without_exposing_passwords() {
        let test_directory = unique_test_directory("vault-info-pfx");
        let vault_path = test_directory.join("vault.json");
        let pfx_path = test_directory.join("vault-info-test.pfx");

        let pfx_password = "pfx-password-must-not-appear";
        let backup_password = "backup-password-must-not-appear";

        let options = SelfSignedCertificateOptions {
            common_name: "PasswordOut Vault Info Test".to_string(),
            friendly_name: "PasswordOut Vault Info Test".to_string(),
            validity_days: 365,
            rsa_bits: 2048,
        };

        let generated = create_self_signed_pfx(&options, pfx_password)
            .expect("self-signed PFX generation should succeed");

        write_pfx(&pfx_path, &generated.pfx_der).expect("PFX file should be written");

        let loaded = load_pfx(&pfx_path, pfx_password).expect("PFX file should load");

        let provider =
            PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider should initialize");

        initialize_certificate_vault(
            &vault_path,
            backup_password,
            &provider,
            CertificateBackend::Pfx {
                suggested_filename: Some("vault-info-test.pfx".to_string()),
            },
        )
        .expect("certificate vault initialization should succeed");

        let output = format_vault_info(&vault_path).expect("vault information should format");

        assert!(output.contains("Format version: 2"));
        assert!(output.contains("Unlock method: X.509 certificate"));
        assert!(output.contains("Certificate backend: Software PFX"));
        assert!(output.contains("Suggested PFX: vault-info-test.pfx"));
        assert!(output.contains("Key-wrap algorithm: rsa-oaep-sha256"));
        assert!(output.contains("Certificate subject: CN=PasswordOut Vault Info Test"));
        assert!(output.contains("Certificate SHA-256:"));
        assert!(output.contains("Backup recovery: Configured"));
        assert!(output.contains("Backup KDF: argon2id"));

        assert!(!output.contains(pfx_password));
        assert!(!output.contains(backup_password));

        let _ = std::fs::remove_dir_all(test_directory);
    }
}
