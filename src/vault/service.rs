use std::path::Path;

use zeroize::Zeroize;

use super::crypto::{create_password_wrapper, encrypt_payload_with_key, generate_vault_key};
use super::format::{
    CURRENT_VAULT_FORMAT_VERSION, CacKeyWrapper, VaultEnvelope, VaultEnvelopeV2, VaultUnlockMethod,
};
use super::{VaultPayload, decrypt_payload, encrypt_payload, read_envelope, write_envelope};

/// Creates a password-unlocked vault.
///
/// New vaults use the version-2 format:
///
/// - a random vault key encrypts the payload;
/// - Argon2id protects the random vault key.
pub fn initialize_password_vault(path: &Path, master_password: &str) -> Result<(), String> {
    ensure_vault_does_not_exist(path)?;

    let payload = VaultPayload::default();
    let envelope = encrypt_payload(&payload, master_password)?;

    write_envelope(path, &envelope)
}

/// Creates a CAC-unlocked vault with a required backup password.
///
/// The vault payload is encrypted with a random vault key. That key is:
///
/// - wrapped using the selected CAC slot-9D certificate; and
/// - wrapped again using the Argon2id-derived backup-password key.
///
/// The callback keeps the vault service independent from PC/SC and
/// smart-card certificate handling.
pub fn initialize_cac_vault<F>(
    path: &Path,
    backup_password: &str,
    wrap_with_cac: F,
) -> Result<(), String>
where
    F: FnOnce(&[u8]) -> Result<CacKeyWrapper, String>,
{
    ensure_vault_does_not_exist(path)?;

    let payload = VaultPayload::default();
    let mut vault_key = generate_vault_key();

    let result = (|| {
        let cipher = encrypt_payload_with_key(&payload, &vault_key)?;

        let cac_wrapper = wrap_with_cac(&vault_key)?;
        cac_wrapper.validate()?;

        let backup_wrapper = create_password_wrapper(&vault_key, backup_password)?;

        let envelope = VaultEnvelope::V2(VaultEnvelopeV2 {
            version: CURRENT_VAULT_FORMAT_VERSION,
            unlock: VaultUnlockMethod::Cac {
                cac_wrapper,
                backup_wrapper,
            },
            cipher,
        });

        envelope.validate()?;
        write_envelope(path, &envelope)
    })();

    vault_key.zeroize();

    result
}

/// Loads a password-unlocked vault.
///
/// This supports:
///
/// - existing version-1 password vaults;
/// - version-2 password vaults.
///
/// CAC vaults must use either the CAC unlock flow or the backup-password
/// recovery flow.
pub fn load_password_vault(path: &Path, master_password: &str) -> Result<VaultPayload, String> {
    let envelope = read_envelope(path)?;

    match &envelope {
        VaultEnvelope::V1(_) => decrypt_payload(&envelope, master_password),

        VaultEnvelope::V2(version_2) => match &version_2.unlock {
            VaultUnlockMethod::Password { .. } => decrypt_payload(&envelope, master_password),

            VaultUnlockMethod::Cac { .. } => Err(
                "this vault uses CAC unlock; use the CAC unlock or backup recovery command"
                    .to_string(),
            ),
        },
    }
}

/// Saves a password-unlocked vault.
///
/// This creates a new random vault key and a new password wrapper each time.
pub fn save_password_vault(
    path: &Path,
    payload: &VaultPayload,
    master_password: &str,
) -> Result<(), String> {
    let existing = read_envelope(path)?;

    match existing {
        VaultEnvelope::V1(_) => {
            // Saving an existing version-1 password vault automatically
            // migrates it to the version-2 password-wrapper format.
        }

        VaultEnvelope::V2(ref version_2) => {
            if matches!(version_2.unlock, VaultUnlockMethod::Cac { .. }) {
                return Err(
                    "cannot save a CAC vault through the password-only save path".to_string(),
                );
            }
        }
    }

    let envelope = encrypt_payload(payload, master_password)?;

    write_envelope(path, &envelope)
}

/// Backward-compatible name used by the existing CLI.
///
/// This currently means password-based loading.
pub fn load_vault(path: &Path, master_password: &str) -> Result<VaultPayload, String> {
    load_password_vault(path, master_password)
}

/// Backward-compatible name used by the existing CLI.
///
/// This currently means password-based saving.
pub fn save_vault(
    path: &Path,
    payload: &VaultPayload,
    master_password: &str,
) -> Result<(), String> {
    save_password_vault(path, payload, master_password)
}

fn ensure_vault_does_not_exist(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!("vault already exists at '{}'", path.display()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::add_entry;
    use crate::vault::format::{VAULT_FORMAT_VERSION_V2, VaultEnvelope, VaultUnlockMethod};
    use crate::vault::read_envelope;

    #[test]
    fn initializes_loads_and_saves_password_vault() {
        let test_dir =
            std::env::temp_dir().join(format!("password-out-service-test-{}", std::process::id()));

        let path = test_dir.join("vault.json");
        let password = "correct horse battery staple";

        initialize_password_vault(&path, password).expect("vault initialization should succeed");

        let envelope = read_envelope(&path).expect("vault envelope should load");

        match envelope {
            VaultEnvelope::V2(version_2) => {
                assert_eq!(version_2.version, VAULT_FORMAT_VERSION_V2);

                assert!(matches!(
                    version_2.unlock,
                    VaultUnlockMethod::Password { .. }
                ));
            }

            VaultEnvelope::V1(_) => {
                panic!("new vault unexpectedly used version 1");
            }
        }

        let mut payload = load_password_vault(&path, password).expect("vault load should succeed");

        assert!(payload.entries.is_empty());

        add_entry(
            &mut payload,
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
        )
        .expect("entry should be added");

        save_password_vault(&path, &payload, password).expect("vault save should succeed");

        let loaded = load_password_vault(&path, password).expect("saved vault should load");

        assert_eq!(loaded, payload);

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn refuses_to_overwrite_existing_vault() {
        let test_dir = std::env::temp_dir().join(format!(
            "password-out-service-existing-test-{}",
            std::process::id()
        ));

        let path = test_dir.join("vault.json");
        let password = "correct horse battery staple";

        initialize_password_vault(&path, password).expect("first initialization should succeed");

        let result = initialize_password_vault(&path, password);

        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn compatibility_functions_use_password_mode() {
        let test_dir = std::env::temp_dir().join(format!(
            "password-out-service-compat-test-{}",
            std::process::id()
        ));

        let path = test_dir.join("vault.json");
        let password = "correct horse battery staple";

        initialize_password_vault(&path, password)
            .expect("compatibility initialization should succeed");

        let payload = load_vault(&path, password).expect("compatibility load should succeed");

        save_vault(&path, &payload, password).expect("compatibility save should succeed");

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
