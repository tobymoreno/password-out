use std::path::Path;

use super::{VaultPayload, decrypt_payload, encrypt_payload, read_envelope, write_envelope};

pub fn initialize_vault(path: &Path, master_password: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("vault already exists at '{}'", path.display()));
    }

    let payload = VaultPayload::default();
    let envelope = encrypt_payload(&payload, master_password)?;

    write_envelope(path, &envelope)
}

pub fn load_vault(path: &Path, master_password: &str) -> Result<VaultPayload, String> {
    let envelope = read_envelope(path)?;
    decrypt_payload(&envelope, master_password)
}

pub fn save_vault(
    path: &Path,
    payload: &VaultPayload,
    master_password: &str,
) -> Result<(), String> {
    let envelope = encrypt_payload(payload, master_password)?;
    write_envelope(path, &envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::add_entry;

    #[test]
    fn initializes_loads_and_saves_vault() {
        let test_dir =
            std::env::temp_dir().join(format!("password-out-service-test-{}", std::process::id()));
        let path = test_dir.join("vault.json");
        let password = "correct horse battery staple";

        initialize_vault(&path, password).expect("vault initialization should succeed");

        let mut payload = load_vault(&path, password).expect("vault load should succeed");

        assert!(payload.entries.is_empty());

        add_entry(
            &mut payload,
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
        )
        .expect("entry should be added");

        save_vault(&path, &payload, password).expect("vault save should succeed");

        let loaded = load_vault(&path, password).expect("saved vault should load");

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

        initialize_vault(&path, password).expect("first initialization should succeed");

        let result = initialize_vault(&path, password);

        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
