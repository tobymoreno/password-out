use std::path::Path;

use crate::entries::{add_entry, list_entries, remove_entry};

use super::access::VaultAccess;

/// Adds an entry through an injected vault-access implementation.
pub fn add_entry_with_access(
    path: &Path,
    access: &mut dyn VaultAccess,
    name: String,
    hotkey: String,
    secret: String,
) -> Result<(), String> {
    let mut payload = access.load(path)?;

    add_entry(&mut payload, name, hotkey, secret)?;

    access.save(path, &payload)
}

/// Returns entry names and hotkeys through an injected vault-access
/// implementation.
///
/// Secrets are never returned by this operation.
pub fn list_entries_with_access(
    path: &Path,
    access: &mut dyn VaultAccess,
) -> Result<Vec<(String, String)>, String> {
    let payload = access.load(path)?;

    Ok(list_entries(&payload)
        .into_iter()
        .map(|(name, hotkey)| (name.to_string(), hotkey.to_string()))
        .collect())
}

/// Removes an entry through an injected vault-access implementation.
pub fn remove_entry_with_access(
    path: &Path,
    access: &mut dyn VaultAccess,
    name: &str,
) -> Result<(String, String), String> {
    let mut payload = access.load(path)?;

    let removed = remove_entry(&mut payload, name)?;

    let result = (removed.name.clone(), removed.hotkey.clone());

    access.save(path, &payload)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{add_entry_with_access, list_entries_with_access, remove_entry_with_access};
    use crate::vault::access::InMemoryVaultAccess;
    use crate::vault::format::{VaultEntry, VaultPayload};

    fn test_path() -> &'static Path {
        Path::new("unused-vault.json")
    }

    fn payload_with_entry() -> VaultPayload {
        VaultPayload {
            settings: Default::default(),
            entries: vec![VaultEntry {
                name: "GitHub".to_string(),
                hotkey: "CTRL+ALT+G".to_string(),
                secret: "github-secret".to_string(),
            }],
        }
    }

    #[test]
    fn add_entry_loads_and_saves_once() {
        let mut access = InMemoryVaultAccess::default();

        add_entry_with_access(
            test_path(),
            &mut access,
            "GitLab".to_string(),
            "CTRL+ALT+L".to_string(),
            "gitlab-secret".to_string(),
        )
        .expect("entry should be added");

        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 1);
        assert_eq!(access.payload().entries.len(), 1);
        assert_eq!(access.payload().entries[0].name, "GitLab");
        assert_eq!(access.payload().entries[0].hotkey, "CTRL+ALT+L");
        assert_eq!(access.payload().entries[0].secret, "gitlab-secret");
    }

    #[test]
    fn add_entry_does_not_save_when_load_fails() {
        let mut access = InMemoryVaultAccess::default();
        access.fail_next_load("simulated load failure");

        let error = add_entry_with_access(
            test_path(),
            &mut access,
            "GitLab".to_string(),
            "CTRL+ALT+L".to_string(),
            "gitlab-secret".to_string(),
        )
        .expect_err("add should fail");

        assert_eq!(error, "simulated load failure");
        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 0);
        assert!(access.payload().entries.is_empty());
    }

    #[test]
    fn add_entry_reports_save_failure() {
        let mut access = InMemoryVaultAccess::default();
        access.fail_next_save("simulated save failure");

        let error = add_entry_with_access(
            test_path(),
            &mut access,
            "GitLab".to_string(),
            "CTRL+ALT+L".to_string(),
            "gitlab-secret".to_string(),
        )
        .expect_err("add should fail");

        assert_eq!(error, "simulated save failure");
        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 1);

        // The failed save must not mutate the persisted in-memory payload.
        assert!(access.payload().entries.is_empty());
    }

    #[test]
    fn list_entries_returns_only_names_and_hotkeys() {
        let mut access = InMemoryVaultAccess::new(payload_with_entry());

        let entries =
            list_entries_with_access(test_path(), &mut access).expect("entries should load");

        assert_eq!(
            entries,
            vec![("GitHub".to_string(), "CTRL+ALT+G".to_string(),)]
        );

        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 0);
    }

    #[test]
    fn remove_entry_loads_and_saves_once() {
        let mut access = InMemoryVaultAccess::new(payload_with_entry());

        let removed = remove_entry_with_access(test_path(), &mut access, "GitHub")
            .expect("entry should be removed");

        assert_eq!(removed, ("GitHub".to_string(), "CTRL+ALT+G".to_string(),));

        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 1);
        assert!(access.payload().entries.is_empty());
    }

    #[test]
    fn remove_missing_entry_does_not_save() {
        let mut access = InMemoryVaultAccess::new(payload_with_entry());

        let error = remove_entry_with_access(test_path(), &mut access, "Missing")
            .expect_err("remove should fail");

        assert_eq!(error, "entry 'Missing' was not found");
        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 0);
        assert_eq!(access.payload().entries.len(), 1);
    }
}
