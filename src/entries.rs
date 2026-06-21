use crate::vault::{VaultEntry, VaultPayload};

pub fn add_entry(
    payload: &mut VaultPayload,
    name: String,
    hotkey: String,
    secret: String,
) -> Result<(), String> {
    validate_name(&name)?;
    validate_hotkey(&hotkey)?;
    validate_secret(&secret)?;

    if payload.contains_name(&name) {
        return Err(format!("an entry named '{name}' already exists"));
    }

    if payload
        .entries
        .iter()
        .any(|entry| entry.hotkey.eq_ignore_ascii_case(&hotkey))
    {
        return Err(format!("hotkey '{hotkey}' is already assigned"));
    }

    payload.entries.push(VaultEntry {
        name,
        hotkey,
        secret,
    });

    payload
        .entries
        .sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));

    Ok(())
}

pub fn remove_entry(payload: &mut VaultPayload, name: &str) -> Result<VaultEntry, String> {
    let index = payload
        .entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| format!("entry '{name}' was not found"))?;

    Ok(payload.entries.remove(index))
}

pub fn list_entries(payload: &VaultPayload) -> Vec<(&str, &str)> {
    payload
        .entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.hotkey.as_str()))
        .collect()
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("entry name cannot be empty".to_string());
    }

    if name.contains('\n') || name.contains('\r') {
        return Err("entry name cannot contain line breaks".to_string());
    }

    Ok(())
}

fn validate_hotkey(hotkey: &str) -> Result<(), String> {
    if hotkey.trim().is_empty() {
        return Err("entry hotkey cannot be empty".to_string());
    }

    if hotkey.contains('\n') || hotkey.contains('\r') {
        return Err("entry hotkey cannot contain line breaks".to_string());
    }

    Ok(())
}

fn validate_secret(secret: &str) -> Result<(), String> {
    if secret.is_empty() {
        return Err("entry secret cannot be empty".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_and_lists_entries() {
        let mut payload = VaultPayload::default();

        add_entry(
            &mut payload,
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
        )
        .expect("entry should be added");

        assert_eq!(list_entries(&payload), vec![("admin01", "CTRL+ALT+1")]);
    }

    #[test]
    fn rejects_duplicate_names_and_hotkeys() {
        let mut payload = VaultPayload::default();

        add_entry(
            &mut payload,
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "first".to_string(),
        )
        .expect("first entry should be added");

        assert!(
            add_entry(
                &mut payload,
                "admin01".to_string(),
                "CTRL+ALT+2".to_string(),
                "second".to_string(),
            )
            .is_err()
        );

        assert!(
            add_entry(
                &mut payload,
                "admin02".to_string(),
                "ctrl+alt+1".to_string(),
                "third".to_string(),
            )
            .is_err()
        );
    }

    #[test]
    fn removes_entries() {
        let mut payload = VaultPayload {
            entries: vec![VaultEntry {
                name: "admin01".to_string(),
                hotkey: "CTRL+ALT+1".to_string(),
                secret: "example-secret".to_string(),
            }],
        };

        let removed = remove_entry(&mut payload, "admin01").expect("entry should be removed");

        assert_eq!(removed.name, "admin01");
        assert_eq!(removed.hotkey, "CTRL+ALT+1");
        assert_eq!(removed.secret, "example-secret");
        assert!(payload.entries.is_empty());
    }
}
