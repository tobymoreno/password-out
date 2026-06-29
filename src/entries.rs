use crate::{
    expiration::validate_expiration_date,
    vault::{VaultEntry, VaultPayload},
};
use uuid::Uuid;

pub fn add_entry(
    payload: &mut VaultPayload,
    domain: String,
    username: String,
    hotkey: String,
    secret: String,
    expires_on: Option<String>,
) -> Result<(), String> {
    validate_domain(&domain)?;
    validate_username(&username)?;
    validate_hotkey(&hotkey)?;
    validate_secret(&secret)?;
    validate_expiration_date(expires_on.as_deref())?;

    if payload.contains_account(&domain, &username) {
        return Err(format!(
            "an entry for '{}\\{}' already exists",
            domain, username
        ));
    }

    if payload
        .entries
        .iter()
        .any(|entry| entry.hotkey.eq_ignore_ascii_case(&hotkey))
    {
        return Err(format!("hotkey '{hotkey}' is already assigned"));
    }

    payload.entries.push(VaultEntry {
        id: Uuid::new_v4(),
        domain,
        username,
        hotkey,
        secret,
        expires_on,
    });

    payload.entries.sort_by(|left, right| {
        left.domain
            .to_lowercase()
            .cmp(&right.domain.to_lowercase())
            .then_with(|| {
                left.username
                    .to_lowercase()
                    .cmp(&right.username.to_lowercase())
            })
    });

    Ok(())
}

pub fn remove_entry(
    payload: &mut VaultPayload,
    domain: &str,
    username: &str,
) -> Result<VaultEntry, String> {
    let index = payload
        .entries
        .iter()
        .position(|entry| {
            entry.domain.eq_ignore_ascii_case(domain)
                && entry.username.eq_ignore_ascii_case(username)
        })
        .ok_or_else(|| format!("entry '{}\\{}' was not found", domain, username))?;

    Ok(payload.entries.remove(index))
}

pub fn list_entries(payload: &VaultPayload) -> Vec<(&str, &str, &str, Option<&str>)> {
    payload
        .entries
        .iter()
        .map(|entry| {
            (
                entry.domain.as_str(),
                entry.username.as_str(),
                entry.hotkey.as_str(),
                entry.expires_on.as_deref(),
            )
        })
        .collect()
}

fn validate_domain(domain: &str) -> Result<(), String> {
    if domain.trim().is_empty() {
        return Err("entry domain cannot be empty".to_string());
    }

    if domain.contains('\n') || domain.contains('\r') {
        return Err("entry domain cannot contain line breaks".to_string());
    }

    Ok(())
}

fn validate_username(username: &str) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("entry username cannot be empty".to_string());
    }

    if username.contains('\n') || username.contains('\r') {
        return Err("entry username cannot contain line breaks".to_string());
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
            "domain".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
            Some("2026-08-15".to_string()),
        )
        .expect("entry should be added");

        assert_eq!(
            list_entries(&payload),
            vec![("domain", "admin01", "CTRL+ALT+1", Some("2026-08-15"))]
        );
        assert!(!payload.entries[0].id.is_nil());
    }

    #[test]
    fn rejects_invalid_expiration_format() {
        let mut payload = VaultPayload::default();

        let error = add_entry(
            &mut payload,
            "domain".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
            Some("08/15/2026".to_string()),
        )
        .expect_err("invalid expiration should be rejected");

        assert!(error.contains("YYYY-MM-DD"));
        assert!(payload.entries.is_empty());
    }

    #[test]
    fn rejects_impossible_expiration_date() {
        let mut payload = VaultPayload::default();

        let error = add_entry(
            &mut payload,
            "domain".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
            Some("2026-02-30".to_string()),
        )
        .expect_err("impossible expiration should be rejected");

        assert!(error.contains("invalid"));
        assert!(payload.entries.is_empty());
    }

    #[test]
    fn allows_entry_without_expiration() {
        let mut payload = VaultPayload::default();

        add_entry(
            &mut payload,
            "domain".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "example-password".to_string(),
            None,
        )
        .expect("entry without expiration should be allowed");

        assert_eq!(payload.entries[0].expires_on, None);
    }

    #[test]
    fn rejects_duplicate_domain_and_username_combination() {
        let mut payload = VaultPayload::default();

        add_entry(
            &mut payload,
            "CORP".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "first".to_string(),
            None,
        )
        .expect("first entry should be added");

        assert!(
            add_entry(
                &mut payload,
                "corp".to_string(),
                "ADMIN01".to_string(),
                "CTRL+ALT+2".to_string(),
                "second".to_string(),
                None,
            )
            .is_err()
        );

        add_entry(
            &mut payload,
            "LAB".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+2".to_string(),
            "third".to_string(),
            None,
        )
        .expect("same username in another domain should be allowed");
    }

    #[test]
    fn rejects_duplicate_hotkeys() {
        let mut payload = VaultPayload::default();

        add_entry(
            &mut payload,
            "CORP".to_string(),
            "admin01".to_string(),
            "CTRL+ALT+1".to_string(),
            "first".to_string(),
            None,
        )
        .expect("first entry should be added");

        assert!(
            add_entry(
                &mut payload,
                "LAB".to_string(),
                "admin02".to_string(),
                "ctrl+alt+1".to_string(),
                "second".to_string(),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn removes_entries_by_domain_and_username() {
        let id = Uuid::new_v4();
        let mut payload = VaultPayload {
            settings: Default::default(),
            entries: vec![VaultEntry {
                id,
                domain: "CORP".to_string(),
                username: "admin01".to_string(),
                hotkey: "CTRL+ALT+1".to_string(),
                secret: "example-secret".to_string(),
                expires_on: None,
            }],
        };

        let removed =
            remove_entry(&mut payload, "corp", "ADMIN01").expect("entry should be removed");

        assert_eq!(removed.id, id);
        assert_eq!(removed.domain, "CORP");
        assert_eq!(removed.username, "admin01");
        assert_eq!(removed.hotkey, "CTRL+ALT+1");
        assert_eq!(removed.secret, "example-secret");
        assert!(payload.entries.is_empty());
    }
}
