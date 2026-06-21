use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SecretEntry {
    pub name: String,
    pub hotkey: String,
    pub secret: String,
}

fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        return PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
    }

    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        return PathBuf::from(home).join(rest);
    }

    PathBuf::from(path)
}

pub fn default_secrets_file() -> PathBuf {
    expand_tilde("~/.config/password-out/secrets.txt")
}

pub fn path_from_arg(path: &str) -> PathBuf {
    expand_tilde(path)
}

pub fn load_entries(path: &Path) -> Result<Vec<SecretEntry>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read secrets file {}: {}", path.display(), e))?;

    let mut entries = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, '|').collect();

        if parts.len() != 3 {
            return Err(format!(
                "invalid line {} in {}. Expected: name|hotkey|password",
                line_num,
                path.display()
            ));
        }

        let name = parts[0].trim().to_string();
        let hotkey = parts[1].trim().to_string();
        let secret = parts[2].trim().to_string();

        if name.is_empty() {
            return Err(format!("line {} has empty name", line_num));
        }

        if hotkey.is_empty() {
            return Err(format!("line {} has empty hotkey", line_num));
        }

        if secret.is_empty() {
            return Err(format!("line {} has empty password", line_num));
        }

        entries.push(SecretEntry {
            name,
            hotkey,
            secret,
        });
    }

    if entries.is_empty() {
        return Err(format!("no entries found in {}", path.display()));
    }

    Ok(entries)
}
