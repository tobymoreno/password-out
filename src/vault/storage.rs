use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use super::format::VaultEnvelope;

const VAULT_FILE_NAME: &str = "vault.json";

pub fn default_vault_path() -> Result<PathBuf, String> {
    let project_dirs = ProjectDirs::from("", "", "password-out")
        .ok_or_else(|| "unable to determine the PasswordOut config directory".to_string())?;

    Ok(project_dirs.config_dir().join(VAULT_FILE_NAME))
}

pub fn read_envelope(path: &Path) -> Result<VaultEnvelope, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("failed to open vault '{}': {error}", path.display()))?;

    let mut contents = String::new();

    file.read_to_string(&mut contents)
        .map_err(|error| format!("failed to read vault '{}': {error}", path.display()))?;

    let envelope: VaultEnvelope = serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse vault '{}': {error}", path.display()))?;

    envelope.validate()?;

    Ok(envelope)
}

pub fn write_envelope(path: &Path, envelope: &VaultEnvelope) -> Result<(), String> {
    envelope.validate()?;

    let parent = path
        .parent()
        .ok_or_else(|| format!("vault path '{}' has no parent directory", path.display()))?;

    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create vault directory '{}': {error}",
            parent.display()
        )
    })?;

    set_directory_permissions(parent)?;

    let serialized = serde_json::to_vec_pretty(envelope)
        .map_err(|error| format!("failed to serialize vault: {error}"))?;

    let temp_path = temporary_path(path);

    let write_result = write_temp_file(&temp_path, &serialized);

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }

    replace_file(&temp_path, path)?;

    Ok(())
}

fn write_temp_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|error| {
        format!(
            "failed to create temporary vault '{}': {error}",
            path.display()
        )
    })?;

    file.write_all(contents).map_err(|error| {
        format!(
            "failed to write temporary vault '{}': {error}",
            path.display()
        )
    })?;

    file.sync_all().map_err(|error| {
        format!(
            "failed to sync temporary vault '{}': {error}",
            path.display()
        )
    })?;

    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(VAULT_FILE_NAME);

    let temp_name = format!("{file_name}.{}.tmp", std::process::id());

    path.with_file_name(temp_name)
}

#[cfg(unix)]
fn replace_file(temp_path: &Path, final_path: &Path) -> Result<(), String> {
    fs::rename(temp_path, final_path).map_err(|error| {
        format!(
            "failed to replace vault '{}' with '{}': {error}",
            final_path.display(),
            temp_path.display()
        )
    })
}

#[cfg(windows)]
fn replace_file(temp_path: &Path, final_path: &Path) -> Result<(), String> {
    if final_path.exists() {
        fs::remove_file(final_path).map_err(|error| {
            format!(
                "failed to remove existing vault '{}': {error}",
                final_path.display()
            )
        })?;
    }

    fs::rename(temp_path, final_path).map_err(|error| {
        format!(
            "failed to move temporary vault '{}' into place '{}': {error}",
            temp_path.display(),
            final_path.display()
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn replace_file(temp_path: &Path, final_path: &Path) -> Result<(), String> {
    if final_path.exists() {
        fs::remove_file(final_path).map_err(|error| {
            format!(
                "failed to remove existing vault '{}': {error}",
                final_path.display()
            )
        })?;
    }

    fs::rename(temp_path, final_path).map_err(|error| {
        format!(
            "failed to move temporary vault '{}' into place '{}': {error}",
            temp_path.display(),
            final_path.display()
        )
    })
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "failed to set vault directory permissions on '{}': {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{
        CIPHER_ALGORITHM, CipherPayload, KDF_ALGORITHM, KdfParameters, VAULT_FORMAT_VERSION_V1,
        VaultEnvelopeV1,
    };

    fn sample_envelope() -> VaultEnvelope {
        VaultEnvelope::V1(VaultEnvelopeV1 {
            version: VAULT_FORMAT_VERSION_V1,
            kdf: KdfParameters {
                algorithm: KDF_ALGORITHM.to_string(),
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
                salt: "c2FsdA".to_string(),
            },
            cipher: CipherPayload {
                algorithm: CIPHER_ALGORITHM.to_string(),
                nonce: "bm9uY2U".to_string(),
                ciphertext: "Y2lwaGVydGV4dA".to_string(),
            },
        })
    }

    #[test]
    fn writes_and_reads_envelope() {
        let test_dir =
            std::env::temp_dir().join(format!("password-out-storage-test-{}", std::process::id()));

        let path = test_dir.join("vault.json");
        let envelope = sample_envelope();

        write_envelope(&path, &envelope).expect("write should succeed");
        let loaded = read_envelope(&path).expect("read should succeed");

        assert_eq!(loaded, envelope);

        let _ = fs::remove_dir_all(test_dir);
    }
}
