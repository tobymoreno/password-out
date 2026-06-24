use base64::{Engine as _, engine::general_purpose::STANDARD};
use password_out::certificate::{
    CertificateKeyProvider, CertificateSource, KeyWrapAlgorithm, certificate_identity_from_der,
    unwrap_key_with_provider, wrap_key_with_certificate,
};

use std::path::Path;

use zeroize::Zeroize;

use super::crypto::{
    create_password_wrapper, decrypt_payload_with_key, encrypt_payload_with_key, generate_vault_key,
};
use super::format::{
    CURRENT_VAULT_FORMAT_VERSION, CacKeyWrapper, CertificateBackend, CertificateKeyWrapper,
    VaultEnvelope, VaultEnvelopeV2, VaultUnlockMethod,
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

/// Initializes a certificate-protected vault.
///
/// A fresh random vault key encrypts the payload. The vault key is wrapped
/// using the supplied X.509 certificate and is also protected by a backup
/// password for recovery.
#[allow(dead_code)]
pub fn initialize_certificate_vault(
    path: &Path,
    backup_password: &str,
    certificate_source: &dyn CertificateSource,
    backend: CertificateBackend,
) -> Result<(), String> {
    ensure_vault_does_not_exist(path)?;

    backend.validate()?;

    let certificate_der = certificate_source.certificate_der()?;

    let identity = certificate_identity_from_der(&certificate_der)?;

    let payload = VaultPayload::default();
    let mut vault_key = generate_vault_key();

    let result = (|| {
        let cipher = encrypt_payload_with_key(&payload, &vault_key)?;

        let wrapped_key = wrap_key_with_certificate(
            &certificate_der,
            KeyWrapAlgorithm::RsaOaepSha256,
            &vault_key,
        )?;

        let backup_wrapper = create_password_wrapper(&vault_key, backup_password)?;

        let certificate_wrapper = CertificateKeyWrapper {
            backend,
            identity,
            algorithm: KeyWrapAlgorithm::RsaOaepSha256,
            wrapped_key: STANDARD.encode(wrapped_key),
        };

        let envelope = VaultEnvelope::V2(VaultEnvelopeV2 {
            version: CURRENT_VAULT_FORMAT_VERSION,
            unlock: VaultUnlockMethod::Certificate {
                certificate_wrapper,
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

/// Loads a generic X.509 certificate-protected vault.
///
/// The provider supplies both the certificate identity and the private-key
/// operation. The vault service verifies that the provider certificate matches
/// the identity recorded in the vault before decrypting the wrapped vault key.
#[allow(dead_code)]
pub fn load_certificate_vault(
    path: &Path,
    provider: &mut dyn CertificateKeyProvider,
) -> Result<VaultPayload, String> {
    let envelope = read_envelope(path)?;

    let VaultEnvelope::V2(version_2) = envelope else {
        return Err("version-1 vaults do not support certificate unlock".to_string());
    };

    let VaultUnlockMethod::Certificate {
        certificate_wrapper,
        ..
    } = &version_2.unlock
    else {
        return match &version_2.unlock {
            VaultUnlockMethod::Password { .. } => Err(
                "this vault uses password unlock; use the password unlock command".to_string(),
            ),
            VaultUnlockMethod::Cac { .. } => Err(
                "this vault uses the legacy CAC format; use the CAC unlock or backup recovery command"
                    .to_string(),
            ),
            VaultUnlockMethod::Certificate { .. } => unreachable!(),
        };
    };

    let wrapped_key = STANDARD
        .decode(&certificate_wrapper.wrapped_key)
        .map_err(|error| format!("certificate-wrapped vault key is not valid base64: {error}"))?;

    let mut unwrapped_key = unwrap_key_with_provider(
        provider,
        &certificate_wrapper.identity,
        certificate_wrapper.algorithm,
        &wrapped_key,
    )?;

    if unwrapped_key.len() != 32 {
        unwrapped_key.zeroize();
        return Err(format!(
            "certificate provider returned a {}-byte vault key; expected 32 bytes",
            unwrapped_key.len()
        ));
    }

    let mut vault_key = [0_u8; 32];
    vault_key.copy_from_slice(&unwrapped_key);
    unwrapped_key.zeroize();

    let result = decrypt_payload_with_key(&version_2.cipher, &vault_key);
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

            VaultUnlockMethod::Cac { .. } | VaultUnlockMethod::Certificate { .. } => Err(
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
            if matches!(
                version_2.unlock,
                VaultUnlockMethod::Cac { .. } | VaultUnlockMethod::Certificate { .. }
            ) {
                return Err(
                    "cannot save a certificate-protected vault through the password-only save path"
                        .to_string(),
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

#[test]
fn initializes_and_unlocks_certificate_vault_with_pfx_provider() {
    use super::*;
    use password_out::certificate::{
        CertificateSource, KeyWrapAlgorithm, PfxKeyProvider, SelfSignedCertificateOptions,
        certificate_identity_from_der, create_self_signed_pfx, load_pfx_der,
    };

    use crate::vault::format::CertificateBackend;

    let test_dir = std::env::temp_dir().join(format!(
        "password-out-certificate-vault-test-{}",
        uuid::Uuid::new_v4()
    ));

    std::fs::create_dir_all(&test_dir).expect("test directory should be created");

    let vault_path = test_dir.join("vault.json");
    let backup_password = "correct horse battery staple";

    let generated = create_self_signed_pfx(
        &SelfSignedCertificateOptions {
            common_name: "PasswordOut Vault Test".to_string(),
            friendly_name: "PasswordOut Vault Test".to_string(),
            rsa_bits: 2048,
            validity_days: 30,
        },
        "pfx-password",
    )
    .expect("PFX generation should succeed");

    let loaded =
        load_pfx_der(&generated.pfx_der, "pfx-password").expect("PFX loading should succeed");

    let mut provider =
        PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider creation should succeed");

    let certificate_der = provider
        .certificate_der()
        .expect("certificate DER encoding should succeed");

    initialize_certificate_vault(
        &vault_path,
        backup_password,
        &provider,
        CertificateBackend::Pfx {
            suggested_filename: Some("password-out-test.pfx".to_string()),
        },
    )
    .expect("certificate vault initialization should succeed");

    let envelope = read_envelope(&vault_path).expect("vault envelope should load");

    let VaultEnvelope::V2(version_2) = envelope else {
        panic!("expected version-2 vault envelope");
    };

    let VaultUnlockMethod::Certificate {
        certificate_wrapper,
        backup_wrapper: _,
    } = version_2.unlock
    else {
        panic!("expected certificate unlock method");
    };

    assert_eq!(
        certificate_wrapper.algorithm,
        KeyWrapAlgorithm::RsaOaepSha256
    );

    let expected_identity =
        certificate_identity_from_der(&certificate_der).expect("certificate identity should load");

    assert_eq!(
        certificate_wrapper.identity.sha256_fingerprint,
        expected_identity.sha256_fingerprint
    );

    let payload = load_certificate_vault(&vault_path, &mut provider)
        .expect("matching PFX provider should unlock the certificate vault");

    assert!(payload.entries.is_empty());

    let _ = std::fs::remove_dir_all(test_dir);
}
