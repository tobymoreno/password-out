use base64::{Engine as _, engine::general_purpose::STANDARD};
use password_out::certificate::{
    CertificateKeyProvider, CertificateSource, KeyWrapAlgorithm, certificate_identity_from_der,
    unwrap_key_with_provider, wrap_key_with_certificate,
};

use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use super::crypto::{
    create_password_wrapper, decrypt_payload_with_key, encrypt_payload_with_key,
    generate_vault_key, unwrap_key_with_password,
};
use super::format::{
    CURRENT_VAULT_FORMAT_VERSION, CertificateBackend, CertificateKeyWrapper, VaultEnvelope,
    VaultEnvelopeV2, VaultUnlockMethod,
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

        let algorithm = key_wrap_algorithm_for_backend(&backend);

        let wrapped_key = wrap_key_with_certificate(&certificate_der, algorithm, &vault_key)?;

        let backup_wrapper = create_password_wrapper(&vault_key, backup_password)?;

        let certificate_wrapper = CertificateKeyWrapper {
            backend,
            identity,
            algorithm,
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

/// Retains the recovered certificate-vault key and original unlock wrappers.
///
/// The key is zeroized automatically when the session is dropped.
pub struct CertificateVaultSession {
    version: u32,
    unlock: VaultUnlockMethod,
    vault_key: Zeroizing<[u8; 32]>,
}

/// Opens a generic X.509 certificate-protected vault and returns a save-capable
/// session.
///
/// The provider certificate must match the identity recorded in the vault.
pub fn open_certificate_vault_session(
    path: &Path,
    provider: &mut dyn CertificateKeyProvider,
) -> Result<(VaultPayload, CertificateVaultSession), String> {
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
        let actual_length = unwrapped_key.len();
        unwrapped_key.zeroize();

        return Err(format!(
            "certificate provider returned a {actual_length}-byte vault key; expected 32 bytes"
        ));
    }

    let mut vault_key = [0_u8; 32];
    vault_key.copy_from_slice(&unwrapped_key);
    unwrapped_key.zeroize();

    let payload = match decrypt_payload_with_key(&version_2.cipher, &vault_key) {
        Ok(payload) => payload,
        Err(error) => {
            vault_key.zeroize();
            return Err(error);
        }
    };

    let session = CertificateVaultSession {
        version: version_2.version,
        unlock: version_2.unlock,
        vault_key: Zeroizing::new(vault_key),
    };

    Ok((payload, session))
}

/// Saves an updated payload while preserving the original certificate wrapper
/// and backup-password wrapper.
///
/// A fresh payload nonce is generated, but the existing wrapped vault key is
/// retained.
pub fn save_certificate_vault_session(
    path: &Path,
    payload: &VaultPayload,
    session: &CertificateVaultSession,
) -> Result<(), String> {
    if !matches!(session.unlock, VaultUnlockMethod::Certificate { .. }) {
        return Err(
            "certificate session does not contain a certificate unlock wrapper".to_string(),
        );
    }

    let cipher = encrypt_payload_with_key(payload, &*session.vault_key)?;

    let envelope = VaultEnvelope::V2(VaultEnvelopeV2 {
        version: session.version,
        unlock: session.unlock.clone(),
        cipher,
    });

    envelope.validate()?;
    write_envelope(path, &envelope)
}

/// Loads a generic X.509 certificate-protected vault without retaining a save
/// session.
#[allow(dead_code)]
pub fn load_certificate_vault(
    path: &Path,
    provider: &mut dyn CertificateKeyProvider,
) -> Result<VaultPayload, String> {
    let (payload, _session) = open_certificate_vault_session(path, provider)?;
    Ok(payload)
}

/// Opens a certificate or legacy CAC vault using its backup password.
///
/// This recovers the same random vault key that is normally unwrapped through
/// the certificate private key and decrypts the payload without changing the
/// vault file or any protection wrappers.
pub fn recover_vault_with_backup_password(
    path: &Path,
    backup_password: &str,
) -> Result<VaultPayload, String> {
    let envelope = read_envelope(path)?;

    let VaultEnvelope::V2(version_2) = envelope else {
        return Err("version-1 vaults do not contain a backup-password wrapper".to_string());
    };

    let mut vault_key = match &version_2.unlock {
        VaultUnlockMethod::Password { .. } => {
            return Err(
                "this vault uses normal password protection and does not require recovery"
                    .to_string(),
            );
        }

        VaultUnlockMethod::Cac { backup_wrapper, .. }
        | VaultUnlockMethod::Certificate { backup_wrapper, .. } => {
            unwrap_key_with_password(backup_wrapper, backup_password)?
        }
    };

    let result = decrypt_payload_with_key(&version_2.cipher, &vault_key);

    vault_key.zeroize();
    result
}

/// Replaces the certificate wrapper using the existing backup password.
///
/// The encrypted payload and backup-password wrapper are preserved unchanged.
/// Only the certificate identity and certificate-wrapped copy of the existing
/// random vault key are replaced.
pub fn rotate_certificate_with_backup_password(
    path: &Path,
    backup_password: &str,
    certificate_source: &dyn CertificateSource,
    backend: CertificateBackend,
) -> Result<(), String> {
    backend.validate()?;

    let certificate_der = certificate_source.certificate_der()?;
    let identity = certificate_identity_from_der(&certificate_der)?;

    let envelope = read_envelope(path)?;

    let VaultEnvelope::V2(version_2) = envelope else {
        return Err("version-1 vaults do not support certificate rotation".to_string());
    };

    let VaultEnvelopeV2 {
        version,
        unlock,
        cipher,
    } = version_2;

    let backup_wrapper = match unlock {
        VaultUnlockMethod::Password { .. } => {
            return Err(
                "this vault uses normal password protection and has no certificate to rotate"
                    .to_string(),
            );
        }

        VaultUnlockMethod::Cac { backup_wrapper, .. }
        | VaultUnlockMethod::Certificate { backup_wrapper, .. } => backup_wrapper,
    };

    let mut vault_key = unwrap_key_with_password(&backup_wrapper, backup_password)?;

    let result = (|| {
        // Verify that the recovered key actually decrypts this vault before
        // replacing any wrapper.
        let _payload = decrypt_payload_with_key(&cipher, &vault_key)?;

        let algorithm = key_wrap_algorithm_for_backend(&backend);

        let wrapped_key = wrap_key_with_certificate(&certificate_der, algorithm, &vault_key)?;

        let certificate_wrapper = CertificateKeyWrapper {
            backend,
            identity,
            algorithm,
            wrapped_key: STANDARD.encode(wrapped_key),
        };

        let rotated = VaultEnvelope::V2(VaultEnvelopeV2 {
            version,
            unlock: VaultUnlockMethod::Certificate {
                certificate_wrapper,
                backup_wrapper,
            },
            cipher,
        });

        rotated.validate()?;
        write_envelope(path, &rotated)
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
/// This currently means password-based saving.
#[allow(dead_code)]
pub fn save_vault(
    path: &Path,
    payload: &VaultPayload,
    master_password: &str,
) -> Result<(), String> {
    save_password_vault(path, payload, master_password)
}

fn key_wrap_algorithm_for_backend(backend: &CertificateBackend) -> KeyWrapAlgorithm {
    match backend {
        CertificateBackend::Cac { .. } => KeyWrapAlgorithm::RsaPkcs1v15,

        CertificateBackend::Pfx { .. } => KeyWrapAlgorithm::RsaOaepSha256,
    }
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

        let payload =
            load_password_vault(&path, password).expect("password vault load should succeed");

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

#[cfg(test)]
mod recovery_rotation_tests {
    use super::*;
    use password_out::certificate::{
        PfxKeyProvider, SelfSignedCertificateOptions, create_self_signed_pfx, load_pfx, write_pfx,
    };
    use std::path::{Path, PathBuf};
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

    fn create_test_pfx(path: &Path, common_name: &str, password: &str) -> PfxKeyProvider {
        let options = SelfSignedCertificateOptions {
            common_name: common_name.to_string(),
            friendly_name: common_name.to_string(),
            validity_days: 365,
            rsa_bits: 2048,
        };

        let generated = create_self_signed_pfx(&options, password)
            .expect("self-signed PFX generation should succeed");

        write_pfx(path, &generated.pfx_der).expect("PFX file should be written");

        let loaded = load_pfx(path, password).expect("PFX should load");

        PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider should initialize")
    }

    fn load_test_pfx(path: &Path, password: &str) -> PfxKeyProvider {
        let loaded = load_pfx(path, password).expect("PFX should reload");

        PfxKeyProvider::from_loaded_pfx(loaded).expect("PFX provider should initialize")
    }

    #[test]
    fn backup_password_recovers_certificate_vault_and_rejects_wrong_password() {
        let test_directory = unique_test_directory("backup-recovery");

        let vault_path = test_directory.join("vault.json");
        let pfx_path = test_directory.join("vault.pfx");

        let pfx_password = "test-pfx-password";
        let backup_password = "correct-backup-password";

        let provider = create_test_pfx(&pfx_path, "PasswordOut Recovery Test", pfx_password);

        initialize_certificate_vault(
            &vault_path,
            backup_password,
            &provider,
            CertificateBackend::Pfx {
                suggested_filename: Some("vault.pfx".to_string()),
            },
        )
        .expect("certificate vault initialization should succeed");

        let payload = recover_vault_with_backup_password(&vault_path, backup_password)
            .expect("correct backup password should recover vault");

        assert!(payload.entries.is_empty());

        let error = recover_vault_with_backup_password(&vault_path, "wrong-backup-password")
            .expect_err("wrong backup password should fail");

        assert!(
            error.contains("incorrect password") || error.contains("damaged wrapper"),
            "unexpected recovery error: {error}"
        );

        let _ = std::fs::remove_dir_all(test_directory);
    }

    #[test]
    fn password_vault_rejects_backup_recovery_and_certificate_rotation() {
        let test_directory = unique_test_directory("password-vault-recovery-rejection");

        let vault_path = test_directory.join("vault.json");
        let replacement_pfx_path = test_directory.join("replacement.pfx");

        initialize_password_vault(&vault_path, "normal-master-password")
            .expect("password vault initialization should succeed");

        let recovery_error =
            recover_vault_with_backup_password(&vault_path, "unused-backup-password")
                .expect_err("password vault should reject backup recovery");

        assert!(
            recovery_error.contains("normal password protection"),
            "unexpected recovery error: {recovery_error}"
        );

        let replacement_provider = create_test_pfx(
            &replacement_pfx_path,
            "PasswordOut Replacement Test",
            "replacement-pfx-password",
        );

        let rotation_error = rotate_certificate_with_backup_password(
            &vault_path,
            "unused-backup-password",
            &replacement_provider,
            CertificateBackend::Pfx {
                suggested_filename: Some("replacement.pfx".to_string()),
            },
        )
        .expect_err("password vault should reject certificate rotation");

        assert!(
            rotation_error.contains("normal password protection")
                || rotation_error.contains("no certificate"),
            "unexpected rotation error: {rotation_error}"
        );

        let _ = std::fs::remove_dir_all(test_directory);
    }

    #[test]
    fn pfx_rotation_preserves_cipher_and_backup_wrapper() {
        let test_directory = unique_test_directory("pfx-rotation");

        let vault_path = test_directory.join("vault.json");
        let old_pfx_path = test_directory.join("old.pfx");
        let new_pfx_path = test_directory.join("new.pfx");

        let old_pfx_password = "old-pfx-password";
        let new_pfx_password = "new-pfx-password";
        let backup_password = "rotation-backup-password";

        let old_provider = create_test_pfx(
            &old_pfx_path,
            "PasswordOut Old Certificate",
            old_pfx_password,
        );

        initialize_certificate_vault(
            &vault_path,
            backup_password,
            &old_provider,
            CertificateBackend::Pfx {
                suggested_filename: Some("old.pfx".to_string()),
            },
        )
        .expect("certificate vault initialization should succeed");

        let before = read_envelope(&vault_path).expect("vault should load before rotation");

        let VaultEnvelope::V2(before_v2) = before else {
            panic!("certificate vault should use version 2");
        };

        let before_nonce = before_v2.cipher.nonce.clone();
        let before_ciphertext = before_v2.cipher.ciphertext.clone();

        let before_backup_wrapper = match before_v2.unlock {
            VaultUnlockMethod::Certificate { backup_wrapper, .. } => {
                serde_json::to_value(backup_wrapper).expect("backup wrapper should serialize")
            }

            other => panic!("expected certificate unlock before rotation, got {other:?}"),
        };

        let replacement_provider = create_test_pfx(
            &new_pfx_path,
            "PasswordOut New Certificate",
            new_pfx_password,
        );

        rotate_certificate_with_backup_password(
            &vault_path,
            backup_password,
            &replacement_provider,
            CertificateBackend::Pfx {
                suggested_filename: Some("new.pfx".to_string()),
            },
        )
        .expect("certificate rotation should succeed");

        let after = read_envelope(&vault_path).expect("vault should load after rotation");

        let VaultEnvelope::V2(after_v2) = after else {
            panic!("rotated certificate vault should use version 2");
        };

        assert_eq!(after_v2.cipher.nonce, before_nonce);
        assert_eq!(after_v2.cipher.ciphertext, before_ciphertext);

        let after_backup_wrapper = match &after_v2.unlock {
            VaultUnlockMethod::Certificate {
                certificate_wrapper,
                backup_wrapper,
            } => {
                assert_eq!(
                    certificate_wrapper.backend,
                    CertificateBackend::Pfx {
                        suggested_filename: Some("new.pfx".to_string(),),
                    }
                );

                serde_json::to_value(backup_wrapper).expect("backup wrapper should serialize")
            }

            other => panic!("expected certificate unlock after rotation, got {other:?}"),
        };

        assert_eq!(
            after_backup_wrapper, before_backup_wrapper,
            "rotation must preserve the backup-password wrapper"
        );

        let mut new_provider = load_test_pfx(&new_pfx_path, new_pfx_password);

        let (payload, _session) = open_certificate_vault_session(&vault_path, &mut new_provider)
            .expect("replacement PFX should unlock rotated vault");

        assert!(payload.entries.is_empty());

        let mut old_provider = load_test_pfx(&old_pfx_path, old_pfx_password);

        let old_result = open_certificate_vault_session(&vault_path, &mut old_provider);

        assert!(
            old_result.is_err(),
            "previous PFX must not unlock rotated vault"
        );

        let recovered = recover_vault_with_backup_password(&vault_path, backup_password)
            .expect("backup password should still recover rotated vault");

        assert!(recovered.entries.is_empty());

        let _ = std::fs::remove_dir_all(test_directory);
    }
}
