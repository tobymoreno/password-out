use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;

use super::format::{
    CIPHER_ALGORITHM, CURRENT_VAULT_FORMAT_VERSION, CipherPayload, KDF_ALGORITHM, KdfParameters,
    PasswordKeyWrapper, VAULT_FORMAT_VERSION_V1, VaultEnvelope, VaultEnvelopeV1, VaultEnvelopeV2,
    VaultPayload, VaultUnlockMethod,
};

const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;

const DEFAULT_MEMORY_KIB: u32 = 65_536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;

/// Creates a new version-2 password vault.
///
/// A random vault key encrypts the payload. Argon2id derives a separate
/// key-encryption key that protects the random vault key.
pub fn encrypt_payload(
    payload: &VaultPayload,
    master_password: &str,
) -> Result<VaultEnvelope, String> {
    validate_password(master_password, "master password")?;

    let plaintext = serde_json::to_vec(payload)
        .map_err(|error| format!("failed to serialize vault payload: {error}"))?;

    let mut vault_key = random_key();

    let payload_cipher = encrypt_bytes(&plaintext, &vault_key)
        .map_err(|error| format!("failed to encrypt vault payload: {error}"))?;

    let password_wrapper = create_password_wrapper(&vault_key, master_password)?;

    vault_key.zeroize();

    Ok(VaultEnvelope::V2(VaultEnvelopeV2 {
        version: CURRENT_VAULT_FORMAT_VERSION,
        unlock: VaultUnlockMethod::Password {
            wrapper: password_wrapper,
        },
        cipher: payload_cipher,
    }))
}

/// Decrypts either:
///
/// - an existing version-1 password vault; or
/// - a version-2 password vault.
///
/// CAC vaults require a separate CAC or backup-password unlock path.
pub fn decrypt_payload(
    envelope: &VaultEnvelope,
    master_password: &str,
) -> Result<VaultPayload, String> {
    validate_password(master_password, "master password")?;
    envelope.validate()?;

    match envelope {
        VaultEnvelope::V1(envelope) => decrypt_v1_payload(envelope, master_password),

        VaultEnvelope::V2(envelope) => match &envelope.unlock {
            VaultUnlockMethod::Password { wrapper } => {
                let mut vault_key = unwrap_key_with_password(wrapper, master_password)?;

                let result = decrypt_payload_with_key(&envelope.cipher, &vault_key);

                vault_key.zeroize();
                result
            }

            VaultUnlockMethod::Cac { .. } | VaultUnlockMethod::Certificate { .. } => Err(
                "this vault uses CAC unlock; use the CAC or backup-password recovery flow"
                    .to_string(),
            ),
        },
    }
}

/// Creates an Argon2id/XChaCha20-Poly1305 wrapper for a vault key.
///
/// This is used for:
///
/// - password-mode vaults; and
/// - the recovery-password wrapper for CAC-mode vaults.
pub fn create_password_wrapper(
    vault_key: &[u8; KEY_LENGTH],
    password: &str,
) -> Result<PasswordKeyWrapper, String> {
    validate_password(password, "password")?;

    let mut salt = [0_u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);

    let mut wrapping_key = derive_key(
        password,
        &salt,
        DEFAULT_MEMORY_KIB,
        DEFAULT_ITERATIONS,
        DEFAULT_PARALLELISM,
    )?;

    let cipher_result = encrypt_bytes(vault_key, &wrapping_key);

    wrapping_key.zeroize();

    let cipher = cipher_result.map_err(|error| format!("failed to wrap vault key: {error}"))?;

    Ok(PasswordKeyWrapper {
        kdf: KdfParameters {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
            salt: STANDARD_NO_PAD.encode(salt),
        },
        cipher,
    })
}

/// Recovers a vault key from an Argon2id password wrapper.
pub fn unwrap_key_with_password(
    wrapper: &PasswordKeyWrapper,
    password: &str,
) -> Result<[u8; KEY_LENGTH], String> {
    validate_password(password, "password")?;
    wrapper.validate("password wrapper")?;

    let salt = decode_exact::<SALT_LENGTH>("password-wrapper salt", &wrapper.kdf.salt)?;

    let mut wrapping_key = derive_key(
        password,
        &salt,
        wrapper.kdf.memory_kib,
        wrapper.kdf.iterations,
        wrapper.kdf.parallelism,
    )?;

    let plaintext_result = decrypt_bytes(&wrapper.cipher, &wrapping_key);

    wrapping_key.zeroize();

    let mut plaintext = plaintext_result.map_err(|_| {
        "unable to unlock vault key: incorrect password or damaged wrapper".to_string()
    })?;

    let key_result = plaintext.as_slice().try_into().map_err(|_| {
        format!(
            "unwrapped vault key has invalid length {}; expected {}",
            plaintext.len(),
            KEY_LENGTH
        )
    });

    plaintext.zeroize();

    key_result
}

/// Encrypts a payload using a caller-provided vault key.
///
/// This will also be used when CAC mode creates a random vault key.
pub fn encrypt_payload_with_key(
    payload: &VaultPayload,
    vault_key: &[u8; KEY_LENGTH],
) -> Result<CipherPayload, String> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|error| format!("failed to serialize vault payload: {error}"))?;

    encrypt_bytes(&plaintext, vault_key)
        .map_err(|error| format!("failed to encrypt vault payload: {error}"))
}

/// Decrypts a payload using an already recovered vault key.
pub fn decrypt_payload_with_key(
    cipher_payload: &CipherPayload,
    vault_key: &[u8; KEY_LENGTH],
) -> Result<VaultPayload, String> {
    let mut plaintext = decrypt_bytes(cipher_payload, vault_key)
        .map_err(|_| "unable to decrypt vault: incorrect key or damaged vault".to_string())?;

    let result = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("decrypted vault payload is invalid: {error}"));

    plaintext.zeroize();
    result
}

/// Generates a new random 256-bit vault key.
pub fn generate_vault_key() -> [u8; KEY_LENGTH] {
    random_key()
}

fn decrypt_v1_payload(
    envelope: &VaultEnvelopeV1,
    master_password: &str,
) -> Result<VaultPayload, String> {
    if envelope.version != VAULT_FORMAT_VERSION_V1 {
        return Err(format!(
            "unsupported version-1 vault value {}",
            envelope.version
        ));
    }

    let salt = decode_exact::<SALT_LENGTH>("salt", &envelope.kdf.salt)?;

    let mut key = derive_key(
        master_password,
        &salt,
        envelope.kdf.memory_kib,
        envelope.kdf.iterations,
        envelope.kdf.parallelism,
    )?;

    let mut plaintext = match decrypt_bytes(&envelope.cipher, &key) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            key.zeroize();

            return Err(
                "unable to decrypt vault: incorrect master password or damaged vault".to_string(),
            );
        }
    };

    key.zeroize();

    let result = serde_json::from_slice(&plaintext)
        .map_err(|error| format!("decrypted vault payload is invalid: {error}"));

    plaintext.zeroize();
    result
}

fn encrypt_bytes(plaintext: &[u8], key: &[u8; KEY_LENGTH]) -> Result<CipherPayload, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "failed to initialize cipher".to_string())?;

    let mut nonce = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| "encryption operation failed".to_string())?;

    Ok(CipherPayload {
        algorithm: CIPHER_ALGORITHM.to_string(),
        nonce: STANDARD_NO_PAD.encode(nonce),
        ciphertext: STANDARD_NO_PAD.encode(ciphertext),
    })
}

fn decrypt_bytes(
    cipher_payload: &CipherPayload,
    key: &[u8; KEY_LENGTH],
) -> Result<Vec<u8>, String> {
    cipher_payload.validate("cipher payload")?;

    let nonce = decode_exact::<NONCE_LENGTH>("nonce", &cipher_payload.nonce)?;

    let ciphertext = STANDARD_NO_PAD
        .decode(&cipher_payload.ciphertext)
        .map_err(|error| format!("ciphertext is not valid base64: {error}"))?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "failed to initialize cipher".to_string())?;

    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "decryption operation failed".to_string())
}

fn random_key() -> [u8; KEY_LENGTH] {
    let mut key = [0_u8; KEY_LENGTH];
    OsRng.fill_bytes(&mut key);
    key
}

fn derive_key(
    password: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; KEY_LENGTH], String> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_LENGTH))
        .map_err(|error| format!("invalid Argon2 parameters: {error}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0_u8; KEY_LENGTH];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| format!("failed to derive vault key: {error}"))?;

    Ok(key)
}

fn decode_exact<const N: usize>(field_name: &str, encoded: &str) -> Result<[u8; N], String> {
    let decoded = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|error| format!("vault {field_name} is not valid base64: {error}"))?;

    decoded.try_into().map_err(|value: Vec<u8>| {
        format!(
            "vault {field_name} has invalid length {}; expected {N}",
            value.len()
        )
    })
}

fn validate_password(password: &str, description: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err(format!("{description} cannot be empty"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{VAULT_FORMAT_VERSION_V2, VaultEntry, VaultUnlockMethod};

    fn sample_payload() -> VaultPayload {
        VaultPayload {
            entries: vec![VaultEntry {
                name: "admin01".to_string(),
                hotkey: "CTRL+ALT+1".to_string(),
                secret: "example-password".to_string(),
            }],
        }
    }

    #[test]
    fn encrypts_new_password_vault_as_version_2() {
        let envelope = encrypt_payload(&sample_payload(), "correct horse battery staple")
            .expect("encryption should succeed");

        match envelope {
            VaultEnvelope::V2(envelope) => {
                assert_eq!(envelope.version, VAULT_FORMAT_VERSION_V2);

                assert!(matches!(
                    envelope.unlock,
                    VaultUnlockMethod::Password { .. }
                ));
            }

            VaultEnvelope::V1(_) => {
                panic!("new vault unexpectedly used version 1")
            }
        }
    }

    #[test]
    fn encrypts_and_decrypts_password_vault() {
        let payload = sample_payload();

        let envelope = encrypt_payload(&payload, "correct horse battery staple")
            .expect("encryption should succeed");

        let decrypted = decrypt_payload(&envelope, "correct horse battery staple")
            .expect("decryption should succeed");

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn rejects_incorrect_master_password() {
        let envelope = encrypt_payload(&sample_payload(), "correct-password")
            .expect("encryption should succeed");

        let result = decrypt_payload(&envelope, "wrong-password");

        assert!(result.is_err());
    }

    #[test]
    fn detects_tampered_v2_payload_ciphertext() {
        let mut envelope = encrypt_payload(&sample_payload(), "correct-password")
            .expect("encryption should succeed");

        match &mut envelope {
            VaultEnvelope::V2(version_2) => {
                version_2.cipher.ciphertext.push('A');
            }

            VaultEnvelope::V1(_) => {
                panic!("expected version-2 vault");
            }
        }

        let result = decrypt_payload(&envelope, "correct-password");

        assert!(result.is_err());
    }

    #[test]
    fn password_wrapper_round_trip() {
        let mut vault_key = generate_vault_key();

        let wrapper = create_password_wrapper(&vault_key, "recovery-password")
            .expect("wrapper creation should succeed");

        let recovered = unwrap_key_with_password(&wrapper, "recovery-password")
            .expect("wrapper unlock should succeed");

        assert_eq!(recovered, vault_key);

        vault_key.zeroize();
    }
}
