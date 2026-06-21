use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;

use super::format::{
    CIPHER_ALGORITHM, CipherPayload, KDF_ALGORITHM, KdfParameters, VAULT_FORMAT_VERSION,
    VaultEnvelope, VaultPayload,
};

const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;

const DEFAULT_MEMORY_KIB: u32 = 65_536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;

pub fn encrypt_payload(
    payload: &VaultPayload,
    master_password: &str,
) -> Result<VaultEnvelope, String> {
    validate_master_password(master_password)?;

    let plaintext = serde_json::to_vec(payload)
        .map_err(|error| format!("failed to serialize vault payload: {error}"))?;

    let mut salt = [0_u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(
        master_password,
        &salt,
        DEFAULT_MEMORY_KIB,
        DEFAULT_ITERATIONS,
        DEFAULT_PARALLELISM,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "failed to initialize vault cipher".to_string())?;

    let mut nonce = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "failed to encrypt vault payload".to_string())?;

    key.zeroize();

    Ok(VaultEnvelope {
        version: VAULT_FORMAT_VERSION,
        kdf: KdfParameters {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
            salt: STANDARD_NO_PAD.encode(salt),
        },
        cipher: CipherPayload {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce: STANDARD_NO_PAD.encode(nonce),
            ciphertext: STANDARD_NO_PAD.encode(ciphertext),
        },
    })
}

pub fn decrypt_payload(
    envelope: &VaultEnvelope,
    master_password: &str,
) -> Result<VaultPayload, String> {
    validate_master_password(master_password)?;
    envelope.validate()?;

    let salt = decode_exact::<SALT_LENGTH>("salt", &envelope.kdf.salt)?;
    let nonce = decode_exact::<NONCE_LENGTH>("nonce", &envelope.cipher.nonce)?;

    let ciphertext = STANDARD_NO_PAD
        .decode(&envelope.cipher.ciphertext)
        .map_err(|error| format!("vault ciphertext is not valid base64: {error}"))?;

    let mut key = derive_key(
        master_password,
        &salt,
        envelope.kdf.memory_kib,
        envelope.kdf.iterations,
        envelope.kdf.parallelism,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "failed to initialize vault cipher".to_string())?;

    let plaintext_result = cipher.decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref());

    key.zeroize();

    let plaintext = plaintext_result.map_err(|_| {
        "unable to decrypt vault: incorrect master password or damaged vault".to_string()
    })?;

    serde_json::from_slice(&plaintext)
        .map_err(|error| format!("decrypted vault payload is invalid: {error}"))
}

fn derive_key(
    master_password: &str,
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
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
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

fn validate_master_password(master_password: &str) -> Result<(), String> {
    if master_password.is_empty() {
        return Err("master password cannot be empty".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::VaultEntry;

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
    fn encrypts_and_decrypts_payload() {
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
    fn detects_tampered_ciphertext() {
        let mut envelope = encrypt_payload(&sample_payload(), "correct-password")
            .expect("encryption should succeed");

        envelope.cipher.ciphertext.push('A');

        let result = decrypt_payload(&envelope, "correct-password");

        assert!(result.is_err());
    }
}
