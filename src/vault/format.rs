use serde::{Deserialize, Serialize};

pub const VAULT_FORMAT_VERSION: u32 = 1;
pub const KDF_ALGORITHM: &str = "argon2id";
pub const CIPHER_ALGORITHM: &str = "xchacha20poly1305";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEnvelope {
    pub version: u32,
    pub kdf: KdfParameters,
    pub cipher: CipherPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParameters {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherPayload {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPayload {
    pub entries: Vec<VaultEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    pub name: String,
    pub hotkey: String,
    pub secret: String,
}

impl VaultEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VAULT_FORMAT_VERSION {
            return Err(format!(
                "unsupported vault format version {}; expected {}",
                self.version, VAULT_FORMAT_VERSION
            ));
        }

        if self.kdf.algorithm != KDF_ALGORITHM {
            return Err(format!(
                "unsupported KDF algorithm '{}'",
                self.kdf.algorithm
            ));
        }

        if self.cipher.algorithm != CIPHER_ALGORITHM {
            return Err(format!(
                "unsupported cipher algorithm '{}'",
                self.cipher.algorithm
            ));
        }

        if self.kdf.memory_kib == 0 {
            return Err("vault KDF memory_kib must be greater than zero".to_string());
        }

        if self.kdf.iterations == 0 {
            return Err("vault KDF iterations must be greater than zero".to_string());
        }

        if self.kdf.parallelism == 0 {
            return Err("vault KDF parallelism must be greater than zero".to_string());
        }

        if self.kdf.salt.is_empty() {
            return Err("vault KDF salt is missing".to_string());
        }

        if self.cipher.nonce.is_empty() {
            return Err("vault cipher nonce is missing".to_string());
        }

        if self.cipher.ciphertext.is_empty() {
            return Err("vault ciphertext is missing".to_string());
        }

        Ok(())
    }
}

impl VaultPayload {
    pub fn find_entry(&self, name: &str) -> Option<&VaultEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    pub fn contains_name(&self, name: &str) -> bool {
        self.find_entry(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_can_find_entries() {
        let payload = VaultPayload {
            entries: vec![VaultEntry {
                name: "admin01".to_string(),
                hotkey: "CTRL+ALT+1".to_string(),
                secret: "example".to_string(),
            }],
        };

        assert!(payload.contains_name("admin01"));
        assert_eq!(
            payload
                .find_entry("admin01")
                .map(|entry| entry.hotkey.as_str()),
            Some("CTRL+ALT+1")
        );
        assert!(!payload.contains_name("missing"));
    }

    #[test]
    fn envelope_validation_rejects_unknown_version() {
        let envelope = VaultEnvelope {
            version: 99,
            kdf: KdfParameters {
                algorithm: KDF_ALGORITHM.to_string(),
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
                salt: "salt".to_string(),
            },
            cipher: CipherPayload {
                algorithm: CIPHER_ALGORITHM.to_string(),
                nonce: "nonce".to_string(),
                ciphertext: "ciphertext".to_string(),
            },
        };

        assert!(envelope.validate().is_err());
    }
}
