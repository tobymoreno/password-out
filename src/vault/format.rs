use password_out::certificate::{CertificateIdentity, KeyWrapAlgorithm};
use serde::{Deserialize, Serialize};

pub const VAULT_FORMAT_VERSION_V1: u32 = 1;
pub const VAULT_FORMAT_VERSION_V2: u32 = 2;
pub const CURRENT_VAULT_FORMAT_VERSION: u32 = VAULT_FORMAT_VERSION_V2;

pub const KDF_ALGORITHM: &str = "argon2id";
pub const CIPHER_ALGORITHM: &str = "xchacha20poly1305";
pub const CAC_WRAP_ALGORITHM_RSA_OAEP_SHA256: &str = "rsa-oaep-sha256";
pub const CAC_KEY_MANAGEMENT_SLOT: &str = "9D";

/// Supports existing version-1 password vaults and the version-2 wrapped-key
/// format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum VaultEnvelope {
    V1(VaultEnvelopeV1),
    V2(VaultEnvelopeV2),
}

/// Existing password-only format.
///
/// In version 1, the Argon2id-derived key directly encrypts the vault payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEnvelopeV1 {
    pub version: u32,
    pub kdf: KdfParameters,
    pub cipher: CipherPayload,
}

/// Version-2 format.
///
/// The vault payload is encrypted using a random vault key. The vault key is
/// then protected by one or more unlock wrappers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEnvelopeV2 {
    pub version: u32,
    pub unlock: VaultUnlockMethod,
    pub cipher: CipherPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum VaultUnlockMethod {
    /// The random vault key is protected only by an Argon2id password wrapper.
    Password { wrapper: PasswordKeyWrapper },

    /// Legacy CAC-specific representation.
    ///
    /// Retained so vaults written before the generic certificate wrapper was
    /// introduced continue to deserialize and validate.
    Cac {
        cac_wrapper: CacKeyWrapper,
        backup_wrapper: PasswordKeyWrapper,
    },

    /// Generic X.509 certificate protection.
    ///
    /// The private-key operation may be supplied by a PFX file, CAC/PIV card,
    /// PKCS#11 token, TPM, or another injected provider. A backup-password
    /// wrapper remains mandatory for recovery.
    Certificate {
        certificate_wrapper: CertificateKeyWrapper,
        backup_wrapper: PasswordKeyWrapper,
    },
}

/// Protects the random vault key using a password-derived key.
///
/// The cipher payload contains the encrypted vault key, not the encrypted
/// password entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordKeyWrapper {
    pub kdf: KdfParameters,
    pub cipher: CipherPayload,
}

/// Legacy CAC-specific wrapper retained for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacKeyWrapper {
    /// PIV key reference, normally "9D".
    pub slot: String,

    /// SHA-256 fingerprint of the complete DER certificate.
    pub certificate_sha256: String,

    /// Public-key wrapping algorithm, initially "rsa-oaep-sha256".
    pub algorithm: String,

    /// Base64-encoded vault key encrypted with the CAC public key.
    pub wrapped_key: String,
}

/// Indicates where PasswordOut expects to find the private key associated with
/// a certificate wrapper.
///
/// This is only a user-interface and provider-selection hint. The certificate
/// fingerprint remains the authoritative binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum CertificateBackend {
    Cac {
        /// PIV key reference, normally "9D".
        slot: String,
    },

    Pfx {
        /// Optional display hint. Unlock callers may choose another path.
        suggested_filename: Option<String>,
    },
}

/// Protects the random vault key using an X.509 certificate public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateKeyWrapper {
    pub backend: CertificateBackend,
    pub identity: CertificateIdentity,
    pub algorithm: KeyWrapAlgorithm,

    /// Base64-encoded public-key-wrapped vault key.
    pub wrapped_key: String,
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

pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: u64 = 30;
pub const MIN_CLIPBOARD_CLEAR_SECONDS: u64 = 1;
pub const MAX_CLIPBOARD_CLEAR_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSettings {
    #[serde(default = "default_clipboard_clear_seconds")]
    pub clipboard_clear_seconds: u64,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            clipboard_clear_seconds: default_clipboard_clear_seconds(),
        }
    }
}

const fn default_clipboard_clear_seconds() -> u64 {
    DEFAULT_CLIPBOARD_CLEAR_SECONDS
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPayload {
    #[serde(default)]
    pub settings: VaultSettings,
    pub entries: Vec<VaultEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    pub name: String,
    pub hotkey: String,
    pub secret: String,
}

impl VaultEnvelope {
    #[allow(dead_code)]
    pub fn version(&self) -> u32 {
        match self {
            Self::V1(envelope) => envelope.version,
            Self::V2(envelope) => envelope.version,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::V1(envelope) => envelope.validate(),
            Self::V2(envelope) => envelope.validate(),
        }
    }
}

impl VaultEnvelopeV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VAULT_FORMAT_VERSION_V1 {
            return Err(format!(
                "invalid version-1 vault format value {}; expected {}",
                self.version, VAULT_FORMAT_VERSION_V1
            ));
        }

        self.kdf.validate("vault KDF")?;
        self.cipher.validate("vault cipher")?;

        Ok(())
    }
}

impl VaultEnvelopeV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VAULT_FORMAT_VERSION_V2 {
            return Err(format!(
                "invalid version-2 vault format value {}; expected {}",
                self.version, VAULT_FORMAT_VERSION_V2
            ));
        }

        self.cipher.validate("vault payload cipher")?;
        self.unlock.validate()?;

        Ok(())
    }
}

impl VaultUnlockMethod {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Password { wrapper } => wrapper.validate("password wrapper"),

            Self::Cac {
                cac_wrapper,
                backup_wrapper,
            } => {
                cac_wrapper.validate()?;
                backup_wrapper.validate("CAC backup wrapper")
            }

            Self::Certificate {
                certificate_wrapper,
                backup_wrapper,
            } => {
                certificate_wrapper.validate()?;
                backup_wrapper.validate("certificate backup wrapper")
            }
        }
    }
}

impl PasswordKeyWrapper {
    pub fn validate(&self, context: &str) -> Result<(), String> {
        self.kdf.validate(&format!("{context} KDF"))?;
        self.cipher.validate(&format!("{context} cipher"))?;

        Ok(())
    }
}

impl CacKeyWrapper {
    pub fn validate(&self) -> Result<(), String> {
        if !self.slot.eq_ignore_ascii_case(CAC_KEY_MANAGEMENT_SLOT) {
            return Err(format!(
                "unsupported CAC slot '{}'; expected {}",
                self.slot, CAC_KEY_MANAGEMENT_SLOT
            ));
        }

        if self.certificate_sha256.trim().is_empty() {
            return Err("CAC certificate SHA-256 fingerprint is missing".to_string());
        }

        if self.algorithm != CAC_WRAP_ALGORITHM_RSA_OAEP_SHA256 {
            return Err(format!(
                "unsupported CAC wrapping algorithm '{}'",
                self.algorithm
            ));
        }

        if self.wrapped_key.trim().is_empty() {
            return Err("CAC-wrapped vault key is missing".to_string());
        }

        Ok(())
    }
}

impl CertificateBackend {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Cac { slot } => {
                if !slot.eq_ignore_ascii_case(CAC_KEY_MANAGEMENT_SLOT) {
                    return Err(format!(
                        "unsupported CAC slot '{}'; expected {}",
                        slot, CAC_KEY_MANAGEMENT_SLOT
                    ));
                }

                Ok(())
            }

            Self::Pfx { suggested_filename } => {
                if suggested_filename
                    .as_deref()
                    .is_some_and(|filename| filename.trim().is_empty())
                {
                    return Err("PFX suggested filename cannot be empty when provided".to_string());
                }

                Ok(())
            }
        }
    }
}

impl CertificateKeyWrapper {
    pub fn validate(&self) -> Result<(), String> {
        self.backend.validate()?;

        if self.identity.sha256_fingerprint.trim().is_empty() {
            return Err("certificate SHA-256 fingerprint is missing".to_string());
        }

        if self.identity.subject.trim().is_empty() {
            return Err("certificate subject is missing".to_string());
        }

        if self.identity.issuer.trim().is_empty() {
            return Err("certificate issuer is missing".to_string());
        }

        if self.identity.serial_number.trim().is_empty() {
            return Err("certificate serial number is missing".to_string());
        }

        if self.wrapped_key.trim().is_empty() {
            return Err("certificate-wrapped vault key is missing".to_string());
        }

        Ok(())
    }
}

impl KdfParameters {
    pub fn validate(&self, context: &str) -> Result<(), String> {
        if self.algorithm != KDF_ALGORITHM {
            return Err(format!(
                "unsupported {context} algorithm '{}'",
                self.algorithm
            ));
        }

        if self.memory_kib == 0 {
            return Err(format!("{context} memory_kib must be greater than zero"));
        }

        if self.iterations == 0 {
            return Err(format!("{context} iterations must be greater than zero"));
        }

        if self.parallelism == 0 {
            return Err(format!("{context} parallelism must be greater than zero"));
        }

        if self.salt.is_empty() {
            return Err(format!("{context} salt is missing"));
        }

        Ok(())
    }
}

impl CipherPayload {
    pub fn validate(&self, context: &str) -> Result<(), String> {
        if self.algorithm != CIPHER_ALGORITHM {
            return Err(format!(
                "unsupported {context} algorithm '{}'",
                self.algorithm
            ));
        }

        if self.nonce.is_empty() {
            return Err(format!("{context} nonce is missing"));
        }

        if self.ciphertext.is_empty() {
            return Err(format!("{context} ciphertext is missing"));
        }

        Ok(())
    }
}

impl VaultSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_CLIPBOARD_CLEAR_SECONDS..=MAX_CLIPBOARD_CLEAR_SECONDS)
            .contains(&self.clipboard_clear_seconds)
        {
            return Err(format!(
                "clipboard clear timeout must be between {} and {} seconds",
                MIN_CLIPBOARD_CLEAR_SECONDS, MAX_CLIPBOARD_CLEAR_SECONDS
            ));
        }

        Ok(())
    }
}

impl VaultPayload {
    pub fn validate(&self) -> Result<(), String> {
        self.settings.validate()
    }

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

    fn test_kdf() -> KdfParameters {
        KdfParameters {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
            salt: "salt".to_string(),
        }
    }

    fn test_cipher() -> CipherPayload {
        CipherPayload {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce: "nonce".to_string(),
            ciphertext: "ciphertext".to_string(),
        }
    }

    fn test_certificate_identity() -> CertificateIdentity {
        CertificateIdentity {
            sha256_fingerprint: "AA:BB:CC:DD".to_string(),
            subject: "CN=PasswordOut Test".to_string(),
            issuer: "CN=PasswordOut Test".to_string(),
            serial_number: "01".to_string(),
            not_before: "Jun 24 00:00:00 2026 GMT".to_string(),
            not_after: "Jun 24 00:00:00 2031 GMT".to_string(),
        }
    }

    #[test]
    fn payload_can_find_entries() {
        let payload = VaultPayload {
            settings: VaultSettings::default(),
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
    fn payload_without_settings_uses_default_timeout() {
        let payload: VaultPayload =
            serde_json::from_str(r#"{"entries":[]}"#).expect("legacy payload should deserialize");

        assert_eq!(
            payload.settings.clipboard_clear_seconds,
            DEFAULT_CLIPBOARD_CLEAR_SECONDS
        );
    }

    #[test]
    fn payload_settings_validate_timeout_range() {
        let mut settings = VaultSettings::default();
        assert!(settings.validate().is_ok());

        settings.clipboard_clear_seconds = 0;
        assert!(settings.validate().is_err());

        settings.clipboard_clear_seconds = MAX_CLIPBOARD_CLEAR_SECONDS + 1;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn version_1_envelope_remains_valid() {
        let envelope = VaultEnvelope::V1(VaultEnvelopeV1 {
            version: VAULT_FORMAT_VERSION_V1,
            kdf: test_kdf(),
            cipher: test_cipher(),
        });

        assert_eq!(envelope.version(), VAULT_FORMAT_VERSION_V1);
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn version_2_password_envelope_is_valid() {
        let envelope = VaultEnvelope::V2(VaultEnvelopeV2 {
            version: VAULT_FORMAT_VERSION_V2,
            unlock: VaultUnlockMethod::Password {
                wrapper: PasswordKeyWrapper {
                    kdf: test_kdf(),
                    cipher: test_cipher(),
                },
            },
            cipher: test_cipher(),
        });

        assert_eq!(envelope.version(), VAULT_FORMAT_VERSION_V2);
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn legacy_version_2_cac_envelope_remains_valid() {
        let envelope = VaultEnvelope::V2(VaultEnvelopeV2 {
            version: VAULT_FORMAT_VERSION_V2,
            unlock: VaultUnlockMethod::Cac {
                cac_wrapper: CacKeyWrapper {
                    slot: CAC_KEY_MANAGEMENT_SLOT.to_string(),
                    certificate_sha256: "sha256-fingerprint".to_string(),
                    algorithm: CAC_WRAP_ALGORITHM_RSA_OAEP_SHA256.to_string(),
                    wrapped_key: "wrapped-key".to_string(),
                },
                backup_wrapper: PasswordKeyWrapper {
                    kdf: test_kdf(),
                    cipher: test_cipher(),
                },
            },
            cipher: test_cipher(),
        });

        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn legacy_cac_wrapper_rejects_wrong_slot() {
        let wrapper = CacKeyWrapper {
            slot: "9A".to_string(),
            certificate_sha256: "sha256-fingerprint".to_string(),
            algorithm: CAC_WRAP_ALGORITHM_RSA_OAEP_SHA256.to_string(),
            wrapped_key: "wrapped-key".to_string(),
        };

        assert!(wrapper.validate().is_err());
    }

    #[test]
    fn version_2_pfx_certificate_envelope_is_valid() {
        let envelope = VaultEnvelope::V2(VaultEnvelopeV2 {
            version: VAULT_FORMAT_VERSION_V2,
            unlock: VaultUnlockMethod::Certificate {
                certificate_wrapper: CertificateKeyWrapper {
                    backend: CertificateBackend::Pfx {
                        suggested_filename: Some("password-out-vault.pfx".to_string()),
                    },
                    identity: test_certificate_identity(),
                    algorithm: KeyWrapAlgorithm::RsaOaepSha256,
                    wrapped_key: "wrapped-key".to_string(),
                },
                backup_wrapper: PasswordKeyWrapper {
                    kdf: test_kdf(),
                    cipher: test_cipher(),
                },
            },
            cipher: test_cipher(),
        });

        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn generic_certificate_wrapper_supports_cac_backend() {
        let wrapper = CertificateKeyWrapper {
            backend: CertificateBackend::Cac {
                slot: CAC_KEY_MANAGEMENT_SLOT.to_string(),
            },
            identity: test_certificate_identity(),
            algorithm: KeyWrapAlgorithm::RsaOaepSha256,
            wrapped_key: "wrapped-key".to_string(),
        };

        assert!(wrapper.validate().is_ok());
    }

    #[test]
    fn generic_certificate_wrapper_rejects_wrong_cac_slot() {
        let wrapper = CertificateKeyWrapper {
            backend: CertificateBackend::Cac {
                slot: "9A".to_string(),
            },
            identity: test_certificate_identity(),
            algorithm: KeyWrapAlgorithm::RsaOaepSha256,
            wrapped_key: "wrapped-key".to_string(),
        };

        assert!(wrapper.validate().is_err());
    }

    #[test]
    fn generic_certificate_wrapper_rejects_empty_pfx_filename_hint() {
        let wrapper = CertificateKeyWrapper {
            backend: CertificateBackend::Pfx {
                suggested_filename: Some("   ".to_string()),
            },
            identity: test_certificate_identity(),
            algorithm: KeyWrapAlgorithm::RsaOaepSha256,
            wrapped_key: "wrapped-key".to_string(),
        };

        assert!(wrapper.validate().is_err());
    }

    #[test]
    fn envelope_validation_rejects_unknown_version() {
        let envelope = VaultEnvelope::V1(VaultEnvelopeV1 {
            version: 99,
            kdf: test_kdf(),
            cipher: test_cipher(),
        });

        assert!(envelope.validate().is_err());
    }
}
