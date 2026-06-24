// Reusable vault cryptography, format, storage, and service APIs.
//
// User-facing CLI commands remain in src/vault/commands.rs and are not
// included here.

#[path = "vault/crypto.rs"]
pub mod crypto;

#[path = "vault/format.rs"]
pub mod format;

#[path = "vault/service.rs"]
pub mod service;

#[path = "vault/storage.rs"]
pub mod storage;

pub use crypto::{decrypt_payload, encrypt_payload};

pub use format::{
    CertificateBackend, CertificateKeyWrapper, VaultEntry, VaultEnvelope, VaultEnvelopeV2,
    VaultPayload, VaultUnlockMethod,
};

pub use service::{
    initialize_cac_vault, initialize_certificate_vault, initialize_password_vault,
    load_certificate_vault, load_password_vault, load_vault, save_password_vault, save_vault,
};

pub use storage::{default_vault_path, read_envelope, write_envelope};
