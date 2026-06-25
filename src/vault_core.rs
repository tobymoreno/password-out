// Reusable vault cryptography, format, storage, and service APIs.
//
// User-facing CLI commands remain in src/vault/commands.rs and are not
// included here.

#[path = "vault/access.rs"]
pub mod access;

#[path = "vault/crypto.rs"]
pub mod crypto;

#[path = "vault/entry_ops.rs"]
pub mod entry_ops;

#[path = "vault/format.rs"]
pub mod format;

#[path = "vault/service.rs"]
pub mod service;

#[path = "vault/storage.rs"]
pub mod storage;

pub use access::{CertificateVaultAccess, PasswordVaultAccess, VaultAccess};

#[cfg(any(test, feature = "dev-tools"))]
pub use access::InMemoryVaultAccess;

pub use crypto::{decrypt_payload, encrypt_payload};

pub use entry_ops::{add_entry_with_access, list_entries_with_access, remove_entry_with_access};

pub use format::{
    CertificateBackend, CertificateKeyWrapper, VaultEntry, VaultEnvelope, VaultEnvelopeV2,
    VaultPayload, VaultUnlockMethod,
};

pub use service::{
    initialize_cac_vault, initialize_certificate_vault, initialize_password_vault,
    load_certificate_vault, load_password_vault, save_password_vault, save_vault,
};

pub use storage::{default_vault_path, read_envelope, write_envelope};
