mod access;
mod entry_ops;

pub use entry_ops::{add_entry_with_access, list_entries_with_access, remove_entry_with_access};

pub mod commands;
pub mod crypto;
pub mod format;
pub mod password;
pub mod service;
pub mod storage;

pub use commands::{run_add, run_init, run_list, run_remove};
pub use crypto::{decrypt_payload, encrypt_payload};
pub use format::{VaultEntry, VaultPayload};
pub use password::{prompt_master_password, prompt_new_master_password};

#[allow(unused_imports)]
pub use service::{
    CertificateVaultSession, initialize_cac_vault, initialize_certificate_vault,
    initialize_password_vault, load_vault, open_certificate_vault_session,
    save_certificate_vault_session, save_vault,
};

pub use storage::{default_vault_path, read_envelope, write_envelope};
