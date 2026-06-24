pub mod commands;
pub mod crypto;
pub mod format;
pub mod password;
pub mod service;
pub mod storage;

pub use commands::{run_add, run_init, run_list, run_remove};
pub use crypto::{decrypt_payload, encrypt_payload};
pub use format::{VaultEntry, VaultPayload};

pub use password::{prompt_cac_pin, prompt_master_password, prompt_new_master_password};

pub use service::{initialize_cac_vault, initialize_password_vault, load_vault, save_vault};
pub use storage::{default_vault_path, read_envelope, write_envelope};
