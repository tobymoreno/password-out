use crate::{
    cli::{self, Mode},
    hotkey, overlay, vault,
};

pub fn run() -> Result<(), String> {
    let config = cli::parse_args(vault::default_vault_path()?)?;

    match config.mode {
        Mode::Listen => {
            let master_password = vault::prompt_master_password("Master password: ")?;
            let payload = vault::load_vault(&config.vault_file, master_password.as_str())?;

            let runtime_entries = payload
                .entries
                .into_iter()
                .map(|entry| hotkey::RuntimeEntry {
                    name: entry.name,
                    hotkey: entry.hotkey,
                    secret: entry.secret,
                })
                .collect();

            hotkey::listen(runtime_entries, config.clear_seconds)
        }

        Mode::VaultInit => vault::run_init(&config.vault_file),

        Mode::VaultRecover => vault::run_recover(&config.vault_file),

        Mode::VaultRotateCertificate => vault::run_rotate_certificate(&config.vault_file),

        Mode::VaultInfo => vault::run_info(&config.vault_file),

        Mode::EntryAdd => vault::run_add(&config.vault_file),

        Mode::EntryList => vault::run_list(&config.vault_file),

        Mode::EntryRemove => vault::run_remove(&config.vault_file),

        Mode::Overlay(message) => {
            overlay::show_overlay(&message);
            Ok(())
        }
    }
}
