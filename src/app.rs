use crate::{
    cli::{self, Mode},
    hotkey, overlay, vault,
};

pub fn run() -> Result<(), String> {
    let config = cli::parse_args(vault::default_vault_path()?)?;

    match config.mode {
        Mode::Listen => {
            let payload = vault::load_payload_for_cli(&config.vault_file)?;

            let clear_seconds = config
                .clear_seconds
                .unwrap_or(payload.settings.clipboard_clear_seconds);

            let runtime_entries = payload
                .entries
                .into_iter()
                .map(|entry| hotkey::RuntimeEntry {
                    name: entry.name,
                    hotkey: entry.hotkey,
                    secret: entry.secret,
                })
                .collect();

            hotkey::listen(runtime_entries, clear_seconds)
        }

        Mode::VaultInit => vault::run_init(&config.vault_file),

        Mode::VaultRecover => vault::run_recover(&config.vault_file),

        Mode::VaultRotateCertificate => vault::run_rotate_certificate(&config.vault_file),

        Mode::VaultInfo => vault::run_info(&config.vault_file),

        Mode::VaultTimeout => vault::run_timeout(&config.vault_file),

        Mode::EntryAdd => vault::run_add(&config.vault_file),

        Mode::EntryList => vault::run_list(&config.vault_file),

        Mode::EntryRemove => vault::run_remove(&config.vault_file),

        Mode::Overlay(message) => {
            overlay::show_overlay(&message);
            Ok(())
        }
    }
}
